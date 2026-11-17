//! Windows handle enumeration using NT APIs

use crate::aligned_buf::AlignedBuf;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::mem;
use std::sync::{LazyLock, RwLock};
#[cfg(feature = "handles_v2")]
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Foundation::{
    NTSTATUS, STATUS_ACCESS_DENIED, STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS,
};

// NT API constants
const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 64;

#[cfg(feature = "handles_v2")]
#[allow(dead_code)]
const OBJECT_TYPE_INFORMATION: u32 = 2;

#[repr(C)]
struct SystemExtendedHandleTableEntryInformation {
    object: *mut std::ffi::c_void,
    unique_process_id: usize,
    handle_value: usize,
    granted_access: u32,
    creator_back_trace_index: u16,
    object_type_index: u16,
    handle_attributes: u32,
    reserved: u32,
}

#[repr(C)]
struct SystemExtendedHandleInformation {
    number_of_handles: usize,
    reserved: usize,
    // Followed by array of SystemExtendedHandleTableEntryInformation
}

#[cfg(feature = "handles_v2")]
#[allow(dead_code)]
#[repr(C)]
struct ObjectTypeInformation {
    type_name: windows::Win32::Foundation::UNICODE_STRING,
    total_number_of_objects: u32,
    total_number_of_handles: u32,
    // ... other fields we don't need
}

// NT API imports
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySystemInformation(
        system_information_class: u32,
        system_information: *mut std::ffi::c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> NTSTATUS;

    #[cfg(feature = "handles_v2")]
    #[allow(dead_code)]
    fn NtQueryObject(
        handle: HANDLE,
        object_information_class: u32,
        object_information: *mut std::ffi::c_void,
        object_information_length: u32,
        return_length: *mut u32,
    ) -> NTSTATUS;
}

/// Raw handle entry from system enumeration
#[derive(Debug, Clone)]
pub struct HandleEntry {
    pub pid: u32,
    pub handle_value: usize,
    pub object_type_index: u16,
    pub granted_access: u32,
}

/// Map common Windows handle type indices to human-readable names
/// These indices are consistent on Windows 10 21H2+ and Windows 11
pub fn get_type_name(type_index: u16) -> String {
    match type_index {
        5 => "Token".to_string(),
        7 => "Process".to_string(),
        8 => "Thread".to_string(),
        12 => "Job".to_string(),
        15 => "Event".to_string(),
        17 => "Mutant".to_string(),
        19 => "Semaphore".to_string(),
        30 => "File".to_string(),
        37 => "Key".to_string(),
        40 => "Section".to_string(),
        42 => "IoCompletion".to_string(),
        _ => format!("TypeIndex{type_index}"),
    }
}

/// Enumerate all handles in the system
///
/// # Safety
/// This function uses NtQuerySystemInformation which is inherently unsafe.
/// The buffer is properly sized and the returned data is validated.
pub fn enumerate_handles() -> Result<Vec<HandleEntry>> {
    /// Hard ceiling on the snapshot buffer (each entry is 40 bytes, so ~2.6M handles).
    const MAX_BUFFER_BYTES: usize = 100 * 1024 * 1024;

    let mut buffer = AlignedBuf::new(1024 * 1024);
    loop {
        let mut return_length: u32 = 0;
        // SAFETY: NtQuerySystemInformation writes at most `buffer.len()` bytes into `buffer`,
        // a valid, writable, 8-byte-aligned allocation of that size.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_EXTENDED_HANDLE_INFORMATION,
                buffer.as_mut_ptr().cast::<std::ffi::c_void>(),
                buffer.len_u32(),
                &raw mut return_length,
            )
        };

        if status == STATUS_SUCCESS {
            break;
        } else if status == STATUS_INFO_LENGTH_MISMATCH {
            // The handle table keeps growing between calls; ask for some headroom.
            let wanted = (return_length as usize)
                .saturating_add(256 * 1024)
                .max(buffer.len().saturating_mul(2));
            if wanted > MAX_BUFFER_BYTES {
                return Err(anyhow!("Handle enumeration requires too much memory"));
            }
            buffer = AlignedBuf::new(wanted);
        } else if status == STATUS_ACCESS_DENIED {
            return Err(anyhow!(
                "Access Denied: Run as Administrator to view handles"
            ));
        } else {
            return Err(anyhow!("NtQuerySystemInformation failed: 0x{:X}", status.0));
        }
    }

    if !buffer.fits::<SystemExtendedHandleInformation>(0) {
        return Ok(Vec::new());
    }
    // SAFETY: the header fits in the buffer, which is 8-byte aligned.
    let number_of_handles =
        unsafe { (*buffer.ptr_at::<SystemExtendedHandleInformation>(0)).number_of_handles };

    // Entries follow the header. Never read past the bytes the buffer actually holds.
    let header_size = mem::size_of::<SystemExtendedHandleInformation>();
    let entry_size = mem::size_of::<SystemExtendedHandleTableEntryInformation>();
    let max_entries = buffer.len().saturating_sub(header_size) / entry_size;
    let count = number_of_handles.min(max_entries);

    let entries = buffer.ptr_at::<SystemExtendedHandleTableEntryInformation>(header_size);
    // SAFETY: `count` entries fit after the header (checked above), the header size is a
    // multiple of 8, and the entries were written by the kernel.
    let entries = unsafe { std::slice::from_raw_parts(entries, count) };

    Ok(entries
        .iter()
        .map(|e| HandleEntry {
            pid: u32::try_from(e.unique_process_id).unwrap_or(u32::MAX),
            handle_value: e.handle_value,
            object_type_index: e.object_type_index,
            granted_access: e.granted_access,
        })
        .collect())
}

/// Global cache for type names (type_index -> type_name)
static TYPE_NAME_CACHE: LazyLock<RwLock<HashMap<u16, String>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Populate type name cache with well-known Windows handle type indices
/// Type indices are consistent on Windows 10 21H2+ and Windows 11
pub fn populate_type_cache(handles: &[HandleEntry]) {
    let mut cache_map = HashMap::new();

    // Helper function to map well-known type indices
    fn well_known_type(idx: u16) -> Option<&'static str> {
        match idx {
            5 => Some("Token"),
            7 => Some("Process"),
            8 => Some("Thread"),
            12 => Some("Job"),
            15 => Some("Event"),
            17 => Some("Mutant"),
            19 => Some("Semaphore"),
            30 => Some("File"),
            37 => Some("Key"),
            40 => Some("Section"),
            42 => Some("IoCompletion"),
            _ => None,
        }
    }

    // Populate cache with well-known names or TypeIndexN for all observed indices
    for entry in handles.iter().take(1000).step_by(10) {
        if cache_map.contains_key(&entry.object_type_index) {
            continue;
        }
        let name = well_known_type(entry.object_type_index).map_or_else(
            || format!("TypeIndex{}", entry.object_type_index),
            std::string::ToString::to_string,
        );
        cache_map.insert(entry.object_type_index, name);
    }

    if let Ok(mut cache) = TYPE_NAME_CACHE.write() {
        *cache = cache_map;
    }
}
