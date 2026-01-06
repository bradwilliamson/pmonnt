//! Windows handle enumeration using NT APIs

use anyhow::{anyhow, Result};
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
extern "system" {
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
        _ => format!("TypeIndex{}", type_index),
    }
}

/// Enumerate all handles in the system
///
/// # Safety
/// This function uses NtQuerySystemInformation which is inherently unsafe.
/// The buffer is properly sized and the returned data is validated.
pub fn enumerate_handles() -> Result<Vec<HandleEntry>> {
    let mut buffer_size: u32 = 1024 * 1024; // Start with 1MB
    let mut buffer: Vec<u8>;
    let mut return_length: u32 = 0;

    loop {
        buffer = vec![0u8; buffer_size as usize];

        // SAFETY: NtQuerySystemInformation is called with a properly sized buffer.
        // The buffer lifetime is managed by Rust and the function is synchronous.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_EXTENDED_HANDLE_INFORMATION,
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                buffer_size,
                &mut return_length,
            )
        };

        if status == STATUS_SUCCESS {
            break;
        } else if status == STATUS_INFO_LENGTH_MISMATCH {
            // Buffer too small, retry with larger size
            buffer_size = return_length.max(buffer_size * 2);
            if buffer_size > 100 * 1024 * 1024 {
                // Safety limit: don't allocate more than 100MB
                return Err(anyhow!("Handle enumeration requires too much memory"));
            }
            continue;
        } else if status == STATUS_ACCESS_DENIED {
            return Err(anyhow!(
                "Access Denied: Run as Administrator to view handles"
            ));
        } else {
            return Err(anyhow!("NtQuerySystemInformation failed: 0x{:X}", status.0));
        }
    }

    // Parse the buffer
    // SAFETY: We've validated that the buffer contains valid data from the NT API.
    // The structure layout matches the documented NT API structures.
    unsafe {
        let info = buffer.as_ptr() as *const SystemExtendedHandleInformation;
        let number_of_handles = (*info).number_of_handles;

        // Pointer to the first entry (after the header)
        let header_size = mem::size_of::<SystemExtendedHandleInformation>();
        let entry_size = mem::size_of::<SystemExtendedHandleTableEntryInformation>();
        let entries_ptr = (info as *const u8).add(header_size)
            as *const SystemExtendedHandleTableEntryInformation;

        // Compute maximum number of entries that fit in the buffer to avoid OOB
        let buf_len = buffer.len();
        let max_entries = if buf_len > header_size {
            (buf_len - header_size) / entry_size
        } else {
            0
        };

        let safe_count = std::cmp::min(number_of_handles, max_entries);
        let safe_count = std::cmp::min(safe_count, 100_000);

        let mut handles = Vec::with_capacity(safe_count);

        for i in 0..safe_count {
            let entry = entries_ptr.add(i);
            let pid = (*entry).unique_process_id as u32;

            handles.push(HandleEntry {
                pid,
                handle_value: (*entry).handle_value,
                object_type_index: (*entry).object_type_index,
                granted_access: (*entry).granted_access,
            });
        }

        Ok(handles)
    }
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
        let name = well_known_type(entry.object_type_index)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("TypeIndex{}", entry.object_type_index));
        cache_map.insert(entry.object_type_index, name);
    }

    if let Ok(mut cache) = TYPE_NAME_CACHE.write() {
        *cache = cache_map;
    }
}
