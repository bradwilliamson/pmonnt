//! Windows process metrics (memory, CPU times)
//! Provides memory and CPU time retrieval via Windows API

use crate::aligned_buf::AlignedBuf;
use crate::win::HandleGuard;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::mem;
use windows::Win32::Foundation::{FILETIME, HANDLE};
use windows::Win32::Foundation::{NTSTATUS, STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS};
use windows::Win32::System::ProcessStatus::{
    GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
};
use windows::Win32::System::Threading::{
    GetPriorityClass, GetProcessIoCounters, GetProcessTimes, IO_COUNTERS, OpenProcess,
    PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
};

// GetGuiResources is in User32, but might need different import path
// For now, we'll call it via dynamic linking
#[link(name = "User32")]
unsafe extern "system" {
    fn GetGuiResources(hProcess: HANDLE, uiFlags: u32) -> u32;
}

const GR_GDIOBJECTS: u32 = 0;
const GR_USEROBJECTS: u32 = 1;

const SYSTEM_PROCESS_INFORMATION_CLASS: u32 = 5;

/// `SYSTEM_PROCESS_INFORMATION` as returned by `NtQuerySystemInformation(SystemProcessInformation)`
/// (documented in winternl.h; the full layout is the one used by Process Hacker/phnt).
#[repr(C)]
struct SystemProcessInformation {
    next_entry_offset: u32,
    number_of_threads: u32,
    working_set_private_size: i64,
    hard_fault_count: u32,
    number_of_threads_high_watermark: u32,
    cycle_time: u64,
    create_time: i64,
    user_time: i64,
    kernel_time: i64,
    image_name: windows::Win32::Foundation::UNICODE_STRING,
    base_priority: i32,
    unique_process_id: windows::Win32::Foundation::HANDLE,
    inherited_from_unique_process_id: windows::Win32::Foundation::HANDLE,
    handle_count: u32,
    session_id: u32,
    unique_process_key: usize,
    peak_virtual_size: usize,
    virtual_size: usize,
    page_fault_count: u32,
    peak_working_set_size: usize,
    working_set_size: usize,
    quota_peak_paged_pool_usage: usize,
    quota_paged_pool_usage: usize,
    quota_peak_non_paged_pool_usage: usize,
    quota_non_paged_pool_usage: usize,
    pagefile_usage: usize,
    peak_pagefile_usage: usize,
    private_page_count: usize,
    read_operation_count: i64,
    write_operation_count: i64,
    other_operation_count: i64,
    read_transfer_count: i64,
    write_transfer_count: i64,
    other_transfer_count: i64,
}

/// Per-process values from one `SystemProcessInformation` snapshot.
///
/// One `NtQuerySystemInformation` call returns these for every process on the system,
/// including ones PMonNT cannot open, so it is both cheaper and more complete than
/// opening each process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemProcessEntry {
    pub pid: u32,
    pub parent_pid: u32,
    pub thread_count: u32,
    pub handle_count: u32,
    pub session_id: u32,
    pub cycle_time: u64,
    /// Creation time as a FILETIME (100 ns ticks since 1601); 0 for the idle process.
    pub create_time: u64,
    /// Kernel-mode CPU time in 100 ns units.
    pub kernel_time_100ns: u64,
    /// User-mode CPU time in 100 ns units.
    pub user_time_100ns: u64,
    pub working_set_bytes: u64,
    pub private_bytes: u64,
    /// Reserved + committed virtual address space.
    pub virtual_size_bytes: u64,
    pub io: IoCounters,
}

impl SystemProcessEntry {
    fn from_raw(spi: &SystemProcessInformation) -> Self {
        let nonneg = |v: i64| u64::try_from(v).unwrap_or(0);
        Self {
            pid: handle_to_pid(spi.unique_process_id),
            parent_pid: handle_to_pid(spi.inherited_from_unique_process_id),
            thread_count: spi.number_of_threads,
            handle_count: spi.handle_count,
            session_id: spi.session_id,
            cycle_time: spi.cycle_time,
            create_time: nonneg(spi.create_time),
            kernel_time_100ns: nonneg(spi.kernel_time),
            user_time_100ns: nonneg(spi.user_time),
            working_set_bytes: spi.working_set_size as u64,
            private_bytes: spi.private_page_count as u64,
            virtual_size_bytes: spi.virtual_size as u64,
            io: IoCounters {
                read_bytes: nonneg(spi.read_transfer_count),
                write_bytes: nonneg(spi.write_transfer_count),
                other_bytes: nonneg(spi.other_transfer_count),
                read_ops: nonneg(spi.read_operation_count),
                write_ops: nonneg(spi.write_operation_count),
                other_ops: nonneg(spi.other_operation_count),
            },
        }
    }
}

/// Process IDs travel through the NT API as HANDLE-sized values; they always fit in a u32.
fn handle_to_pid(h: windows::Win32::Foundation::HANDLE) -> u32 {
    u32::try_from(h.0 as usize).unwrap_or(u32::MAX)
}

/// Upper bound for the SystemProcessInformation buffer. A system with ~100k threads needs
/// about 10 MB, so this leaves plenty of room while still bounding a runaway loop.
const MAX_SPI_BUFFER_BYTES: usize = 64 * 1024 * 1024;

/// Fetch the raw `SystemProcessInformation` table, growing the buffer until it fits.
fn query_spi_buffer() -> Result<AlignedBuf> {
    let mut buffer = AlignedBuf::new(1024 * 1024);
    loop {
        let mut return_length: u32 = 0;
        // SAFETY: NtQuerySystemInformation writes at most `buffer.len()` bytes into `buffer`,
        // which is a valid, writable, 8-byte-aligned allocation of that size.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_PROCESS_INFORMATION_CLASS,
                buffer.as_mut_ptr().cast::<std::ffi::c_void>(),
                buffer.len_u32(),
                &raw mut return_length,
            )
        };

        if status == STATUS_SUCCESS {
            return Ok(buffer);
        }
        if status != STATUS_INFO_LENGTH_MISMATCH {
            return Err(anyhow!(
                "NtQuerySystemInformation(SystemProcessInformation) failed: 0x{:X}",
                status.0
            ));
        }

        // The table can grow between calls, so ask for headroom beyond what was reported.
        let wanted = (return_length as usize)
            .saturating_add(64 * 1024)
            .max(buffer.len().saturating_mul(2));
        if wanted > MAX_SPI_BUFFER_BYTES {
            return Err(anyhow!(
                "SystemProcessInformation buffer too large ({wanted} bytes)"
            ));
        }
        buffer = AlignedBuf::new(wanted);
    }
}

/// Walk the entries of a `SystemProcessInformation` buffer.
fn for_each_spi_entry(buffer: &AlignedBuf, mut f: impl FnMut(&SystemProcessInformation) -> bool) {
    let mut offset: usize = 0;
    while buffer.fits::<SystemProcessInformation>(offset) {
        // SAFETY: `fits` checked that a whole entry lies inside the buffer. The buffer start is
        // 8-byte aligned and the kernel aligns every NextEntryOffset to 8 bytes.
        let spi = unsafe { &*buffer.ptr_at::<SystemProcessInformation>(offset) };
        if !f(spi) || spi.next_entry_offset == 0 {
            break;
        }
        offset = offset.saturating_add(spi.next_entry_offset as usize);
    }
}

/// Query every process's counters with a single system call.
pub fn query_system_processes() -> Result<Vec<SystemProcessEntry>> {
    let buffer = query_spi_buffer()?;
    let mut entries = Vec::with_capacity(512);
    for_each_spi_entry(&buffer, |spi| {
        entries.push(SystemProcessEntry::from_raw(spi));
        true
    });
    Ok(entries)
}

/// Every process with its image name, from a single `SystemProcessInformation` query.
///
/// PID, parent, creation time and name all come from the same kernel snapshot, so they
/// always describe the same process instance (two separate queries can see different
/// processes under a recycled PID).
pub fn query_processes_with_names() -> Result<Vec<(SystemProcessEntry, String)>> {
    let buffer = query_spi_buffer()?;
    let mut entries = Vec::with_capacity(512);
    for_each_spi_entry(&buffer, |spi| {
        entries.push((
            SystemProcessEntry::from_raw(spi),
            spi_image_name(&buffer, &spi.image_name),
        ));
        true
    });
    Ok(entries)
}

/// Decode an entry's image name. The kernel points `Buffer` into the same output buffer; the
/// name is read from the buffer's bytes, and a pointer or length outside it yields "".
fn spi_image_name(
    buffer: &AlignedBuf,
    name: &windows::Win32::Foundation::UNICODE_STRING,
) -> String {
    let len_bytes = usize::from(name.Length);
    let Some(offset) = (name.Buffer.0 as usize).checked_sub(buffer.as_ptr() as usize) else {
        return String::new();
    };
    let Some(bytes) = offset
        .checked_add(len_bytes)
        .and_then(|end| buffer.as_bytes().get(offset..end))
    else {
        return String::new();
    };
    // An odd trailing byte (malformed length) is ignored.
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| u16::from_le_bytes(pair));
    char::decode_utf16(units)
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Counters for one process from a fresh `SystemProcessInformation` query.
///
/// Callers that need several values for the same PID should call this once rather than
/// using the single-value helpers below, which each re-query the whole table.
pub fn system_process_entry(pid: u32) -> Option<SystemProcessEntry> {
    if pid == 0 {
        return None;
    }
    let buffer = query_spi_buffer().ok()?;
    let mut found = None;
    for_each_spi_entry(&buffer, |spi| {
        if handle_to_pid(spi.unique_process_id) == pid {
            found = Some(SystemProcessEntry::from_raw(spi));
            false
        } else {
            true
        }
    });
    found
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySystemInformation(
        system_information_class: u32,
        system_information: *mut std::ffi::c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> NTSTATUS;
}

pub use crate::metrics::{IoCounters, IoRate, IoRateCalculator, ProcessIoCounters};

/// Get cumulative I/O counters for a process by PID.
///
/// These counters are cumulative since process start; callers generally want to compute rates
/// by sampling and taking deltas over time.
pub fn get_io_counters(pid: u32) -> Result<IoCounters> {
    // SAFETY: OpenProcess requires a valid PID. On success it returns an owned process HANDLE.
    // We immediately wrap it in HandleGuard to ensure CloseHandle is called exactly once.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)? };
    let _guard = HandleGuard::new(handle);

    let mut counters = IO_COUNTERS::default();
    // SAFETY: GetProcessIoCounters requires a valid process HANDLE and a valid mutable pointer
    // to an IO_COUNTERS struct.
    unsafe { GetProcessIoCounters(handle, &raw mut counters)? };

    Ok(IoCounters {
        read_bytes: counters.ReadTransferCount,
        write_bytes: counters.WriteTransferCount,
        other_bytes: counters.OtherTransferCount,
        read_ops: counters.ReadOperationCount,
        write_ops: counters.WriteOperationCount,
        other_ops: counters.OtherOperationCount,
    })
}

/// Get the working set size (memory) for a process by PID
/// Returns None if access is denied or the process doesn't exist
/// Note: Memory info requires additional Windows API calls (psapi.dll GetProcessMemoryInfo)
/// which is more complex to integrate. For now, we return None as a placeholder.
pub fn get_process_memory_by_pid(pid: u32) -> Option<u64> {
    if pid == 0 {
        return None;
    }

    // For working set bytes, we do NOT need PROCESS_VM_READ.
    // Try the lowest privileges first for better coverage.
    // SAFETY: OpenProcess requires a valid PID. On success it returns an owned process HANDLE.
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(h) => h,
        // SAFETY: Retry OpenProcess with a different access mask; same preconditions.
        Err(_) => match unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) } {
            Ok(h) => h,
            Err(_) => return None,
        },
    };

    let guard = HandleGuard::new(handle);
    let result = get_process_memory(guard.raw());
    drop(guard);
    result
}

/// Get Private Bytes (a.k.a. Private Usage) for a process by PID.
///
/// Private Bytes are closer to what Process Explorer shows in its "Private Bytes" graph.
pub fn get_process_private_bytes_by_pid(pid: u32) -> Option<u64> {
    if pid == 0 {
        return None;
    }

    // Private bytes also come from GetProcessMemoryInfo; no VM_READ needed.
    // SAFETY: OpenProcess requires a valid PID. On success it returns an owned process HANDLE.
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(h) => h,
        // SAFETY: Retry OpenProcess with a different access mask; same preconditions.
        Err(_) => match unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) } {
            Ok(h) => h,
            Err(_) => return None,
        },
    };

    let guard = HandleGuard::new(handle);
    let result = get_process_private_bytes(guard.raw());
    drop(guard);
    result
}

/// Get cumulative I/O counters for a process by PID.
///
/// These counters are cumulative since process start; callers generally want to compute rates
/// by sampling and taking deltas over time.
pub fn get_process_io_counters_by_pid(pid: u32) -> Option<ProcessIoCounters> {
    if pid == 0 {
        return None;
    }

    get_io_counters(pid).ok()
}

/// Get a best-effort map of `pid -> working_set_bytes` using
/// `NtQuerySystemInformation(SystemProcessInformation)`.
///
/// This is how Task Manager gets per-process working set with good coverage,
/// and avoids per-PID OpenProcess calls.
pub fn get_working_set_bytes_map() -> Result<HashMap<u32, u64>> {
    Ok(query_system_processes()?
        .into_iter()
        .map(|e| (e.pid, e.working_set_bytes))
        .collect())
}

/// Get kernel + user time for a process by PID (in 100-nanosecond units)
/// Returns (kernel_time, user_time) or None if access is denied
pub fn get_process_times_by_pid(pid: u32) -> Option<(u64, u64)> {
    if pid == 0 {
        return None;
    }

    // SAFETY: OpenProcess requires a valid PID. On success it returns an owned process HANDLE.
    let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) }) else {
        return None;
    };

    let guard = HandleGuard::new(handle);
    let result = get_process_times(guard.raw());
    drop(guard);
    result
}

/// Get the working set size (memory) for a process handle
/// Returns None if access is denied or the process doesn't exist
fn get_process_memory(handle: HANDLE) -> Option<u64> {
    // SAFETY: PROCESS_MEMORY_COUNTERS is a plain-old-data Windows struct; all-zero is a valid
    // initial value before the OS fills it.
    let mut pmc: PROCESS_MEMORY_COUNTERS = unsafe { mem::zeroed() };
    pmc.cb = mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;

    // SAFETY: GetProcessMemoryInfo writes to the structure if successful
    let success = unsafe {
        GetProcessMemoryInfo(
            handle,
            &raw mut pmc,
            mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
    };

    if success.is_ok() {
        Some(pmc.WorkingSetSize as u64)
    } else {
        None
    }
}

fn get_process_private_bytes(handle: HANDLE) -> Option<u64> {
    // SAFETY: Creating zero-initialized POD struct PROCESS_MEMORY_COUNTERS_EX which will be filled by GetProcessMemoryInfo
    let mut pmc: PROCESS_MEMORY_COUNTERS_EX = unsafe { mem::zeroed() };
    pmc.cb = mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;

    // SAFETY: GetProcessMemoryInfo is called with valid handle and properly sized buffer
    let success = unsafe {
        GetProcessMemoryInfo(
            handle,
            // SAFETY: PROCESS_MEMORY_COUNTERS_EX begins with PROCESS_MEMORY_COUNTERS.
            (&raw mut pmc).cast::<PROCESS_MEMORY_COUNTERS>(),
            mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        )
    };

    if success.is_ok() {
        Some(pmc.PrivateUsage as u64)
    } else {
        None
    }
}

/// Convert FILETIME to u64 (100-nanosecond units since epoch)
fn filetime_to_u64(ft: FILETIME) -> u64 {
    let low = u64::from(ft.dwLowDateTime);
    let high = u64::from(ft.dwHighDateTime) << 32;
    low | high
}

/// Get kernel + user time for a process handle (in 100-nanosecond units)
/// Returns (kernel_time, user_time) or None if access is denied
fn get_process_times(handle: HANDLE) -> Option<(u64, u64)> {
    let mut creation_time = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit_time = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut kernel_time = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut user_time = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };

    // SAFETY: GetProcessTimes writes to the structures if successful
    let success = unsafe {
        GetProcessTimes(
            handle,
            &raw mut creation_time,
            &raw mut exit_time,
            &raw mut kernel_time,
            &raw mut user_time,
        )
    };

    if success.is_ok() {
        let kernel_100ns = filetime_to_u64(kernel_time);
        let user_100ns = filetime_to_u64(user_time);
        Some((kernel_100ns, user_100ns))
    } else {
        None
    }
}

pub fn get_process_priority_class_by_pid(pid: u32) -> Option<u32> {
    if pid == 0 {
        return None;
    }

    // SAFETY: OpenProcess requires a valid PID. On success it returns an owned process HANDLE.
    let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) }) else {
        return None;
    };

    let guard = HandleGuard::new(handle);
    // SAFETY: GetPriorityClass requires a valid process HANDLE.
    let result = unsafe { GetPriorityClass(guard.raw()) };
    drop(guard);
    if result == 0 { None } else { Some(result) }
}

pub fn get_process_cycle_time_by_pid(pid: u32) -> Option<u64> {
    system_process_entry(pid).map(|e| e.cycle_time)
}

pub fn get_process_memory_info_by_pid(pid: u32) -> Option<PROCESS_MEMORY_COUNTERS_EX> {
    if pid == 0 {
        return None;
    }

    // SAFETY: OpenProcess requires a valid PID. On success it returns an owned process HANDLE.
    let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) }) else {
        return None;
    };

    let guard = HandleGuard::new(handle);
    // SAFETY: Creating zero-initialized POD struct PROCESS_MEMORY_COUNTERS_EX which will be filled by GetProcessMemoryInfo
    let mut pmc: PROCESS_MEMORY_COUNTERS_EX = unsafe { mem::zeroed() };
    pmc.cb = mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;

    // SAFETY: GetProcessMemoryInfo is called with valid handle and properly sized buffer
    let success = unsafe {
        GetProcessMemoryInfo(
            guard.raw(),
            (&raw mut pmc).cast::<PROCESS_MEMORY_COUNTERS>(),
            mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        )
    };

    drop(guard);
    if success.is_ok() { Some(pmc) } else { None }
}

pub fn get_process_handle_count_by_pid(pid: u32) -> Option<u32> {
    system_process_entry(pid).map(|e| e.handle_count)
}

pub fn get_process_gdi_handles_by_pid(pid: u32) -> Option<u32> {
    if pid == 0 {
        return None;
    }

    // SAFETY: OpenProcess requires a valid PID. On success it returns an owned process HANDLE.
    let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) }) else {
        return None;
    };

    let guard = HandleGuard::new(handle);
    // SAFETY: GetGuiResources requires a valid process HANDLE.
    let count = unsafe { GetGuiResources(guard.raw(), GR_GDIOBJECTS) };
    drop(guard);

    if count > 0 { Some(count) } else { None }
}

pub fn get_process_user_handles_by_pid(pid: u32) -> Option<u32> {
    if pid == 0 {
        return None;
    }

    // SAFETY: OpenProcess requires a valid PID. On success it returns an owned process HANDLE.
    let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) }) else {
        return None;
    };

    let guard = HandleGuard::new(handle);
    // SAFETY: GetGuiResources requires a valid process HANDLE.
    let count = unsafe { GetGuiResources(guard.raw(), GR_USEROBJECTS) };
    drop(guard);

    if count > 0 { Some(count) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn system_process_information_matches_documented_x64_layout() {
        assert_eq!(
            mem::offset_of!(SystemProcessInformation, unique_process_id),
            80
        );
        assert_eq!(mem::offset_of!(SystemProcessInformation, handle_count), 96);
        assert_eq!(
            mem::offset_of!(SystemProcessInformation, working_set_size),
            144
        );
        assert_eq!(
            mem::offset_of!(SystemProcessInformation, private_page_count),
            200
        );
        assert_eq!(
            mem::offset_of!(SystemProcessInformation, read_transfer_count),
            232
        );
        assert_eq!(mem::size_of::<SystemProcessInformation>(), 256);
    }

    #[test]
    fn query_system_processes_finds_this_process() {
        let me = std::process::id();
        let entries = query_system_processes().expect("SystemProcessInformation query");
        let entry = entries
            .iter()
            .find(|e| e.pid == me)
            .expect("own pid listed");
        assert!(entry.thread_count >= 1);
        assert!(entry.working_set_bytes > 0);
        assert_eq!(system_process_entry(me).map(|e| e.pid), Some(me));
    }
}
