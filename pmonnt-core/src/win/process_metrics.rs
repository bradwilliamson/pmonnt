//! Windows process metrics (memory, CPU times)
//! Provides memory and CPU time retrieval via Windows API

use crate::win::HandleGuard;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::mem;
use std::time::Instant;
use windows::Win32::Foundation::{FILETIME, HANDLE};
use windows::Win32::Foundation::{NTSTATUS, STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS};
use windows::Win32::System::ProcessStatus::{
    GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
};
use windows::Win32::System::Threading::{
    GetPriorityClass, GetProcessIoCounters, GetProcessTimes, OpenProcess, IO_COUNTERS,
    PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
};

// GetGuiResources is in User32, but might need different import path
// For now, we'll call it via dynamic linking
#[link(name = "User32")]
extern "system" {
    fn GetGuiResources(hProcess: HANDLE, uiFlags: u32) -> u32;
}

const GR_GDIOBJECTS: u32 = 0;
const GR_USEROBJECTS: u32 = 1;

const SYSTEM_PROCESS_INFORMATION_CLASS: u32 = 5;

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
}

#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(
        system_information_class: u32,
        system_information: *mut std::ffi::c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> NTSTATUS;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IoCounters {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub other_bytes: u64,
    pub read_ops: u64,
    pub write_ops: u64,
    pub other_ops: u64,
}

// Back-compat for existing UI code.
pub type ProcessIoCounters = IoCounters;

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct IoRate {
    pub read_bytes_per_sec: f64,
    pub write_bytes_per_sec: f64,
}

#[derive(Debug, Default)]
pub struct IoRateCalculator {
    prev_counters: HashMap<u32, (Instant, IoCounters)>,
}

impl IoRateCalculator {
    pub fn calculate_rate(&mut self, pid: u32, current: IoCounters) -> IoRate {
        let now = Instant::now();
        let rate = if let Some((prev_time, prev_counters)) = self.prev_counters.get(&pid) {
            let elapsed = now.duration_since(*prev_time).as_secs_f64();
            compute_io_rate(prev_counters, &current, elapsed)
        } else {
            IoRate::default()
        };

        self.prev_counters.insert(pid, (now, current));
        rate
    }

    pub fn remove_pid(&mut self, pid: u32) {
        self.prev_counters.remove(&pid);
    }

    pub fn retain_pids<I>(&mut self, live_pids: I)
    where
        I: IntoIterator<Item = u32>,
    {
        let live: std::collections::HashSet<u32> = live_pids.into_iter().collect();
        self.prev_counters.retain(|pid, _| live.contains(pid));
    }
}

fn compute_io_rate(prev: &IoCounters, current: &IoCounters, elapsed_secs: f64) -> IoRate {
    if elapsed_secs.partial_cmp(&0.0) != Some(std::cmp::Ordering::Greater) {
        return IoRate::default();
    }

    let read_delta = current.read_bytes.saturating_sub(prev.read_bytes);
    let write_delta = current.write_bytes.saturating_sub(prev.write_bytes);

    IoRate {
        read_bytes_per_sec: read_delta as f64 / elapsed_secs,
        write_bytes_per_sec: write_delta as f64 / elapsed_secs,
    }
}

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
    unsafe { GetProcessIoCounters(handle, &mut counters)? };

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
    let mut buffer_size: u32 = 1024 * 1024; // 1MB initial
    let mut return_length: u32 = 0;

    let buffer: Vec<u8> = loop {
        let mut buffer = vec![0u8; buffer_size as usize];
        // SAFETY: NtQuerySystemInformation writes up to `buffer_size` bytes into `buffer`.
        // `buffer` is a valid, writable allocation of that size and `return_length` is valid.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_PROCESS_INFORMATION_CLASS,
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                buffer_size,
                &mut return_length,
            )
        };

        if status == STATUS_SUCCESS {
            break buffer;
        }
        if status == STATUS_INFO_LENGTH_MISMATCH {
            buffer_size = return_length.max(buffer_size.saturating_mul(2));
            if buffer_size > 64 * 1024 * 1024 {
                return Err(anyhow!(
                    "SystemProcessInformation buffer too large ({} bytes)",
                    buffer_size
                ));
            }
            continue;
        }

        return Err(anyhow!(
            "NtQuerySystemInformation(SystemProcessInformation) failed: 0x{:X}",
            status.0
        ));
    };

    let mut map = HashMap::new();
    let mut offset: usize = 0;
    while offset + mem::size_of::<SystemProcessInformation>() <= buffer.len() {
        // SAFETY: We bounds-check the minimum header size and step by NextEntryOffset.
        let spi = unsafe { &*(buffer.as_ptr().add(offset) as *const SystemProcessInformation) };

        let pid = spi.unique_process_id.0 as usize as u32;
        map.insert(pid, spi.working_set_size as u64);

        if spi.next_entry_offset == 0 {
            break;
        }
        offset = offset.saturating_add(spi.next_entry_offset as usize);
    }

    Ok(map)
}

/// Get kernel + user time for a process by PID (in 100-nanosecond units)
/// Returns (kernel_time, user_time) or None if access is denied
pub fn get_process_times_by_pid(pid: u32) -> Option<(u64, u64)> {
    if pid == 0 {
        return None;
    }

    // SAFETY: OpenProcess requires a valid PID. On success it returns an owned process HANDLE.
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) } {
        Ok(h) => h,
        Err(_) => return None,
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
            &mut pmc,
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
    // SAFETY: PROCESS_MEMORY_COUNTERS_EX is a plain-old-data Windows struct; all-zero is a valid
    // initial value before the OS fills it.
    let mut pmc: PROCESS_MEMORY_COUNTERS_EX = unsafe { mem::zeroed() };
    pmc.cb = mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;

    let success = unsafe {
        GetProcessMemoryInfo(
            handle,
            // SAFETY: PROCESS_MEMORY_COUNTERS_EX begins with PROCESS_MEMORY_COUNTERS.
            &mut pmc as *mut PROCESS_MEMORY_COUNTERS_EX as *mut PROCESS_MEMORY_COUNTERS,
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
    let low = ft.dwLowDateTime as u64;
    let high = (ft.dwHighDateTime as u64) << 32;
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
            &mut creation_time,
            &mut exit_time,
            &mut kernel_time,
            &mut user_time,
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
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) } {
        Ok(h) => h,
        Err(_) => return None,
    };

    let guard = HandleGuard::new(handle);
    // SAFETY: GetPriorityClass requires a valid process HANDLE.
    let result = unsafe { GetPriorityClass(guard.raw()) };
    drop(guard);
    if result == 0 {
        None
    } else {
        Some(result)
    }
}

pub fn get_process_cycle_time_by_pid(pid: u32) -> Option<u64> {
    if pid == 0 {
        return None;
    }

    // Use NtQuerySystemInformation to get cycle time from SystemProcessInformation
    let buffer_size: u32 = 1024 * 1024; // 1MB initial
    let mut return_length: u32 = 0;

    let buffer: Vec<u8> = loop {
        let mut buffer = vec![0u8; buffer_size as usize];
        // SAFETY: NtQuerySystemInformation writes up to `buffer_size` bytes into `buffer`.
        // `buffer` is a valid, writable allocation of that size and `return_length` is valid.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_PROCESS_INFORMATION_CLASS,
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                buffer_size,
                &mut return_length,
            )
        };

        if status == STATUS_SUCCESS {
            break buffer;
        }
        if status == STATUS_INFO_LENGTH_MISMATCH {
            let new_size = return_length.max(buffer_size.saturating_mul(2));
            if new_size > 64 * 1024 * 1024 {
                return None;
            }
            // buffer_size = new_size; but we need to loop
            continue;
        }
        return None;
    };

    let mut offset: usize = 0;
    while offset + mem::size_of::<SystemProcessInformation>() <= buffer.len() {
        // SAFETY: We bounds-check the minimum header size and step by NextEntryOffset.
        let spi = unsafe { &*(buffer.as_ptr().add(offset) as *const SystemProcessInformation) };
        let current_pid = spi.unique_process_id.0 as usize as u32;
        if current_pid == pid {
            return Some(spi.cycle_time);
        }
        if spi.next_entry_offset == 0 {
            break;
        }
        offset = offset.saturating_add(spi.next_entry_offset as usize);
    }

    None
}

pub fn get_process_memory_info_by_pid(pid: u32) -> Option<PROCESS_MEMORY_COUNTERS_EX> {
    if pid == 0 {
        return None;
    }

    // SAFETY: OpenProcess requires a valid PID. On success it returns an owned process HANDLE.
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) } {
        Ok(h) => h,
        Err(_) => return None,
    };

    let guard = HandleGuard::new(handle);
    // SAFETY: PROCESS_MEMORY_COUNTERS_EX is a plain-old-data Windows struct; all-zero is a valid
    // initial value before the OS fills it.
    let mut pmc: PROCESS_MEMORY_COUNTERS_EX = unsafe { mem::zeroed() };
    pmc.cb = mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;

    let success = unsafe {
        GetProcessMemoryInfo(
            guard.raw(),
            &mut pmc as *mut PROCESS_MEMORY_COUNTERS_EX as *mut PROCESS_MEMORY_COUNTERS,
            mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        )
    };

    drop(guard);
    if success.is_ok() {
        Some(pmc)
    } else {
        None
    }
}

pub fn get_process_handle_count_by_pid(pid: u32) -> Option<u32> {
    if pid == 0 {
        return None;
    }

    let buffer_size: u32 = 1024 * 1024; // 1MB initial
    let mut return_length: u32 = 0;

    let buffer: Vec<u8> = loop {
        let mut buffer = vec![0u8; buffer_size as usize];
        // SAFETY: NtQuerySystemInformation writes up to `buffer_size` bytes into `buffer`.
        // `buffer` is a valid, writable allocation of that size and `return_length` is valid.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_PROCESS_INFORMATION_CLASS,
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                buffer_size,
                &mut return_length,
            )
        };

        if status == STATUS_SUCCESS {
            break buffer;
        }
        if status == STATUS_INFO_LENGTH_MISMATCH {
            let new_size = return_length.max(buffer_size.saturating_mul(2));
            if new_size > 64 * 1024 * 1024 {
                return None;
            }
            continue;
        }
        return None;
    };

    let mut offset: usize = 0;
    while offset + mem::size_of::<SystemProcessInformation>() <= buffer.len() {
        // SAFETY: We bounds-check the minimum header size and step by NextEntryOffset.
        let spi = unsafe { &*(buffer.as_ptr().add(offset) as *const SystemProcessInformation) };
        let current_pid = spi.unique_process_id.0 as usize as u32;
        if current_pid == pid {
            return Some(spi.handle_count);
        }
        if spi.next_entry_offset == 0 {
            break;
        }
        offset = offset.saturating_add(spi.next_entry_offset as usize);
    }

    None
}

pub fn get_process_gdi_handles_by_pid(pid: u32) -> Option<u32> {
    if pid == 0 {
        return None;
    }

    // SAFETY: OpenProcess requires a valid PID. On success it returns an owned process HANDLE.
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) } {
        Ok(h) => h,
        Err(_) => return None,
    };

    let guard = HandleGuard::new(handle);
    // SAFETY: GetGuiResources requires a valid process HANDLE.
    let count = unsafe { GetGuiResources(guard.raw(), GR_GDIOBJECTS) };
    drop(guard);

    if count > 0 {
        Some(count)
    } else {
        None
    }
}

pub fn get_process_user_handles_by_pid(pid: u32) -> Option<u32> {
    if pid == 0 {
        return None;
    }

    // SAFETY: OpenProcess requires a valid PID. On success it returns an owned process HANDLE.
    let handle = match unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) } {
        Ok(h) => h,
        Err(_) => return None,
    };

    let guard = HandleGuard::new(handle);
    // SAFETY: GetGuiResources requires a valid process HANDLE.
    let count = unsafe { GetGuiResources(guard.raw(), GR_USEROBJECTS) };
    drop(guard);

    if count > 0 {
        Some(count)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_io_rate_uses_saturating_sub() {
        let prev = IoCounters {
            read_bytes: 100,
            write_bytes: 100,
            other_bytes: 0,
            read_ops: 0,
            write_ops: 0,
            other_ops: 0,
        };
        let current = IoCounters {
            read_bytes: 50,
            write_bytes: 90,
            other_bytes: 0,
            read_ops: 0,
            write_ops: 0,
            other_ops: 0,
        };

        let rate = compute_io_rate(&prev, &current, 1.0);
        assert_eq!(rate.read_bytes_per_sec, 0.0);
        assert_eq!(rate.write_bytes_per_sec, 0.0);
    }

    #[test]
    fn compute_io_rate_scales_by_elapsed() {
        let prev = IoCounters {
            read_bytes: 0,
            write_bytes: 0,
            other_bytes: 0,
            read_ops: 0,
            write_ops: 0,
            other_ops: 0,
        };
        let current = IoCounters {
            read_bytes: 1000,
            write_bytes: 500,
            other_bytes: 0,
            read_ops: 0,
            write_ops: 0,
            other_ops: 0,
        };

        let rate = compute_io_rate(&prev, &current, 2.0);
        assert_eq!(rate.read_bytes_per_sec, 500.0);
        assert_eq!(rate.write_bytes_per_sec, 250.0);
    }
}
