//! Windows thread inspection (unsafe code confined here)
//! Invariants: All handles are closed, all buffer reads are alignment-safe.
use crate::thread::ThreadInfo;
use crate::win::HandleGuard;
use crate::PmonntError;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::time::{SystemTime, UNIX_EPOCH};
use windows::Win32::Foundation::HANDLE as WIN_HANDLE;
use windows_sys::Win32::Foundation::{FILETIME, HANDLE as SYS_HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::Threading::{
    GetThreadDescription, GetThreadPriority, GetThreadTimes, OpenThread,
    THREAD_QUERY_LIMITED_INFORMATION,
};

// THREAD_QUERY_INFORMATION is needed to query thread start address via NtQueryInformationThread
// Define it manually as windows_sys may not export it
const THREAD_QUERY_INFORMATION: u32 = 0x0040;

// Define LocalFree function manually for freeing GetThreadDescription buffer
#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(hmem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
}

// NtQueryInformationThread from ntdll for getting thread start address and other info
#[allow(clippy::upper_case_acronyms)]
type NTSTATUS = i32;

#[allow(clippy::upper_case_acronyms)]
type THREADINFOCLASS = i32;
const THREAD_QUERY_SET_WIN32_START_ADDRESS: THREADINFOCLASS = 9;
const THREAD_BASIC_INFORMATION: THREADINFOCLASS = 0;
const THREAD_CYCLE_TIME: THREADINFOCLASS = 23;
const THREAD_SUSPEND_COUNT: THREADINFOCLASS = 35;

// THREAD_BASIC_INFORMATION structure
#[repr(C)]
#[allow(non_snake_case)]
struct THREAD_BASIC_INFO {
    ExitStatus: i32,
    TebBaseAddress: usize,
    ClientId_UniqueProcess: usize,
    ClientId_UniqueThread: usize,
    AffinityMask: usize,
    Priority: i32,
    BasePriority: i32,
}

// THREAD_CYCLE_TIME_INFORMATION
#[repr(C)]
#[allow(non_snake_case)]
struct THREAD_CYCLE_TIME_INFO {
    AccumulatedCycles: u64,
}

#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationThread(
        thread_handle: WIN_HANDLE,
        thread_information_class: THREADINFOCLASS,
        thread_information: *mut std::ffi::c_void,
        thread_information_length: u32,
        return_length: *mut u32,
    ) -> NTSTATUS;
}

fn sys_handle_to_win_handle(h: SYS_HANDLE) -> WIN_HANDLE {
    // Convert `windows-sys` HANDLE to `windows` HANDLE.
    // In this workspace these are layout-compatible, so this is a simple wrapper conversion.
    WIN_HANDLE(h)
}

// Compute length of a null-terminated wide string safely, bounded by `max` u16 code units.
// Returns the number of u16 code units before the NUL (0) or `max` if NUL not found.
unsafe fn fn_strlen_wide_bounded(ptr: *const u16, max: usize) -> usize {
    if ptr.is_null() {
        return 0;
    }
    let mut i: usize = 0;
    while i < max {
        let ch = *ptr.add(i);
        if ch == 0 {
            break;
        }
        i += 1;
    }
    i
}

pub fn list_threads(pid: u32) -> Result<Vec<ThreadInfo>, PmonntError> {
    let mut threads = Vec::new();
    // SAFETY: CreateToolhelp32Snapshot is called with valid flags; thread-local GetLastError is safe
    unsafe {
        let snapshot: SYS_HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(PmonntError::ThreadEnumerationFailed(
                "CreateToolhelp32Snapshot failed".to_string(),
            ));
        }
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        let mut ok = Thread32First(snapshot, &mut entry) != 0;
        while ok {
            if entry.th32OwnerProcessID == pid {
                let mut info = ThreadInfo {
                    tid: entry.th32ThreadID,
                    owner_pid: entry.th32OwnerProcessID,
                    base_priority: entry.tpBasePri,
                    priority: None,
                    kernel_time_100ns: 0,
                    user_time_100ns: 0,
                    created_at: None,
                    name: None,
                    start_address: None,
                    error: None,
                    suspend_count: None,
                    context_switches: None,
                    cycle_time: None,
                    wait_reason: None,
                    state: None,
                    ideal_processor: None,
                };
                let thread_handle: SYS_HANDLE = OpenThread(
                    THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
                    0,
                    entry.th32ThreadID,
                );
                // OpenThread follows the normal Win32 convention: NULL indicates failure.
                // Do not check INVALID_HANDLE_VALUE here (that's for APIs like CreateFileW).
                if (thread_handle as usize) != 0 {
                    let handle_guard = HandleGuard::new(sys_handle_to_win_handle(thread_handle));
                    // GetThreadTimes - use raw handle for windows_sys API
                    let mut create = std::mem::zeroed();
                    let mut exit = std::mem::zeroed();
                    let mut kernel = std::mem::zeroed();
                    let mut user = std::mem::zeroed();
                    if GetThreadTimes(
                        thread_handle,
                        &mut create,
                        &mut exit,
                        &mut kernel,
                        &mut user,
                    ) != 0
                    {
                        info.kernel_time_100ns = filetime_to_u64(kernel);
                        info.user_time_100ns = filetime_to_u64(user);
                        info.created_at = Some(filetime_to_systemtime(create));
                    }
                    // GetThreadPriority - use raw handle for windows_sys API
                    let prio = GetThreadPriority(thread_handle);
                    if prio != 0x7FFFFFFF_i32 {
                        // THREAD_PRIORITY_ERROR_RETURN
                        info.priority = Some(prio);
                    }
                    // GetThreadDescription (optional) - use bounded length to avoid OOB reads
                    let mut desc = std::ptr::null_mut();
                    if GetThreadDescription(thread_handle, &mut desc) >= 0 && !desc.is_null() {
                        // Bound the maximum wide-string length to avoid walking into invalid memory
                        const MAX_WSTR_LEN: usize = 32 * 1024; // 32k characters
                                                               // SAFETY: desc is non-null and points to a null-terminated wide string allocated by Windows.
                        let len = fn_strlen_wide_bounded(desc as *const u16, MAX_WSTR_LEN);
                        let slice = std::slice::from_raw_parts(desc as *const u16, len);
                        info.name = Some(OsString::from_wide(slice).to_string_lossy().into_owned());
                        // Free the buffer allocated by GetThreadDescription
                        LocalFree(desc as *mut std::ffi::c_void);
                    }

                    // Query thread start address using NtQueryInformationThread
                    // This may fail on protected processes or if access rights are insufficient
                    // Invariant: start_addr is properly aligned (usize), output buffer size matches
                    let mut start_addr: usize = 0;
                    let mut ret_len: u32 = 0;
                    let status = NtQueryInformationThread(
                        handle_guard.raw(),
                        THREAD_QUERY_SET_WIN32_START_ADDRESS,
                        &mut start_addr as *mut usize as *mut std::ffi::c_void,
                        std::mem::size_of::<usize>() as u32,
                        &mut ret_len,
                    );

                    // NT_SUCCESS macro: (status >= 0)
                    if status >= 0 && start_addr != 0 {
                        info.start_address = Some(start_addr as u64);
                    }

                    // Query THREAD_BASIC_INFORMATION for context switches
                    let mut basic_info: THREAD_BASIC_INFO = std::mem::zeroed();
                    let mut ret_len: u32 = 0;
                    let status = NtQueryInformationThread(
                        handle_guard.raw(),
                        THREAD_BASIC_INFORMATION,
                        &mut basic_info as *mut _ as *mut std::ffi::c_void,
                        std::mem::size_of::<THREAD_BASIC_INFO>() as u32,
                        &mut ret_len,
                    );
                    if status >= 0 {
                        // Priority from basic info is more reliable
                        info.priority = Some(basic_info.Priority);
                        info.base_priority = basic_info.BasePriority;
                    }

                    // Query cycle time
                    let mut cycle_info: THREAD_CYCLE_TIME_INFO = std::mem::zeroed();
                    let status = NtQueryInformationThread(
                        handle_guard.raw(),
                        THREAD_CYCLE_TIME,
                        &mut cycle_info as *mut _ as *mut std::ffi::c_void,
                        std::mem::size_of::<THREAD_CYCLE_TIME_INFO>() as u32,
                        &mut ret_len,
                    );
                    if status >= 0 {
                        info.cycle_time = Some(cycle_info.AccumulatedCycles);
                    }

                    // Query suspend count (Windows 8.1+)
                    let mut suspend_count: u32 = 0;
                    let status = NtQueryInformationThread(
                        handle_guard.raw(),
                        THREAD_SUSPEND_COUNT,
                        &mut suspend_count as *mut _ as *mut std::ffi::c_void,
                        std::mem::size_of::<u32>() as u32,
                        &mut ret_len,
                    );
                    if status >= 0 {
                        info.suspend_count = Some(suspend_count);
                    }

                    // On failure (access denied, etc.), start_address remains None
                    // SAFETY: handle_guard automatically closes handle when dropped at end of scope
                } else {
                    info.error = Some("OpenThread failed".to_string());
                }
                threads.push(info);
            }
            ok = Thread32Next(snapshot, &mut entry) != 0;
        }
        drop(HandleGuard::new(sys_handle_to_win_handle(snapshot)));
    }
    Ok(threads)
}

fn filetime_to_u64(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
}
fn filetime_to_systemtime(ft: FILETIME) -> SystemTime {
    // FILETIME is 100ns ticks since 1601-01-01.
    const WINDOWS_TO_UNIX_EPOCH_SECS: u64 = 11_644_473_600; // 1601-01-01 -> 1970-01-01
    let ticks_100ns = filetime_to_u64(ft);
    let secs = ticks_100ns / 10_000_000;
    let nanos = (ticks_100ns % 10_000_000) * 100;

    if secs < WINDOWS_TO_UNIX_EPOCH_SECS {
        return UNIX_EPOCH;
    }

    UNIX_EPOCH
        + std::time::Duration::from_secs(secs - WINDOWS_TO_UNIX_EPOCH_SECS)
        + std::time::Duration::from_nanos(nanos)
}

/// Fast global thread count per PID using CreateToolhelp32Snapshot.
/// This is O(total_threads) and completes in <10ms typically.
/// Returns a HashMap<PID, thread_count> for all processes.
pub fn count_threads_global() -> Result<std::collections::HashMap<u32, usize>, PmonntError> {
    use std::collections::HashMap;

    let mut counts: HashMap<u32, usize> = HashMap::new();

    // SAFETY: CreateToolhelp32Snapshot is called with valid flags; thread-local GetLastError is safe
    unsafe {
        let snapshot: SYS_HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(PmonntError::ThreadEnumerationFailed(
                "CreateToolhelp32Snapshot failed".to_string(),
            ));
        }

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        let mut ok = Thread32First(snapshot, &mut entry) != 0;
        while ok {
            *counts.entry(entry.th32OwnerProcessID).or_insert(0) += 1;
            ok = Thread32Next(snapshot, &mut entry) != 0;
        }

        drop(crate::win::HandleGuard::new(sys_handle_to_win_handle(
            snapshot,
        )));
    }

    Ok(counts)
}
