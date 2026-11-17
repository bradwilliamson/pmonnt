use thiserror::Error;

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, FILETIME, GetLastError, HANDLE,
    WIN32_ERROR,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Threading::{
    CreateProcessW, GetProcessTimes, OpenProcess, PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE, STARTUPINFOW,
    TerminateProcess,
};
use windows::core::{PCSTR, PCWSTR, PWSTR};

use crate::win::HandleGuard;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProcessControlError {
    #[error("Refusing to terminate PID {pid} ({reason})")]
    Refused { pid: u32, reason: &'static str },

    #[error("Access denied")]
    AccessDenied,

    #[error("Process not found (PID {pid})")]
    NotFound { pid: u32 },

    #[error("PID {pid} now belongs to a different process; nothing was terminated")]
    Replaced { pid: u32 },

    #[error("Windows error {code}")]
    Win32 { code: u32 },

    #[error("Failed to load ntdll function: {0}")]
    NtdllError(String),

    #[error("Failed to spawn process: {0}")]
    SpawnError(String),
}

fn map_last_error(pid: u32) -> ProcessControlError {
    // SAFETY: GetLastError is a thread-local FFI call to retrieve the last error code
    let code = unsafe { GetLastError() }.0;
    match WIN32_ERROR(code) {
        ERROR_ACCESS_DENIED => ProcessControlError::AccessDenied,
        ERROR_INVALID_PARAMETER => ProcessControlError::NotFound { pid },
        _ => ProcessControlError::Win32 { code },
    }
}

/// Terminate one process instance.
///
/// `expected_create_time` is the creation time (FILETIME ticks) of the process the caller
/// means, normally taken from the snapshot the user confirmed against. Windows recycles PIDs,
/// so the process is opened first, its creation time is compared on that handle, and the
/// same handle is used to terminate it: a process that has exited and had its PID reused is
/// reported as [`ProcessControlError::Replaced`] and left running.
///
/// Safety checks:
/// - Blocks PID 0 (System Idle) and PID 4 (System)
/// - Blocks terminating the current process (PMonNT)
#[cfg(windows)]
pub fn kill_process(pid: u32, expected_create_time: u64) -> Result<(), ProcessControlError> {
    if pid == 0 {
        return Err(ProcessControlError::Refused {
            pid,
            reason: "System Idle",
        });
    }
    if pid == 4 {
        return Err(ProcessControlError::Refused {
            pid,
            reason: "System",
        });
    }

    let self_pid = std::process::id();
    if pid == self_pid {
        return Err(ProcessControlError::Refused {
            pid,
            reason: "PMonNT",
        });
    }

    // SAFETY: OpenProcess has no pointer arguments; on success the returned handle is owned
    // here and closed by the guard.
    let handle = unsafe {
        OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            pid,
        )
    };
    let Ok(handle) = handle else {
        return Err(map_last_error(pid));
    };
    let _guard = HandleGuard::new(handle);

    // The handle keeps this process object alive, so the check below and the termination
    // apply to the same instance even if the PID is recycled in between.
    if process_create_time(handle).ok_or_else(|| map_last_error(pid))? != expected_create_time {
        return Err(ProcessControlError::Replaced { pid });
    }

    // SAFETY: TerminateProcess FFI call with valid process handle
    if unsafe { TerminateProcess(handle, 1) }.is_err() {
        return Err(map_last_error(pid));
    }

    Ok(())
}

/// Creation time of an open process as FILETIME ticks.
#[cfg(windows)]
fn process_create_time(handle: HANDLE) -> Option<u64> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: `handle` is an open process handle with query access, and every out-pointer
    // refers to a live FILETIME.
    unsafe {
        GetProcessTimes(
            handle,
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    }
    .ok()?;
    Some((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

/// Creation time of a running process, for callers that do not have a snapshot entry.
#[cfg(windows)]
pub fn query_process_create_time(pid: u32) -> Result<u64, ProcessControlError> {
    // SAFETY: OpenProcess has no pointer arguments; the guard owns the returned handle.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .map_err(|_| map_last_error(pid))?;
    let _guard = HandleGuard::new(handle);
    process_create_time(handle).ok_or_else(|| map_last_error(pid))
}

/// Suspend a process by PID using NtSuspendProcess.
#[cfg(windows)]
pub fn suspend_process(pid: u32) -> Result<(), ProcessControlError> {
    // SAFETY: GetModuleHandleA, GetProcAddress, and transmute to get NtSuspendProcess function pointer with correct signature
    unsafe {
        let ntdll = GetModuleHandleA(PCSTR(c"ntdll.dll".as_ptr().cast()))
            .map_err(|_| ProcessControlError::NtdllError("Could not load ntdll.dll".to_string()))?;
        let nt_suspend_process_addr =
            GetProcAddress(ntdll, PCSTR(c"NtSuspendProcess".as_ptr().cast()));

        if let Some(addr) = nt_suspend_process_addr {
            let nt_suspend_process: unsafe extern "system" fn(HANDLE) -> i32 =
                std::mem::transmute(addr);

            let handle =
                OpenProcess(PROCESS_SUSPEND_RESUME, false, pid).map_err(|_| map_last_error(pid))?;
            let _guard = HandleGuard::new(handle);

            let status = nt_suspend_process(handle);
            if status != 0 {
                return Err(ProcessControlError::Win32 {
                    code: status as u32,
                });
            }
            Ok(())
        } else {
            Err(ProcessControlError::NtdllError(
                "NtSuspendProcess not found".to_string(),
            ))
        }
    }
}

/// Resume a process by PID using NtResumeProcess.
#[cfg(windows)]
pub fn resume_process(pid: u32) -> Result<(), ProcessControlError> {
    // SAFETY: GetModuleHandleA, GetProcAddress, and transmute to get NtResumeProcess function pointer with correct signature
    unsafe {
        let ntdll = GetModuleHandleA(PCSTR(c"ntdll.dll".as_ptr().cast()))
            .map_err(|_| ProcessControlError::NtdllError("Could not load ntdll.dll".to_string()))?;
        let nt_resume_process_addr =
            GetProcAddress(ntdll, PCSTR(c"NtResumeProcess".as_ptr().cast()));

        if let Some(addr) = nt_resume_process_addr {
            let nt_resume_process: unsafe extern "system" fn(HANDLE) -> i32 =
                std::mem::transmute(addr);

            let handle =
                OpenProcess(PROCESS_SUSPEND_RESUME, false, pid).map_err(|_| map_last_error(pid))?;
            let _guard = HandleGuard::new(handle);

            let status = nt_resume_process(handle);
            if status != 0 {
                return Err(ProcessControlError::Win32 {
                    code: status as u32,
                });
            }
            Ok(())
        } else {
            Err(ProcessControlError::NtdllError(
                "NtResumeProcess not found".to_string(),
            ))
        }
    }
}

/// Restart a process by killing it and spawning a new instance with the same command line.
///
/// `expected_create_time` identifies the instance to stop, as for [`kill_process`].
#[cfg(windows)]
pub fn restart_process(
    pid: u32,
    expected_create_time: u64,
    command_line: &str,
    working_dir: Option<&str>,
) -> Result<(), ProcessControlError> {
    // 1. Kill the process
    kill_process(pid, expected_create_time)?;

    // 2. Wait a bit for it to exit (simple sleep for now, could be better with WaitForSingleObject if we kept the handle)
    std::thread::sleep(std::time::Duration::from_millis(200));

    // 3. Spawn new process
    spawn_process_with_command_line(command_line, working_dir)
}

fn spawn_process_with_command_line(
    cmd_line: &str,
    cwd: Option<&str>,
) -> Result<(), ProcessControlError> {
    // SAFETY: CreateProcessW FFI call with valid null-terminated UTF-16 command line and properly initialized STARTUPINFOW structure
    unsafe {
        let startup_info = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut process_info = PROCESS_INFORMATION::default();

        // CreateProcessW modifies the command line buffer, so we need a mutable vector
        let mut cmd_line_wide: Vec<u16> = OsStr::new(cmd_line)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let cwd_wide = cwd.map(|s| {
            OsStr::new(s)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>()
        });
        let cwd_ptr = cwd_wide
            .as_ref()
            .map_or(PCWSTR::null(), |v| PCWSTR(v.as_ptr()));

        let success = CreateProcessW(
            None,
            Some(PWSTR(cmd_line_wide.as_mut_ptr())),
            None,
            None,
            false,
            windows::Win32::System::Threading::CREATE_NEW_CONSOLE, // Or 0?
            None,
            cwd_ptr,
            &raw const startup_info,
            &raw mut process_info,
        );

        if success.is_ok() {
            let _ = CloseHandle(process_info.hProcess);
            let _ = CloseHandle(process_info.hThread);
            Ok(())
        } else {
            let err = GetLastError().0;
            Err(ProcessControlError::Win32 { code: err })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_pid_0() {
        let err = kill_process(0, 0).unwrap_err();
        assert_eq!(
            err,
            ProcessControlError::Refused {
                pid: 0,
                reason: "System Idle"
            }
        );
    }

    #[test]
    fn blocks_pid_4() {
        let err = kill_process(4, 0).unwrap_err();
        assert_eq!(
            err,
            ProcessControlError::Refused {
                pid: 4,
                reason: "System"
            }
        );
    }

    /// A child process that is still running, killed on drop if a test fails early.
    struct Child(std::process::Child);

    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn spawn_sleeper() -> Child {
        // `ping -n 60` waits about a minute without needing a console or user input.
        Child(
            std::process::Command::new("ping")
                .args(["-n", "60", "127.0.0.1"])
                .stdout(std::process::Stdio::null())
                .spawn()
                .expect("spawn ping"),
        )
    }

    #[test]
    fn refuses_a_different_instance_of_the_pid() {
        let mut child = spawn_sleeper();
        let pid = child.0.id();
        let create_time = query_process_create_time(pid).unwrap();

        // Pretend the confirmed process was an older instance that has since exited.
        let err = kill_process(pid, create_time - 1).unwrap_err();
        assert_eq!(err, ProcessControlError::Replaced { pid });
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "process must survive"
        );

        kill_process(pid, create_time).unwrap();
        let status = child.0.wait().unwrap();
        assert_eq!(status.code(), Some(1));
    }

    #[test]
    fn snapshot_and_handle_creation_times_agree() {
        // Kills compare the snapshot's creation time (SystemProcessInformation) with the one
        // read from the opened handle (GetProcessTimes); they must be the same value.
        let child = spawn_sleeper();
        let pid = child.0.id();
        let from_spi = crate::win::process_metrics::system_process_entry(pid)
            .expect("child in SystemProcessInformation")
            .create_time;
        assert_eq!(query_process_create_time(pid).unwrap(), from_spi);
    }

    #[test]
    fn blocks_self() {
        let pid = std::process::id();
        let err = kill_process(pid, 0).unwrap_err();
        assert_eq!(
            err,
            ProcessControlError::Refused {
                pid,
                reason: "PMonNT"
            }
        );
    }
}
