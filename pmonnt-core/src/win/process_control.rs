use thiserror::Error;

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::{PCSTR, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, HANDLE, WIN32_ERROR,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Threading::{
    CreateProcessW, OpenProcess, TerminateProcess, PROCESS_INFORMATION, PROCESS_SUSPEND_RESUME,
    PROCESS_TERMINATE, STARTUPINFOW,
};

use crate::win::HandleGuard;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProcessControlError {
    #[error("Refusing to terminate PID {pid} ({reason})")]
    Refused { pid: u32, reason: &'static str },

    #[error("Access denied")]
    AccessDenied,

    #[error("Process not found (PID {pid})")]
    NotFound { pid: u32 },

    #[error("Windows error {code}")]
    Win32 { code: u32 },

    #[error("Failed to load ntdll function: {0}")]
    NtdllError(String),

    #[error("Failed to spawn process: {0}")]
    SpawnError(String),
}

fn map_last_error(pid: u32) -> ProcessControlError {
    let code = unsafe { GetLastError() }.0;
    match WIN32_ERROR(code) {
        ERROR_ACCESS_DENIED => ProcessControlError::AccessDenied,
        ERROR_INVALID_PARAMETER => ProcessControlError::NotFound { pid },
        _ => ProcessControlError::Win32 { code },
    }
}

/// Terminate a single process by PID.
///
/// Safety checks:
/// - Blocks PID 0 (System Idle) and PID 4 (System)
/// - Blocks terminating the current process (PMonNT)
#[cfg(windows)]
pub fn kill_process(pid: u32) -> Result<(), ProcessControlError> {
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

    let handle = unsafe { OpenProcess(PROCESS_TERMINATE, false, pid) };
    let Ok(handle) = handle else {
        return Err(map_last_error(pid));
    };
    let _guard = HandleGuard::new(handle);

    if unsafe { TerminateProcess(handle, 1) }.is_err() {
        return Err(map_last_error(pid));
    }

    Ok(())
}

/// Suspend a process by PID using NtSuspendProcess.
#[cfg(windows)]
pub fn suspend_process(pid: u32) -> Result<(), ProcessControlError> {
    unsafe {
        let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr() as _))
            .map_err(|_| ProcessControlError::NtdllError("Could not load ntdll.dll".to_string()))?;
        let nt_suspend_process_addr =
            GetProcAddress(ntdll, PCSTR(b"NtSuspendProcess\0".as_ptr() as _));

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
    unsafe {
        let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr() as _))
            .map_err(|_| ProcessControlError::NtdllError("Could not load ntdll.dll".to_string()))?;
        let nt_resume_process_addr =
            GetProcAddress(ntdll, PCSTR(b"NtResumeProcess\0".as_ptr() as _));

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
#[cfg(windows)]
pub fn restart_process(
    pid: u32,
    command_line: &str,
    working_dir: Option<&str>,
) -> Result<(), ProcessControlError> {
    // 1. Kill the process
    kill_process(pid)?;

    // 2. Wait a bit for it to exit (simple sleep for now, could be better with WaitForSingleObject if we kept the handle)
    std::thread::sleep(std::time::Duration::from_millis(200));

    // 3. Spawn new process
    spawn_process_with_command_line(command_line, working_dir)
}

fn spawn_process_with_command_line(
    cmd_line: &str,
    cwd: Option<&str>,
) -> Result<(), ProcessControlError> {
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
            .map(|v| PCWSTR(v.as_ptr()))
            .unwrap_or(PCWSTR::null());

        let success = CreateProcessW(
            None,
            PWSTR(cmd_line_wide.as_mut_ptr()),
            None,
            None,
            false,
            windows::Win32::System::Threading::CREATE_NEW_CONSOLE, // Or 0?
            None,
            cwd_ptr,
            &startup_info,
            &mut process_info,
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
        let err = kill_process(0).unwrap_err();
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
        let err = kill_process(4).unwrap_err();
        assert_eq!(
            err,
            ProcessControlError::Refused {
                pid: 4,
                reason: "System"
            }
        );
    }

    #[test]
    fn blocks_self() {
        let pid = std::process::id();
        let err = kill_process(pid).unwrap_err();
        assert_eq!(
            err,
            ProcessControlError::Refused {
                pid,
                reason: "PMonNT"
            }
        );
    }
}
