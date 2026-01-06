use thiserror::Error;

use windows::Win32::Foundation::{
    GetLastError, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, WIN32_ERROR,
};
use windows::Win32::System::Threading::{
    OpenThread, ResumeThread, SuspendThread, TerminateThread, THREAD_ACCESS_RIGHTS,
    THREAD_SUSPEND_RESUME, THREAD_TERMINATE,
};

use crate::win::HandleGuard;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ThreadControlError {
    #[error("Access denied")]
    AccessDenied,

    #[error("Thread not found (TID {tid})")]
    NotFound { tid: u32 },

    #[error("Windows error {code}")]
    Win32 { code: u32 },
}

fn map_last_error(tid: u32) -> ThreadControlError {
    let code = unsafe { GetLastError() }.0;
    match WIN32_ERROR(code) {
        ERROR_ACCESS_DENIED => ThreadControlError::AccessDenied,
        ERROR_INVALID_PARAMETER => ThreadControlError::NotFound { tid },
        _ => ThreadControlError::Win32 { code },
    }
}

#[cfg(windows)]
pub fn suspend_thread(tid: u32) -> Result<(), ThreadControlError> {
    let handle = unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, tid) };
    let Ok(handle) = handle else {
        return Err(map_last_error(tid));
    };
    let _guard = HandleGuard::new(handle);

    let prev = unsafe { SuspendThread(handle) };
    if prev == u32::MAX {
        return Err(map_last_error(tid));
    }

    Ok(())
}

#[cfg(windows)]
pub fn resume_thread(tid: u32) -> Result<(), ThreadControlError> {
    let handle = unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, tid) };
    let Ok(handle) = handle else {
        return Err(map_last_error(tid));
    };
    let _guard = HandleGuard::new(handle);

    let prev = unsafe { ResumeThread(handle) };
    if prev == u32::MAX {
        return Err(map_last_error(tid));
    }

    Ok(())
}

#[cfg(windows)]
pub fn kill_thread(tid: u32, exit_code: u32) -> Result<(), ThreadControlError> {
    // TerminateThread requires THREAD_TERMINATE.
    let desired = THREAD_ACCESS_RIGHTS(THREAD_TERMINATE.0);
    let handle = unsafe { OpenThread(desired, false, tid) };
    let Ok(handle) = handle else {
        return Err(map_last_error(tid));
    };
    let _guard = HandleGuard::new(handle);

    unsafe { TerminateThread(handle, exit_code) }.map_err(|_| map_last_error(tid))?;
    Ok(())
}
