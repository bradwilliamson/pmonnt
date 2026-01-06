//! Windows process image path retrieval

use crate::win::HandleGuard;
use anyhow::{anyhow, Result};
use windows::Win32::Foundation::MAX_PATH;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_ACCESS_RIGHTS,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Get the full executable path for a process
///
/// # Arguments
/// * `pid` - Process ID to query
///
/// # Returns
/// * `Ok(String)` - Full path to the executable
/// * `Err` - If access is denied or path cannot be retrieved
pub fn get_process_image_path(pid: u32) -> Result<String> {
    // SAFETY: OpenProcess is a Windows API that opens a handle to a process.
    // We use PROCESS_QUERY_LIMITED_INFORMATION which is the least privileged access right.
    let handle = unsafe {
        OpenProcess(
            PROCESS_ACCESS_RIGHTS(PROCESS_QUERY_LIMITED_INFORMATION.0),
            false,
            pid,
        )?
    };

    if handle.is_invalid() {
        return Err(anyhow!("Failed to open process {}", pid));
    }

    let mut path_buf = vec![0u16; MAX_PATH as usize];
    let mut size = path_buf.len() as u32;

    // SAFETY: QueryFullProcessImageNameW retrieves the full path of the executable.
    // The buffer is properly sized and initialized.
    let success = unsafe {
        QueryFullProcessImageNameW(
            handle,
            windows::Win32::System::Threading::PROCESS_NAME_WIN32,
            windows::core::PWSTR(path_buf.as_mut_ptr()),
            &mut size,
        )
    };

    // SAFETY: Close the process handle via RAII
    drop(HandleGuard::new(handle));

    if success.is_err() {
        return Err(anyhow!("Failed to query image path for PID {}", pid));
    }

    // Convert UTF-16 to Rust String
    let path = String::from_utf16_lossy(&path_buf[..size as usize]);
    Ok(path)
}
