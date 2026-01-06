// Token information class constants for clarity
const TOKEN_USER_CLASS: TOKEN_INFORMATION_CLASS = TOKEN_INFORMATION_CLASS(1); // TokenUser
const TOKEN_PRIVILEGES_CLASS: TOKEN_INFORMATION_CLASS = TOKEN_INFORMATION_CLASS(3); // TokenPrivileges
const TOKEN_ELEVATION_CLASS: TOKEN_INFORMATION_CLASS = TOKEN_INFORMATION_CLASS(20); // TokenElevation
const TOKEN_INTEGRITY_LEVEL_CLASS: TOKEN_INFORMATION_CLASS = TOKEN_INFORMATION_CLASS(25); // TokenIntegrityLevel
const TOKEN_IS_APP_CONTAINER_CLASS: TOKEN_INFORMATION_CLASS = TOKEN_INFORMATION_CLASS(29); // TokenIsAppContainer
                                                                                           // Windows API wrappers for process token inspection
                                                                                           //
                                                                                           // This module provides safe wrappers around Windows token APIs.
                                                                                           // All unsafe code is contained here with documented invariants.

use crate::token::{PrivilegeInfo, TokenInfo};
use crate::win::HandleGuard;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_INFORMATION_CLASS, TOKEN_QUERY,
};
use windows::Win32::Security::{SID_NAME_USE, TOKEN_USER};
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Inspect the token of a process by PID
///
/// # Safety
/// This function calls Windows APIs that require proper handle management.
/// All handles are properly closed before returning.
pub fn inspect_process_token(pid: u32) -> TokenInfo {
    // Try to open the process
    let process_handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
    {
        Ok(handle) => handle,
        Err(e) => {
            return TokenInfo {
                error: Some(format!("Failed to open process: {}", e)),
                ..Default::default()
            }
        }
    };

    // Ensure process handle is closed
    let _process_guard = HandleGuard::new(process_handle);

    // Try to open the process token
    let mut token_handle = HANDLE::default();
    if unsafe { OpenProcessToken(process_handle, TOKEN_QUERY, &mut token_handle) }.is_err() {
        return TokenInfo {
            error: Some(format!(
                "Failed to open process token: {}",
                std::io::Error::last_os_error()
            )),
            ..Default::default()
        };
    }

    // Validate handle
    if token_handle.is_invalid() {
        return TokenInfo {
            error: Some("Received invalid token handle".to_string()),
            ..Default::default()
        };
    }

    // Ensure token handle is closed
    let _token_guard = HandleGuard::new(token_handle);

    // Query token information
    let user = get_token_user(token_handle);
    let integrity = get_token_integrity(token_handle);
    let elevated = get_token_elevation(token_handle);
    let is_app_container = get_token_is_app_container(token_handle);
    let privileges = get_token_privileges(token_handle);

    // If any critical field is None, set error
    let error = if user.is_none() || integrity.is_none() {
        Some("Could not resolve user or integrity level".to_string())
    } else {
        None
    };

    TokenInfo {
        user,
        integrity,
        elevated,
        is_app_container,
        privileges,
        error,
    }
}

// Use shared `HandleGuard` from parent `win` module

/// Get the user associated with a token
fn get_token_user(token: HANDLE) -> Option<String> {
    // SAFETY: Only called with a valid token handle. All buffer allocations checked.
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows::core::PWSTR;
    use windows::Win32::Security::LookupAccountSidW;

    // Query TOKEN_USER size
    let mut required_size = 0u32;
    let _ = unsafe { GetTokenInformation(token, TOKEN_USER_CLASS, None, 0, &mut required_size) };
    if required_size == 0 {
        return None;
    }
    let mut buffer = vec![0u8; required_size as usize];
    if unsafe {
        GetTokenInformation(
            token,
            TOKEN_USER_CLASS,
            Some(buffer.as_mut_ptr() as *mut _),
            required_size,
            &mut required_size,
        )
    }
    .is_err()
    {
        return None;
    }
    // Alignment-safe parsing: read TOKEN_USER struct with read_unaligned
    // SAFETY: buffer is valid and large enough for TOKEN_USER
    let token_user = unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const TOKEN_USER) };
    let sid = token_user.User.Sid;

    // Try LookupAccountSidW for DOMAIN\User
    let mut name = vec![0u16; 256];
    let mut domain = vec![0u16; 256];
    let mut name_len = name.len() as u32;
    let mut domain_len = domain.len() as u32;
    let mut sid_type = SID_NAME_USE(0);
    let lookup_result = unsafe {
        LookupAccountSidW(
            None,
            sid,
            PWSTR(name.as_mut_ptr()),
            &mut name_len,
            PWSTR(domain.as_mut_ptr()),
            &mut domain_len,
            &mut sid_type,
        )
    };
    if lookup_result.is_ok() {
        let name = OsString::from_wide(&name[..name_len as usize])
            .to_string_lossy()
            .into_owned();
        let domain = OsString::from_wide(&domain[..domain_len as usize])
            .to_string_lossy()
            .into_owned();
        let full = if !domain.is_empty() {
            format!("{}\\{}", domain, name)
        } else {
            name.to_owned()
        };
        return Some(full);
    }

    // Fallback: ConvertSidToStringSidW (commented out to avoid import issues)
    // let mut sid_string = PWSTR::null();
    // if unsafe { ConvertSidToStringSidW(sid, &mut sid_string).is_ok() } && !sid_string.is_null() {
    //     let len = unsafe {
    //         let mut ptr = sid_string.as_ptr();
    //         let mut len = 0;
    //         while *ptr != 0 {
    //             ptr = ptr.add(1);
    //             len += 1;
    //         }
    //         len
    //     };
    //     let slice = unsafe { std::slice::from_raw_parts(sid_string.as_ptr(), len) };
    //     let os_string = OsString::from_wide(slice);
    //     let result = os_string.to_str().map(|s| s.to_string());
    //     unsafe { windows::Win32::Foundation::LocalFree(sid_string.as_ptr() as _) };
    //     return result;
    // }
    None
}

/// Get the integrity level of a token
fn get_token_integrity(token: HANDLE) -> Option<String> {
    // SAFETY: Only called with a valid token handle. All buffer allocations checked.
    use windows::Win32::Security::TOKEN_MANDATORY_LABEL;

    // Query TOKEN_MANDATORY_LABEL size
    let mut required_size = 0u32;
    let _ = unsafe {
        GetTokenInformation(
            token,
            TOKEN_INTEGRITY_LEVEL_CLASS,
            None,
            0,
            &mut required_size,
        )
    };
    if required_size == 0 {
        return None;
    }
    let mut buffer = vec![0u8; required_size as usize];
    if unsafe {
        GetTokenInformation(
            token,
            TOKEN_INTEGRITY_LEVEL_CLASS,
            Some(buffer.as_mut_ptr() as *mut _),
            required_size,
            &mut required_size,
        )
    }
    .is_err()
    {
        return None;
    }
    // Alignment-safe parsing: read TOKEN_MANDATORY_LABEL struct with read_unaligned
    // SAFETY: buffer is valid and large enough for TOKEN_MANDATORY_LABEL
    let label =
        unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const TOKEN_MANDATORY_LABEL) };
    let sid = label.Label.Sid;

    // Parse last subauthority RID using Win32 helpers
    unsafe {
        let count = windows::Win32::Security::GetSidSubAuthorityCount(sid);
        if count.is_null() || *count == 0 {
            return None;
        }
        let rid_ptr = windows::Win32::Security::GetSidSubAuthority(sid, (*count - 1) as u32);
        if rid_ptr.is_null() {
            return None;
        }
        let rid = *rid_ptr;
        match rid {
            0x0000 => Some("Untrusted".to_string()),
            0x1000 => Some("Low".to_string()),
            0x2000 => Some("Medium".to_string()),
            0x2100 => Some("Medium Plus".to_string()),
            0x3000 => Some("High".to_string()),
            0x4000 => Some("System".to_string()),
            0x5000 => Some("Protected".to_string()),
            _ => Some(format!("Unknown (0x{:X})", rid)),
        }
    }
}

/// Get the elevation status of a token
fn get_token_elevation(token: HANDLE) -> Option<bool> {
    let mut elevation = TOKEN_ELEVATION::default();
    let mut required_size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;

    if unsafe {
        GetTokenInformation(
            token,
            TOKEN_ELEVATION_CLASS, // TokenElevation
            Some(&mut elevation as *mut _ as *mut _),
            required_size,
            &mut required_size,
        )
    }
    .is_ok()
    {
        Some(elevation.TokenIsElevated != 0)
    } else {
        None
    }
}

/// Get whether the token is in an app container
fn get_token_is_app_container(token: HANDLE) -> Option<bool> {
    let mut is_app_container = 0u32;
    let mut required_size = std::mem::size_of::<u32>() as u32;

    if unsafe {
        GetTokenInformation(
            token,
            TOKEN_IS_APP_CONTAINER_CLASS, // TokenIsAppContainer
            Some(&mut is_app_container as *mut _ as *mut _),
            required_size,
            &mut required_size,
        )
    }
    .is_ok()
    {
        Some(is_app_container != 0)
    } else {
        None
    }
}

/// Get the privileges of a token
fn get_token_privileges(token: HANDLE) -> Vec<PrivilegeInfo> {
    // First call to get required buffer size
    let mut required_size = 0u32;
    let _ = unsafe {
        GetTokenInformation(token, TOKEN_PRIVILEGES_CLASS, None, 0, &mut required_size)
        // TokenPrivileges
    };

    if required_size == 0 {
        return Vec::new();
    }

    // Allocate buffer and get the data
    let mut buffer = vec![0u8; required_size as usize];
    if unsafe {
        GetTokenInformation(
            token,
            TOKEN_PRIVILEGES_CLASS, // TokenPrivileges
            Some(buffer.as_mut_ptr() as *mut _),
            required_size,
            &mut required_size,
        )
    }
    .is_err()
    {
        return Vec::new();
    }

    // Alignment-safe parsing
    use std::mem::size_of;
    use std::ptr;
    use windows::Win32::Security::LUID_AND_ATTRIBUTES;

    if buffer.len() < 4 {
        return Vec::new();
    }
    let privilege_count = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
    let mut privileges = Vec::new();
    let entry_size = size_of::<LUID_AND_ATTRIBUTES>();
    let mut offset = 4;
    for _ in 0..privilege_count {
        if offset + entry_size > buffer.len() {
            break;
        }
        // SAFETY: We use read_unaligned to avoid UB
        let entry =
            unsafe { ptr::read_unaligned(buffer[offset..].as_ptr() as *const LUID_AND_ATTRIBUTES) };
        if let Some(name) = luid_to_privilege_name(entry.Luid) {
            let enabled = (entry.Attributes.0 & 0x00000002) != 0; // SE_PRIVILEGE_ENABLED
            privileges.push(PrivilegeInfo::new(name, enabled));
        }
        offset += entry_size;
    }
    privileges
}
fn luid_to_privilege_name(luid: windows::Win32::Foundation::LUID) -> Option<String> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows::core::PWSTR;
    use windows::Win32::Security::LookupPrivilegeNameW;

    // First call to get required buffer size
    let mut required_size = 0u32;
    let _ = unsafe { LookupPrivilegeNameW(None, &luid, PWSTR::null(), &mut required_size) };

    if required_size == 0 {
        return None;
    }

    // Allocate buffer and get the name
    let mut buffer = vec![0u16; required_size as usize];
    if unsafe { LookupPrivilegeNameW(None, &luid, PWSTR(buffer.as_mut_ptr()), &mut required_size) }
        .is_ok()
    {
        // Convert UTF-16 to String
        let os_string = OsString::from_wide(&buffer[..(required_size as usize).saturating_sub(1)]);
        os_string.to_str().map(|s| s.to_string())
    } else {
        None
    }
}
