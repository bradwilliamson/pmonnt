use pmonnt_core::win::HandleGuard;
use windows::{
    core::*,
    Win32::{
        Foundation::*,
        Security::*,
        System::{ProcessStatus::*, Threading::*},
    },
};

/// Get image path for a process
pub fn get_image_path(pid: u32) -> Option<String> {
    // SAFETY: This block calls Win32 APIs that operate on process handles and output buffers.
    // Buffers are stack-allocated with correct element types, and the process HANDLE is wrapped
    // in HandleGuard to ensure it is closed. No raw pointers escape this function.
    unsafe {
        let h = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(handle) => HandleGuard::new(handle),
            Err(_) => {
                log::debug!(
                    "[ProcessInfo] OpenProcess failed for PID {}: access denied",
                    pid
                );
                return None;
            }
        };

        // Try QueryFullProcessImageNameW first
        let mut buf = [0u16; 260];
        let mut size = buf.len() as u32;
        if QueryFullProcessImageNameW(
            h.raw(),
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        )
        .is_ok()
        {
            return Some(String::from_utf16_lossy(&buf[..size as usize]));
        }

        // Fallback to GetProcessImageFileNameW
        let mut buf2 = [0u16; 260];
        let size2 = GetProcessImageFileNameW(h.raw(), &mut buf2);
        if size2 > 0 {
            return Some(String::from_utf16_lossy(&buf2[..size2 as usize]));
        }

        log::debug!("[ProcessInfo] Failed to get image path for PID {}", pid);
        None
    }
}

/// Get command line for a process
pub fn get_command_line(pid: u32) -> Option<String> {
    match pmonnt_core::win::process_details::get_command_line(pid) {
        Ok(s) => Some(s),
        Err(e) => {
            log::debug!(
                "[ProcessInfo] Failed to get command line for PID {}: {}",
                pid,
                e
            );
            None
        }
    }
}

/// Get current directory for a process (best-effort).
pub fn get_current_directory(pid: u32) -> Option<String> {
    match pmonnt_core::win::process_details::get_process_details(pid, false) {
        Ok(d) => d.current_directory,
        Err(e) => {
            log::debug!(
                "[ProcessInfo] Failed to get current directory for PID {}: {}",
                pid,
                e
            );
            None
        }
    }
}

/// Get company name and file description from version info
pub fn get_file_version_info(_path: &str) -> (Option<String>, Option<String>) {
    // TODO: Implement file version info retrieval
    // Requires GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW
    (None, None)
}

/// Get integrity level for a process
pub fn get_integrity_level(pid: u32) -> Option<String> {
    // SAFETY: This block calls Win32 APIs for token querying. Buffers are sized based on
    // GetTokenInformation's reported required size, and handle lifetimes are managed by HandleGuard.
    unsafe {
        let h = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(handle) => HandleGuard::new(handle),
            Err(_) => {
                log::debug!(
                    "[ProcessInfo] OpenProcess failed for PID {}: access denied",
                    pid
                );
                return None;
            }
        };

        let mut token = HANDLE::default();
        if OpenProcessToken(h.raw(), TOKEN_QUERY, &mut token).is_err() {
            log::debug!("[ProcessInfo] OpenProcessToken failed for PID {}", pid);
            return None;
        }

        let token = HandleGuard::new(token);

        let mut info_size = 0u32;
        let _ = GetTokenInformation(token.raw(), TokenIntegrityLevel, None, 0, &mut info_size);
        if info_size == 0 {
            return None;
        }

        let mut buf = vec![0u8; info_size as usize];
        if GetTokenInformation(
            token.raw(),
            TokenIntegrityLevel,
            Some(buf.as_mut_ptr() as *mut _),
            info_size,
            &mut info_size,
        )
        .is_err()
        {
            return None;
        }

        // Parse TOKEN_MANDATORY_LABEL
        if (info_size as usize) >= std::mem::size_of::<TOKEN_MANDATORY_LABEL>() {
            let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
            let sid_ptr = label.Label.Sid;
            // SID S-1-16-X where X is integrity level
            let sid = std::ptr::read(sid_ptr.0.cast::<SID>());
            if sid.SubAuthorityCount >= 1 {
                let integrity = sid.SubAuthority[0];
                let level = match integrity {
                    0x0000..=0x0FFF => "Untrusted",
                    0x1000..=0x1FFF => "Low",
                    0x2000..=0x2FFF => "Medium",
                    0x3000..=0x3FFF => "High",
                    0x4000..=0xFFFF => "System",
                    _ => "Unknown",
                };
                return Some(level.to_string());
            }
        }

        None
    }
}

/// Get user name for a process
pub fn get_user(pid: u32) -> Option<String> {
    // SAFETY: This block calls Win32 token APIs and LookupAccountSidW.
    // Output buffers are stack-allocated and sizes are passed via in/out length parameters.
    // The SID pointer read from TOKEN_USER is used immediately and does not outlive `buf`.
    unsafe {
        let h = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(handle) => HandleGuard::new(handle),
            Err(_) => {
                log::debug!(
                    "[ProcessInfo] OpenProcess failed for PID {}: access denied",
                    pid
                );
                return None;
            }
        };

        let mut token = HANDLE::default();
        if OpenProcessToken(h.raw(), TOKEN_QUERY, &mut token).is_err() {
            log::debug!("[ProcessInfo] OpenProcessToken failed for PID {}", pid);
            return None;
        }

        let token = HandleGuard::new(token);

        let mut info_size = 0u32;
        let _ = GetTokenInformation(token.raw(), TokenUser, None, 0, &mut info_size);
        if info_size == 0 {
            return None;
        }

        let mut buf = vec![0u8; info_size as usize];
        if GetTokenInformation(
            token.raw(),
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            info_size,
            &mut info_size,
        )
        .is_err()
        {
            return None;
        }

        // Parse TOKEN_USER
        if (info_size as usize) >= std::mem::size_of::<TOKEN_USER>() {
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            let sid_ptr = user.User.Sid;
            // Convert SID to name
            let mut name = [0u16; 256];
            let mut domain = [0u16; 256];
            let mut name_len = name.len() as u32;
            let mut domain_len = domain.len() as u32;
            let mut use_type = SID_NAME_USE::default();

            if LookupAccountSidW(
                PCWSTR(std::ptr::null()),
                sid_ptr,
                PWSTR(name.as_mut_ptr()),
                &mut name_len,
                PWSTR(domain.as_mut_ptr()),
                &mut domain_len,
                &mut use_type,
            )
            .is_ok()
            {
                let name_str = String::from_utf16_lossy(&name[..name_len as usize]);
                let domain_str = String::from_utf16_lossy(&domain[..domain_len as usize]);
                return Some(format!("{}\\{}", domain_str, name_str));
            }
        }

        None
    }
}

/// Get session ID for a process
pub fn get_session_id(pid: u32) -> Option<u32> {
    // Use ProcessIdToSessionId from kernel32 via FFI
    // SAFETY: Declares an external Win32 function and calls it with a valid pointer to `session`.
    // `session` lives for the duration of the call and is only written by the API.
    unsafe {
        #[link(name = "kernel32")]
        extern "system" {
            fn ProcessIdToSessionId(dwProcessId: u32, pSessionId: *mut u32) -> i32;
        }

        let mut session: u32 = 0;
        let ok = ProcessIdToSessionId(pid, &mut session as *mut u32);
        if ok != 0 {
            Some(session)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_session_id() {
        // Test with current process
        let pid = std::process::id();
        let session = get_session_id(pid);
        assert!(session.is_some());
    }

    #[test]
    fn test_integrity_level_mapping() {
        // Test with current process
        let pid = std::process::id();
        let level = get_integrity_level(pid);
        assert!(level.is_some());
        assert!(matches!(
            level.as_deref(),
            Some("Low") | Some("Medium") | Some("High") | Some("System") | Some("Untrusted")
        ));
    }
}
