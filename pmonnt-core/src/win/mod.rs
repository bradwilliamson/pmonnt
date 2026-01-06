//! Windows-specific implementations

pub mod aclui_process_permissions;
pub mod dump;
pub mod handles;
pub mod module;
pub mod ntdll;
pub mod process_control;
pub mod process_details;
pub mod process_enum;
pub mod process_metrics;
pub mod process_path;
pub mod process_priority;
pub mod signature;
pub mod thread;
pub mod thread_control;
pub mod thread_permissions;
pub mod thread_stack;
pub mod token;
pub mod token_info;

use windows::Win32::Foundation::{CloseHandle, HANDLE};

use crate::win::ntdll::NtQueryInformationProcess;

/// RAII wrapper for Windows HANDLEs. Closes the handle on Drop.
pub struct HandleGuard(HANDLE);

impl HandleGuard {
    pub fn new(h: HANDLE) -> Self {
        Self(h)
    }

    /// Get the raw HANDLE value (by copy).
    pub fn raw(&self) -> HANDLE {
        self.0
    }

    /// Consume the guard and return the raw HANDLE without closing it.
    /// Useful when transferring ownership to another API.
    pub fn into_raw(self) -> HANDLE {
        let h = self.0;
        std::mem::forget(self);
        h
    }
}

impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            // Be defensive: don't close NULL or INVALID_HANDLE_VALUE.
            if !self.0.is_invalid() && !self.0 .0.is_null() {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// Check if the current process is running with administrative privileges
pub fn is_app_elevated() -> bool {
    unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() }
}

/// Enable SeDebugPrivilege for the current process
pub fn enable_debug_privilege() -> windows::core::Result<()> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{GetLastError, HANDLE, LUID, WIN32_ERROR};
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token_handle = HANDLE::default();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token_handle,
        )
        .is_err()
        {
            let err = GetLastError();
            return Err(windows::core::Error::from(err));
        }

        // Wrap token handle in RAII guard to ensure it is closed on return
        let _token_guard = HandleGuard::new(token_handle);

        let mut luid = LUID::default();
        let se_debug_name = "SeDebugPrivilege\0".encode_utf16().collect::<Vec<u16>>();

        if LookupPrivilegeValueW(
            PCWSTR::null(),
            PCWSTR::from_raw(se_debug_name.as_ptr()),
            &mut luid,
        )
        .is_err()
        {
            let err = GetLastError();
            return Err(windows::core::Error::from(err));
        }

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        if AdjustTokenPrivileges(token_handle, false, Some(&tp), 0, None, None).is_err() {
            let err = GetLastError();
            return Err(windows::core::Error::from(err));
        }

        // Even on success, check for partial failure
        let last_err = GetLastError();
        if last_err.0 == 1300 {
            // ERROR_NOT_ALL_ASSIGNED
            return Err(windows::core::Error::from(WIN32_ERROR(1300))); // Privilege not held
        }

        Ok(())
    }
}

/// Check if a process is Protected Process Light (PPL)
/// Returns (is_protected, protection_level)
pub fn get_process_protection(pid: u32) -> (bool, Option<String>) {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    /* CloseHandle not needed here; HandleGuard used instead */

    // Try to open with minimal rights
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };

    let Ok(handle) = handle else {
        // Can't even open - likely protected or exited
        return (true, Some("Cannot open process".to_string()));
    };

    // Wrap immediately for RAII cleanup on all paths.
    let handle_guard = HandleGuard::new(handle);

    // Query PS_PROTECTION via NtQueryInformationProcess
    #[repr(C)]
    struct PS_PROTECTION {
        level: u8,
        _pad: [u8; 3],
    }

    const PROCESS_PROTECTION_INFORMATION: u32 = 61;

    let mut protection = PS_PROTECTION {
        level: 0,
        _pad: [0; 3],
    };
    let mut ret_len = 0u32;

    let status = unsafe {
        NtQueryInformationProcess(
            handle_guard.raw(),
            PROCESS_PROTECTION_INFORMATION,
            &mut protection as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<PS_PROTECTION>() as u32,
            &mut ret_len,
        )
    };

    if status.0 >= 0 && protection.level != 0 {
        let level_str = match protection.level & 0x07 {
            0 => "None",
            1 => "Light (PPL)",
            2 => "Full",
            _ => "Unknown",
        };
        let signer = match (protection.level >> 4) & 0x0F {
            0 => "None",
            1 => "Authenticode",
            2 => "CodeGen",
            3 => "Antimalware",
            4 => "Lsa",
            5 => "Windows",
            6 => "WinTcb",
            _ => "Unknown",
        };
        (true, Some(format!("{} ({})", level_str, signer)))
    } else {
        (false, None)
    }
}

pub use signature::{verify_signature, SignatureInfo, SignatureStatus};

pub use process_priority::{
    get_affinity, get_priority_class, set_affinity, set_priority_class, AffinityInfo,
    PriorityClass, PriorityError,
};
