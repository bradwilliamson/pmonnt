use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use thiserror::Error;
use windows::Win32::Foundation::{
    GetLastError, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};
use windows::Win32::System::Threading::{OpenThread, THREAD_ACCESS_RIGHTS};

use crate::win::HandleGuard;

// GetSecurityInfo and ConvertSecurityDescriptorToStringSecurityDescriptorW allocate memory
// that must be freed with LocalFree.
#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(hmem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
}

// windows-rs doesn't always expose ConvertSecurityDescriptorToStringSecurityDescriptorW
// depending on enabled features, so bind it directly.
#[link(name = "advapi32")]
extern "system" {
    fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
        security_descriptor: *const core::ffi::c_void,
        requested_string_sd_revision: u32,
        security_information: u32,
        string_security_descriptor: *mut *mut u16,
        string_security_descriptor_len: *mut u32,
    ) -> i32;
}

const READ_CONTROL_RIGHT: u32 = 0x0002_0000;
const SDDL_REVISION_1: u32 = 1;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ThreadPermissionsError {
    #[error("Access denied")]
    AccessDenied,

    #[error("Thread not found (TID {tid})")]
    NotFound { tid: u32 },

    #[error("Win32 error ({context}): {code}")]
    Win32 { context: &'static str, code: u32 },
}

fn map_last_error(tid: u32) -> ThreadPermissionsError {
    // SAFETY: GetLastError retrieves the thread-local error code, which is always safe
    let code = unsafe { GetLastError() }.0;
    match WIN32_ERROR(code) {
        ERROR_ACCESS_DENIED => ThreadPermissionsError::AccessDenied,
        ERROR_INVALID_PARAMETER => ThreadPermissionsError::NotFound { tid },
        _ => ThreadPermissionsError::Win32 {
            context: "GetLastError",
            code,
        },
    }
}

fn map_code(context: &'static str, code: u32, tid: u32) -> ThreadPermissionsError {
    match WIN32_ERROR(code) {
        ERROR_ACCESS_DENIED => ThreadPermissionsError::AccessDenied,
        ERROR_INVALID_PARAMETER => ThreadPermissionsError::NotFound { tid },
        _ => ThreadPermissionsError::Win32 { context, code },
    }
}

#[cfg(windows)]
pub fn thread_security_sddl(tid: u32) -> Result<String, ThreadPermissionsError> {
    // Need READ_CONTROL to read the security descriptor.
    let desired = THREAD_ACCESS_RIGHTS(READ_CONTROL_RIGHT);
    // SAFETY: OpenThread is called with valid TID and access rights; error handling checks result
    let handle = unsafe { OpenThread(desired, false, tid) };
    let Ok(handle) = handle else {
        return Err(map_last_error(tid));
    };
    let _guard = HandleGuard::new(handle);

    // Request owner/group/dacl. SACL requires privileges and is not needed for the UI.
    let sec_info: OBJECT_SECURITY_INFORMATION =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

    let mut sd = PSECURITY_DESCRIPTOR::default();

    // Per docs, GetSecurityInfo allocates with LocalAlloc; caller frees with LocalFree.
    // SAFETY: GetSecurityInfo is called with a valid thread handle; output pointer is valid
    let err = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            sec_info,
            None,
            None,
            None,
            None,
            Some(&mut sd),
        )
    };

    if err != WIN32_ERROR(0) {
        return Err(map_code("GetSecurityInfo", err.0, tid));
    }

    struct LocalFreeGuard(*mut core::ffi::c_void);
    impl Drop for LocalFreeGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: LocalFree is called with a pointer previously allocated by GetSecurityInfo or ConvertSecurityDescriptorToStringSecurityDescriptorW
                unsafe {
                    let _ = LocalFree(self.0);
                }
            }
        }
    }

    let _sd_free = LocalFreeGuard(sd.0 as *mut _);

    let mut sddl_ptr: *mut u16 = std::ptr::null_mut();
    let mut sddl_len: u32 = 0;

    // SAFETY: ConvertSecurityDescriptorToStringSecurityDescriptorW is called with valid security descriptor from GetSecurityInfo
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd.0 as *const _,
            SDDL_REVISION_1,
            sec_info.0,
            &mut sddl_ptr,
            &mut sddl_len,
        )
    };

    if ok == 0 || sddl_ptr.is_null() {
        return Err(map_last_error(tid));
    }

    let _sddl_free = LocalFreeGuard(sddl_ptr as *mut _);

    // sddl_len includes the NUL terminator.
    let len = (sddl_len as usize).saturating_sub(1);
    if len == 0 {
        return Ok(String::new());
    }

    // SAFETY: from_raw_parts is safe here because sddl_ptr is valid, non-null, and len is the size returned by the API
    let slice = unsafe { std::slice::from_raw_parts(sddl_ptr, len) };
    Ok(OsString::from_wide(slice).to_string_lossy().into_owned())
}
