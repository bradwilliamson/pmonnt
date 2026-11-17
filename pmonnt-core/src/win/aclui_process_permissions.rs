#![cfg(windows)]

use thiserror::Error;

use windows::Win32::Foundation::{HWND, SetLastError, WIN32_ERROR};
use windows::Win32::Security::Authorization::UI::{
    EditSecurity, ISecurityInformation, ISecurityInformation_Impl, SECURITY_INFO_PAGE_FLAGS,
    SI_ACCESS, SI_INHERIT_TYPE, SI_OBJECT_INFO, SI_OBJECT_INFO_FLAGS, SI_PAGE_TYPE, SI_VIEW_ONLY,
};
use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT, SetSecurityInfo};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GENERIC_MAPPING, GetSecurityDescriptorDacl, MapGenericMask,
    OBJECT_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};
use windows::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, CoInitializeEx, CoTaskMemAlloc, CoUninitialize,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::Controls::PSPCB_MESSAGE;
use windows::core::{BOOL, Error as WinError, GUID, PCWSTR, PWSTR, implement};

use super::HandleGuard;

#[derive(Debug, Error, Clone)]
pub enum PermissionsError {
    #[error("access denied")]
    AccessDenied,

    #[error("process exited")]
    ProcessExited,

    #[error("win32 error ({context}): {code}")]
    Win32 { context: &'static str, code: u32 },

    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessPermissionsAccess {
    Denied,
    ReadOnly,
    ReadWrite,
}

fn to_wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// Standard access-right bits (same as WinNT.h).
const READ_CONTROL_RIGHT: u32 = 0x0002_0000;
const WRITE_DAC_RIGHT: u32 = 0x0004_0000;

fn win32_code_from_error(err: &WinError) -> u32 {
    // windows-rs reports Win32 failures as HRESULTs (typically HRESULT_FROM_WIN32(x)).
    // The low 16 bits contain the original Win32 error code for this common case.
    (err.code().0 as u32) & 0xFFFF
}

fn map_error(context: &'static str, err: WinError) -> PermissionsError {
    match win32_code_from_error(&err) {
        5 => PermissionsError::AccessDenied,
        87 | 1168 => PermissionsError::ProcessExited,
        code => PermissionsError::Win32 { context, code },
    }
}

fn open_process_for_permissions(
    pid: u32,
    want_write: bool,
) -> Result<(HandleGuard, ProcessPermissionsAccess), PermissionsError> {
    let mut desired = PROCESS_QUERY_LIMITED_INFORMATION.0 | READ_CONTROL_RIGHT;
    let access = if want_write {
        desired |= WRITE_DAC_RIGHT;
        ProcessPermissionsAccess::ReadWrite
    } else {
        ProcessPermissionsAccess::ReadOnly
    };

    // SAFETY: Valid PID with proper access rights; error handling via Result
    let h = unsafe { OpenProcess(PROCESS_ACCESS_RIGHTS(desired), false, pid) }
        .map_err(|e| map_error("OpenProcess", e))?;
    Ok((HandleGuard::new(h), access))
}

/// Quick, non-blocking probe for whether we can view/edit the process object's DACL.
pub fn probe_process_object_permissions(
    pid: u32,
) -> Result<ProcessPermissionsAccess, PermissionsError> {
    if open_process_for_permissions(pid, true).is_ok() {
        return Ok(ProcessPermissionsAccess::ReadWrite);
    }
    if open_process_for_permissions(pid, false).is_ok() {
        return Ok(ProcessPermissionsAccess::ReadOnly);
    }
    Ok(ProcessPermissionsAccess::Denied)
}

#[implement(ISecurityInformation)]
struct ProcessSecurityInformation {
    handle: HandleGuard,
    object_name_w: Vec<u16>,
    readonly: bool,
    access_rights: Vec<(Vec<u16>, u32)>,
}

impl ProcessSecurityInformation {
    fn new(handle: HandleGuard, object_name: String, access: ProcessPermissionsAccess) -> Self {
        let object_name_w = to_wide_z(&object_name);
        let readonly = access != ProcessPermissionsAccess::ReadWrite;

        // Keep these strings alive for the dialog's lifetime.
        // The masks here are process-specific rights.
        let access_rights = vec![
            (to_wide_z("Terminate"), 0x0001),
            (to_wide_z("Create thread"), 0x0002),
            (to_wide_z("VM operation"), 0x0008),
            (to_wide_z("VM read"), 0x0010),
            (to_wide_z("VM write"), 0x0020),
            (to_wide_z("Duplicate handle"), 0x0040),
            (to_wide_z("Set information"), 0x0200),
            (to_wide_z("Query information"), 0x0400),
            (to_wide_z("Suspend/Resume"), 0x0800),
            (to_wide_z("Query limited information"), 0x1000),
            (to_wide_z("Read control"), READ_CONTROL_RIGHT),
            (to_wide_z("Write DAC"), WRITE_DAC_RIGHT),
        ];

        Self {
            handle,
            object_name_w,
            readonly,
            access_rights,
        }
    }
}

impl ISecurityInformation_Impl for ProcessSecurityInformation_Impl {
    fn GetObjectInformation(&self, pobjectinfo: *mut SI_OBJECT_INFO) -> windows::core::Result<()> {
        // SAFETY: ISecurityInformation callback; pobjectinfo validated before dereferencing
        unsafe {
            if pobjectinfo.is_null() {
                return Err(WinError::from_thread());
            }

            let mut flags = SI_OBJECT_INFO_FLAGS(0);
            if self.this.readonly {
                flags |= SI_VIEW_ONLY;
            }

            *pobjectinfo = SI_OBJECT_INFO {
                dwFlags: flags,
                hInstance: Default::default(),
                pszServerName: PWSTR::null(),
                pszObjectName: PWSTR(self.this.object_name_w.as_ptr().cast_mut()),
                pszPageTitle: PWSTR::null(),
                guidObjectType: Default::default(),
            };

            Ok(())
        }
    }

    fn GetSecurity(
        &self,
        requestedinformation: OBJECT_SECURITY_INFORMATION,
        ppsecuritydescriptor: *mut PSECURITY_DESCRIPTOR,
        _fdefault: BOOL,
    ) -> windows::core::Result<()> {
        // SAFETY: ISecurityInformation callback with valid handle; ppsecuritydescriptor validated
        unsafe {
            if ppsecuritydescriptor.is_null() {
                return Err(WinError::from_thread());
            }

            let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();
            let status = GetSecurityInfo(
                self.this.handle.raw(),
                SE_KERNEL_OBJECT,
                requestedinformation,
                None,
                None,
                None,
                None,
                Some(&raw mut sd),
            );

            if status.0 != 0 {
                // Some WIN32_ERROR-returning APIs set last-error, but make it explicit.
                SetLastError(WIN32_ERROR(status.0));
                return Err(WinError::from_thread());
            }

            *ppsecuritydescriptor = sd;
            Ok(())
        }
    }

    fn SetSecurity(
        &self,
        securityinformation: OBJECT_SECURITY_INFORMATION,
        psecuritydescriptor: PSECURITY_DESCRIPTOR,
    ) -> windows::core::Result<()> {
        // SAFETY: ISecurityInformation callback with valid handle and security descriptor from system
        unsafe {
            // We only support updating the DACL.
            if (securityinformation & DACL_SECURITY_INFORMATION) == OBJECT_SECURITY_INFORMATION(0) {
                return Ok(());
            }

            if self.this.readonly {
                return Err(WinError::from_thread());
            }

            let mut present = BOOL(0);
            let mut defaulted = BOOL(0);
            let mut dacl: *mut ACL = std::ptr::null_mut();
            GetSecurityDescriptorDacl(
                psecuritydescriptor,
                &raw mut present,
                &raw mut dacl,
                &raw mut defaulted,
            )?;

            let status = SetSecurityInfo(
                self.this.handle.raw(),
                SE_KERNEL_OBJECT,
                securityinformation,
                None,
                None,
                if present.as_bool() { Some(dacl) } else { None },
                None,
            );

            if status.0 != 0 {
                SetLastError(WIN32_ERROR(status.0));
                return Err(WinError::from_thread());
            }
            Ok(())
        }
    }

    fn GetAccessRights(
        &self,
        _pguidobjecttype: *const GUID,
        _dwflags: SECURITY_INFO_PAGE_FLAGS,
        ppaccess: *mut *mut SI_ACCESS,
        pcaccesses: *mut u32,
        pidefaultaccess: *mut u32,
    ) -> windows::core::Result<()> {
        // SAFETY: ISecurityInformation callback; out-parameters validated before dereferencing
        unsafe {
            if ppaccess.is_null() || pcaccesses.is_null() || pidefaultaccess.is_null() {
                return Err(WinError::from_thread());
            }

            let count = self.this.access_rights.len();
            let total_size = count * std::mem::size_of::<SI_ACCESS>();
            let mem = CoTaskMemAlloc(total_size);
            if mem.is_null() {
                return Err(WinError::from_thread());
            }

            let access_slice = std::slice::from_raw_parts_mut(mem.cast::<SI_ACCESS>(), count);
            for (idx, (name_w, mask)) in self.this.access_rights.iter().enumerate() {
                access_slice[idx] = SI_ACCESS {
                    pguid: std::ptr::null(),
                    mask: *mask,
                    pszName: PCWSTR(name_w.as_ptr()),
                    dwFlags: 0,
                };
            }

            *ppaccess = mem.cast::<SI_ACCESS>();
            *pcaccesses = count as u32;
            *pidefaultaccess = 0;
            Ok(())
        }
    }

    fn MapGeneric(
        &self,
        _pguidobjecttype: *const GUID,
        _paceflags: *mut u8,
        pmask: *mut u32,
    ) -> windows::core::Result<()> {
        // SAFETY: ISecurityInformation callback; pmask validated before dereferencing
        unsafe {
            if pmask.is_null() {
                return Ok(());
            }

            let mapping = GENERIC_MAPPING {
                GenericRead: READ_CONTROL_RIGHT,
                GenericWrite: WRITE_DAC_RIGHT,
                GenericExecute: 0,
                GenericAll: 0x001F0FFF,
            };

            MapGenericMask(pmask, &raw const mapping);
            Ok(())
        }
    }

    fn GetInheritTypes(
        &self,
        ppinherittypes: *mut *mut SI_INHERIT_TYPE,
        pcinherittypes: *mut u32,
    ) -> windows::core::Result<()> {
        // SAFETY: ISecurityInformation callback; pointers validated before dereferencing
        unsafe {
            if !ppinherittypes.is_null() {
                *ppinherittypes = std::ptr::null_mut();
            }
            if !pcinherittypes.is_null() {
                *pcinherittypes = 0;
            }
            Ok(())
        }
    }

    fn PropertySheetPageCallback(
        &self,
        _hwnd: HWND,
        _umsg: PSPCB_MESSAGE,
        _upage: SI_PAGE_TYPE,
    ) -> windows::core::Result<()> {
        Ok(())
    }
}

/// Opens the native Windows “Permissions…” (ACL editor) dialog for the *process kernel object*.
///
/// - `owner_hwnd`: native HWND to own the modal dialog (0 for none)
pub fn open_process_permissions_dialog(
    owner_hwnd: isize,
    pid: u32,
    object_name: String,
) -> Result<(), PermissionsError> {
    let access = match probe_process_object_permissions(pid)? {
        ProcessPermissionsAccess::Denied => return Err(PermissionsError::AccessDenied),
        a => a,
    };

    let (handle, _access) = match access {
        ProcessPermissionsAccess::ReadWrite => open_process_for_permissions(pid, true)?,
        ProcessPermissionsAccess::ReadOnly => open_process_for_permissions(pid, false)?,
        ProcessPermissionsAccess::Denied => return Err(PermissionsError::AccessDenied),
    };

    // SAFETY: Standard COM initialization with proper cleanup via RAII guard
    unsafe {
        CoInitializeEx(None, COINIT_APARTMENTTHREADED)
            .ok()
            .map_err(|e| map_error("CoInitializeEx", e))?;
    }

    struct ComGuard;
    impl Drop for ComGuard {
        fn drop(&mut self) {
            // SAFETY: Paired with CoInitializeEx; called exactly once per initialization
            unsafe { CoUninitialize() };
        }
    }
    let _com = ComGuard;

    let sec_info: ISecurityInformation =
        ProcessSecurityInformation::new(handle, object_name, access).into();

    // SAFETY: Valid HWND and ISecurityInformation interface pointer from successful creation
    unsafe {
        EditSecurity(HWND(owner_hwnd as _), &sec_info).map_err(|e| map_error("EditSecurity", e))?;
    }

    Ok(())
}
