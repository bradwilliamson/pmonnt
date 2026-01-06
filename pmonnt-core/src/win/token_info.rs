use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use thiserror::Error;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{GetLastError, HANDLE};
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, LookupAccountSidW,
    LookupPrivilegeDisplayNameW, LookupPrivilegeNameW, LUID_AND_ATTRIBUTES, PSID,
    SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_REMOVED,
    SE_PRIVILEGE_USED_FOR_ACCESS, SID_AND_ATTRIBUTES, SID_NAME_USE, TOKEN_ELEVATION_TYPE,
    TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_QUERY,
    TOKEN_STATISTICS, TOKEN_USER,
};
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::{get_process_protection, HandleGuard};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityLevel {
    Untrusted,
    Low,
    Medium,
    MediumPlus,
    High,
    System,
    Protected,
    Unknown(String),
}

#[derive(Debug, Clone)]
pub struct TokenSummary {
    pub user: String,
    pub user_sid: String,
    pub session_id: u32,
    pub logon_luid: Option<String>,
    pub integrity: IntegrityLevel,
    pub elevation: Option<String>,
    pub virtualization_enabled: Option<bool>,
    pub is_app_container: Option<bool>,
    pub is_protected_process: Option<bool>,
    pub is_ppl: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct GroupEntry {
    pub name: String,
    pub sid: String,
    pub attributes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PrivEntry {
    pub name: String,
    pub display: String,
    pub enabled: bool,
    pub attributes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SecurityInfo {
    pub summary: TokenSummary,
    pub groups: Vec<GroupEntry>,
    pub groups_error: Option<SecurityError>,
    pub privileges: Vec<PrivEntry>,
    pub privileges_error: Option<SecurityError>,
}

#[derive(Debug, Error, Clone)]
pub enum SecurityError {
    #[error("access denied")]
    AccessDenied,

    #[error("process exited")]
    ProcessExited,

    #[error("win32 error ({context}): {code}")]
    Win32 { context: &'static str, code: u32 },

    #[error("{0}")]
    Other(String),
}

// ConvertSidToStringSidW isn't consistently exposed via windows-rs in this repo's feature set,
// so we bind it directly.
#[link(name = "advapi32")]
extern "system" {
    fn ConvertSidToStringSidW(sid: *const core::ffi::c_void, string_sid: *mut *mut u16) -> i32;
}

// ConvertSidToStringSidW returns memory that must be freed with LocalFree.
#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(hmem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
}

fn win32_code(err: windows::core::Error) -> u32 {
    err.code().0 as u32
}

fn map_open_error(context: &'static str, err: windows::core::Error) -> SecurityError {
    match win32_code(err) {
        5 => SecurityError::AccessDenied,          // ERROR_ACCESS_DENIED
        87 | 1168 => SecurityError::ProcessExited, // ERROR_INVALID_PARAMETER / ERROR_NOT_FOUND-ish
        code => SecurityError::Win32 { context, code },
    }
}

fn map_last_error(context: &'static str) -> SecurityError {
    // SAFETY: `GetLastError` has no preconditions; it only reads thread-local state.
    let err = unsafe { GetLastError() };
    let code = err.0;
    match code {
        5 => SecurityError::AccessDenied,
        87 | 1168 => SecurityError::ProcessExited,
        _ => SecurityError::Win32 { context, code },
    }
}

fn token_info_raw(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<u8>, SecurityError> {
    let mut needed = 0u32;
    // SAFETY: `token` is expected to be a valid token handle. Passing a null buffer with size 0 is
    // the documented pattern to query the required buffer size.
    let _ = unsafe { GetTokenInformation(token, class, None, 0, &mut needed) };
    if needed == 0 {
        return Err(map_last_error("GetTokenInformation(size)"));
    }

    let mut buf = vec![0u8; needed as usize];
    // SAFETY: `buf` is a valid writable allocation of `needed` bytes. The pointer and length we
    // pass match that allocation, and `needed` is a valid out-parameter.
    unsafe {
        GetTokenInformation(
            token,
            class,
            Some(buf.as_mut_ptr() as *mut _),
            needed,
            &mut needed,
        )
    }
    .map_err(|e| map_open_error("GetTokenInformation(data)", e))?;

    Ok(buf)
}

fn wide_string_from_buf(buf: &[u16]) -> String {
    let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    OsString::from_wide(&buf[..end])
        .to_string_lossy()
        .into_owned()
}

fn sid_to_string(sid: PSID) -> Result<String, SecurityError> {
    // SAFETY: ConvertSidToStringSidW, string traversal, and LocalFree operations
    // - sid must be a valid SID pointer from caller
    // - ConvertSidToStringSidW allocates string that must be freed with LocalFree
    unsafe {
        let mut out_ptr: *mut u16 = std::ptr::null_mut();
        // SAFETY: `sid` must be a valid SID pointer for the duration of the call.
        // `ConvertSidToStringSidW` returns a NUL-terminated UTF-16 string allocated by the OS.
        let ok = ConvertSidToStringSidW(sid.0, &mut out_ptr);
        if ok == 0 || out_ptr.is_null() {
            return Err(map_last_error("ConvertSidToStringSidW"));
        }

        let mut len = 0usize;
        // SAFETY: `out_ptr` points to a NUL-terminated UTF-16 string as guaranteed by
        // `ConvertSidToStringSidW` on success.
        while *out_ptr.add(len) != 0 {
            len += 1;
        }
        // SAFETY: `out_ptr` is valid for `len` UTF-16 code units as scanned above.
        let slice = std::slice::from_raw_parts(out_ptr, len);
        let s = OsString::from_wide(slice).to_string_lossy().into_owned();

        // SAFETY: Memory returned by `ConvertSidToStringSidW` must be freed with `LocalFree`.
        let _ = LocalFree(out_ptr as _);
        Ok(s)
    }
}

fn lookup_account_name(sid: PSID) -> Option<String> {
    // SAFETY: LookupAccountSidW operations with valid SID pointer from caller
    // - Two-phase pattern: size query then data retrieval
    // - Buffers sized from first call
    unsafe {
        // SAFETY: `sid` must be a valid SID pointer for the duration of these Win32 calls.
        // First call to get required sizes
        let mut name_len = 0u32;
        let mut domain_len = 0u32;
        let mut use_type = SID_NAME_USE(0);

        let _ = LookupAccountSidW(
            None,
            sid,
            PWSTR::null(),
            &mut name_len,
            PWSTR::null(),
            &mut domain_len,
            &mut use_type,
        );

        if name_len == 0 {
            return None;
        }

        let mut name_buf = vec![0u16; name_len as usize + 2];
        let mut domain_buf = vec![0u16; domain_len as usize + 2];

        if LookupAccountSidW(
            None,
            sid,
            PWSTR(name_buf.as_mut_ptr()),
            &mut name_len,
            PWSTR(domain_buf.as_mut_ptr()),
            &mut domain_len,
            &mut use_type,
        )
        .is_err()
        {
            return None;
        }

        let name = wide_string_from_buf(&name_buf);
        let domain = wide_string_from_buf(&domain_buf);

        if domain.is_empty() {
            Some(name)
        } else {
            Some(format!("{}\\{}", domain, name))
        }
    }
}

fn integrity_from_token(token: HANDLE) -> Result<IntegrityLevel, SecurityError> {
    let buf = token_info_raw(token, TOKEN_INFORMATION_CLASS(25))?; // TokenIntegrityLevel
    // SAFETY: buf is populated by GetTokenInformation(TokenIntegrityLevel) and begins with TOKEN_MANDATORY_LABEL
    // - Use read_unaligned because Vec<u8> does not guarantee alignment
    let label = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL) };
    let sid = label.Label.Sid;

    // SAFETY: SID from token-provided TOKEN_MANDATORY_LABEL, valid for query helpers
    unsafe {
        // SAFETY: `sid` comes from the token-provided `TOKEN_MANDATORY_LABEL` and is expected to
        // be a valid SID pointer for these query helpers.
        let count_ptr = GetSidSubAuthorityCount(sid);
        if count_ptr.is_null() || *count_ptr == 0 {
            return Ok(IntegrityLevel::Unknown("<invalid sid>".to_string()));
        }
        let rid_ptr = GetSidSubAuthority(sid, (*count_ptr - 1) as u32);
        if rid_ptr.is_null() {
            return Ok(IntegrityLevel::Unknown("<invalid sid>".to_string()));
        }
        let rid = *rid_ptr;
        Ok(match rid {
            0x0000 => IntegrityLevel::Untrusted,
            0x1000 => IntegrityLevel::Low,
            0x2000 => IntegrityLevel::Medium,
            0x2100 => IntegrityLevel::MediumPlus,
            0x3000 => IntegrityLevel::High,
            0x4000 => IntegrityLevel::System,
            0x5000 => IntegrityLevel::Protected,
            other => IntegrityLevel::Unknown(format!("0x{other:X}")),
        })
    }
}

fn elevation_from_token(token: HANDLE) -> Option<String> {
    // TokenElevationType is 18. TOKEN_ELEVATION_TYPE exists and is a u32 repr.
    let buf = token_info_raw(token, TOKEN_INFORMATION_CLASS(18)).ok()?;
    // SAFETY: `buf` is populated by `GetTokenInformation(TokenElevationType)` and begins with a
    // `TOKEN_ELEVATION_TYPE`. We use `read_unaligned` because `Vec<u8>` does not guarantee
    // alignment for the target type.
    let t = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const TOKEN_ELEVATION_TYPE) };
    // TOKEN_ELEVATION_TYPE values: 1=Default,2=Full,3=Limited
    Some(match t {
        TOKEN_ELEVATION_TYPE(1) => "Default".to_string(),
        TOKEN_ELEVATION_TYPE(2) => "Full".to_string(),
        TOKEN_ELEVATION_TYPE(3) => "Limited".to_string(),
        _ => format!("Unknown ({})", t.0),
    })
}

fn bool_token_flag(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Option<bool> {
    let buf = token_info_raw(token, class).ok()?;
    if buf.len() < 4 {
        return None;
    }
    let v = u32::from_ne_bytes(buf[0..4].try_into().ok()?);
    Some(v != 0)
}

fn u32_token_value(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Option<u32> {
    let buf = token_info_raw(token, class).ok()?;
    if buf.len() < 4 {
        return None;
    }
    Some(u32::from_ne_bytes(buf[0..4].try_into().ok()?))
}

fn token_user(token: HANDLE) -> Result<(String, String), SecurityError> {
    let buf = token_info_raw(token, TOKEN_INFORMATION_CLASS(1))?; // TokenUser
                                                                  // SAFETY: `buf` is populated by `GetTokenInformation(TokenUser)` and begins with a
                                                                  // `TOKEN_USER`. We use `read_unaligned` because `Vec<u8>` does not guarantee alignment.
    let token_user = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const TOKEN_USER) };
    let sid = token_user.User.Sid;

    let sid_str = sid_to_string(sid)?;
    let name = lookup_account_name(sid).unwrap_or_else(|| sid_str.clone());
    Ok((name, sid_str))
}

fn group_attrs_to_strings(attrs: u32) -> Vec<String> {
    // TokenGroups attributes are plain bitflags from winnt.h.
    const SE_GROUP_MANDATORY_U32: u32 = 0x0000_0001;
    const SE_GROUP_ENABLED_BY_DEFAULT_U32: u32 = 0x0000_0002;
    const SE_GROUP_ENABLED_U32: u32 = 0x0000_0004;
    const SE_GROUP_OWNER_U32: u32 = 0x0000_0008;
    const SE_GROUP_USE_FOR_DENY_ONLY_U32: u32 = 0x0000_0010;
    const SE_GROUP_INTEGRITY_U32: u32 = 0x0000_0020;
    const SE_GROUP_INTEGRITY_ENABLED_U32: u32 = 0x0000_0040;
    const SE_GROUP_RESOURCE_U32: u32 = 0x2000_0000;
    const SE_GROUP_LOGON_ID_U32: u32 = 0xC000_0000;

    let mut out = Vec::new();
    if attrs & SE_GROUP_MANDATORY_U32 != 0 {
        out.push("Mandatory".to_string());
    }
    if attrs & SE_GROUP_ENABLED_BY_DEFAULT_U32 != 0 {
        out.push("EnabledByDefault".to_string());
    }
    if attrs & SE_GROUP_ENABLED_U32 != 0 {
        out.push("Enabled".to_string());
    }
    if attrs & SE_GROUP_OWNER_U32 != 0 {
        out.push("Owner".to_string());
    }
    if attrs & SE_GROUP_USE_FOR_DENY_ONLY_U32 != 0 {
        out.push("DenyOnly".to_string());
    }
    if attrs & SE_GROUP_LOGON_ID_U32 != 0 {
        out.push("LogonId".to_string());
    }
    if attrs & SE_GROUP_RESOURCE_U32 != 0 {
        out.push("Resource".to_string());
    }
    if attrs & SE_GROUP_INTEGRITY_U32 != 0 {
        out.push("Integrity".to_string());
    }
    if attrs & SE_GROUP_INTEGRITY_ENABLED_U32 != 0 {
        out.push("IntegrityEnabled".to_string());
    }
    if out.is_empty() {
        out.push(format!("0x{attrs:X}"));
    }
    out
}

fn privilege_attrs_to_strings(attrs: u32) -> Vec<String> {
    let mut out = Vec::new();
    if attrs & SE_PRIVILEGE_ENABLED_BY_DEFAULT.0 != 0 {
        out.push("EnabledByDefault".to_string());
    }
    if attrs & SE_PRIVILEGE_ENABLED.0 != 0 {
        out.push("Enabled".to_string());
    }
    if attrs & SE_PRIVILEGE_REMOVED.0 != 0 {
        out.push("Removed".to_string());
    }
    if attrs & SE_PRIVILEGE_USED_FOR_ACCESS.0 != 0 {
        out.push("UsedForAccess".to_string());
    }
    if out.is_empty() {
        out.push(format!("0x{attrs:X}"));
    }
    out
}

fn token_groups(token: HANDLE) -> Result<Vec<GroupEntry>, SecurityError> {
    let buf = token_info_raw(token, TOKEN_INFORMATION_CLASS(2))?; // TokenGroups
                                                                  // SAFETY: `buf` is populated by `GetTokenInformation(TokenGroups)` and begins with a
                                                                  // `TOKEN_GROUPS`. We use `read_unaligned` because `Vec<u8>` does not guarantee alignment.
    let groups = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const TOKEN_GROUPS) };

    let count = groups.GroupCount as usize;
    // SAFETY: The groups array begins at the `Groups` field within the returned `TOKEN_GROUPS`
    // buffer. The OS promises the buffer is large enough for `count` entries.
    let first = unsafe {
        buf.as_ptr()
            .add(std::mem::offset_of!(TOKEN_GROUPS, Groups))
            .cast::<SID_AND_ATTRIBUTES>()
    };
    // SAFETY: `first` points into `buf`, and `count` comes from the OS-provided header.
    let slice = unsafe { std::slice::from_raw_parts(first, count) };

    let mut out = Vec::with_capacity(count);
    for g in slice {
        let sid_ptr = g.Sid;
        let sid = sid_to_string(sid_ptr)?;
        let name = lookup_account_name(sid_ptr).unwrap_or_else(|| sid.clone());
        out.push(GroupEntry {
            name,
            sid,
            attributes: group_attrs_to_strings(g.Attributes),
        });
    }
    Ok(out)
}

fn luid_to_name(luid: &windows::Win32::Foundation::LUID) -> Option<String> {
    // SAFETY: LookupPrivilegeNameW operations with valid LUID pointer
    // - Two-phase pattern: size query with null buffer, then data retrieval
    // - Buffer sized from first call
    unsafe {
        let mut len = 0u32;
        // SAFETY: `luid` is a valid pointer for the duration of the call; passing a null output
        // buffer is the documented pattern to query the required length.
        let _ = LookupPrivilegeNameW(None, luid, PWSTR::null(), &mut len);
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u16; len as usize + 2];
        // SAFETY: `buf` is a writable UTF-16 buffer of `len` elements (plus spare), and `luid` is
        // valid for the call.
        if LookupPrivilegeNameW(None, luid, PWSTR(buf.as_mut_ptr()), &mut len).is_err() {
            return None;
        }
        Some(wide_string_from_buf(&buf))
    }
}

fn luid_to_display(name: &str) -> Option<String> {
    // SAFETY: LookupPrivilegeDisplayNameW operations with valid null-terminated UTF-16 string
    // - Two-phase pattern: size query then data retrieval
    // - name_w is valid for the duration of both calls
    unsafe {
        // First query size.
        let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut len = 0u32;
        let mut lang = 0u32;
        // SAFETY: `name_w` is NUL-terminated UTF-16 for the duration of the call; passing a null
        // output buffer is the documented pattern to query the required length.
        let _ = LookupPrivilegeDisplayNameW(
            PCWSTR::null(),
            PCWSTR(name_w.as_ptr()),
            PWSTR::null(),
            &mut len,
            &mut lang,
        );
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u16; len as usize + 2];
        // SAFETY: `buf` is a writable UTF-16 buffer of `len` elements (plus spare). `name_w` is a
        // valid NUL-terminated UTF-16 string for the duration of the call.
        if LookupPrivilegeDisplayNameW(
            PCWSTR::null(),
            PCWSTR(name_w.as_ptr()),
            PWSTR(buf.as_mut_ptr()),
            &mut len,
            &mut lang,
        )
        .is_err()
        {
            return None;
        }
        Some(wide_string_from_buf(&buf))
    }
}

fn token_privileges(token: HANDLE) -> Result<Vec<PrivEntry>, SecurityError> {
    let buf = token_info_raw(token, TOKEN_INFORMATION_CLASS(3))?; // TokenPrivileges
                                                                  // SAFETY: `buf` is populated by `GetTokenInformation(TokenPrivileges)` and begins with a
                                                                  // `TOKEN_PRIVILEGES`. We use `read_unaligned` because `Vec<u8>` does not guarantee alignment.
    let tp = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const TOKEN_PRIVILEGES) };
    let count = tp.PrivilegeCount as usize;

    log::debug!("token_privileges: found {} privilege(s)", count);

    // SAFETY: The privileges array begins at the `Privileges` field within the returned
    // `TOKEN_PRIVILEGES` buffer. The OS promises the buffer is large enough for `count` entries.
    let first = unsafe {
        buf.as_ptr()
            .add(std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges))
            .cast::<LUID_AND_ATTRIBUTES>()
    };
    // SAFETY: `first` points into `buf`, and `count` comes from the OS-provided header.
    let slice = unsafe { std::slice::from_raw_parts(first, count) };

    let mut out = Vec::with_capacity(count);
    for p in slice {
        let attrs = p.Attributes.0;
        let name = luid_to_name(&p.Luid)
            .unwrap_or_else(|| format!("LUID({}:{})", p.Luid.HighPart, p.Luid.LowPart));
        let display = luid_to_display(&name).unwrap_or_else(|| name.clone());
        let enabled = (attrs & SE_PRIVILEGE_ENABLED.0) != 0;
        out.push(PrivEntry {
            name: name.clone(),
            display,
            enabled,
            attributes: privilege_attrs_to_strings(attrs),
        });
        log::debug!("  privilege: {} (enabled={})", name, enabled);
    }

    out.sort_by(|a, b| a.name.cmp(&b.name));
    log::debug!("token_privileges: returning {} entries", out.len());
    Ok(out)
}

fn token_statistics_logon_luid(token: HANDLE) -> Option<String> {
    let buf = token_info_raw(token, TOKEN_INFORMATION_CLASS(10)).ok()?; // TokenStatistics
                                                                        // SAFETY: `buf` is populated by `GetTokenInformation(TokenStatistics)` and begins with a
                                                                        // `TOKEN_STATISTICS`. We use `read_unaligned` because `Vec<u8>` does not guarantee alignment.
    let stats = unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const TOKEN_STATISTICS) };
    let luid = stats.AuthenticationId;
    Some(format!(
        "0x{:08X}{:08X}",
        (luid.HighPart as u32),
        luid.LowPart
    ))
}

/// Returns detailed process token/security info.
///
/// This is designed to work for normal processes without admin. For protected/system processes,
/// this may return `SecurityError::AccessDenied`.
pub fn get_process_security_info(pid: u32) -> Result<SecurityInfo, SecurityError> {
    // SAFETY: Win32 requires this call to be `unsafe`. We pass a PID and request only
    // `PROCESS_QUERY_LIMITED_INFORMATION`.
    let process_handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .map_err(|e| map_open_error("OpenProcess", e))?;
    let _process_guard = HandleGuard::new(process_handle);

    let mut token = HANDLE::default();
    // SAFETY: `process_handle` is a valid handle from `OpenProcess`, and `token` is a valid
    // out-parameter for the duration of the call.
    unsafe { OpenProcessToken(process_handle, TOKEN_QUERY, &mut token) }
        .map_err(|e| map_open_error("OpenProcessToken", e))?;
    if token.is_invalid() {
        return Err(SecurityError::Other("invalid token handle".to_string()));
    }
    let _token_guard = HandleGuard::new(token);

    let (user, user_sid) = token_user(token)?;

    let session_id = u32_token_value(token, TOKEN_INFORMATION_CLASS(12)) // TokenSessionId
        .unwrap_or(0);

    let integrity =
        integrity_from_token(token).unwrap_or(IntegrityLevel::Unknown("<unavailable>".to_string()));

    let elevation = elevation_from_token(token);

    let virtualization_enabled = bool_token_flag(token, TOKEN_INFORMATION_CLASS(23)); // TokenVirtualizationEnabled
    let is_app_container = bool_token_flag(token, TOKEN_INFORMATION_CLASS(29)); // TokenIsAppContainer

    let logon_luid = token_statistics_logon_luid(token);

    // Best-effort: protection/PPL
    let (prot, level) = get_process_protection(pid);
    let (is_protected_process, is_ppl) = match level {
        Some(ref s) if prot => {
            let ppl = s.contains("PPL");
            (Some(true), Some(ppl))
        }
        Some(_) => (Some(false), Some(false)),
        None => (Some(false), None),
    };

    let summary = TokenSummary {
        user,
        user_sid,
        session_id,
        logon_luid,
        integrity,
        elevation,
        virtualization_enabled,
        is_app_container,
        is_protected_process,
        is_ppl,
    };

    // Best-effort groups/privileges: keep summary even if these fail,
    // but preserve the error so callers can render a friendly message.
    let (groups, groups_error) = match token_groups(token) {
        Ok(v) => {
            log::debug!(
                "get_process_security_info(pid={}): got {} groups",
                pid,
                v.len()
            );
            (v, None)
        }
        Err(e) => {
            log::warn!(
                "get_process_security_info(pid={}): groups failed: {}",
                pid,
                e
            );
            (Vec::new(), Some(e))
        }
    };

    let (privileges, privileges_error) = match token_privileges(token) {
        Ok(v) => {
            log::debug!(
                "get_process_security_info(pid={}): got {} privileges",
                pid,
                v.len()
            );
            (v, None)
        }
        Err(e) => {
            log::warn!(
                "get_process_security_info(pid={}): privileges failed: {}",
                pid,
                e
            );
            (Vec::new(), Some(e))
        }
    };

    log::info!(
        "get_process_security_info(pid={}): returning SecurityInfo with {} groups, {} privileges",
        pid,
        groups.len(),
        privileges.len()
    );

    Ok(SecurityInfo {
        summary,
        groups,
        groups_error,
        privileges,
        privileges_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_flags_are_human_readable() {
        let flags = 0x0000_0001 | 0x0000_0004 | 0x0000_0010;
        let s = group_attrs_to_strings(flags);
        assert!(s.iter().any(|x| x == "Mandatory"));
        assert!(s.iter().any(|x| x == "Enabled"));
        assert!(s.iter().any(|x| x == "DenyOnly"));
    }

    #[test]
    fn privilege_state_flags_are_human_readable() {
        let flags = SE_PRIVILEGE_ENABLED.0 | SE_PRIVILEGE_ENABLED_BY_DEFAULT.0;
        let s = privilege_attrs_to_strings(flags);
        assert!(s.iter().any(|x| x == "Enabled"));
        assert!(s.iter().any(|x| x == "EnabledByDefault"));
    }
}
