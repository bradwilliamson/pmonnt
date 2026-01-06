use std::{ffi::OsString, os::windows::ffi::OsStringExt};

use anyhow::Result;

use windows::{
    core::{PCWSTR, PWSTR},
    Win32::System::Performance::{PdhExpandWildCardPathW, PDH_MORE_DATA},
};

pub(super) type PdhCounterHandle = isize;
pub(super) type PdhQueryHandle = isize;

pub(super) struct WideString {
    inner: Vec<u16>,
}

impl WideString {
    pub(super) fn as_pwstr(&self) -> PCWSTR {
        PCWSTR(self.inner.as_ptr())
    }
}

pub(super) fn wstring(s: &str) -> WideString {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    WideString { inner: v }
}

#[inline]
pub(super) fn pdh_ok(status: u32) -> bool {
    // PDH returns 0 (ERROR_SUCCESS) on success; any non-zero is an error code
    status == 0
}

pub(super) fn expand_paths(path: &str) -> Result<Vec<String>> {
    let mut required: u32 = 0;
    let path_w = wstring(path);

    // First call to get required buffer size
    // SAFETY: PdhExpandWildCardPathW reads the input PCWSTR and writes the required size to
    // `required`. The output buffer is null for this size-query call by design.
    let status =
        unsafe { PdhExpandWildCardPathW(None, path_w.as_pwstr(), PWSTR::null(), &mut required, 0) };
    log::trace!(
        "[GPU PDH] PdhExpandWildCardPathW(size query) for '{}': status=0x{:08X}, required={}",
        path,
        status,
        required
    );

    // PDH_MORE_DATA (0x800007D2) indicates we need to allocate a buffer
    // Also check if status == 0 with required > 0 (some PDH versions)
    if status == PDH_MORE_DATA || (status == 0 && required > 0) {
        let mut buf: Vec<u16> = vec![0; required as usize];
        // SAFETY: `buf` is allocated to `required` UTF-16 code units and remains alive for the call.
        // PDH writes a MULTI_SZ (double-NUL terminated) into the buffer.
        let status2 = unsafe {
            PdhExpandWildCardPathW(
                None,
                path_w.as_pwstr(),
                PWSTR(buf.as_mut_ptr()),
                &mut required,
                0,
            )
        };
        log::trace!(
            "[GPU PDH] PdhExpandWildCardPathW(get data): status=0x{:08X}",
            status2
        );

        if pdh_ok(status2) {
            let paths = parse_multi_sz(&buf);
            log::debug!("[GPU PDH] Expanded '{}' to {} paths", path, paths.len());
            return Ok(paths);
        }
        return Err(anyhow::anyhow!(
            "PdhExpandWildCardPathW data call failed: 0x{status2:08X}"
        ));
    }

    // If required == 0, there are no matching counters
    if required == 0 {
        log::debug!(
            "[GPU PDH] No counters found matching '{}' (status=0x{:08X})",
            path,
            status
        );
        return Ok(Vec::new());
    }

    Err(anyhow::anyhow!(
        "PdhExpandWildCardPathW failed for '{}': status=0x{status:08X}",
        path
    ))
}

pub(super) fn parse_multi_sz(buf: &[u16]) -> Vec<String> {
    let mut result = Vec::new();
    let mut start = 0;
    for i in 0..buf.len() {
        if buf[i] == 0 {
            if start == i {
                break;
            }
            let slice = &buf[start..i];
            let os = OsString::from_wide(slice);
            result.push(os.to_string_lossy().into_owned());
            start = i + 1;
        }
    }
    result
}

pub(super) fn extract_pid(path: &str) -> Option<u32> {
    // Look for "pid_1234" in the instance path
    if let Some(idx) = path.find("pid_") {
        let tail = &path[idx + 4..];
        let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() {
            if let Ok(pid) = digits.parse::<u32>() {
                return Some(pid);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // --------------------------------------------------------------------------
    // extract_pid tests
    // --------------------------------------------------------------------------
    #[test]
    fn test_extract_pid_gpu_engine() {
        // Real GPU Engine counter path pattern
        let path = r"\GPU Engine(pid_1234_luid_0x00000000_0x0000B1E3_phys_0_eng_0_engtype_3D)\Utilization Percentage";
        assert_eq!(extract_pid(path), Some(1234));
    }

    #[test]
    fn test_extract_pid_process_memory() {
        // Real GPU Process Memory counter path pattern
        let path =
            r"\GPU Process Memory(pid_5678_luid_0x00000000_0x0000B1E3_phys_0)\Dedicated Usage";
        assert_eq!(extract_pid(path), Some(5678));
    }

    #[test]
    fn test_extract_pid_large_value() {
        let path = r"\GPU Engine(pid_4294967295_luid_0x00000000_0x0000B1E3_phys_0_eng_0_engtype_3D)\Utilization Percentage";
        assert_eq!(extract_pid(path), Some(4294967295)); // u32::MAX
    }

    #[test]
    fn test_extract_pid_no_pid() {
        let path = r"\GPU Engine(_Total)\Utilization Percentage";
        assert_eq!(extract_pid(path), None);
    }

    #[test]
    fn test_extract_pid_malformed() {
        let path = r"\GPU Engine(pid_abc)\Utilization Percentage";
        assert_eq!(extract_pid(path), None);
    }

    #[test]
    fn test_extract_pid_empty() {
        assert_eq!(extract_pid(""), None);
    }

    // --------------------------------------------------------------------------
    // parse_multi_sz tests
    // --------------------------------------------------------------------------
    #[test]
    fn test_parse_multi_sz_two_strings() {
        // "foo\0bar\0\0" in UTF-16
        let buf: Vec<u16> = vec![
            'f' as u16, 'o' as u16, 'o' as u16, 0, 'b' as u16, 'a' as u16, 'r' as u16, 0,
            0, // double-null terminator
        ];
        let result = parse_multi_sz(&buf);
        assert_eq!(result, vec!["foo", "bar"]);
    }

    #[test]
    fn test_parse_multi_sz_single_string() {
        // "hello\0\0" in UTF-16
        let buf: Vec<u16> = vec![
            'h' as u16, 'e' as u16, 'l' as u16, 'l' as u16, 'o' as u16, 0,
            0, // double-null terminator
        ];
        let result = parse_multi_sz(&buf);
        assert_eq!(result, vec!["hello"]);
    }

    #[test]
    fn test_parse_multi_sz_empty() {
        // Just double-null
        let buf: Vec<u16> = vec![0, 0];
        let result = parse_multi_sz(&buf);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_multi_sz_realistic_path() {
        // Realistic counter path
        let path = r"\GPU Engine(pid_1234_luid_0x00000000_0x0000B1E3_phys_0_eng_0_engtype_3D)\Utilization Percentage";
        let mut buf: Vec<u16> = path.encode_utf16().collect();
        buf.push(0); // null terminator for this string
        buf.push(0); // double-null terminator
        let result = parse_multi_sz(&buf);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], path);
    }

    // --------------------------------------------------------------------------
    // pdh_ok tests
    // --------------------------------------------------------------------------
    #[test]
    fn test_pdh_ok_success() {
        assert!(pdh_ok(0)); // ERROR_SUCCESS
    }

    #[test]
    fn test_pdh_ok_failure_codes() {
        assert!(!pdh_ok(0x800007D0)); // PDH_CSTATUS_NO_OBJECT
        assert!(!pdh_ok(0x800007D2)); // PDH_MORE_DATA
        assert!(!pdh_ok(0xC0000BB8)); // PDH_INVALID_DATA
        assert!(!pdh_ok(1)); // Generic error
        assert!(!pdh_ok(u32::MAX)); // Edge case
    }

    // --------------------------------------------------------------------------
    // wstring smoke
    // --------------------------------------------------------------------------
    #[test]
    fn test_wstring_null_terminated() {
        let w = wstring("abc");
        assert_eq!(*w.inner.last().unwrap_or(&1), 0);
    }

    #[test]
    fn test_wstring_empty() {
        let w = wstring("");
        assert_eq!(w.inner, vec![0]);
    }
}
