//! Process details retrieval via PEB parsing (command line, current directory, environment).
//!
//! This uses `NtQueryInformationProcess(ProcessBasicInformation)` to locate the PEB and then
//! `ReadProcessMemory` to read `RTL_USER_PROCESS_PARAMETERS` from the remote process.
//!
//! Notes:
//! - Requires `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`.
//! - Will fail for protected processes (PPL) and for elevated processes when not elevated.
//! - Supports querying WoW64 (32-bit) processes from a 64-bit process by using
//!   `ProcessWow64Information` to obtain the 32-bit PEB address.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::ffi::c_void;
use std::mem;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

use crate::win::ntdll::NtQueryInformationProcess;
use crate::win::HandleGuard;

#[derive(Debug, Clone, Default)]
pub struct ProcessDetails {
    pub command_line: Option<String>,
    pub current_directory: Option<String>,
    pub image_path: Option<String>,
    pub environment: Option<HashMap<String, String>>,
}

const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;
const PROCESS_WOW64_INFORMATION_CLASS: u32 = 26;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct PROCESS_BASIC_INFORMATION {
    _reserved1: *mut c_void,
    peb_base_address: *mut c_void,
    _reserved2: [*mut c_void; 2],
    _unique_process_id: usize,
    _reserved3: *mut c_void,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct UNICODE_STRING64 {
    length: u16,
    maximum_length: u16,
    buffer: usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct CURDIR64 {
    dos_path: UNICODE_STRING64,
    handle: usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct RTL_USER_PROCESS_PARAMETERS64 {
    maximum_length: u32,
    length: u32,
    flags: u32,
    debug_flags: u32,
    console_handle: usize,
    console_flags: u32,
    // Align to 8
    _pad1: u32,
    standard_input: usize,
    standard_output: usize,
    standard_error: usize,
    current_directory: CURDIR64,
    dll_path: UNICODE_STRING64,
    image_path_name: UNICODE_STRING64,
    command_line: UNICODE_STRING64,
    environment: usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct PEB64 {
    reserved1: [u8; 2],
    being_debugged: u8,
    reserved2: u8,
    reserved3: [usize; 2],
    ldr: usize,
    process_parameters: usize,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct UNICODE_STRING32 {
    length: u16,
    maximum_length: u16,
    buffer: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct CURDIR32 {
    dos_path: UNICODE_STRING32,
    handle: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct RTL_USER_PROCESS_PARAMETERS32 {
    maximum_length: u32,
    length: u32,
    flags: u32,
    debug_flags: u32,
    console_handle: u32,
    console_flags: u32,
    standard_input: u32,
    standard_output: u32,
    standard_error: u32,
    current_directory: CURDIR32,
    dll_path: UNICODE_STRING32,
    image_path_name: UNICODE_STRING32,
    command_line: UNICODE_STRING32,
    environment: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct PEB32 {
    reserved1: [u8; 2],
    being_debugged: u8,
    reserved2: u8,
    reserved3: [u32; 2],
    ldr: u32,
    process_parameters: u32,
}

fn nt_success(status: windows::Win32::Foundation::NTSTATUS) -> bool {
    status.0 >= 0
}

fn query_process_basic_information(handle: HANDLE) -> Result<PROCESS_BASIC_INFORMATION> {
    let mut pbi = PROCESS_BASIC_INFORMATION {
        _reserved1: std::ptr::null_mut(),
        peb_base_address: std::ptr::null_mut(),
        _reserved2: [std::ptr::null_mut(), std::ptr::null_mut()],
        _unique_process_id: 0,
        _reserved3: std::ptr::null_mut(),
    };
    let mut ret_len = 0u32;
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_BASIC_INFORMATION_CLASS,
            &mut pbi as *mut _ as *mut c_void,
            mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut ret_len,
        )
    };
    if !nt_success(status) {
        return Err(anyhow!(
            "NtQueryInformationProcess(ProcessBasicInformation) failed: {}",
            status.0
        ));
    }
    Ok(pbi)
}

fn query_wow64_peb_address(handle: HANDLE) -> Result<Option<u32>> {
    // Returns the 32-bit PEB address for WoW64 processes. If 0, the process is not WoW64.
    let mut peb32: usize = 0;
    let mut ret_len = 0u32;
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_WOW64_INFORMATION_CLASS,
            &mut peb32 as *mut _ as *mut c_void,
            mem::size_of::<usize>() as u32,
            &mut ret_len,
        )
    };
    if !nt_success(status) {
        // Some processes (protected) may fail here; treat as "unknown" and fall back to PBI.
        return Ok(None);
    }
    if peb32 == 0 {
        Ok(None)
    } else {
        Ok(Some(peb32 as u32))
    }
}

fn read_process_memory_exact(
    process_handle: HANDLE,
    address: usize,
    size: usize,
) -> Result<Vec<u8>> {
    if size == 0 {
        return Ok(Vec::new());
    }

    unsafe {
        let mut buffer = vec![0u8; size];
        let mut bytes_read: usize = 0;
        let ok = ReadProcessMemory(
            process_handle,
            address as *const _,
            buffer.as_mut_ptr() as *mut _,
            size,
            Some(&mut bytes_read),
        );
        if ok.is_err() {
            return Err(anyhow!("ReadProcessMemory failed at 0x{address:x}"));
        }
        if bytes_read != size {
            return Err(anyhow!(
                "ReadProcessMemory short read at 0x{address:x}: {bytes_read}/{size}"
            ));
        }
        Ok(buffer)
    }
}

fn read_process_memory<T: Copy>(process_handle: HANDLE, address: usize) -> Result<T> {
    let bytes = read_process_memory_exact(process_handle, address, mem::size_of::<T>())?;
    // SAFETY: `bytes` is exactly size_of::<T>() and `T: Copy`.
    Ok(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const T) })
}

fn decode_utf16_bytes(bytes: &[u8]) -> Result<String> {
    if bytes.is_empty() {
        return Ok(String::new());
    }
    if !bytes.len().is_multiple_of(2) {
        return Err(anyhow!("UTF-16 buffer length is not even"));
    }
    let mut u16s = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        u16s.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    Ok(String::from_utf16_lossy(&u16s))
}

fn read_remote_unicode_string64(handle: HANDLE, us: UNICODE_STRING64) -> Result<Option<String>> {
    if us.length == 0 || us.buffer == 0 {
        return Ok(None);
    }
    // Length is in bytes.
    let bytes = read_process_memory_exact(handle, us.buffer, us.length as usize)?;
    let s = decode_utf16_bytes(&bytes)?;
    Ok(Some(s))
}

fn read_remote_unicode_string32(handle: HANDLE, us: UNICODE_STRING32) -> Result<Option<String>> {
    if us.length == 0 || us.buffer == 0 {
        return Ok(None);
    }
    let bytes = read_process_memory_exact(handle, us.buffer as usize, us.length as usize)?;
    let s = decode_utf16_bytes(&bytes)?;
    Ok(Some(s))
}

fn looks_sensitive_env_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    [
        "KEY", "TOKEN", "SECRET", "PASSWORD", "PASS", "PWD", "AUTH", "BEARER", "COOKIE",
    ]
    .into_iter()
    .any(|needle| upper.contains(needle))
}

fn sanitize_env_pair(key: String, mut value: String) -> (String, String) {
    if looks_sensitive_env_key(&key) {
        return (key, "<redacted>".to_string());
    }
    const MAX_VALUE_CHARS: usize = 4096;
    if value.chars().count() > MAX_VALUE_CHARS {
        value = value.chars().take(MAX_VALUE_CHARS).collect::<String>() + "…";
    }
    (key, value)
}

fn parse_environment_block_utf16(block: &[u16]) -> HashMap<String, String> {
    // Environment block is a sequence of NUL-terminated UTF-16 strings, terminated by an empty string.
    // Example: "FOO=bar\0PATH=...\0\0"
    let mut out = HashMap::new();
    let mut start = 0usize;
    while start < block.len() {
        // Find NUL
        let mut end = start;
        while end < block.len() && block[end] != 0 {
            end += 1;
        }
        if end == start {
            // Empty string => terminator
            break;
        }
        let entry = String::from_utf16_lossy(&block[start..end]);
        if let Some(eq) = entry.find('=') {
            let (k, v) = entry.split_at(eq);
            let key = k.to_string();
            let value = v[1..].to_string();
            let (key, value) = sanitize_env_pair(key, value);
            out.insert(key, value);
        } else {
            // Not a key=value pair; keep as-is under a synthetic key.
            out.insert(entry, String::new());
        }
        start = end + 1;
    }
    out
}

fn read_environment_block_u16(
    handle: HANDLE,
    env_ptr: usize,
    max_bytes: usize,
) -> Result<Vec<u16>> {
    if env_ptr == 0 {
        return Ok(Vec::new());
    }

    const CHUNK_BYTES: usize = 16 * 1024;
    let mut bytes = Vec::new();
    let mut offset = 0usize;

    while bytes.len() < max_bytes {
        let to_read = CHUNK_BYTES.min(max_bytes - bytes.len());
        let chunk = unsafe {
            let mut buffer = vec![0u8; to_read];
            let mut bytes_read: usize = 0;
            let ok = ReadProcessMemory(
                handle,
                (env_ptr + offset) as *const _,
                buffer.as_mut_ptr() as *mut _,
                to_read,
                Some(&mut bytes_read),
            );
            if ok.is_err() {
                return Err(anyhow!(
                    "ReadProcessMemory failed reading environment at 0x{:x}",
                    env_ptr + offset
                ));
            }
            buffer.truncate(bytes_read);
            buffer
        };

        if chunk.is_empty() {
            break;
        }

        bytes.extend_from_slice(&chunk);

        // Scan for UTF-16 double NUL terminator.
        if bytes.len() >= 4 {
            let mut i = bytes.len().saturating_sub(chunk.len());
            if i >= 2 {
                i -= 2;
            }
            while i + 3 < bytes.len() {
                if bytes[i] == 0 && bytes[i + 1] == 0 && bytes[i + 2] == 0 && bytes[i + 3] == 0 {
                    bytes.truncate(i + 4);
                    // Convert to u16s.
                    let mut u16s = Vec::with_capacity(bytes.len() / 2);
                    for pair in bytes.chunks_exact(2) {
                        u16s.push(u16::from_le_bytes([pair[0], pair[1]]));
                    }
                    return Ok(u16s);
                }
                i += 2;
            }
        }

        offset += chunk.len();
        if chunk.len() < to_read {
            break;
        }
    }

    // Convert what we got.
    let mut u16s = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        u16s.push(u16::from_le_bytes([pair[0], pair[1]]));
    }
    Ok(u16s)
}

/// Retrieve full process details by PID.
///
/// If `include_environment` is false, the environment is not read.
pub fn get_process_details(pid: u32, include_environment: bool) -> Result<ProcessDetails> {
    if pid == 0 {
        return Ok(ProcessDetails::default());
    }

    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }?;
    let guard = HandleGuard::new(handle);

    // Prefer WoW64 PEB when available; otherwise use native PEB via PBI.
    if let Some(peb32_addr) = query_wow64_peb_address(guard.raw())? {
        let peb32: PEB32 = read_process_memory(guard.raw(), peb32_addr as usize)?;
        if peb32.process_parameters == 0 {
            return Ok(ProcessDetails::default());
        }
        let params: RTL_USER_PROCESS_PARAMETERS32 =
            read_process_memory(guard.raw(), peb32.process_parameters as usize)?;

        let command_line = read_remote_unicode_string32(guard.raw(), params.command_line)?;
        let current_directory =
            read_remote_unicode_string32(guard.raw(), params.current_directory.dos_path)?;
        let image_path = read_remote_unicode_string32(guard.raw(), params.image_path_name)?;

        let environment = if include_environment && params.environment != 0 {
            // Cap environment reads to 1MB.
            let block =
                read_environment_block_u16(guard.raw(), params.environment as usize, 1024 * 1024)?;
            Some(parse_environment_block_utf16(&block))
        } else {
            None
        };

        return Ok(ProcessDetails {
            command_line,
            current_directory,
            image_path,
            environment,
        });
    }

    let pbi = query_process_basic_information(guard.raw())?;
    if pbi.peb_base_address.is_null() {
        return Ok(ProcessDetails::default());
    }

    let peb: PEB64 = read_process_memory(guard.raw(), pbi.peb_base_address as usize)?;
    if peb.process_parameters == 0 {
        return Ok(ProcessDetails::default());
    }

    let params: RTL_USER_PROCESS_PARAMETERS64 =
        read_process_memory(guard.raw(), peb.process_parameters as usize)?;

    let command_line = read_remote_unicode_string64(guard.raw(), params.command_line)?;
    let current_directory =
        read_remote_unicode_string64(guard.raw(), params.current_directory.dos_path)?;
    let image_path = read_remote_unicode_string64(guard.raw(), params.image_path_name)?;

    let environment = if include_environment && params.environment != 0 {
        let block =
            read_environment_block_u16(guard.raw(), params.environment as usize, 1024 * 1024)?;
        Some(parse_environment_block_utf16(&block))
    } else {
        None
    };

    Ok(ProcessDetails {
        command_line,
        current_directory,
        image_path,
        environment,
    })
}

/// Convenience: retrieve command line only.
pub fn get_command_line(pid: u32) -> Result<String> {
    let details = get_process_details(pid, false)?;
    details
        .command_line
        .ok_or_else(|| anyhow!("Command line unavailable"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_process_details_current_process_is_accessible() {
        let pid = std::process::id();
        let details = get_process_details(pid, false).expect("current process should be queryable");
        // Command line is best-effort; on Windows this should usually be present.
        assert!(details.command_line.is_some() || details.image_path.is_some());
    }

    #[test]
    fn get_process_details_invalid_pid_returns_err() {
        let pid = u32::MAX;
        assert!(get_process_details(pid, false).is_err());
    }

    #[test]
    fn parse_environment_block_basic() {
        let mut block: Vec<u16> = Vec::new();
        block.extend("FOO=bar".encode_utf16());
        block.push(0);
        block.extend("PATH=C\\Windows".encode_utf16());
        block.push(0);
        block.push(0);

        let env = parse_environment_block_utf16(&block);
        assert_eq!(env.get("FOO").map(|s| s.as_str()), Some("bar"));
        assert_eq!(env.get("PATH").map(|s| s.as_str()), Some("C\\Windows"));
    }

    #[test]
    fn sanitize_env_redacts_sensitive_keys() {
        let (k, v) = sanitize_env_pair("API_TOKEN".to_string(), "123".to_string());
        assert_eq!(k, "API_TOKEN");
        assert_eq!(v, "<redacted>");
    }

    #[test]
    #[ignore]
    fn get_process_details_wow64_child_process_smoke() {
        // Best-effort WoW64 smoke test: spawn 32-bit cmd.exe if present and query its details.
        // Ignored by default because it depends on the OS image and can be flaky in CI.
        use std::os::windows::process::CommandExt;

        let syswow64_cmd = std::path::Path::new(r"C:\Windows\SysWOW64\cmd.exe");
        if !syswow64_cmd.exists() {
            return;
        }

        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let mut child = std::process::Command::new(syswow64_cmd)
            .args(["/c", "timeout", "/t", "3", "/nobreak"])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .expect("spawn wow64 cmd");

        let pid = child.id();

        // Give the process a brief moment to initialize PEB/process parameters.
        std::thread::sleep(std::time::Duration::from_millis(100));

        let details = get_process_details(pid, false).expect("should query wow64 process details");
        assert!(details.command_line.is_some() || details.image_path.is_some());

        let _ = child.wait();
    }
}
