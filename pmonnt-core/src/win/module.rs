//! Windows module enumeration and signature verification (unsafe code confined here)
//! Invariants: All handles are closed, all buffer reads are alignment-safe.
//! WinVerifyTrust is called with valid file paths and proper GUID initialization.
//!
//! This module provides three methods for enumerating loaded modules:
//! 1. ToolHelp32 (CreateToolhelp32Snapshot) - fastest, but blocked by sandboxes
//! 2. PSAPI (K32EnumProcessModulesEx) - alternative API, also often blocked
//! 3. PEB walking (NtQueryInformationProcess + ReadProcessMemory) - most robust

use crate::module::ModuleInfo;
use crate::win::ntdll::NtQueryInformationProcess;
use crate::win::HandleGuard;
use crate::PmonntError;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use windows::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};

// PSAPI / K32 functions for fallback module enumeration
#[link(name = "kernel32")]
extern "system" {
    fn K32EnumProcessModulesEx(
        hProcess: isize,
        lphModule: *mut usize,
        cb: u32,
        lpcbNeeded: *mut u32,
        dwFilterFlag: u32,
    ) -> i32;

    fn K32GetModuleBaseNameW(
        hProcess: isize,
        hModule: usize,
        lpBaseName: *mut u16,
        nSize: u32,
    ) -> u32;

    fn K32GetModuleFileNameExW(
        hProcess: isize,
        hModule: usize,
        lpFilename: *mut u16,
        nSize: u32,
    ) -> u32;

    fn K32GetModuleInformation(
        hProcess: isize,
        hModule: usize,
        lpmodinfo: *mut Moduleinfo,
        cb: u32,
    ) -> i32;

    fn ReadProcessMemory(
        hProcess: isize,
        lpBaseAddress: usize,
        lpBuffer: *mut std::ffi::c_void,
        nSize: usize,
        lpNumberOfBytesRead: *mut usize,
    ) -> i32;
}

const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;

#[repr(C)]
#[allow(non_snake_case)]
struct Moduleinfo {
    lpBaseOfDll: *mut std::ffi::c_void,
    SizeOfImage: u32,
    EntryPoint: *mut std::ffi::c_void,
}

#[repr(C)]
#[allow(non_snake_case)]
struct PROCESS_BASIC_INFORMATION {
    Reserved1: usize,
    PebBaseAddress: usize,
    Reserved2: [usize; 2],
    UniqueProcessId: usize,
    Reserved3: usize,
}

// PEB structures for 64-bit Windows
// These structures must match the exact layout Windows uses
#[repr(C)]
#[allow(non_snake_case)]
struct PEB_LDR_DATA {
    Length: u32,
    Initialized: u32, // Actually BOOLEAN but padded to 4 bytes
    SsHandle: usize,
    InLoadOrderModuleList: LIST_ENTRY,
    InMemoryOrderModuleList: LIST_ENTRY,
    InInitializationOrderModuleList: LIST_ENTRY,
}

#[repr(C)]
#[allow(non_snake_case)]
struct LIST_ENTRY {
    Flink: usize,
    Blink: usize,
}

#[repr(C)]
#[allow(non_snake_case)]
struct LDR_DATA_TABLE_ENTRY {
    InLoadOrderLinks: LIST_ENTRY,
    InMemoryOrderLinks: LIST_ENTRY,
    InInitializationOrderLinks: LIST_ENTRY,
    DllBase: usize,
    EntryPoint: usize,
    SizeOfImage: u32,
    _padding: u32,
    FullDllName: UNICODE_STRING,
    BaseDllName: UNICODE_STRING,
    // ... more fields we don't need
}

#[repr(C)]
#[allow(non_snake_case)]
struct UNICODE_STRING {
    Length: u16,
    MaximumLength: u16,
    _padding: u32,
    Buffer: usize,
}

const LIST_MODULES_ALL: u32 = 0x03;

// WinVerifyTrust definitions - manually define since windows-sys may not have full wintrust
#[repr(C)]
#[allow(non_snake_case)]
struct WINTRUST_FILE_INFO {
    cbStruct: u32,
    pcwszFilePath: *const u16,
    hFile: HANDLE,
    pgKnownSubject: *const GUID,
}

#[repr(C)]
#[allow(non_snake_case)]
struct WINTRUST_DATA {
    cbStruct: u32,
    pPolicyCallbackData: *mut std::ffi::c_void,
    pSIPClientData: *mut std::ffi::c_void,
    dwUIChoice: u32,
    fdwRevocationChecks: u32,
    dwUnionChoice: u32,
    pFile: *mut WINTRUST_FILE_INFO,
    dwStateAction: u32,
    hWVTStateData: HANDLE,
    pwszURLReference: *const u16,
    dwProvFlags: u32,
    dwUIContext: u32,
    pSignatureSettings: *mut std::ffi::c_void,
}

#[repr(C)]
#[allow(non_snake_case)]
#[allow(clippy::upper_case_acronyms)]
struct GUID {
    Data1: u32,
    Data2: u16,
    Data3: u16,
    Data4: [u8; 8],
}

// WinVerifyTrust constants
const WTD_UI_NONE: u32 = 2;
const WTD_REVOKE_NONE: u32 = 0;
const WTD_CHOICE_FILE: u32 = 1;
const WTD_STATEACTION_VERIFY: u32 = 1;
const WTD_STATEACTION_CLOSE: u32 = 2;

// WINTRUST_ACTION_GENERIC_VERIFY_V2 GUID
const WINTRUST_ACTION_GENERIC_VERIFY_V2: GUID = GUID {
    Data1: 0x00AAC56B,
    Data2: 0xCD44,
    Data3: 0x11d0,
    Data4: [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
};

// Trust error codes
const TRUST_E_NOSIGNATURE: i32 = -0x7FF6FE00_i32; // 0x800B0100
const TRUST_E_EXPLICIT_DISTRUST: i32 = -0x7FF6FDFC_i32; // 0x800B0104
const TRUST_E_SUBJECT_NOT_TRUSTED: i32 = -0x7FF6FDFE_i32; // 0x800B0102
const CRYPT_E_SECURITY_SETTINGS: i32 = -0x7FF6CFFD_i32; // 0x80092003

#[link(name = "wintrust")]
extern "system" {
    fn WinVerifyTrust(hwnd: HANDLE, pgActionID: *const GUID, pWVTData: *mut WINTRUST_DATA) -> i32;
}

/// List modules for a process using multiple fallback methods
/// Tries: 1) ToolHelp32, 2) PSAPI, 3) PEB walking
pub fn list_modules(pid: u32) -> Result<Vec<ModuleInfo>, PmonntError> {
    // First try ToolHelp32 - this is the preferred method
    match list_modules_toolhelp(pid) {
        Ok(modules) if !modules.is_empty() => {
            log::trace!(
                "ToolHelp32 succeeded for PID {} with {} modules",
                pid,
                modules.len()
            );
            return Ok(modules);
        }
        Ok(_) => {
            log::debug!(
                "ToolHelp32 returned empty for PID {}, trying PSAPI fallback",
                pid
            );
        }
        Err(e) => {
            log::debug!(
                "ToolHelp32 failed for PID {}: {}, trying PSAPI fallback",
                pid,
                e
            );
        }
    }

    // Second try: PSAPI (EnumProcessModulesEx)
    match list_modules_psapi(pid) {
        Ok(modules) if !modules.is_empty() => {
            log::trace!(
                "PSAPI succeeded for PID {} with {} modules",
                pid,
                modules.len()
            );
            return Ok(modules);
        }
        Ok(_) => {
            log::debug!("PSAPI returned empty for PID {}, trying PEB fallback", pid);
        }
        Err(e) => {
            log::debug!("PSAPI failed for PID {}: {}, trying PEB fallback", pid, e);
        }
    }

    // Third try: Read PEB directly (works for some sandboxed processes)
    match list_modules_peb(pid) {
        Ok(modules) if !modules.is_empty() => {
            log::trace!(
                "PEB walk succeeded for PID {} with {} modules",
                pid,
                modules.len()
            );
            return Ok(modules);
        }
        Ok(_) => {
            log::debug!("PEB walk returned empty for PID {}", pid);
        }
        Err(e) => {
            log::debug!("PEB walk failed for PID {}: {}", pid, e);
        }
    }

    // All methods failed
    Err(PmonntError::ModuleEnumerationFailed(format!(
        "All enumeration methods failed for PID {}",
        pid
    )))
}

/// List modules using ToolHelp32 snapshot
fn list_modules_toolhelp(pid: u32) -> Result<Vec<ModuleInfo>, PmonntError> {
    let mut modules = Vec::new();

    // SAFETY: CreateToolhelp32Snapshot, Module32FirstW, Module32NextW FFI calls with valid PID and properly initialized MODULEENTRY32W structure
    unsafe {
        // TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32 to get both 32 and 64-bit modules
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snapshot == INVALID_HANDLE_VALUE {
            // Get last error for better diagnostics
            let err = std::io::Error::last_os_error();
            return Err(PmonntError::ModuleEnumerationFailed(format!(
                "ToolHelp32 access denied or process not found: {}",
                err
            )));
        }

        let mut entry: MODULEENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

        let mut ok = Module32FirstW(snapshot, &mut entry) != 0;
        while ok {
            let name = wchar_to_string(&entry.szModule);
            let path = wchar_to_string(&entry.szExePath);

            let info = ModuleInfo {
                name,
                path: if path.is_empty() { None } else { Some(path) },
                base_address: entry.modBaseAddr as u64,
                size: entry.modBaseSize,
                signed: None,
                error: None,
            };
            modules.push(info);

            ok = Module32NextW(snapshot, &mut entry) != 0;
        }

        drop(HandleGuard::new(HANDLE(snapshot)));
    }

    Ok(modules)
}

/// List modules using PSAPI (K32EnumProcessModulesEx) - fallback for sandboxed processes
fn list_modules_psapi(pid: u32) -> Result<Vec<ModuleInfo>, PmonntError> {
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let mut modules = Vec::new();

    // SAFETY: K32EnumProcessModulesEx, K32GetModuleBaseNameW, K32GetModuleFileNameExW, K32GetModuleInformation FFI calls with valid process handle and properly sized buffers
    unsafe {
        // Need PROCESS_QUERY_INFORMATION | PROCESS_VM_READ for EnumProcessModulesEx
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        let Ok(handle) = handle else {
            let err = std::io::Error::last_os_error();
            return Err(PmonntError::ModuleEnumerationFailed(format!(
                "PSAPI: Cannot open process {}: {}",
                pid, err
            )));
        };

        let handle_guard = HandleGuard::new(handle);
        let raw_handle = handle_guard.raw().0 as isize;

        // First call to get required size
        let mut needed: u32 = 0;
        let result = K32EnumProcessModulesEx(
            raw_handle,
            std::ptr::null_mut(),
            0,
            &mut needed,
            LIST_MODULES_ALL,
        );

        if result == 0 && needed == 0 {
            let err = std::io::Error::last_os_error();
            return Err(PmonntError::ModuleEnumerationFailed(format!(
                "PSAPI: EnumProcessModulesEx failed: {}",
                err
            )));
        }

        // Allocate buffer for module handles
        let module_count = (needed as usize) / std::mem::size_of::<usize>();
        if module_count == 0 {
            return Ok(modules);
        }

        let mut module_handles: Vec<usize> = vec![0; module_count];
        let mut actual_needed: u32 = 0;

        let result = K32EnumProcessModulesEx(
            raw_handle,
            module_handles.as_mut_ptr(),
            needed,
            &mut actual_needed,
            LIST_MODULES_ALL,
        );

        if result == 0 {
            let err = std::io::Error::last_os_error();
            return Err(PmonntError::ModuleEnumerationFailed(format!(
                "PSAPI: EnumProcessModulesEx (second call) failed: {}",
                err
            )));
        }

        // Get info for each module
        let actual_count = (actual_needed as usize) / std::mem::size_of::<usize>();
        for &hmod in &module_handles[..actual_count] {
            // Get module name
            let mut name_buf: [u16; 260] = [0; 260];
            let name_len = K32GetModuleBaseNameW(raw_handle, hmod, name_buf.as_mut_ptr(), 260);
            let name = if name_len > 0 {
                wchar_to_string(&name_buf[..name_len as usize])
            } else {
                String::new()
            };

            // Get module path
            let mut path_buf: [u16; 520] = [0; 520];
            let path_len = K32GetModuleFileNameExW(raw_handle, hmod, path_buf.as_mut_ptr(), 520);
            let path = if path_len > 0 {
                Some(wchar_to_string(&path_buf[..path_len as usize]))
            } else {
                None
            };

            // Get module info (base address, size)
            let mut mod_info: Moduleinfo = std::mem::zeroed();
            let info_result = K32GetModuleInformation(
                raw_handle,
                hmod,
                &mut mod_info,
                std::mem::size_of::<Moduleinfo>() as u32,
            );

            let (base_address, size) = if info_result != 0 {
                (mod_info.lpBaseOfDll as u64, mod_info.SizeOfImage)
            } else {
                // If GetModuleInformation fails, use the module handle as base address
                // (module handles are actually base addresses)
                (hmod as u64, 0)
            };

            if !name.is_empty() || path.is_some() {
                modules.push(ModuleInfo {
                    name: if name.is_empty() {
                        path.as_ref()
                            .and_then(|p| p.rsplit('\\').next())
                            .unwrap_or("<unknown>")
                            .to_string()
                    } else {
                        name
                    },
                    path,
                    base_address,
                    size,
                    signed: None,
                    error: None,
                });
            }
        }
    }

    Ok(modules)
}

/// List modules by reading the PEB loader data structures directly
/// This is the most robust method and works for many sandboxed processes
fn list_modules_peb(pid: u32) -> Result<Vec<ModuleInfo>, PmonntError> {
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let mut modules = Vec::new();

    // SAFETY: NtQueryInformationProcess and ReadProcessMemory FFI calls to read PEB structures with valid process handle and properly aligned buffers
    unsafe {
        // Need PROCESS_QUERY_INFORMATION | PROCESS_VM_READ for PEB access
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        let Ok(handle) = handle else {
            let err = std::io::Error::last_os_error();
            return Err(PmonntError::ModuleEnumerationFailed(format!(
                "PEB: Cannot open process {}: {}",
                pid, err
            )));
        };

        let handle_guard = HandleGuard::new(handle);
        let raw_handle = handle_guard.raw().0 as isize;

        // Get PEB address via NtQueryInformationProcess
        let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
        let mut ret_len: u32 = 0;
        let status = NtQueryInformationProcess(
            handle_guard.raw(),
            PROCESS_BASIC_INFORMATION_CLASS,
            &mut pbi as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut ret_len,
        );

        if status.0 < 0 || pbi.PebBaseAddress == 0 {
            return Err(PmonntError::ModuleEnumerationFailed(format!(
                "PEB: NtQueryInformationProcess failed with status 0x{:08X}",
                status.0 as u32
            )));
        }

        // Read Ldr pointer from PEB (offset 0x18 on x64)
        let ldr_offset = 0x18usize;
        let mut ldr_ptr: usize = 0;
        let mut bytes_read: usize = 0;

        let result = ReadProcessMemory(
            raw_handle,
            pbi.PebBaseAddress + ldr_offset,
            &mut ldr_ptr as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<usize>(),
            &mut bytes_read,
        );

        if result == 0 || ldr_ptr == 0 {
            return Err(PmonntError::ModuleEnumerationFailed(
                "PEB: Failed to read Ldr pointer".to_string(),
            ));
        }

        // Read PEB_LDR_DATA to get the module list head
        let mut ldr_data: PEB_LDR_DATA = std::mem::zeroed();
        let result = ReadProcessMemory(
            raw_handle,
            ldr_ptr,
            &mut ldr_data as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<PEB_LDR_DATA>(),
            &mut bytes_read,
        );

        if result == 0 {
            return Err(PmonntError::ModuleEnumerationFailed(
                "PEB: Failed to read LDR_DATA".to_string(),
            ));
        }

        // Walk the InLoadOrderModuleList
        let list_head = ldr_ptr + offset_of_in_load_order();
        let mut current = ldr_data.InLoadOrderModuleList.Flink;
        let mut count = 0;
        const MAX_MODULES: usize = 1000; // Safety limit

        while current != list_head && current != 0 && count < MAX_MODULES {
            // Read the LDR_DATA_TABLE_ENTRY
            let mut entry: LDR_DATA_TABLE_ENTRY = std::mem::zeroed();
            let result = ReadProcessMemory(
                raw_handle,
                current,
                &mut entry as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<LDR_DATA_TABLE_ENTRY>(),
                &mut bytes_read,
            );

            if result == 0 {
                break;
            }

            // Read the module name
            let name = read_unicode_string(raw_handle, &entry.BaseDllName);
            let path = read_unicode_string(raw_handle, &entry.FullDllName);

            if !name.is_empty() || !path.is_empty() {
                modules.push(ModuleInfo {
                    name: if name.is_empty() {
                        path.rsplit('\\').next().unwrap_or("<unknown>").to_string()
                    } else {
                        name
                    },
                    path: if path.is_empty() { None } else { Some(path) },
                    base_address: entry.DllBase as u64,
                    size: entry.SizeOfImage,
                    signed: None,
                    error: None,
                });
            }

            current = entry.InLoadOrderLinks.Flink;
            count += 1;
        }
    }

    Ok(modules)
}

/// Get offset of InLoadOrderModuleList in PEB_LDR_DATA
fn offset_of_in_load_order() -> usize {
    // In PEB_LDR_DATA: Length(4) + Initialized(1) + padding(3) + SsHandle(8) = 16 bytes
    // Then InLoadOrderModuleList starts
    16
}

/// Read a UNICODE_STRING from the target process
unsafe fn read_unicode_string(handle: isize, us: &UNICODE_STRING) -> String {
    if us.Buffer == 0 || us.Length == 0 {
        return String::new();
    }

    let len_chars = (us.Length / 2) as usize;
    if len_chars == 0 || len_chars > 32768 {
        return String::new();
    }

    let mut buffer: Vec<u16> = vec![0; len_chars];
    let mut bytes_read: usize = 0;

    let result = ReadProcessMemory(
        handle,
        us.Buffer,
        buffer.as_mut_ptr() as *mut std::ffi::c_void,
        us.Length as usize,
        &mut bytes_read,
    );

    if result == 0 {
        return String::new();
    }

    wchar_to_string(&buffer)
}

/// Check signature status for a file path
/// Safety: WinVerifyTrust is called with valid null-terminated UTF-16 path
pub fn check_signature(path: &str) -> (Option<bool>, Option<String>) {
    let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

    // SAFETY: WinVerifyTrust FFI call with valid null-terminated UTF-16 path and properly initialized structures
    unsafe {
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: wide_path.as_ptr(),
            hFile: HANDLE::default(),
            pgKnownSubject: std::ptr::null(),
        };

        let mut wvt_data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            pPolicyCallbackData: std::ptr::null_mut(),
            pSIPClientData: std::ptr::null_mut(),
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            pFile: &mut file_info,
            dwStateAction: WTD_STATEACTION_VERIFY,
            hWVTStateData: HANDLE::default(),
            pwszURLReference: std::ptr::null(),
            dwProvFlags: 0,
            dwUIContext: 0,
            pSignatureSettings: std::ptr::null_mut(),
        };

        let action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let result = WinVerifyTrust(HANDLE::default(), &action_guid, &mut wvt_data);

        // Close the state data
        wvt_data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(HANDLE::default(), &action_guid, &mut wvt_data);

        match result {
            0 => (Some(true), None), // Signature is valid
            TRUST_E_NOSIGNATURE => (Some(false), Some("Not signed".to_string())),
            TRUST_E_EXPLICIT_DISTRUST => (Some(false), Some("Explicitly distrusted".to_string())),
            TRUST_E_SUBJECT_NOT_TRUSTED => (Some(false), Some("Subject not trusted".to_string())),
            CRYPT_E_SECURITY_SETTINGS => {
                (None, Some("Security settings prevented check".to_string()))
            }
            e => (
                None,
                Some(format!("Verification error: 0x{:08X}", e as u32)),
            ),
        }
    }
}

/// Convert null-terminated wide string to Rust String
fn wchar_to_string(wstr: &[u16]) -> String {
    let len = wstr.iter().position(|&c| c == 0).unwrap_or(wstr.len());
    OsString::from_wide(&wstr[..len])
        .to_string_lossy()
        .into_owned()
}
