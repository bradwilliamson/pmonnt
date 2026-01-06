//! Windows process memory reading utilities
//!
//! This module is primarily used by the YARA process scanner to enumerate
//! committed, readable regions and to provide safe chunked reads.

use std::vec::Vec;
use thiserror::Error;
use windows::core::{Error as WinError, HRESULT};
use windows::Win32::Foundation::{
    CloseHandle, BOOL, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, HANDLE,
};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_NOCACHE,
    PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOMBINE, PAGE_WRITECOPY,
};
use windows::Win32::System::Threading::{
    IsWow64Process, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

/// Represents a readable memory region
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub base_address: usize,
    pub size: usize,
    pub protection: u32,
    pub state: u32,
    pub region_type: u32,
}

/// Result of reading a memory region
pub struct MemoryBuffer {
    pub region: MemoryRegion,
    pub data: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("Failed to open process {pid}: access denied")]
    AccessDenied { pid: u32 },

    #[error("Failed to open process {pid}: process not found")]
    ProcessNotFound { pid: u32 },

    /// Generic read error; the underlying WinError is preserved for diagnostics.
    #[error("Failed to read memory at {address:#x}: {source}")]
    ReadFailed {
        address: usize,
        #[source]
        source: WinError,
    },

    #[error("Windows API error: {0}")]
    WindowsError(#[from] WinError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessBitness {
    Bit32,
    Bit64,
    Unknown,
}

fn classify_open_process_error(pid: u32, e: WinError) -> MemoryError {
    // `windows` reports Win32 last-error as an HRESULT via HRESULT_FROM_WIN32.
    // Map a couple of common cases for clearer UX.
    let code = e.code();
    if code == HRESULT::from_win32(ERROR_ACCESS_DENIED.0) {
        return MemoryError::AccessDenied { pid };
    }
    if code == HRESULT::from_win32(ERROR_INVALID_PARAMETER.0) {
        return MemoryError::ProcessNotFound { pid };
    }
    MemoryError::WindowsError(e)
}

/// Best-effort process bitness detection.
///
/// This can help diagnose cross-bitness failures (e.g., 32-bit app attempting to read some
/// 64-bit targets). If the OS/API doesn't support bitness detection, this returns
/// `Ok(ProcessBitness::Unknown)`.
pub fn get_process_bitness(process_handle: HANDLE) -> Result<ProcessBitness, MemoryError> {
    // SAFETY: All calls in this block are Win32 FFI. `process_handle` is assumed to be a valid
    // handle owned by the caller; we only pass a valid pointer to `wow64`, and no pointers escape.
    unsafe {
        let mut wow64 = BOOL(0);
        if let Err(_e) = IsWow64Process(process_handle, &mut wow64) {
            return Ok(ProcessBitness::Unknown);
        }

        if wow64.as_bool() {
            Ok(ProcessBitness::Bit32)
        } else {
            #[cfg(target_pointer_width = "64")]
            {
                Ok(ProcessBitness::Bit64)
            }
            #[cfg(not(target_pointer_width = "64"))]
            {
                Ok(ProcessBitness::Unknown)
            }
        }
    }
}

/// Return `true` if the protection flags indicate the region is readable.
///
/// This mirrors the logic in the process scanner (Quick/Deep YARA modes) so the
/// enumerated regions align with what we actually attempt to scan.
fn is_readable_protection(mut protect: u32) -> bool {
    // Strip modifier flags; we only care about the base access type.
    protect &= !PAGE_GUARD.0;
    protect &= !PAGE_NOCACHE.0;
    protect &= !PAGE_WRITECOMBINE.0;

    if protect == PAGE_NOACCESS.0 {
        return false;
    }

    let base_flags = PAGE_READONLY.0
        | PAGE_READWRITE.0
        | PAGE_WRITECOPY.0
        | PAGE_EXECUTE_READ.0
        | PAGE_EXECUTE_READWRITE.0
        | PAGE_EXECUTE_WRITECOPY.0;

    (protect & base_flags) != 0
}

/// Enumerate committed, readable memory regions for a process.
///
/// This intentionally filters down to regions that are:
/// - `MEM_COMMIT`
/// - non-guard
/// - readable, based on protection flags
///
/// YARA scanning policy (Quick vs Deep, region size caps, chunking, etc.) is handled
/// by the higher-level `ProcessScanner`.
pub fn enumerate_memory_regions(pid: u32) -> Result<Vec<MemoryRegion>, MemoryError> {
    // SAFETY: This block performs Win32 FFI calls (OpenProcess/VirtualQueryEx/CloseHandle).
    // We close the returned process handle on all paths. The `address` pointer passed to
    // VirtualQueryEx is derived from an integer address and used only as a query hint.
    unsafe {
        let handle = match OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            false, // do not inherit handle
            pid,
        ) {
            Ok(h) => h,
            Err(e) => return Err(classify_open_process_error(pid, e)),
        };
        if handle.is_invalid() {
            return Err(MemoryError::AccessDenied { pid });
        }

        let mut regions = Vec::new();
        let mut address: usize = 0;
        let max_address: usize = usize::MAX;

        // Safety valve: VirtualQueryEx is expected to make forward progress.
        // Guard against pathological cases (e.g., region size 0 or repeated addresses).
        const MAX_QUERIES: usize = 1_000_000;
        let mut queries = 0usize;

        while address < max_address {
            queries += 1;
            if queries > MAX_QUERIES {
                log::warn!(
                    "VirtualQueryEx exceeded {} iterations for pid {}; stopping enumeration",
                    MAX_QUERIES,
                    pid
                );
                break;
            }

            let mut mbi = MEMORY_BASIC_INFORMATION::default();
            let res = VirtualQueryEx(
                handle,
                Some(address as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            if res == 0 {
                break;
            }

            let region_state = mbi.State.0;
            let region_protect = mbi.Protect.0;
            let region_type = mbi.Type.0;
            let base = mbi.BaseAddress as usize;
            let region_size = mbi.RegionSize;

            if region_size == 0 {
                log::debug!(
                    "VirtualQueryEx returned zero region size at 0x{:x} (pid {}); stopping",
                    base,
                    pid
                );
                break;
            }

            let next = base.saturating_add(region_size);

            // Only consider committed regions; State is enum-like, so equality is clearer.
            if region_state != MEM_COMMIT.0 {
                address = next;
                continue;
            }

            // Skip guard pages; these are likely to cause spurious read failures.
            if (region_protect & PAGE_GUARD.0) != 0 {
                address = next;
                continue;
            }

            // Skip regions that are clearly not readable.
            if !is_readable_protection(region_protect) {
                address = next;
                continue;
            }

            regions.push(MemoryRegion {
                base_address: base,
                size: region_size,
                protection: region_protect,
                state: region_state,
                region_type,
            });

            if next <= address {
                // Something went very wrong (wraparound or non-forward progress).
                break;
            }
            address = next;
        }

        let _ = CloseHandle(handle);
        Ok(regions)
    }
}

/// Read a single memory region into a buffer.
///
/// For YARA scanning you normally don’t use this directly; `ProcessScanner`
/// will read the region in chunks via `read_process_memory_chunk`.
pub fn read_memory_region(
    process_handle: HANDLE,
    region: &MemoryRegion,
) -> Result<MemoryBuffer, MemoryError> {
    let data = read_process_memory_chunk(process_handle, region.base_address, region.size)?;
    Ok(MemoryBuffer {
        region: region.clone(),
        data,
    })
}

/// Read a chunk of process memory at an arbitrary address.
///
/// This is the primitive used by higher-level scanners (e.g., YARA engine) to
/// stream regions in chunks, rather than reading entire mappings into memory.
pub fn read_process_memory_chunk(
    process_handle: HANDLE,
    address: usize,
    size: usize,
) -> Result<Vec<u8>, MemoryError> {
    if size == 0 {
        return Ok(Vec::new());
    }

    // SAFETY: ReadProcessMemory writes at most `size` bytes into `buffer`, which we allocate to
    // exactly that size. `bytes_read` is a valid out-pointer for the duration of the call.
    unsafe {
        let mut buffer = vec![0u8; size];
        let mut bytes_read: usize = 0;

        match ReadProcessMemory(
            process_handle,
            address as *const _,
            buffer.as_mut_ptr() as *mut _,
            size,
            Some(&mut bytes_read),
        ) {
            Ok(()) => {
                buffer.truncate(bytes_read);
                if bytes_read > 0 && bytes_read < size {
                    // Partial reads can happen if protection changes mid-scan or the region spans
                    // subranges with different access rights.
                    let ratio = bytes_read as f64 / size as f64;
                    if ratio < 0.5 {
                        log::debug!(
                            "Partial ReadProcessMemory at 0x{:x}: {}/{} bytes",
                            address,
                            bytes_read,
                            size
                        );
                    }
                }
                Ok(buffer)
            }
            Err(e) => Err(MemoryError::ReadFailed { address, source: e }),
        }
    }
}

/// Stream memory regions for scanning (memory efficient).
///
/// This is a simple iterator that reads full regions; for YARA you’ll likely
/// prefer the chunked approach in `ProcessScanner`, but this can still be handy
/// for simpler use cases.
pub struct MemoryRegionIterator {
    process_handle: HANDLE,
    regions: Vec<MemoryRegion>,
    current_index: usize,
}

impl MemoryRegionIterator {
    pub fn new(process_handle: HANDLE, regions: Vec<MemoryRegion>) -> Self {
        Self {
            process_handle,
            regions,
            current_index: 0,
        }
    }
}

impl Iterator for MemoryRegionIterator {
    type Item = Result<MemoryBuffer, MemoryError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_index >= self.regions.len() {
            return None;
        }
        let idx = self.current_index;
        self.current_index += 1;
        Some(read_memory_region(self.process_handle, &self.regions[idx]))
    }
}
