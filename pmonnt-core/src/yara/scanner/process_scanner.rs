use super::types::{ScanError, ScanMatch, ScanMode, ScanOptions, ScanProgress, ScanResult};

use crate::win::HandleGuard;
use crate::yara::engine::YaraEngine;
use crate::yara::memory::{enumerate_memory_regions, read_process_memory_chunk, MemoryRegion};

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use windows::Win32::System::Memory::{
    MEM_PRIVATE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
};

#[derive(Clone)]
pub struct ProcessScanner {
    engine: Arc<YaraEngine>,
}

struct ScanSink<'a> {
    seen: &'a mut HashSet<(usize, u64)>,
    matches: &'a mut Vec<ScanMatch>,
    errors: &'a mut Vec<String>,
}

impl ProcessScanner {
    pub fn new(engine: Arc<YaraEngine>) -> Self {
        Self { engine }
    }

    #[inline]
    pub fn is_readable(protect: u32) -> bool {
        if protect & PAGE_NOACCESS.0 != 0 {
            return false;
        }
        if protect & PAGE_GUARD.0 != 0 {
            return false;
        }

        let readable_flags = PAGE_READONLY.0
            | PAGE_READWRITE.0
            | PAGE_EXECUTE_READ.0
            | PAGE_EXECUTE_READWRITE.0
            | PAGE_WRITECOPY.0
            | PAGE_EXECUTE_WRITECOPY.0;

        (protect & readable_flags) != 0
    }

    #[inline]
    pub fn is_executable(protect: u32) -> bool {
        let exec_flags = PAGE_EXECUTE.0
            | PAGE_EXECUTE_READ.0
            | PAGE_EXECUTE_READWRITE.0
            | PAGE_EXECUTE_WRITECOPY.0;
        (protect & exec_flags) != 0
    }

    fn should_scan_region(reg: &MemoryRegion, options: &ScanOptions) -> bool {
        if reg.size == 0 {
            return false;
        }
        if !Self::is_readable(reg.protection) {
            return false;
        }
        if reg.size > options.max_region_bytes {
            return false;
        }

        match options.mode {
            ScanMode::Quick => {
                // High signal: private executable pages (typical injection / unpacked code).
                reg.region_type == MEM_PRIVATE.0 && Self::is_executable(reg.protection)
            }
            ScanMode::Deep => true,
        }
    }

    fn rule_name_hash(rule_name: &str) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        rule_name.hash(&mut hasher);
        hasher.finish()
    }

    fn scan_region_chunked(
        &self,
        handle: windows::Win32::Foundation::HANDLE,
        reg: &MemoryRegion,
        options: &ScanOptions,
        sink: &mut ScanSink<'_>,
    ) -> Result<usize, ScanError> {
        let mut bytes_scanned = 0usize;

        // If many reads fail in a region, stop early to reduce churn on protected regions.
        const MAX_FAILED_READS_PER_REGION: usize = 64;
        let mut failed_reads = 0usize;

        let chunk_size = options.chunk_size.max(4096);
        let overlap = options.chunk_overlap.min(chunk_size.saturating_sub(1));
        let step = chunk_size.saturating_sub(overlap).max(1);

        let mut offset = 0usize;
        while offset < reg.size {
            let remaining = reg.size - offset;
            let to_read = remaining.min(chunk_size);
            let addr = reg.base_address.saturating_add(offset);

            let data = match read_process_memory_chunk(handle, addr, to_read) {
                Ok(d) => d,
                Err(e) => {
                    // In Quick mode we expect some failures; keep it quiet.
                    // We still count this region as attempted.
                    log::debug!("Skipped chunk at 0x{:x}: {}", addr, e);
                    failed_reads += 1;
                    if failed_reads >= MAX_FAILED_READS_PER_REGION {
                        break;
                    }
                    offset = offset.saturating_add(step);
                    continue;
                }
            };

            bytes_scanned = bytes_scanned.saturating_add(data.len());
            if data.is_empty() {
                offset = offset.saturating_add(step);
                continue;
            }

            match self.engine.scan_buffer(&data) {
                Ok(region_matches) => {
                    for m in region_matches {
                        let matched_offset =
                            m.matched_strings.first().map(|ms| ms.offset).unwrap_or(0);
                        let memory_address = addr.saturating_add(matched_offset);
                        let rule_hash = Self::rule_name_hash(&m.rule_name);
                        if !sink.seen.insert((memory_address, rule_hash)) {
                            continue;
                        }

                        if options.is_suppressed(&m.rule_name) {
                            continue;
                        }

                        let scan_match = ScanMatch {
                            rule_name: m.rule_name,
                            rule_description: m.description,
                            severity: m.severity,
                            tags: m.rule_tags,
                            memory_address,
                            region_base: reg.base_address,
                            matched_strings: m.matched_strings,
                        };
                        sink.matches.push(scan_match);
                    }
                }
                Err(e) => {
                    sink.errors
                        .push(format!("Scan error in chunk {:#x}: {}", addr, e));
                }
            }

            offset = offset.saturating_add(step);
        }

        Ok(bytes_scanned)
    }

    /// Scan a process asynchronously with progress reporting and cancellation support
    pub async fn scan_process(
        &self,
        pid: u32,
        progress_tx: mpsc::Sender<ScanProgress>,
        cancellation_token: CancellationToken,
    ) -> Result<ScanResult, ScanError> {
        self.scan_process_with_options(pid, ScanOptions::default(), progress_tx, cancellation_token)
            .await
    }

    /// Scan a process asynchronously with progress reporting and cancellation support
    pub async fn scan_process_with_options(
        &self,
        pid: u32,
        options: ScanOptions,
        progress_tx: mpsc::Sender<ScanProgress>,
        cancellation_token: CancellationToken,
    ) -> Result<ScanResult, ScanError> {
        let start = Instant::now();
        let regions = enumerate_memory_regions(pid).map_err(ScanError::MemoryError)?;
        let regions: Vec<MemoryRegion> = regions
            .into_iter()
            .filter(|r| Self::should_scan_region(r, &options))
            .collect();
        let total_bytes: usize = regions
            .iter()
            .map(|r| r.size.min(options.max_region_bytes))
            .sum();
        let total_regions = regions.len();

        let process_name = crate::win::process_path::get_process_image_path(pid)
            .ok()
            .and_then(|p| {
                Path::new(&p)
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
            })
            .unwrap_or_else(|| format!("pid {}", pid));

        let _ = progress_tx
            .send(ScanProgress::Starting {
                pid,
                process_name: process_name.clone(),
                total_regions,
                total_bytes,
            })
            .await;

        let mut bytes_scanned = 0usize;
        let mut regions_scanned = 0usize;
        let mut regions_skipped = 0usize;
        let mut matches: Vec<ScanMatch> = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        // Open process handle once
        // SAFETY: OpenProcess is a Win32 FFI call. We pass a plain PID and request read/query
        // access; the returned handle is immediately wrapped in HandleGuard for RAII closing.
        let handle = unsafe {
            windows::Win32::System::Threading::OpenProcess(
                windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION
                    | windows::Win32::System::Threading::PROCESS_VM_READ,
                windows::Win32::Foundation::BOOL(0),
                pid,
            )?
        };

        // RAII guard ensures handle is closed on any return path (including cancellation)
        let _handle_guard = HandleGuard::new(handle);

        let mut seen: HashSet<(usize, u64)> = HashSet::new();
        let mut sink = ScanSink {
            seen: &mut seen,
            matches: &mut matches,
            errors: &mut errors,
        };

        for (i, reg) in regions.into_iter().enumerate() {
            // Check for cancellation
            if cancellation_token.is_cancelled() {
                let _ = progress_tx.send(ScanProgress::Cancelled).await;
                return Err(ScanError::Cancelled);
            }

            let matches_before = sink.matches.len();
            let scanned = self.scan_region_chunked(handle, &reg, &options, &mut sink);

            match scanned {
                Ok(region_bytes) => {
                    let has_any = region_bytes > 0 || sink.matches.len() > matches_before;
                    if has_any {
                        regions_scanned += 1;
                        bytes_scanned = bytes_scanned.saturating_add(region_bytes);

                        // Reliable progress delivery: send match events after the region scan.
                        for m in sink.matches.iter().skip(matches_before) {
                            let _ = progress_tx
                                .send(ScanProgress::MatchFound {
                                    rule_name: m.rule_name.clone(),
                                    severity: m.severity,
                                    address: m.memory_address,
                                })
                                .await;
                        }
                    } else {
                        regions_skipped += 1;
                    }
                }
                Err(e) => {
                    regions_skipped += 1;
                    log::debug!("Skipped region at 0x{:x}: {}", reg.base_address, e);
                }
            }

            let _ = progress_tx
                .send(ScanProgress::ScanningRegion {
                    current_region: i + 1,
                    total_regions,
                    bytes_scanned,
                    total_bytes,
                    current_address: reg.base_address,
                })
                .await;
        }

        let dur = start.elapsed().as_millis() as u64;
        if regions_skipped > 0 {
            log::info!(
                "Memory scan complete: {} regions scanned ({} bytes), {} regions skipped (protected/inaccessible)",
                regions_scanned,
                bytes_scanned,
                regions_skipped
            );
        }
        let result = ScanResult {
            pid,
            process_name,
            bytes_scanned,
            regions_scanned,
            regions_skipped,
            duration_ms: dur,
            matches,
            errors,
        };

        let _ = progress_tx
            .send(ScanProgress::Completed {
                result: result.clone(),
            })
            .await;

        Ok(result)
    }

    pub fn scan_process_sync(
        &self,
        pid: u32,
        progress_tx: std::sync::mpsc::Sender<ScanProgress>,
    ) -> Result<ScanResult, ScanError> {
        self.scan_process_sync_with_options(pid, ScanOptions::default(), progress_tx)
    }

    pub fn scan_process_sync_with_options(
        &self,
        pid: u32,
        options: ScanOptions,
        progress_tx: std::sync::mpsc::Sender<ScanProgress>,
    ) -> Result<ScanResult, ScanError> {
        let start = Instant::now();
        let regions = enumerate_memory_regions(pid).map_err(ScanError::MemoryError)?;
        let regions: Vec<MemoryRegion> = regions
            .into_iter()
            .filter(|r| Self::should_scan_region(r, &options))
            .collect();
        let total_bytes: usize = regions
            .iter()
            .map(|r| r.size.min(options.max_region_bytes))
            .sum();
        let total_regions = regions.len();

        let process_name = crate::win::process_path::get_process_image_path(pid)
            .ok()
            .and_then(|p| {
                Path::new(&p)
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
            })
            .unwrap_or_else(|| format!("pid {}", pid));
        let _ = progress_tx.send(ScanProgress::Starting {
            pid,
            process_name: process_name.clone(),
            total_regions,
            total_bytes,
        });

        let mut bytes_scanned: u64 = 0;
        let mut regions_scanned: usize = 0;
        let mut regions_skipped: usize = 0;
        let mut matches: Vec<ScanMatch> = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        // Open process handle once
        // SAFETY: OpenProcess is a Win32 FFI call. We pass a plain PID and request read/query
        // access; the returned handle is immediately wrapped in HandleGuard for RAII closing.
        let handle = unsafe {
            windows::Win32::System::Threading::OpenProcess(
                windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION
                    | windows::Win32::System::Threading::PROCESS_VM_READ,
                windows::Win32::Foundation::BOOL(0),
                pid,
            )?
        };

        // RAII guard ensures handle is closed on any return path
        let _handle_guard = HandleGuard::new(handle);

        let mut seen: HashSet<(usize, u64)> = HashSet::new();
        let mut sink = ScanSink {
            seen: &mut seen,
            matches: &mut matches,
            errors: &mut errors,
        };

        for (i, reg) in regions.into_iter().enumerate() {
            let matches_before = sink.matches.len();
            let scanned = self.scan_region_chunked(handle, &reg, &options, &mut sink);

            match scanned {
                Ok(region_bytes) => {
                    let has_any = region_bytes > 0 || sink.matches.len() > matches_before;
                    if has_any {
                        regions_scanned += 1;
                        bytes_scanned = bytes_scanned.saturating_add(region_bytes as u64);

                        for m in sink.matches.iter().skip(matches_before) {
                            let _ = progress_tx.send(ScanProgress::MatchFound {
                                rule_name: m.rule_name.clone(),
                                severity: m.severity,
                                address: m.memory_address,
                            });
                        }
                    } else {
                        regions_skipped += 1;
                    }
                }
                Err(e) => {
                    regions_skipped += 1;
                    log::debug!("Skipped region at 0x{:x}: {}", reg.base_address, e);
                }
            }
            let _ = progress_tx.send(ScanProgress::ScanningRegion {
                current_region: i + 1,
                total_regions,
                bytes_scanned: bytes_scanned as usize,
                total_bytes,
                current_address: reg.base_address,
            });
        }

        let dur = start.elapsed().as_millis() as u64;
        if regions_skipped > 0 {
            log::info!(
                "Memory scan complete: {} regions scanned ({} bytes), {} regions skipped (protected/inaccessible)",
                regions_scanned,
                bytes_scanned,
                regions_skipped
            );
        }
        let result = ScanResult {
            pid,
            process_name,
            bytes_scanned: bytes_scanned as usize,
            regions_scanned,
            regions_skipped,
            duration_ms: dur,
            matches,
            errors,
        };
        let _ = progress_tx.send(ScanProgress::Completed {
            result: result.clone(),
        });
        Ok(result)
    }

    pub fn scan_region(
        &self,
        _pid: u32,
        _address: usize,
        _size: usize,
    ) -> Result<Vec<ScanMatch>, ScanError> {
        Ok(Vec::new())
    }
}
