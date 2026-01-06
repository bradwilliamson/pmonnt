use std::{collections::HashMap, mem};

use anyhow::Result;

use windows::Win32::System::Performance::{
    PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterValue,
    PDH_FMT_COUNTERVALUE, PDH_FMT_DOUBLE, PDH_FMT_LARGE,
};

use crate::gpu::GpuSnapshot;

use super::pdh::{expand_paths, extract_pid, pdh_ok, wstring, PdhCounterHandle, PdhQueryHandle};
use super::warnings::should_warn;

const ENGINE_PATH: &str = r"\GPU Engine(*)\Utilization Percentage";
const PROCESS_MEM_PATH: &str = r"\GPU Process Memory(*)\Dedicated Usage";
const SHARED_MEM_PATH: &str = r"\GPU Process Memory(*)\Shared Usage";

pub struct GpuPdhSampler {
    query: PdhQueryHandle,
    usage_counters: Vec<(PdhCounterHandle, u32)>,
    mem_counters: Vec<(PdhCounterHandle, u32)>,
    shared_counters: Vec<(PdhCounterHandle, u32)>,
    first_sample_done: bool,
}

impl GpuPdhSampler {
    pub fn new() -> Result<Self> {
        let mut query: PdhQueryHandle = Default::default();
        // SAFETY: PdhOpenQueryW writes a query handle into `query` on success.
        let status =
            unsafe { windows::Win32::System::Performance::PdhOpenQueryW(None, 0, &mut query) };
        if !pdh_ok(status) {
            return Err(anyhow::anyhow!("PdhOpenQueryW failed: {status:?}"));
        }
        let mut sampler = Self {
            query,
            usage_counters: Vec::new(),
            mem_counters: Vec::new(),
            shared_counters: Vec::new(),
            first_sample_done: false,
        };
        // Initialize counters immediately so sample() has something to query
        sampler.rebuild_counters()?;

        // Runtime smoke test: verify PDH is working before returning
        if let Err(e) = sampler.smoke_test() {
            log::warn!("[GPU PDH] Smoke test failed: {e}");
            // Don't fail completely - GPU data may appear later
        }

        Ok(sampler)
    }

    /// Runtime self-check: collect 2 samples to verify PDH is responsive
    fn smoke_test(&mut self) -> Result<()> {
        if self.usage_counters.is_empty()
            && self.mem_counters.is_empty()
            && self.shared_counters.is_empty()
        {
            return Err(anyhow::anyhow!(
                "No GPU counters found - GPU metrics unavailable"
            ));
        }

        // First sample (baseline)
        // SAFETY: PdhCollectQueryData expects a valid PDH query handle.
        let status1 = unsafe { PdhCollectQueryData(self.query) };
        if !pdh_ok(status1) {
            return Err(anyhow::anyhow!(
                "Smoke test: PdhCollectQueryData #1 failed: 0x{status1:08X}"
            ));
        }

        // Brief delay to allow counter values to accumulate
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Second sample (compute deltas)
        // SAFETY: PdhCollectQueryData expects a valid PDH query handle.
        let status2 = unsafe { PdhCollectQueryData(self.query) };
        if !pdh_ok(status2) {
            return Err(anyhow::anyhow!(
                "Smoke test: PdhCollectQueryData #2 failed: 0x{status2:08X}"
            ));
        }

        // Mark first sample as done so next sample() returns real data
        self.first_sample_done = true;

        log::info!("[GPU PDH] Smoke test passed: {} usage counters, {} mem counters, {} shared counters ready",
            self.usage_counters.len(), self.mem_counters.len(), self.shared_counters.len());
        Ok(())
    }

    pub fn rebuild_counters(&mut self) -> Result<()> {
        // Close and reopen query to drop stale counters
        // SAFETY: PdhCloseQuery is safe to call on a PDH query handle that we own.
        let _ = unsafe { PdhCloseQuery(self.query) };
        let mut query: PdhQueryHandle = Default::default();
        // SAFETY: PdhOpenQueryW writes a query handle into `query` on success.
        let status =
            unsafe { windows::Win32::System::Performance::PdhOpenQueryW(None, 0, &mut query) };
        if !pdh_ok(status) {
            if should_warn() {
                log::warn!("[GPU PDH] PdhOpenQueryW failed: status=0x{status:08X}");
            }
            return Err(anyhow::anyhow!("PdhOpenQueryW failed: 0x{status:08X}"));
        }
        self.query = query;
        self.usage_counters.clear();
        self.mem_counters.clear();
        self.shared_counters.clear();
        self.first_sample_done = false;

        log::debug!("[GPU PDH] Expanding wildcard: {}", ENGINE_PATH);
        let usage_paths = match expand_paths(ENGINE_PATH) {
            Ok(paths) => {
                log::debug!("[GPU PDH] Expanded {} GPU Engine paths", paths.len());
                if !paths.is_empty() {
                    for (i, p) in paths.iter().enumerate().take(3) {
                        log::trace!("[GPU PDH]   Example usage path {}: {}", i, p);
                    }
                }
                paths
            }
            Err(e) => {
                if should_warn() {
                    log::warn!("[GPU PDH] Failed to expand ENGINE_PATH: {e}");
                }
                Vec::new()
            }
        };

        let mut usage_added = 0;
        for path in usage_paths {
            if let Some(pid) = extract_pid(&path) {
                let mut counter: PdhCounterHandle = Default::default();
                let wide = wstring(&path);
                // SAFETY: `wide` is NUL-terminated UTF-16 and lives for the duration of the call.
                // PDH writes a counter handle into `counter` on success.
                let status =
                    unsafe { PdhAddEnglishCounterW(self.query, wide.as_pwstr(), 0, &mut counter) };
                if !pdh_ok(status) {
                    log::trace!("[GPU PDH] Failed to add usage counter for PID {pid}: status=0x{status:08X}");
                    continue;
                }
                self.usage_counters.push((counter, pid));
                usage_added += 1;
            } else {
                log::trace!("[GPU PDH] Could not extract PID from path: {}", path);
            }
        }
        log::debug!("[GPU PDH] Added {} GPU usage counters", usage_added);

        log::debug!("[GPU PDH] Expanding wildcard: {}", PROCESS_MEM_PATH);
        let mem_paths = match expand_paths(PROCESS_MEM_PATH) {
            Ok(paths) => {
                log::debug!(
                    "[GPU PDH] Expanded {} GPU Process Memory paths",
                    paths.len()
                );
                if !paths.is_empty() {
                    for (i, p) in paths.iter().enumerate().take(3) {
                        log::trace!("[GPU PDH]   Example path {}: {}", i, p);
                    }
                }
                paths
            }
            Err(e) => {
                if should_warn() {
                    log::warn!("[GPU PDH] Failed to expand PROCESS_MEM_PATH: {e}");
                }
                Vec::new()
            }
        };
        for path in mem_paths {
            if let Some(pid) = extract_pid(&path) {
                let mut counter: PdhCounterHandle = Default::default();
                let wide = wstring(&path);
                // SAFETY: `wide` is NUL-terminated UTF-16 and lives for the duration of the call.
                // PDH writes a counter handle into `counter` on success.
                let status =
                    unsafe { PdhAddEnglishCounterW(self.query, wide.as_pwstr(), 0, &mut counter) };
                if !pdh_ok(status) {
                    log::trace!(
                        "[GPU PDH] Failed to add mem counter for PID {pid}: status=0x{status:08X}"
                    );
                    continue;
                }
                self.mem_counters.push((counter, pid));
            } else {
                log::trace!("[GPU PDH] Could not extract PID from mem path: {}", path);
            }
        }
        log::debug!(
            "[GPU PDH] Added {} GPU memory counters",
            self.mem_counters.len()
        );

        log::debug!("[GPU PDH] Expanding wildcard: {}", SHARED_MEM_PATH);
        let shared_paths = match expand_paths(SHARED_MEM_PATH) {
            Ok(paths) => {
                log::debug!("[GPU PDH] Expanded {} GPU Shared Memory paths", paths.len());
                if !paths.is_empty() {
                    for (i, p) in paths.iter().enumerate().take(3) {
                        log::trace!("[GPU PDH]   Example shared path {}: {}", i, p);
                    }
                }
                paths
            }
            Err(e) => {
                if should_warn() {
                    log::warn!("[GPU PDH] Failed to expand SHARED_MEM_PATH: {e}");
                }
                Vec::new()
            }
        };
        for path in shared_paths {
            if let Some(pid) = extract_pid(&path) {
                let mut counter: PdhCounterHandle = Default::default();
                let wide = wstring(&path);
                // SAFETY: `wide` is NUL-terminated UTF-16 and lives for the duration of the call.
                // PDH writes a counter handle into `counter` on success.
                let status =
                    unsafe { PdhAddEnglishCounterW(self.query, wide.as_pwstr(), 0, &mut counter) };
                if !pdh_ok(status) {
                    log::trace!("[GPU PDH] Failed to add shared counter for PID {pid}: status=0x{status:08X}");
                    continue;
                }
                self.shared_counters.push((counter, pid));
            } else {
                log::trace!("[GPU PDH] Could not extract PID from shared path: {}", path);
            }
        }
        log::debug!(
            "[GPU PDH] Added {} GPU shared memory counters",
            self.shared_counters.len()
        );

        Ok(())
    }

    pub fn sample(&mut self) -> Result<GpuSnapshot> {
        // SAFETY: PdhCollectQueryData expects a valid PDH query handle.
        let status = unsafe { PdhCollectQueryData(self.query) };
        if !pdh_ok(status) {
            if should_warn() {
                log::warn!("[GPU PDH] PdhCollectQueryData failed: status=0x{status:08X}");
            }
            return Err(anyhow::anyhow!(
                "PdhCollectQueryData failed: 0x{status:08X}"
            ));
        }

        // PDH needs two samples to compute utilization; skip first result
        if !self.first_sample_done {
            self.first_sample_done = true;
            log::debug!("[GPU PDH] First sample collected (grace period)");
            return Ok(GpuSnapshot::default());
        }

        let mut percent_map: HashMap<u32, f32> = HashMap::new();
        let mut mem_map: HashMap<u32, u64> = HashMap::new();
        let mut shared_map: HashMap<u32, u64> = HashMap::new();

        for (counter, pid) in &self.usage_counters {
            // SAFETY: PDH_FMT_COUNTERVALUE is a plain-old-data struct; zero init is valid.
            let mut value: PDH_FMT_COUNTERVALUE = unsafe { mem::zeroed() };
            let status =
                unsafe { PdhGetFormattedCounterValue(*counter, PDH_FMT_DOUBLE, None, &mut value) };
            if pdh_ok(status) && value.CStatus == 0 {
                // SAFETY: On success, PDH initializes the union field for the requested format.
                let val = unsafe { value.Anonymous.doubleValue } as f32;
                if val.is_finite() && val >= 0.0 {
                    let entry = percent_map.entry(*pid).or_insert(0.0);
                    if val > *entry {
                        *entry = val.min(100.0);
                    }
                }
            }
        }

        for (counter, pid) in &self.mem_counters {
            // SAFETY: PDH_FMT_COUNTERVALUE is a plain-old-data struct; zero init is valid.
            let mut value: PDH_FMT_COUNTERVALUE = unsafe { mem::zeroed() };
            let status =
                unsafe { PdhGetFormattedCounterValue(*counter, PDH_FMT_LARGE, None, &mut value) };
            if pdh_ok(status) && value.CStatus == 0 {
                // SAFETY: On success, PDH initializes the union field for the requested format.
                let val = unsafe { value.Anonymous.largeValue };
                if val > 0 {
                    let entry = mem_map.entry(*pid).or_insert(0u64);
                    *entry = entry.saturating_add(val as u64);
                }
            }
        }

        for (counter, pid) in &self.shared_counters {
            // SAFETY: PDH_FMT_COUNTERVALUE is a plain-old-data struct; zero init is valid.
            let mut value: PDH_FMT_COUNTERVALUE = unsafe { mem::zeroed() };
            let status =
                unsafe { PdhGetFormattedCounterValue(*counter, PDH_FMT_LARGE, None, &mut value) };
            if pdh_ok(status) && value.CStatus == 0 {
                // SAFETY: On success, PDH initializes the union field for the requested format.
                let val = unsafe { value.Anonymous.largeValue };
                if val > 0 {
                    let entry = shared_map.entry(*pid).or_insert(0u64);
                    *entry = entry.saturating_add(val as u64);
                }
            }
        }

        // Compute total GPU memory per PID
        let mut total_map: HashMap<u32, u64> = HashMap::new();
        for (&pid, &dedicated) in &mem_map {
            let shared = shared_map.get(&pid).copied().unwrap_or(0);
            total_map.insert(pid, dedicated.saturating_add(shared));
        }
        for (&pid, &shared) in &shared_map {
            total_map.entry(pid).or_insert(shared);
        }

        // Log sample results periodically (every 30 samples = ~1 minute)
        static SAMPLE_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let count = SAMPLE_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count.is_multiple_of(30) {
            log::debug!("[GPU PDH] Sample #{}: {} PIDs with GPU%, {} PIDs with dedicated, {} PIDs with shared",
                count, percent_map.len(), mem_map.len(), shared_map.len());
        }

        Ok(GpuSnapshot {
            gpu_percent: percent_map,
            gpu_dedicated_bytes: mem_map,
            gpu_shared_bytes: shared_map,
            gpu_total_bytes: total_map,
            sample_timestamp: std::time::Instant::now(),
        })
    }
}

impl Drop for GpuPdhSampler {
    fn drop(&mut self) {
        unsafe {
            let _ = PdhCloseQuery(self.query);
        }
    }
}
