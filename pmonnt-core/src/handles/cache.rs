use super::{HandleLeakDetector, HandleSummary, LeakDetectorConfig};

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

/// Cache for handle summaries per process
#[derive(Clone)]
pub struct HandleCache {
    summaries: HashMap<u32, HandleSummary>,
    leak_detectors: HashMap<u32, HandleLeakDetector>,
    type_history: HashMap<u32, VecDeque<HashMap<u16, u32>>>, // Last N raw type counts per PID
    last_update: Instant,
    ttl_secs: u64,
    config_by_path: HashMap<String, LeakDetectorConfig>, // Persisted config by image path
    pub last_error: Option<String>,
}

impl HandleCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            summaries: HashMap::new(),
            leak_detectors: HashMap::new(),
            type_history: HashMap::new(),
            last_update: Instant::now(),
            ttl_secs,
            config_by_path: HashMap::new(),
            last_error: None,
        }
    }

    /// Load config from JSON file
    pub fn load_config(&mut self, path: &std::path::Path) -> anyhow::Result<()> {
        if !path.exists() {
            return Ok(()); // No config file yet
        }

        let data = std::fs::read_to_string(path)?;
        self.config_by_path = serde_json::from_str(&data)?;
        Ok(())
    }

    /// Save config to JSON file atomically (write to .tmp then rename)
    pub fn save_config(&self, path: &std::path::Path) -> anyhow::Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Write to temporary file (same directory = same volume = atomic rename)
        let tmp_path = path.with_extension("tmp");
        let data = serde_json::to_string_pretty(&self.config_by_path)?;
        std::fs::write(&tmp_path, data)?;

        // Atomically rename over original (Windows-safe)
        // If rename fails because target exists, remove target first
        if let Err(e) = std::fs::rename(&tmp_path, path) {
            // Try removing target and retry rename
            let _ = std::fs::remove_file(path); // Ignore errors if file doesn't exist
            if let Err(rename_err) = std::fs::rename(&tmp_path, path) {
                // Clean up tmp file on failure (best-effort)
                let _ = std::fs::remove_file(&tmp_path);
                return Err(anyhow::anyhow!(
                    "Rename failed: {} (original error: {})",
                    rename_err,
                    e
                ));
            }
        }
        Ok(())
    }

    /// Normalize image path for config key (strip \\?\, normalize slashes, lowercase)
    fn normalize_path(path: &str) -> String {
        let mut normalized = path.to_string();

        // Strip \\?\ prefix if present (Windows extended-length path prefix)
        if normalized.starts_with(r"\\?\") {
            normalized = normalized[4..].to_string();
        }

        // Normalize slashes to backslash (Windows standard)
        normalized = normalized.replace('/', r"\");

        // Lowercase for case-insensitive comparison
        normalized.to_lowercase()
    }

    /// Get or create detector with config from image path
    fn get_or_create_detector(
        &mut self,
        pid: u32,
        image_path: Option<&str>,
    ) -> &mut HandleLeakDetector {
        self.leak_detectors.entry(pid).or_insert_with(|| {
            // Check if we have persisted config for this image path
            if let Some(path) = image_path {
                let normalized = Self::normalize_path(path);
                if let Some(config) = self.config_by_path.get(&normalized) {
                    return HandleLeakDetector::new_with_config(
                        config.consecutive_threshold,
                        config.leak_threshold,
                        config.flat_tolerance,
                    );
                }
            }
            // No path or no saved config → use defaults
            HandleLeakDetector::new()
        })
    }

    /// Get cached summary if still fresh
    pub fn get(&self, pid: u32) -> Option<&HandleSummary> {
        if self.last_update.elapsed().as_secs() >= self.ttl_secs {
            return None;
        }
        self.summaries.get(&pid)
    }

    /// Check if the cache has been populated (scan completed at least once)
    pub fn has_data(&self) -> bool {
        !self.summaries.is_empty()
    }

    /// Update summaries for all processes
    /// Pass pid_to_path mapping to support config persistence
    pub fn update(&mut self, summaries: HashMap<u32, HandleSummary>) {
        self.update_with_paths(summaries, &HashMap::new());
    }

    /// Update summaries with image path mapping for config persistence
    pub fn update_with_paths(
        &mut self,
        summaries: HashMap<u32, HandleSummary>,
        pid_to_path: &HashMap<u32, String>,
    ) {
        // Update leak detectors
        for (pid, summary) in &summaries {
            let image_path = pid_to_path.get(pid).map(|s| s.as_str());
            let detector = self.get_or_create_detector(*pid, image_path);
            detector.add_sample(summary.total);
        }

        self.summaries = summaries;
        self.last_update = Instant::now();
    }

    /// Update type history for growth tracking (call with raw type counts)
    pub fn update_type_history(&mut self, type_counts: &HashMap<u32, HashMap<u16, u32>>) {
        const HISTORY_WINDOW: usize = 5; // Keep last 5 samples

        for (pid, current_types) in type_counts {
            let history = self.type_history.entry(*pid).or_default();

            // Add current sample (clone the HashMap)
            history.push_back(current_types.clone());

            // Cap history size
            while history.len() > HISTORY_WINDOW {
                history.pop_front();
            }
        }

        // Clean up old PIDs
        let active_pids: std::collections::HashSet<u32> = type_counts.keys().cloned().collect();
        self.type_history.retain(|pid, _| active_pids.contains(pid));
    }

    /// Get top growing handle types for a PID (last N samples)
    pub fn get_top_growing_types(&self, pid: u32) -> Option<Vec<(u16, i64, u32)>> {
        const TOP_K: usize = 6;

        let history = self.type_history.get(&pid)?;
        if history.len() < 2 {
            return None; // Need at least 2 samples for comparison
        }

        let oldest = history.front()?;
        let newest = history.back()?;

        // Calculate deltas for all types present in either snapshot
        let mut deltas: Vec<(u16, i64, u32)> = Vec::new();

        // Get union of all type indices
        let mut all_types = std::collections::HashSet::new();
        all_types.extend(oldest.keys());
        all_types.extend(newest.keys());

        for type_idx in all_types {
            let old_count = oldest.get(type_idx).copied().unwrap_or(0) as i64;
            let new_count = newest.get(type_idx).copied().unwrap_or(0) as i64;
            let delta = new_count - old_count;

            if delta > 0 {
                deltas.push((*type_idx, delta, new_count as u32));
            }
        }

        // Sort by delta descending, take top K
        deltas.sort_by(|a, b| b.1.cmp(&a.1));
        deltas.truncate(TOP_K);

        Some(deltas)
    }

    /// Check if a process is leaking handles
    pub fn is_leaking(&self, pid: u32) -> bool {
        self.leak_detectors
            .get(&pid)
            .map(|d| d.is_leaking())
            .unwrap_or(false)
    }

    /// Get delta from previous sample
    pub fn get_delta(&self, pid: u32) -> Option<i32> {
        let detector = self.leak_detectors.get(&pid)?;
        let current = detector.current_count()?;
        let previous = detector.previous_count()?;
        Some(current as i32 - previous as i32)
    }

    /// Get leak explanation for UI display
    pub fn get_leak_explanation(&self, pid: u32) -> Option<(usize, u32, usize)> {
        self.leak_detectors.get(&pid)?.get_leak_explanation()
    }

    /// Reset leak detector for a specific PID (clears rolling window + counters)
    pub fn reset_detector(&mut self, pid: u32) {
        if let Some(detector) = self.leak_detectors.get_mut(&pid) {
            detector.reset();
        }
    }

    /// Update leak detector config for a specific PID and persist by image path
    pub fn update_detector_config(
        &mut self,
        pid: u32,
        image_path: Option<&str>,
        consecutive: usize,
        delta: u32,
        flat_tol: usize,
    ) {
        // Update in-memory detector
        if let Some(detector) = self.leak_detectors.get_mut(&pid) {
            detector.update_config(consecutive, delta, flat_tol);
        }

        // Persist config by image path (normalized, skip if no path)
        if let Some(path) = image_path {
            let normalized = Self::normalize_path(path);
            self.config_by_path.insert(
                normalized,
                LeakDetectorConfig {
                    consecutive_threshold: consecutive,
                    leak_threshold: delta,
                    flat_tolerance: flat_tol,
                },
            );
        }
    }

    /// Get current detector config for a PID (or default if not exists)
    pub fn get_detector_config(&self, pid: u32) -> (usize, u32, usize) {
        self.leak_detectors
            .get(&pid)
            .map(|d| d.get_config())
            .unwrap_or((20, 200, 2))
    }

    /// Get config for an image path (for displaying defaults)
    pub fn get_path_config(&self, image_path: &str) -> LeakDetectorConfig {
        let normalized = Self::normalize_path(image_path);
        self.config_by_path
            .get(&normalized)
            .cloned()
            .unwrap_or_default()
    }

    /// Cleanup old entries
    pub fn cleanup(&mut self, active_pids: &[u32]) {
        let active_set: std::collections::HashSet<u32> = active_pids.iter().copied().collect();
        self.summaries.retain(|pid, _| active_set.contains(pid));
        self.leak_detectors
            .retain(|pid, _| active_set.contains(pid));
        self.type_history.retain(|pid, _| active_set.contains(pid));
    }
}

impl Default for HandleCache {
    fn default() -> Self {
        Self::new(5)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_top_growing_types() {
        let mut cache = HandleCache::new(5);

        // Simulate 3 samples with growing handle types
        let mut sample1 = HashMap::new();
        sample1.insert(1u16, 10u32); // Type 1: 10 handles
        sample1.insert(2u16, 5u32); // Type 2: 5 handles

        let mut sample2 = HashMap::new();
        sample2.insert(1u16, 15u32); // Type 1: +5
        sample2.insert(2u16, 8u32); // Type 2: +3
        sample2.insert(3u16, 12u32); // Type 3: +12 (new)

        let mut sample3 = HashMap::new();
        sample3.insert(1u16, 18u32); // Type 1: +3 more
        sample3.insert(2u16, 8u32); // Type 2: flat (0)
        sample3.insert(3u16, 20u32); // Type 3: +8 more

        // Add samples for PID 123
        let mut pid_data = HashMap::new();
        pid_data.insert(123u32, sample1);
        cache.update_type_history(&pid_data);

        pid_data.clear();
        pid_data.insert(123u32, sample2);
        cache.update_type_history(&pid_data);

        pid_data.clear();
        pid_data.insert(123u32, sample3);
        cache.update_type_history(&pid_data);

        // Check top growing types (compares oldest vs newest)
        let growing = cache.get_top_growing_types(123).unwrap();

        // Should show: Type3 (+20), Type1 (+8), Type2 (+3)
        assert_eq!(growing.len(), 3);
        assert_eq!(growing[0], (3u16, 20i64, 20u32)); // Type 3: 20-0 = +20
        assert_eq!(growing[1], (1u16, 8i64, 18u32)); // Type 1: 18-10 = +8
        assert_eq!(growing[2], (2u16, 3i64, 8u32)); // Type 2: 8-5 = +3
    }
}
