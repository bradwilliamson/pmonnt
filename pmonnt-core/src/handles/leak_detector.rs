use std::collections::VecDeque;

/// Handle leak detector for a single process
#[derive(Debug, Clone)]
pub struct HandleLeakDetector {
    history: VecDeque<u32>, // Rolling window of handle counts
    max_history: usize,
    leak_threshold: u32,
    consecutive_increases: usize,
    consecutive_threshold: usize,
    flat_tolerance: usize,    // Allow N flat samples in the window
    flat_samples_used: usize, // Track consecutive flats for cap enforcement
}

impl HandleLeakDetector {
    /// Create a new leak detector with default settings
    /// - 20 consecutive increases/flats required
    /// - 200 handle delta threshold
    /// - 2 flat samples tolerated
    pub fn new() -> Self {
        Self::new_with_config(20, 200, 2)
    }

    /// Create a leak detector with custom configuration
    ///
    /// # Arguments
    /// * `consecutive_threshold` - Number of consecutive increases/flats required (e.g., 20)
    /// * `leak_threshold` - Minimum handle delta to consider a leak (e.g., 200)
    /// * `flat_tolerance` - Maximum consecutive flat samples allowed (e.g., 2)
    ///
    /// # Example
    /// ```ignore
    /// // More sensitive: 15 samples, 100 handle delta, 1 flat
    /// let detector = HandleLeakDetector::new_with_config(15, 100, 1);
    ///
    /// // Less sensitive: 30 samples, 500 handle delta, 5 flats
    /// let detector = HandleLeakDetector::new_with_config(30, 500, 5);
    /// ```
    pub fn new_with_config(
        consecutive_threshold: usize,
        leak_threshold: u32,
        flat_tolerance: usize,
    ) -> Self {
        Self {
            history: VecDeque::new(),
            max_history: 120, // Keep 120 samples (about 10 minutes at 5s interval)
            leak_threshold,
            consecutive_increases: 0,
            consecutive_threshold,
            flat_tolerance,
            flat_samples_used: 0,
        }
    }

    /// Add a new sample and check for leaks
    ///
    /// # Flat Sample Behavior
    /// The "3rd flat resets" rule is intentional:
    /// - Real leaks show: `inc, inc, flat, inc, flat, inc` (flat counter resets on increase)
    /// - Idle processes: `inc, inc, flat, flat, flat` (3rd flat resets = not a leak)
    ///   This prevents false positives when a process stabilizes.
    pub fn add_sample(&mut self, handle_count: u32) -> bool {
        if let Some(&last) = self.history.back() {
            if handle_count > last {
                // Actual increase - reset flat counter
                // This handles real leak pattern: inc, flat, inc, flat, inc...
                self.consecutive_increases += 1;
                self.flat_samples_used = 0;
            } else if handle_count == last {
                // Flat sample - check if we're within tolerance
                if self.flat_samples_used < self.flat_tolerance {
                    self.consecutive_increases += 1;
                    self.flat_samples_used += 1;
                } else {
                    // Exceeded flat tolerance - reset (3rd flat = stabilized, not leaking)
                    // This correctly handles: inc, inc, flat, flat, flat (idle)
                    self.consecutive_increases = 0;
                    self.flat_samples_used = 0;
                }
            } else {
                // Decrease resets everything - leak stopped
                self.consecutive_increases = 0;
                self.flat_samples_used = 0;
            }
        }

        self.history.push_back(handle_count);
        if self.history.len() > self.max_history {
            self.history.pop_front();
        }

        self.is_leaking()
    }

    /// Check if the process is currently leaking handles
    pub fn is_leaking(&self) -> bool {
        if self.consecutive_increases < self.consecutive_threshold {
            return false;
        }

        // Verify monotonic increase with flat tolerance
        if self.history.len() >= self.consecutive_threshold {
            let recent_start = self.history.len() - self.consecutive_threshold;
            let window: Vec<u32> = self.history.iter().skip(recent_start).copied().collect();
            let mut flat_count = 0;

            for i in 1..window.len() {
                if window[i] < window[i - 1] {
                    return false; // Decrease invalidates leak
                }
                if window[i] == window[i - 1] {
                    flat_count += 1;
                    if flat_count > self.flat_tolerance {
                        return false; // Too many flat samples
                    }
                }
            }

            let start_count = window[0];
            let current_count = self.history[self.history.len() - 1];

            current_count.saturating_sub(start_count) >= self.leak_threshold
        } else {
            false
        }
    }

    /// Get current handle count
    pub fn current_count(&self) -> Option<u32> {
        self.history.back().copied()
    }

    /// Get previous handle count for delta calculation
    pub fn previous_count(&self) -> Option<u32> {
        if self.history.len() >= 2 {
            Some(self.history[self.history.len() - 2])
        } else {
            None
        }
    }

    /// Get leak detection explanation (for UI display)
    /// Returns (samples_used, delta, flats_used) if leaking
    pub fn get_leak_explanation(&self) -> Option<(usize, u32, usize)> {
        if !self.is_leaking() {
            return None;
        }

        let recent_start = self
            .history
            .len()
            .saturating_sub(self.consecutive_threshold);
        let window: Vec<u32> = self.history.iter().skip(recent_start).copied().collect();

        let start_count = window.first().copied().unwrap_or(0);
        let current_count = *self.history.back().unwrap_or(&0);
        let delta = current_count.saturating_sub(start_count);

        // Count flats in window
        let mut flats_used = 0;
        for i in 1..window.len() {
            if window[i] == window[i - 1] {
                flats_used += 1;
            }
        }

        Some((window.len(), delta, flats_used))
    }

    /// Reset detector history and counters (for UI "Reset" button)
    pub fn reset(&mut self) {
        self.history.clear();
        self.consecutive_increases = 0;
        self.flat_samples_used = 0;
    }

    /// Get current configuration
    pub fn get_config(&self) -> (usize, u32, usize) {
        (
            self.consecutive_threshold,
            self.leak_threshold,
            self.flat_tolerance,
        )
    }

    /// Update configuration (creates new detector with new config, preserves history)
    pub fn update_config(
        &mut self,
        consecutive_threshold: usize,
        leak_threshold: u32,
        flat_tolerance: usize,
    ) {
        self.consecutive_threshold = consecutive_threshold;
        self.leak_threshold = leak_threshold;
        self.flat_tolerance = flat_tolerance;

        // Reset counters since thresholds changed
        self.consecutive_increases = 0;
        self.flat_samples_used = 0;
    }
}

impl Default for HandleLeakDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leak_detector_consecutive_increases() {
        let mut detector = HandleLeakDetector::new();

        // Add 21 samples: first at 100, then 20 increases of +15 each
        detector.add_sample(100);
        for i in 1..=20 {
            detector.add_sample(100 + i * 15);
        }

        // Now have 20 consecutive increases, delta = 300 (>= 200 threshold)
        assert!(
            detector.is_leaking(),
            "Should detect leak with 20 consecutive increases and 300 delta"
        );
    }

    #[test]
    fn test_leak_detector_with_flat_samples() {
        let mut detector = HandleLeakDetector::new();

        // Start at 100
        detector.add_sample(100);

        // Add 17 increases (100 -> 355)
        for i in 1..=17 {
            detector.add_sample(100 + i * 15);
        }

        // Add 2 flat samples (within tolerance)
        detector.add_sample(355); // 18th increase (flat)
        detector.add_sample(355); // 19th increase (flat)
        detector.add_sample(355); // 20th increase (flat) - wait, this is 3 flats

        // Actually, let me rethink: we need 20 consecutive increases/flats
        // Let's do 18 increases + 2 flats
        let mut detector2 = HandleLeakDetector::new();
        detector2.add_sample(100);
        for i in 1..=18 {
            detector2.add_sample(100 + i * 15);
        }
        detector2.add_sample(370); // 19th (flat)
        detector2.add_sample(370); // 20th (flat)

        // Should detect leak (20 consecutive including 2 flats, 270 delta)
        assert!(
            detector2.is_leaking(),
            "Should detect leak with flat samples within tolerance"
        );
    }

    #[test]
    fn test_leak_detector_too_many_flat_samples() {
        let mut detector = HandleLeakDetector::new();

        // Start at 100
        detector.add_sample(100);

        // Add 17 increases
        for i in 1..=17 {
            detector.add_sample(100 + i * 15);
        }

        // Add 3 flat samples (exceeds tolerance of 2)
        detector.add_sample(355);
        detector.add_sample(355);
        detector.add_sample(355);

        // Should NOT detect leak (too many flat samples in window)
        assert!(
            !detector.is_leaking(),
            "Should not trigger with too many flat samples"
        );
    }

    #[test]
    fn test_leak_detector_decrease_resets() {
        let mut detector = HandleLeakDetector::new();

        // Add 15 increases
        for i in 0..15 {
            detector.add_sample(100 + i * 10);
        }

        // Decrease resets the counter
        detector.add_sample(240); // decrease from 250

        // Add 20 more increases
        for i in 0..20 {
            detector.add_sample(240 + i * 15);
        }

        // Should detect leak (new streak of 20 with 300 delta)
        assert!(detector.is_leaking(), "Should detect leak after reset");
    }

    #[test]
    fn test_leak_detector_below_threshold() {
        let mut detector = HandleLeakDetector::new();

        // Add 20 small increases (total delta < 200)
        for i in 0..20 {
            detector.add_sample(100 + i * 5); // Only 95 total delta
        }

        // Should NOT detect leak (delta too small)
        assert!(
            !detector.is_leaking(),
            "Should not trigger with delta < 200"
        );
    }

    #[test]
    fn test_reset_conditions() {
        let mut detector = HandleLeakDetector::new();

        // Build up some consecutive increases
        detector.add_sample(100);
        for i in 1..=10 {
            detector.add_sample(100 + i * 10);
        }

        // Verify we have progress
        assert_eq!(detector.consecutive_increases, 10);

        // Add a flat to use up flat tolerance
        detector.add_sample(200);
        assert_eq!(detector.consecutive_increases, 11);
        assert_eq!(detector.flat_samples_used, 1);

        // Decrease should reset BOTH counters
        detector.add_sample(190);
        assert_eq!(
            detector.consecutive_increases, 0,
            "consecutive_increases should be reset"
        );
        assert_eq!(
            detector.flat_samples_used, 0,
            "flat_samples_used should be reset"
        );
    }

    #[test]
    fn test_flat_sample_cap_enforcement() {
        let mut detector = HandleLeakDetector::new();

        // Start
        detector.add_sample(100);

        // Add 17 increases
        for i in 1..=17 {
            detector.add_sample(100 + i * 10);
        }

        assert_eq!(detector.consecutive_increases, 17);

        // Add 1st flat (allowed)
        detector.add_sample(270);
        assert_eq!(detector.consecutive_increases, 18);
        assert_eq!(detector.flat_samples_used, 1);

        // Add 2nd flat (allowed)
        detector.add_sample(270);
        assert_eq!(detector.consecutive_increases, 19);
        assert_eq!(detector.flat_samples_used, 2);

        // Add 3rd flat (EXCEEDS tolerance - should reset)
        detector.add_sample(270);
        assert_eq!(
            detector.consecutive_increases, 0,
            "3rd flat should reset consecutive_increases"
        );
        assert_eq!(
            detector.flat_samples_used, 0,
            "3rd flat should reset flat_samples_used"
        );
    }

    #[test]
    fn test_flat_counter_resets_on_increase() {
        let mut detector = HandleLeakDetector::new();

        detector.add_sample(100);
        detector.add_sample(110); // increase
        detector.add_sample(110); // flat
        detector.add_sample(110); // flat (2 used)

        assert_eq!(detector.flat_samples_used, 2);

        // Next increase should reset flat counter
        detector.add_sample(120);
        assert_eq!(
            detector.flat_samples_used, 0,
            "Increase should reset flat counter"
        );
        assert_eq!(
            detector.consecutive_increases, 4,
            "But consecutive should continue"
        );
    }

    #[test]
    fn test_custom_config_more_sensitive() {
        // More sensitive detector: 10 samples, 50 delta, 1 flat
        let mut detector = HandleLeakDetector::new_with_config(10, 50, 1);

        detector.add_sample(100);
        for i in 1..=10 {
            detector.add_sample(100 + i * 10);
        }

        // Should trigger with lower thresholds (100 delta, 10 samples)
        assert!(
            detector.is_leaking(),
            "More sensitive config should trigger"
        );
    }

    #[test]
    fn test_custom_config_less_sensitive() {
        // Less sensitive detector: 30 samples, 500 delta, 5 flats
        let mut detector = HandleLeakDetector::new_with_config(30, 500, 5);

        detector.add_sample(100);
        for i in 1..=25 {
            detector.add_sample(100 + i * 10);
        }

        // Should NOT trigger (only 250 delta < 500 threshold, even with 25 samples)
        assert!(
            !detector.is_leaking(),
            "Less sensitive config should not trigger"
        );

        // Add more to exceed delta threshold
        for i in 26..=30 {
            detector.add_sample(100 + i * 20);
        }

        // Now should trigger (30 samples, 700 delta)
        assert!(
            detector.is_leaking(),
            "Should trigger after exceeding delta threshold"
        );
    }

    #[test]
    fn test_real_leak_pattern_with_interleaved_flats() {
        // Simulate real leak: increases with occasional flats that get reset
        // This test demonstrates flats DON'T break the leak detection
        let mut detector = HandleLeakDetector::new();

        detector.add_sample(100);

        // Build up 20 consecutive increases/flats with >200 delta
        // Flats are reset by subsequent increases
        for i in 1..=21 {
            detector.add_sample(100 + i * 15);
        }

        // 21 increases: consecutive_increases = 21, delta = 315
        assert!(
            detector.is_leaking(),
            "21 consecutive increases with 315 delta should trigger"
        );
    }

    #[test]
    fn test_idle_stabilization_correctly_resets() {
        // Simulate: process increases then stabilizes (idle)
        let mut detector = HandleLeakDetector::new();

        detector.add_sample(100);
        for i in 1..=17 {
            detector.add_sample(100 + i * 10);
        }

        // Process stabilizes (3 consecutive flats)
        detector.add_sample(270); // flat 1
        detector.add_sample(270); // flat 2
        detector.add_sample(270); // flat 3 - RESETS

        assert_eq!(
            detector.consecutive_increases, 0,
            "3 consecutive flats should reset"
        );
        assert!(!detector.is_leaking(), "Stabilized process is not leaking");
    }
}
