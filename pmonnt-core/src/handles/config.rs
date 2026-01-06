use serde::{Deserialize, Serialize};

/// Leak detector configuration (persisted per image path)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeakDetectorConfig {
    pub consecutive_threshold: usize,
    pub leak_threshold: u32,
    pub flat_tolerance: usize,
}

impl Default for LeakDetectorConfig {
    fn default() -> Self {
        Self {
            consecutive_threshold: 20,
            leak_threshold: 200,
            flat_tolerance: 2,
        }
    }
}
