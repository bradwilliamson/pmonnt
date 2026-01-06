use crate::yara::rules::Severity;

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    Quick,
    Deep,
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub mode: ScanMode,
    pub max_region_bytes: usize,
    pub chunk_size: usize,
    pub chunk_overlap: usize,
    pub suppressed_rule_prefixes: Vec<String>,
    pub suppressed_rule_names: Vec<String>,
}

impl ScanOptions {
    pub fn quick() -> Self {
        Self {
            mode: ScanMode::Quick,
            // Keep this intentionally small to reduce noise and scanning time.
            max_region_bytes: 16 * 1024 * 1024,
            chunk_size: 2 * 1024 * 1024,
            chunk_overlap: 16 * 1024,
            suppressed_rule_prefixes: vec!["test_".to_string()],
            suppressed_rule_names: vec!["DetectEncryptedVariants".to_string()],
        }
    }

    pub fn deep() -> Self {
        Self {
            mode: ScanMode::Deep,
            max_region_bytes: 100 * 1024 * 1024,
            chunk_size: 4 * 1024 * 1024,
            chunk_overlap: 16 * 1024,
            suppressed_rule_prefixes: Vec::new(),
            suppressed_rule_names: Vec::new(),
        }
    }

    pub(crate) fn is_suppressed(&self, rule_name: &str) -> bool {
        if self
            .suppressed_rule_names
            .iter()
            .any(|n| n.eq_ignore_ascii_case(rule_name))
        {
            return true;
        }
        self.suppressed_rule_prefixes
            .iter()
            .any(|p| rule_name.starts_with(p))
    }
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self::deep()
    }
}

#[derive(Debug, Clone)]
pub enum ScanProgress {
    Starting {
        pid: u32,
        process_name: String,
        total_regions: usize,
        total_bytes: usize,
    },
    ScanningRegion {
        current_region: usize,
        total_regions: usize,
        bytes_scanned: usize,
        total_bytes: usize,
        current_address: usize,
    },
    MatchFound {
        rule_name: String,
        severity: Severity,
        address: usize,
    },
    Completed {
        result: ScanResult,
    },
    Error {
        error: String,
    },
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub pid: u32,
    pub process_name: String,
    pub bytes_scanned: usize,
    pub regions_scanned: usize,
    pub regions_skipped: usize,
    pub duration_ms: u64,
    pub matches: Vec<ScanMatch>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ScanMatch {
    pub rule_name: String,
    pub rule_description: Option<String>,
    pub severity: Severity,
    pub tags: Vec<String>,
    pub memory_address: usize,
    pub region_base: usize,
    pub matched_strings: Vec<crate::yara::engine::MatchedString>,
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("Memory error: {0}")]
    MemoryError(#[from] crate::yara::memory::MemoryError),
    #[error("Engine error: {0}")]
    EngineError(#[from] crate::yara::engine::EngineError),
    #[error("Scan cancelled")]
    Cancelled,
    #[error("Windows error: {0}")]
    WindowsError(#[from] windows::core::Error),
}
