//! High-level scanning orchestration

pub mod process_scanner;
mod types;

pub use process_scanner::ProcessScanner;
pub use types::{ScanError, ScanMatch, ScanMode, ScanOptions, ScanProgress, ScanResult};
