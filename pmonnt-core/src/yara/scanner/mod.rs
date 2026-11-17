//! High-level scanning orchestration

#[cfg(windows)]
pub mod process_scanner;
mod types;

#[cfg(windows)]
pub use process_scanner::ProcessScanner;
pub use types::{ScanError, ScanMatch, ScanMode, ScanOptions, ScanProgress, ScanResult};
