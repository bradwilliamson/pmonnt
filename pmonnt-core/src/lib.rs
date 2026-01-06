//! PMonNT Core library
//! Provides core functionality for process monitoring

use thiserror::Error;

/// PMonNT error type for Windows operations
#[derive(Error, Debug, Clone)]
pub enum PmonntError {
    #[error("Windows API error: {0}")]
    WinApiError(String),

    #[error("Thread enumeration failed: {0}")]
    ThreadEnumerationFailed(String),

    #[error("Module enumeration failed: {0}")]
    ModuleEnumerationFailed(String),

    #[error("{0}")]
    Other(String),
}

#[cfg(windows)]
pub mod diff;
#[cfg(windows)]
pub mod handles;
pub mod hashing;
pub mod local_cache;
#[cfg(windows)]
pub mod module;
#[cfg(windows)]
pub mod network;
#[cfg(windows)]
pub mod process;
pub mod providers;
pub mod reputation;
#[cfg(windows)]
pub mod reputation_service;
#[cfg(windows)]
pub mod service_control;
#[cfg(windows)]
pub mod services;
#[cfg(windows)]
pub mod snapshot;
#[cfg(windows)]
pub mod thread;
#[cfg(windows)]
pub mod token;
pub mod vt;
#[cfg(windows)]
pub mod win;
#[cfg(windows)]
pub use win::handles as win_handles;
#[cfg(windows)]
pub use win::module as win_module;
#[cfg(windows)]
pub use win::process_metrics as win_process_metrics;
#[cfg(windows)]
pub use win::process_path as win_process_path;
#[cfg(windows)]
pub use win::thread as win_thread;
#[cfg(windows)]
pub mod yara;

pub use win::signature::{verify_signature, SignatureInfo, SignatureStatus};

/// Get the current tick count for display
pub fn get_tick_count() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Get the library version
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_tick_count() {
        let count = get_tick_count();
        assert!(count > 0);
    }
}
