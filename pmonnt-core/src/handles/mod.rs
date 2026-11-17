//! Handle tracking and leak detection

mod cache;
mod compute;
mod config;
pub mod entry;
mod leak_detector;
mod summary;

pub use cache::HandleCache;
pub use compute::{compute_summaries, count_handle_types, summaries_from_counts};
pub use config::LeakDetectorConfig;
pub use entry::{HandleEntry, get_type_name};
pub use leak_detector::HandleLeakDetector;
pub use summary::HandleSummary;
