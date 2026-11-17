//! Platform-independent view model for the process list.
//!
//! These functions turn a process snapshot plus per-PID metrics into the rows the UI draws
//! (the hierarchical tree view and the Task-Manager-style grouped view), including sorting,
//! filtering and aggregation. They run on every frame, so they live here, free of any GUI or
//! Win32 dependency, where they can be unit-tested and benchmarked under Valgrind on Linux
//! (see `benches/`).

use std::collections::HashMap;

use crate::SignatureInfo;
use crate::handles::HandleCache;
use crate::metrics::IoRate;

mod grouped;
#[cfg(test)]
mod tests;
mod tree;

pub use grouped::build_grouped_rows;
pub use tree::{build_process_rows, compare_tree_pids};

/// Column the process list is sorted by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub enum GroupSort {
    Name,
    VerifiedSigner,
    CPU,
    Memory,
    Disk,
    GPU,
    GPUMemory,
    Handles,
    PID,
    Threads,
}

/// Row in the virtualized process tree.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcRow {
    pub pid: u32,
    pub depth: usize,
    pub has_children: bool,
    pub is_expanded: bool,
    pub is_match: bool,
    pub is_selected: bool,
    /// e.g. "explorer.exe (8860)"
    pub label: String,
}

/// Row in the grouped view (flat, no collapsing, like Task Manager).
#[derive(Debug, Clone, PartialEq)]
pub struct GroupedRow {
    pub name: String,
    pub count: usize,
    pub is_match: bool,
    /// True if any member is selected.
    pub is_selected: bool,
    /// "Best" PID to select when clicking the group.
    pub representative_pid: u32,
    /// Aggregated handle count.
    pub total_handles: u32,
    /// At least one PID had handle data.
    pub handles_any_available: bool,
    /// All PIDs had handle data.
    pub handles_all_available: bool,
    /// Aggregated thread count.
    pub thread_count: usize,
    /// Total CPU % across group members (sum).
    pub cpu_percent: f32,
    /// Sum of memory bytes across members (None if unavailable for all members).
    pub memory_bytes: Option<u64>,
    /// Sum of read+write bytes/sec across members.
    pub disk_bytes_per_sec: f64,
    /// Max GPU % across members.
    pub gpu_percent: f32,
    /// Sum of dedicated GPU memory across members.
    pub gpu_dedicated_bytes: u64,
    /// Sum of shared GPU memory across members.
    pub gpu_shared_bytes: u64,
    /// Sum of total GPU memory across members.
    pub gpu_total_bytes: u64,
    /// All PIDs in this group, ascending.
    pub member_pids: Vec<u32>,
    /// Image path of the representative PID.
    pub image_path: Option<String>,
}

/// Per-PID metric lookups the row builders sort and aggregate by.
#[derive(Clone, Copy)]
pub struct RowMetrics<'a> {
    pub handle_cache: &'a HandleCache,
    pub global_thread_counts: &'a HashMap<u32, usize>,
    /// PID -> (CPU %, working set bytes)
    pub cpu_memory_data: &'a HashMap<u32, (f32, Option<u64>)>,
    pub io_rate_by_pid: &'a HashMap<u32, IoRate>,
    /// PID -> (GPU %, dedicated bytes, shared bytes, total bytes)
    pub gpu_data: &'a HashMap<u32, (f32, u64, u64, u64)>,
    pub signature_cache_by_path: &'a HashMap<String, SignatureInfo>,
}
