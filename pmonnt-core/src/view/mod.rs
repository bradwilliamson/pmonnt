//! Platform-independent view model for the process list.
//!
//! These functions turn a process snapshot plus per-PID metrics into the rows the UI draws
//! (the hierarchical tree view and the Task-Manager-style grouped view), including sorting,
//! filtering and aggregation. They run on every frame, so they live here, free of any GUI or
//! Win32 dependency, where they can be unit-tested and benchmarked under Valgrind on Linux
//! (see `benches/`).

use std::collections::{HashMap, HashSet};

use crate::SignatureInfo;
use crate::handles::HandleCache;
use crate::metrics::IoRate;
use crate::snapshot::ProcessSnapshot;

mod grouped;
#[cfg(test)]
mod reference;
mod sort;
#[cfg(test)]
mod tests;
mod tree;

pub use grouped::build_grouped_rows;
pub use tree::{build_process_rows, sorted_roots};

/// Inputs for the tree view besides the snapshot and metrics.
#[derive(Clone, Copy)]
pub struct TreeOptions<'a> {
    /// PIDs whose children are shown.
    pub expanded: &'a HashSet<u32>,
    pub selected_pid: Option<u32>,
    /// When filtering: the PIDs to show (see [`filter_visible_pids`]).
    pub visible_pids: Option<&'a HashSet<u32>>,
    /// Lowercased filter text ("" when not filtering); marks matching rows.
    pub filter_text_lower: &'a str,
    /// Deepest level rendered (guards against parent cycles).
    pub max_depth: usize,
    pub sort: GroupSort,
    pub sort_desc: bool,
}

/// Inputs for the grouped view besides the snapshot and metrics.
#[derive(Clone, Copy)]
pub struct GroupedOptions<'a> {
    pub selected_pid: Option<u32>,
    /// Lowercased filter text ("" when not filtering).
    pub filter_text_lower: &'a str,
    pub sort: GroupSort,
    pub sort_desc: bool,
    /// Sort groups by their top member ("leader") instead of the group aggregate.
    pub sort_by_leader: bool,
}

/// PIDs the tree shows for a filter: matching processes (name or PID), all their
/// ancestors (so they stay reachable from a root), and their direct children for context.
/// Returns `None` when `filter_text_lower` is empty.
pub fn filter_visible_pids(
    snapshot: &ProcessSnapshot,
    filter_text_lower: &str,
) -> Option<HashSet<u32>> {
    const MAX_DEPTH: usize = 128;
    if filter_text_lower.is_empty() {
        return None;
    }
    let matching: Vec<u32> = snapshot
        .processes
        .iter()
        .filter(|p| {
            snapshot.lower_name(p.pid).contains(filter_text_lower)
                || sort::pid_contains(p.pid, filter_text_lower)
        })
        .map(|p| p.pid)
        .collect();

    let mut visible: HashSet<u32> = matching.iter().copied().collect();
    let mut seen = HashSet::new();
    for &pid in &matching {
        // Walk up to the root, with cycle and depth protection.
        let mut current = pid;
        seen.clear();
        let mut depth = 0;
        while depth < MAX_DEPTH && seen.insert(current) {
            match snapshot.get_process(current).and_then(|p| p.ppid) {
                Some(parent) if parent != 0 && parent != current => {
                    visible.insert(parent);
                    current = parent;
                    depth += 1;
                }
                _ => break,
            }
        }
    }
    let children = &snapshot.view_index().children;
    for pid in &matching {
        if let Some(kids) = children.get(pid) {
            visible.extend(kids.iter().copied());
        }
    }
    Some(visible)
}

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
    /// e.g. "explorer.exe (8860)"; shared with the snapshot, so cloning rows is cheap.
    pub label: std::sync::Arc<str>,
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
    /// PID -> executable path (resolved lazily by the UI; `Process::path` is usually unset).
    pub pid_to_image_path: &'a HashMap<u32, String>,
}
