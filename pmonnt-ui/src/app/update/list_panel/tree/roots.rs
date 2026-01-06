use std::collections::{HashMap, HashSet};

use pmonnt_core::process;

use crate::app::PMonNTApp;
use crate::process_rows::compare_tree_pids;

pub(super) fn compute_sorted_roots(
    app: &PMonNTApp,
    pid_set: &HashSet<u32>,
    pid_to_proc: &HashMap<u32, &process::Process>,
    visible_pids: Option<&HashSet<u32>>,
) -> Vec<u32> {
    // Find root PIDs: ppid is None, ppid is 0, or parent not in pid_set
    // Exclude PID 0 itself (it's not a real process)
    let mut roots: Vec<u32> = app
        .current_snapshot
        .processes
        .iter()
        .filter(|p| p.pid != 0) // Never render PID 0
        .filter(|p| match p.ppid {
            None => true,
            Some(0) => true,
            Some(parent) => !pid_set.contains(&parent),
        })
        .map(|p| p.pid)
        .collect();

    // Filter roots if filter is active
    if let Some(visible) = visible_pids {
        roots.retain(|pid| visible.contains(pid));
    }

    // Deduplicate and sort roots based on current sort mode
    roots.sort_by(|&a, &b| {
        compare_tree_pids(
            a,
            b,
            app.group_sort,
            app.sort_desc,
            pid_to_proc,
            &app.handle_cache,
            &app.global_thread_counts,
            &app.cpu_memory_data,
            &app.io_rate_by_pid,
            &app.gpu_data,
            &app.signature_cache_by_path,
        )
    });
    roots.dedup();

    roots
}
