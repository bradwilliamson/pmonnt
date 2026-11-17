//! Tree view rows.

use crate::snapshot::ProcessSnapshot;

use super::sort::{Handles, pid_contains, sort_tree_pids};
use super::{ProcRow, RowMetrics, TreeOptions};

/// Root PIDs of the tree, filtered to `visible` and sorted by the current sort mode.
pub fn sorted_roots(
    snapshot: &ProcessSnapshot,
    opts: &TreeOptions<'_>,
    metrics: &RowMetrics<'_>,
) -> Vec<u32> {
    let handles = metrics.handle_cache.fresh_summaries();
    sorted_roots_with(snapshot, opts, metrics, handles)
}

fn sorted_roots_with(
    snapshot: &ProcessSnapshot,
    opts: &TreeOptions<'_>,
    metrics: &RowMetrics<'_>,
    handles: Handles<'_>,
) -> Vec<u32> {
    let mut roots = snapshot.view_index().roots.clone();
    if let Some(visible) = opts.visible_pids {
        roots.retain(|pid| visible.contains(pid));
    }
    sort_tree_pids(
        &mut roots,
        snapshot,
        opts.sort,
        opts.sort_desc,
        metrics,
        handles,
    );
    roots.dedup();
    roots
}

/// Build the flattened, virtualized row list for the tree view: sorted roots, then each
/// expanded node's children in sort order, depth-first.
pub fn build_process_rows(
    snapshot: &ProcessSnapshot,
    opts: &TreeOptions<'_>,
    metrics: &RowMetrics<'_>,
) -> Vec<ProcRow> {
    let handles = metrics.handle_cache.fresh_summaries();
    let roots = sorted_roots_with(snapshot, opts, metrics, handles);
    let mut walk = Walk {
        snapshot,
        opts,
        metrics,
        handles,
        visited: vec![false; snapshot.len()],
        rows: Vec::with_capacity(snapshot.len()),
    };
    for root in roots {
        walk.visit(root, 0);
    }
    walk.rows
}

struct Walk<'a, 'm> {
    snapshot: &'a ProcessSnapshot,
    opts: &'a TreeOptions<'a>,
    metrics: &'a RowMetrics<'m>,
    handles: Handles<'m>,
    /// Indexed by position in `snapshot.processes` (every PID reached is in the snapshot).
    visited: Vec<bool>,
    rows: Vec<ProcRow>,
}

impl Walk<'_, '_> {
    fn visit(&mut self, pid: u32, depth: usize) {
        let opts = self.opts;
        // Prevent cycles and runaway depth. (Marked visited before the PID 0 / filter checks,
        // as before.) Roots and children all come from the snapshot, so `index_of` succeeds.
        if depth >= opts.max_depth {
            return;
        }
        let Some(idx) = self.snapshot.index_of(pid) else {
            return;
        };
        if std::mem::replace(&mut self.visited[idx], true) {
            return;
        }
        if pid == 0 {
            return;
        }
        if let Some(visible) = opts.visible_pids
            && !visible.contains(&pid)
        {
            return;
        }
        let is_match = !opts.filter_text_lower.is_empty()
            && (view_lower(self.snapshot, idx).contains(opts.filter_text_lower)
                || pid_contains(pid, opts.filter_text_lower));

        let view = self.snapshot.view_index();
        let child_pids = view.children.get(&pid);
        let has_children = child_pids.is_some_and(|c| !c.is_empty());
        let is_expanded = opts.expanded.contains(&pid);

        self.rows.push(ProcRow {
            pid,
            depth,
            has_children,
            is_expanded,
            is_match,
            is_selected: opts.selected_pid == Some(pid),
            label: view.labels[idx].clone(),
        });

        if is_expanded
            && depth < opts.max_depth
            && let Some(child_pids) = child_pids
        {
            let mut sorted = child_pids.clone();
            sort_tree_pids(
                &mut sorted,
                self.snapshot,
                opts.sort,
                opts.sort_desc,
                self.metrics,
                self.handles,
            );
            for child in sorted {
                self.visit(child, depth + 1);
            }
        }
    }
}

fn view_lower(snapshot: &ProcessSnapshot, idx: usize) -> &str {
    &snapshot.view_index().lower_names[idx]
}
