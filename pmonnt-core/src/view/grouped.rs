//! Grouped (Task Manager style) view rows.

use std::cmp::Ordering;

use crate::snapshot::{NameGroup, ProcessSnapshot};

use super::sort::{Handles, metric_value, num, pid_contains, signer_key};
use super::{GroupSort, GroupedOptions, GroupedRow, RowMetrics};

/// Per-group sort key, computed once per group per frame.
struct Keyed<'s> {
    group: &'s NameGroup,
    /// Leader mode: value and PID of the member with the highest value.
    leader: Option<f64>,
    leader_pid: Option<u32>,
    /// Aggregate value (sum, or max for GPU %); `None` only when no member has data and
    /// the mode distinguishes that (handles).
    agg: Option<f64>,
    min_pid: u32,
}

/// Build grouped rows for the Task Manager-style view (flat, no collapsing).
pub fn build_grouped_rows(
    snapshot: &ProcessSnapshot,
    opts: &GroupedOptions<'_>,
    metrics: &RowMetrics<'_>,
) -> Vec<GroupedRow> {
    let handles = metrics.handle_cache.fresh_summaries();
    let groups = &snapshot.view_index().groups;

    let mut keyed: Vec<Keyed<'_>> = groups
        .iter()
        .map(|g| key_group(g, opts, metrics, handles))
        .collect();
    sort_groups(&mut keyed, opts);

    let filter = opts.filter_text_lower;
    let mut rows = Vec::with_capacity(keyed.len());
    for k in &keyed {
        let group = k.group;
        let group_matches = !filter.is_empty() && group.lower_name.contains(filter);
        if !filter.is_empty()
            && !group_matches
            && !group.pids.iter().any(|&pid| pid_contains(pid, filter))
        {
            continue;
        }

        let mut pids = group.pids.clone();
        pids.sort_unstable();
        rows.push(aggregate_row(
            snapshot,
            group,
            pids,
            group_matches,
            opts.selected_pid,
            metrics,
            handles,
        ));
    }

    if opts.sort == GroupSort::VerifiedSigner {
        // Cache-only signature lookups, so sorting never triggers verification work.
        let mut decorated: Vec<((u8, String), String, GroupedRow)> = rows
            .into_iter()
            .map(|row| {
                let key = signer_key(row.image_path.as_ref(), metrics.signature_cache_by_path);
                let lower = crate::snapshot::lowercase(&row.name);
                (key, lower, row)
            })
            .collect();
        decorated.sort_by(|(ka, la, _), (kb, lb, _)| {
            let base = ka.cmp(kb).then_with(|| la.cmp(lb));
            if opts.sort_desc { base.reverse() } else { base }
        });
        rows = decorated.into_iter().map(|(_, _, row)| row).collect();
    }

    rows
}

fn key_group<'s>(
    group: &'s NameGroup,
    opts: &GroupedOptions<'_>,
    metrics: &RowMetrics<'_>,
    handles: Handles<'_>,
) -> Keyed<'s> {
    let pids = &group.pids;
    let min_pid = pids.iter().copied().min().unwrap_or(u32::MAX);
    let mut k = Keyed {
        group,
        leader: None,
        leader_pid: None,
        agg: None,
        min_pid,
    };

    if opts.sort_by_leader {
        let sort = match opts.sort {
            GroupSort::Name | GroupSort::VerifiedSigner => GroupSort::CPU,
            other => other,
        };
        if sort == GroupSort::PID {
            // Leader for PID = highest PID in the group.
            let max = pids.iter().copied().max();
            k.leader = max.map(f64::from);
            k.leader_pid = max;
            return k;
        }
        let mut best: Option<(f64, u32)> = None;
        let mut agg: Option<f64> = if sort == GroupSort::Handles {
            None
        } else {
            Some(0.0)
        };
        for &pid in pids {
            let Some(v) = metric_value(pid, sort, metrics, handles) else {
                continue;
            };
            agg = Some(match (sort, agg) {
                (GroupSort::GPU, a) => a.unwrap_or(0.0).max(v),
                (_, a) => a.unwrap_or(0.0) + v,
            });
            if best.is_none_or(|(b, _)| v > b) {
                best = Some((v, pid));
            }
        }
        k.leader = best.map(|(v, _)| v);
        k.leader_pid = best.map(|(_, pid)| pid);
        k.agg = agg.and_then(num);
        return k;
    }

    // Aggregate mode. Sums use each metric's native type, accumulated in enumeration
    // order, so values (and therefore ties) match the per-row totals users see.
    k.agg = match opts.sort {
        GroupSort::CPU => {
            let sum: f32 = pids
                .iter()
                .filter_map(|p| metrics.cpu_memory_data.get(p).map(|(c, _)| *c))
                .sum();
            num(f64::from(sum))
        }
        GroupSort::Memory => {
            let sum: u64 = pids
                .iter()
                .filter_map(|p| metrics.cpu_memory_data.get(p).and_then(|(_, m)| *m))
                .sum();
            Some(sum as f64)
        }
        GroupSort::Disk => {
            let sum: f64 = pids
                .iter()
                .filter_map(|p| metrics.io_rate_by_pid.get(p))
                .map(|r| r.read_bytes_per_sec + r.write_bytes_per_sec)
                .sum();
            num(sum)
        }
        GroupSort::GPU => {
            let max = pids
                .iter()
                .filter_map(|p| metrics.gpu_data.get(p).map(|(pct, ..)| *pct))
                .fold(0.0_f32, f32::max);
            num(f64::from(max))
        }
        GroupSort::GPUMemory => {
            let sum: u64 = pids
                .iter()
                .filter_map(|p| metrics.gpu_data.get(p).map(|(.., total)| *total))
                .sum();
            Some(sum as f64)
        }
        GroupSort::Threads => {
            let sum: usize = pids
                .iter()
                .filter_map(|p| metrics.global_thread_counts.get(p))
                .sum();
            Some(sum as f64)
        }
        GroupSort::Handles => {
            let mut total: u32 = 0;
            let mut any = false;
            for p in pids {
                if let Some(s) = handles.and_then(|m| m.get(p)) {
                    total = total.saturating_add(s.total);
                    any = true;
                }
            }
            any.then_some(f64::from(total))
        }
        GroupSort::Name | GroupSort::PID | GroupSort::VerifiedSigner => None,
    };
    k
}

fn sort_groups(keyed: &mut [Keyed<'_>], opts: &GroupedOptions<'_>) {
    let desc = opts.sort_desc;
    let flip = |o: Ordering| if desc { o.reverse() } else { o };
    let name = |a: &Keyed<'_>, b: &Keyed<'_>| a.group.lower_name.cmp(&b.group.lower_name);
    // Final tie-break on the exact name keeps the order deterministic when two groups differ
    // only in case.
    let exact = |a: &Keyed<'_>, b: &Keyed<'_>| a.group.name.cmp(&b.group.name);

    if opts.sort_by_leader {
        keyed.sort_by(|a, b| {
            let lead = match (a.leader, b.leader) {
                (Some(x), Some(y)) => flip(x.total_cmp(&y)),
                // No data sorts last when descending, first when ascending.
                (Some(_), None) => flip(Ordering::Greater),
                (None, Some(_)) => flip(Ordering::Less),
                (None, None) => Ordering::Equal,
            };
            let agg = || match (a.agg, b.agg) {
                (Some(x), Some(y)) => flip(x.total_cmp(&y)),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            };
            lead.then_with(agg)
                .then_with(|| name(a, b))
                .then_with(|| {
                    a.leader_pid
                        .unwrap_or(u32::MAX)
                        .cmp(&b.leader_pid.unwrap_or(u32::MAX))
                })
                .then_with(|| exact(a, b))
        });
        return;
    }

    match opts.sort {
        // Rows are re-sorted by signer afterwards; order by name first.
        GroupSort::VerifiedSigner => keyed.sort_by(|a, b| name(a, b).then_with(|| exact(a, b))),
        GroupSort::Name => keyed.sort_by(|a, b| {
            flip(name(a, b))
                .then(a.min_pid.cmp(&b.min_pid))
                .then_with(|| name(a, b))
                .then_with(|| exact(a, b))
        }),
        GroupSort::PID => keyed.sort_by(|a, b| {
            flip(a.min_pid.cmp(&b.min_pid))
                .then_with(|| name(a, b))
                .then_with(|| exact(a, b))
        }),
        _ => keyed.sort_by(|a, b| {
            let primary = match (a.agg, b.agg) {
                (Some(x), Some(y)) => flip(x.total_cmp(&y)),
                // Groups with data come first in both directions.
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            };
            primary
                .then(a.min_pid.cmp(&b.min_pid))
                .then_with(|| name(a, b))
                .then_with(|| exact(a, b))
        }),
    }
}

fn aggregate_row(
    snapshot: &ProcessSnapshot,
    group: &NameGroup,
    pids: Vec<u32>,
    is_match: bool,
    selected_pid: Option<u32>,
    metrics: &RowMetrics<'_>,
    handles: Handles<'_>,
) -> GroupedRow {
    // Representative: the lowest PID whose parent is outside the group (the group's root).
    let representative_pid = pids
        .iter()
        .copied()
        .find(|&pid| {
            snapshot
                .get_process(pid)
                .and_then(|p| p.ppid)
                .is_none_or(|ppid| pids.binary_search(&ppid).is_err())
        })
        .unwrap_or(pids[0]);

    let mut row = GroupedRow {
        name: group.name.clone(),
        count: pids.len(),
        is_match,
        is_selected: selected_pid.is_some_and(|s| pids.contains(&s)),
        representative_pid,
        total_handles: 0,
        handles_any_available: false,
        handles_all_available: true,
        thread_count: 0,
        cpu_percent: 0.0,
        memory_bytes: None,
        disk_bytes_per_sec: 0.0,
        gpu_percent: 0.0,
        gpu_dedicated_bytes: 0,
        gpu_shared_bytes: 0,
        gpu_total_bytes: 0,
        member_pids: Vec::new(),
        image_path: metrics.pid_to_image_path.get(&representative_pid).cloned(),
    };

    let mut total_memory: u64 = 0;
    let mut any_memory = false;
    for &pid in &pids {
        match handles.and_then(|m| m.get(&pid)) {
            Some(summary) => {
                row.total_handles = row.total_handles.saturating_add(summary.total);
                row.handles_any_available = true;
            }
            None => row.handles_all_available = false,
        }
        if let Some(&count) = metrics.global_thread_counts.get(&pid) {
            row.thread_count += count;
        }
        if let Some((cpu, mem)) = metrics.cpu_memory_data.get(&pid) {
            row.cpu_percent += cpu;
            if let Some(mem) = mem {
                total_memory = total_memory.saturating_add(*mem);
                any_memory = true;
            }
        }
        if let Some(r) = metrics.io_rate_by_pid.get(&pid) {
            row.disk_bytes_per_sec += r.read_bytes_per_sec + r.write_bytes_per_sec;
        }
        if let Some((pct, dedicated, shared, total)) = metrics.gpu_data.get(&pid) {
            row.gpu_percent = row.gpu_percent.max(*pct);
            row.gpu_dedicated_bytes += dedicated;
            row.gpu_shared_bytes += shared;
            row.gpu_total_bytes += total;
        }
    }
    row.memory_bytes = any_memory.then_some(total_memory);
    row.member_pids = pids;
    row
}
