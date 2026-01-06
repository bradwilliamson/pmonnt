use pmonnt_core::{handles::HandleCache, process, win_process_metrics::IoRate};
use std::collections::{HashMap, HashSet};

use crate::view::{GroupSort, ProcRow};

/// Build a flattened list of visible rows for virtualized rendering
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_process_rows(
    roots: &[u32],
    children: &HashMap<u32, Vec<u32>>,
    pid_to_proc: &HashMap<u32, &process::Process>,
    expanded: &HashSet<u32>,
    selected_pid: Option<u32>,
    visible_pids: Option<&HashSet<u32>>,
    filter_text_lower: &str,
    max_depth: usize,
    group_sort: GroupSort,
    sort_desc: bool,
    handle_cache: &HandleCache,
    global_thread_counts: &HashMap<u32, usize>,
    cpu_memory_data: &HashMap<u32, (f32, Option<u64>)>,
    io_rate_by_pid: &HashMap<u32, IoRate>,
    gpu_data: &HashMap<u32, (f32, u64, u64, u64)>,
    signature_cache_by_path: &HashMap<String, pmonnt_core::SignatureInfo>,
) -> Vec<ProcRow> {
    let mut rows = Vec::new();
    let mut visited = HashSet::new();

    for &root_pid in roots {
        build_rows_recursive(
            root_pid,
            children,
            pid_to_proc,
            expanded,
            selected_pid,
            visible_pids,
            filter_text_lower,
            0,
            max_depth,
            &mut visited,
            &mut rows,
            group_sort,
            sort_desc,
            handle_cache,
            global_thread_counts,
            cpu_memory_data,
            io_rate_by_pid,
            gpu_data,
            signature_cache_by_path,
        );
    }

    rows
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn compare_tree_pids(
    a: u32,
    b: u32,
    group_sort: GroupSort,
    sort_desc: bool,
    pid_to_proc: &HashMap<u32, &process::Process>,
    handle_cache: &HandleCache,
    global_thread_counts: &HashMap<u32, usize>,
    cpu_memory_data: &HashMap<u32, (f32, Option<u64>)>,
    io_rate_by_pid: &HashMap<u32, IoRate>,
    gpu_data: &HashMap<u32, (f32, u64, u64, u64)>,
    signature_cache_by_path: &HashMap<String, pmonnt_core::SignatureInfo>,
) -> std::cmp::Ordering {
    let name_a = pid_to_proc.get(&a).map(|p| p.name.as_str()).unwrap_or("");
    let name_b = pid_to_proc.get(&b).map(|p| p.name.as_str()).unwrap_or("");

    let lower_a = name_a.to_lowercase();
    let lower_b = name_b.to_lowercase();

    let ord = match group_sort {
        GroupSort::Name => {
            let base = lower_a.cmp(&lower_b).then(a.cmp(&b));
            if sort_desc {
                base.reverse()
            } else {
                base
            }
        }
        GroupSort::PID => {
            let base = a.cmp(&b).then(lower_a.cmp(&lower_b));
            if sort_desc {
                base.reverse()
            } else {
                base
            }
        }
        GroupSort::Handles => {
            let ha = handle_cache.get(a).map(|s| s.total);
            let hb = handle_cache.get(b).map(|s| s.total);
            match (ha, hb) {
                (Some(va), Some(vb)) => {
                    let base = va.cmp(&vb);
                    let ord = if sort_desc { base.reverse() } else { base };
                    if ord == std::cmp::Ordering::Equal {
                        a.cmp(&b).then(lower_a.cmp(&lower_b))
                    } else {
                        ord
                    }
                }
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.cmp(&b).then(lower_a.cmp(&lower_b)),
            }
        }
        GroupSort::Threads => {
            let ta = global_thread_counts.get(&a).copied();
            let tb = global_thread_counts.get(&b).copied();
            match (ta, tb) {
                (Some(va), Some(vb)) => {
                    let base = va.cmp(&vb);
                    let ord = if sort_desc { base.reverse() } else { base };
                    if ord == std::cmp::Ordering::Equal {
                        a.cmp(&b).then(lower_a.cmp(&lower_b))
                    } else {
                        ord
                    }
                }
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.cmp(&b).then(lower_a.cmp(&lower_b)),
            }
        }
        GroupSort::CPU => {
            let ca = cpu_memory_data.get(&a).map(|(cpu, _)| *cpu);
            let cb = cpu_memory_data.get(&b).map(|(cpu, _)| *cpu);
            match (ca, cb) {
                (Some(va), Some(vb)) => {
                    let base = va.partial_cmp(&vb).unwrap_or(std::cmp::Ordering::Equal);
                    let ord = if sort_desc { base.reverse() } else { base };
                    if ord == std::cmp::Ordering::Equal {
                        a.cmp(&b).then(lower_a.cmp(&lower_b))
                    } else {
                        ord
                    }
                }
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.cmp(&b).then(lower_a.cmp(&lower_b)),
            }
        }
        GroupSort::Memory => {
            let ma = cpu_memory_data.get(&a).and_then(|(_, mem)| *mem);
            let mb = cpu_memory_data.get(&b).and_then(|(_, mem)| *mem);
            match (ma, mb) {
                (Some(va), Some(vb)) => {
                    let base = va.cmp(&vb);
                    let ord = if sort_desc { base.reverse() } else { base };
                    if ord == std::cmp::Ordering::Equal {
                        a.cmp(&b).then(lower_a.cmp(&lower_b))
                    } else {
                        ord
                    }
                }
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.cmp(&b).then(lower_a.cmp(&lower_b)),
            }
        }
        GroupSort::Disk => {
            let da = io_rate_by_pid
                .get(&a)
                .map(|r| r.read_bytes_per_sec + r.write_bytes_per_sec);
            let db = io_rate_by_pid
                .get(&b)
                .map(|r| r.read_bytes_per_sec + r.write_bytes_per_sec);
            match (da, db) {
                (Some(va), Some(vb)) => {
                    let base = va.partial_cmp(&vb).unwrap_or(std::cmp::Ordering::Equal);
                    let ord = if sort_desc { base.reverse() } else { base };
                    if ord == std::cmp::Ordering::Equal {
                        a.cmp(&b).then(lower_a.cmp(&lower_b))
                    } else {
                        ord
                    }
                }
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.cmp(&b).then(lower_a.cmp(&lower_b)),
            }
        }
        GroupSort::GPU => {
            let ga = gpu_data.get(&a).map(|(pct, _, _, _)| *pct);
            let gb = gpu_data.get(&b).map(|(pct, _, _, _)| *pct);
            match (ga, gb) {
                (Some(va), Some(vb)) => {
                    let base = va.partial_cmp(&vb).unwrap_or(std::cmp::Ordering::Equal);
                    let ord = if sort_desc { base.reverse() } else { base };
                    if ord == std::cmp::Ordering::Equal {
                        a.cmp(&b).then(lower_a.cmp(&lower_b))
                    } else {
                        ord
                    }
                }
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.cmp(&b).then(lower_a.cmp(&lower_b)),
            }
        }
        GroupSort::GPUMemory => {
            let ga = gpu_data.get(&a).map(|(_, _, _, total)| *total);
            let gb = gpu_data.get(&b).map(|(_, _, _, total)| *total);
            match (ga, gb) {
                (Some(va), Some(vb)) => {
                    let base = va.cmp(&vb);
                    let ord = if sort_desc { base.reverse() } else { base };
                    if ord == std::cmp::Ordering::Equal {
                        a.cmp(&b).then(lower_a.cmp(&lower_b))
                    } else {
                        ord
                    }
                }
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.cmp(&b).then(lower_a.cmp(&lower_b)),
            }
        }
        GroupSort::VerifiedSigner => {
            fn sig_sort_key(
                pid: u32,
                pid_to_proc: &HashMap<u32, &process::Process>,
                signature_cache_by_path: &HashMap<String, pmonnt_core::SignatureInfo>,
            ) -> (u8, String) {
                let Some(proc) = pid_to_proc.get(&pid) else {
                    return (5, String::new());
                };
                let Some(ref path) = proc.path else {
                    return (5, String::new());
                };
                let Some(info) = signature_cache_by_path.get(path) else {
                    return (4, String::new());
                };

                match info.status() {
                    pmonnt_core::SignatureStatus::Valid => (
                        0,
                        info.signer_name
                            .clone()
                            .unwrap_or_else(|| "verified".to_string())
                            .to_lowercase(),
                    ),
                    pmonnt_core::SignatureStatus::CatalogSigned => (
                        1,
                        info.signer_name
                            .clone()
                            .unwrap_or_else(|| "verified (catalog)".to_string())
                            .to_lowercase(),
                    ),
                    pmonnt_core::SignatureStatus::NotSigned => (3, "not signed".to_string()),
                    pmonnt_core::SignatureStatus::Untrusted => (2, "untrusted".to_string()),
                    pmonnt_core::SignatureStatus::Expired => (2, "expired".to_string()),
                    pmonnt_core::SignatureStatus::Invalid => (2, "invalid".to_string()),
                }
            }

            let ka = sig_sort_key(a, pid_to_proc, signature_cache_by_path);
            let kb = sig_sort_key(b, pid_to_proc, signature_cache_by_path);
            let base = ka.cmp(&kb).then(lower_a.cmp(&lower_b)).then(a.cmp(&b));
            if sort_desc {
                base.reverse()
            } else {
                base
            }
        }
    };

    if ord == std::cmp::Ordering::Equal {
        // Always keep deterministic ordering.
        a.cmp(&b).then(lower_a.cmp(&lower_b))
    } else {
        ord
    }
}

#[allow(clippy::too_many_arguments)]
fn build_rows_recursive(
    pid: u32,
    children: &HashMap<u32, Vec<u32>>,
    pid_to_proc: &HashMap<u32, &process::Process>,
    expanded: &HashSet<u32>,
    selected_pid: Option<u32>,
    visible_pids: Option<&HashSet<u32>>,
    filter_text_lower: &str,
    depth: usize,
    max_depth: usize,
    visited: &mut HashSet<u32>,
    rows: &mut Vec<ProcRow>,
    group_sort: GroupSort,
    sort_desc: bool,
    handle_cache: &HandleCache,
    global_thread_counts: &HashMap<u32, usize>,
    cpu_memory_data: &HashMap<u32, (f32, Option<u64>)>,
    io_rate_by_pid: &HashMap<u32, IoRate>,
    gpu_data: &HashMap<u32, (f32, u64, u64, u64)>,
    signature_cache_by_path: &HashMap<String, pmonnt_core::SignatureInfo>,
) {
    // Prevent cycles and stack overflow
    if visited.contains(&pid) || depth >= max_depth {
        return;
    }
    visited.insert(pid);

    // Skip PID 0
    if pid == 0 {
        return;
    }

    // Skip if filtered out
    if let Some(visible) = visible_pids {
        if !visible.contains(&pid) {
            return;
        }
    }

    // Get process info
    let proc = match pid_to_proc.get(&pid) {
        Some(p) => *p,
        None => return,
    };

    // Check if this process matches the filter
    let is_match = if !filter_text_lower.is_empty() {
        proc.name.to_lowercase().contains(filter_text_lower)
            || proc.pid.to_string().contains(filter_text_lower)
    } else {
        false
    };

    // Check if this node has children
    let child_pids = children.get(&pid);
    let has_children = child_pids.map(|c| !c.is_empty()).unwrap_or(false);
    let is_expanded = expanded.contains(&pid);
    let is_selected = selected_pid == Some(pid);

    let label = format!("{} ({})", proc.name, proc.pid);

    rows.push(ProcRow {
        pid,
        depth,
        has_children,
        is_expanded,
        is_match,
        is_selected,
        label,
    });

    // Render children if expanded
    if is_expanded && depth < max_depth {
        if let Some(child_pids) = child_pids {
            // Sort children by current mode
            let mut sorted_children: Vec<u32> = child_pids.to_vec();
            sorted_children.sort_by(|&a, &b| {
                compare_tree_pids(
                    a,
                    b,
                    group_sort,
                    sort_desc,
                    pid_to_proc,
                    handle_cache,
                    global_thread_counts,
                    cpu_memory_data,
                    io_rate_by_pid,
                    gpu_data,
                    signature_cache_by_path,
                )
            });

            for &child_pid in &sorted_children {
                build_rows_recursive(
                    child_pid,
                    children,
                    pid_to_proc,
                    expanded,
                    selected_pid,
                    visible_pids,
                    filter_text_lower,
                    depth + 1,
                    max_depth,
                    visited,
                    rows,
                    group_sort,
                    sort_desc,
                    handle_cache,
                    global_thread_counts,
                    cpu_memory_data,
                    io_rate_by_pid,
                    gpu_data,
                    signature_cache_by_path,
                );
            }
        }
    }
}
