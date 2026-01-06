use pmonnt_core::{handles::HandleCache, process, win_process_metrics::IoRate};
use std::collections::{HashMap, HashSet};

use crate::view::{GroupSort, GroupedRow};

/// Build grouped rows for Task Manager-style view (flat, no collapsing)
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_grouped_rows(
    processes: &[process::Process],
    selected_pid: Option<u32>,
    filter_text_lower: &str,
    group_sort: GroupSort,
    sort_desc: bool,
    sort_by_leader: bool,
    handle_cache: &HandleCache,
    global_thread_counts: &HashMap<u32, usize>,
    cpu_memory_data: &HashMap<u32, (f32, Option<u64>)>,
    io_rate_by_pid: &HashMap<u32, IoRate>,
    gpu_data: &HashMap<u32, (f32, u64, u64, u64)>,
    pid_to_image_path: &HashMap<u32, String>,
    signature_cache_by_path: &HashMap<String, pmonnt_core::SignatureInfo>,
    pid_to_command_line: &HashMap<u32, String>,
    pid_to_company_name: &HashMap<u32, String>,
    pid_to_file_description: &HashMap<u32, String>,
    pid_to_integrity_level: &HashMap<u32, String>,
    pid_to_user: &HashMap<u32, String>,
    pid_to_session_id: &HashMap<u32, u32>,
) -> Vec<GroupedRow> {
    let mut rows = Vec::new();

    // Group processes by executable name
    let mut groups: HashMap<String, Vec<u32>> = HashMap::new();
    for proc in processes {
        if proc.pid == 0 {
            continue; // Skip system idle
        }
        if proc.name.trim().is_empty() {
            continue; // Skip processes with empty names
        }
        groups.entry(proc.name.clone()).or_default().push(proc.pid);
    }

    // Convert to sorted vec of (name, pids)
    let mut group_list: Vec<(String, Vec<u32>)> = groups.into_iter().collect();

    // Leader-based sorting (Grouped view):
    // - Leader = child process within the group with the highest value for the active sort metric.
    // - Missing leader values are treated as "no data" (None). None sorts last for descending and
    //   first for ascending (consistent rule).
    // - Tie-breakers (stable): group aggregate value (if available), then group name, then PID.
    if sort_by_leader {
        let leader_sort = match group_sort {
            GroupSort::Name | GroupSort::VerifiedSigner => GroupSort::CPU,
            other => other,
        };
        let name_key = |name: &str| name.to_lowercase();

        // Returns (leader_value, leader_pid, aggregate_value).
        // Values are normalized to f64 for comparisons.
        let leader_and_agg = |pids: &[u32]| -> (Option<f64>, Option<u32>, Option<f64>) {
            match leader_sort {
                GroupSort::CPU => {
                    let mut leader: Option<(f64, u32)> = None;
                    let mut agg: f64 = 0.0;
                    for pid in pids {
                        if let Some((cpu, _)) = cpu_memory_data.get(pid) {
                            let v = *cpu as f64;
                            agg += v;
                            if leader.map(|(best, _)| v > best).unwrap_or(true) {
                                leader = Some((v, *pid));
                            }
                        }
                    }
                    (
                        leader.map(|(v, _)| v),
                        leader.map(|(_, pid)| pid),
                        Some(agg),
                    )
                }
                GroupSort::Memory => {
                    let mut leader: Option<(f64, u32)> = None;
                    let mut agg: f64 = 0.0;
                    for pid in pids {
                        if let Some((_, Some(mem))) = cpu_memory_data.get(pid) {
                            let v = *mem as f64;
                            agg += v;
                            if leader.map(|(best, _)| v > best).unwrap_or(true) {
                                leader = Some((v, *pid));
                            }
                        }
                    }
                    (
                        leader.map(|(v, _)| v),
                        leader.map(|(_, pid)| pid),
                        Some(agg),
                    )
                }
                GroupSort::Disk => {
                    let mut leader: Option<(f64, u32)> = None;
                    let mut agg: f64 = 0.0;
                    for pid in pids {
                        if let Some(r) = io_rate_by_pid.get(pid) {
                            let v = r.read_bytes_per_sec + r.write_bytes_per_sec;
                            agg += v;
                            if leader.map(|(best, _)| v > best).unwrap_or(true) {
                                leader = Some((v, *pid));
                            }
                        }
                    }
                    (
                        leader.map(|(v, _)| v),
                        leader.map(|(_, pid)| pid),
                        Some(agg),
                    )
                }
                GroupSort::GPU => {
                    let mut leader: Option<(f64, u32)> = None;
                    // Aggregate for GPU sort is effectively the max.
                    let mut agg: f64 = 0.0;
                    for pid in pids {
                        if let Some((pct, _, _, _)) = gpu_data.get(pid) {
                            let v = *pct as f64;
                            if v > agg {
                                agg = v;
                            }
                            if leader.map(|(best, _)| v > best).unwrap_or(true) {
                                leader = Some((v, *pid));
                            }
                        }
                    }
                    (
                        leader.map(|(v, _)| v),
                        leader.map(|(_, pid)| pid),
                        Some(agg),
                    )
                }
                GroupSort::GPUMemory => {
                    let mut leader: Option<(f64, u32)> = None;
                    let mut agg: f64 = 0.0;
                    for pid in pids {
                        if let Some((_, _, _, total)) = gpu_data.get(pid) {
                            let v = *total as f64;
                            agg += v;
                            if leader.map(|(best, _)| v > best).unwrap_or(true) {
                                leader = Some((v, *pid));
                            }
                        }
                    }
                    (
                        leader.map(|(v, _)| v),
                        leader.map(|(_, pid)| pid),
                        Some(agg),
                    )
                }
                GroupSort::Handles => {
                    let mut leader: Option<(f64, u32)> = None;
                    let mut agg: Option<f64> = None;
                    for pid in pids {
                        if let Some(summary) = handle_cache.get(*pid) {
                            let v = summary.total as f64;
                            agg = Some(agg.unwrap_or(0.0) + v);
                            if leader.map(|(best, _)| v > best).unwrap_or(true) {
                                leader = Some((v, *pid));
                            }
                        }
                    }
                    (leader.map(|(v, _)| v), leader.map(|(_, pid)| pid), agg)
                }
                GroupSort::Threads => {
                    let mut leader: Option<(f64, u32)> = None;
                    let mut agg: f64 = 0.0;
                    for pid in pids {
                        if let Some(count) = global_thread_counts.get(pid) {
                            let v = *count as f64;
                            agg += v;
                            if leader.map(|(best, _)| v > best).unwrap_or(true) {
                                leader = Some((v, *pid));
                            }
                        }
                    }
                    (
                        leader.map(|(v, _)| v),
                        leader.map(|(_, pid)| pid),
                        Some(agg),
                    )
                }
                GroupSort::PID => {
                    // Leader for PID = highest PID in group.
                    let max_pid = pids.iter().max().copied();
                    (max_pid.map(|p| p as f64), max_pid, None)
                }
                // For non-numeric sorts, leader isn't meaningful.
                GroupSort::Name | GroupSort::VerifiedSigner => (None, None, None),
            }
        };

        group_list.sort_by(|a, b| {
            let (leader_a, pid_a, agg_a) = leader_and_agg(&a.1);
            let (leader_b, pid_b, agg_b) = leader_and_agg(&b.1);

            let ord = match (leader_a, leader_b) {
                (Some(va), Some(vb)) => {
                    let base = va.partial_cmp(&vb).unwrap_or(std::cmp::Ordering::Equal);
                    if sort_desc {
                        base.reverse()
                    } else {
                        base
                    }
                }
                (Some(_), None) => {
                    // None last for descending, first for ascending.
                    if sort_desc {
                        std::cmp::Ordering::Less
                    } else {
                        std::cmp::Ordering::Greater
                    }
                }
                (None, Some(_)) => {
                    if sort_desc {
                        std::cmp::Ordering::Greater
                    } else {
                        std::cmp::Ordering::Less
                    }
                }
                (None, None) => std::cmp::Ordering::Equal,
            };
            if ord != std::cmp::Ordering::Equal {
                return ord;
            }

            let ord = match (agg_a, agg_b) {
                (Some(va), Some(vb)) => {
                    let base = va.partial_cmp(&vb).unwrap_or(std::cmp::Ordering::Equal);
                    if sort_desc {
                        base.reverse()
                    } else {
                        base
                    }
                }
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            };
            if ord != std::cmp::Ordering::Equal {
                return ord;
            }

            let name_ord = name_key(&a.0).cmp(&name_key(&b.0));
            if name_ord != std::cmp::Ordering::Equal {
                return name_ord;
            }

            let pid_a = pid_a.unwrap_or(u32::MAX);
            let pid_b = pid_b.unwrap_or(u32::MAX);
            pid_a.cmp(&pid_b)
        });
    } else {
        // Sort groups (existing aggregate behavior)
        match group_sort {
            GroupSort::VerifiedSigner => {
                // Build rows first, then do a cache-only sort by representative signature.
                // (Keeping this cache-only avoids triggering verification work during sorting.)
                group_list.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));
            }
            GroupSort::CPU => {
                // Sort by total CPU % across group members (sum).
                group_list.sort_by(|a, b| {
                    let cpu_a: f32 =
                        a.1.iter()
                            .filter_map(|pid| cpu_memory_data.get(pid).map(|(cpu, _)| *cpu))
                            .sum();
                    let cpu_b: f32 =
                        b.1.iter()
                            .filter_map(|pid| cpu_memory_data.get(pid).map(|(cpu, _)| *cpu))
                            .sum();

                    let base = cpu_a
                        .partial_cmp(&cpu_b)
                        .unwrap_or(std::cmp::Ordering::Equal);
                    let ord = if sort_desc { base.reverse() } else { base };
                    if ord == std::cmp::Ordering::Equal {
                        let min_a = a.1.iter().min().copied().unwrap_or(u32::MAX);
                        let min_b = b.1.iter().min().copied().unwrap_or(u32::MAX);
                        let pid_ord = min_a.cmp(&min_b);
                        if pid_ord == std::cmp::Ordering::Equal {
                            a.0.to_lowercase().cmp(&b.0.to_lowercase())
                        } else {
                            pid_ord
                        }
                    } else {
                        ord
                    }
                });
            }
            GroupSort::Memory => {
                // Sort by total memory bytes (sum).
                group_list.sort_by(|a, b| {
                    let mem_a: u64 =
                        a.1.iter()
                            .filter_map(|pid| cpu_memory_data.get(pid).and_then(|(_, mem)| *mem))
                            .sum();
                    let mem_b: u64 =
                        b.1.iter()
                            .filter_map(|pid| cpu_memory_data.get(pid).and_then(|(_, mem)| *mem))
                            .sum();
                    let base = mem_a.cmp(&mem_b);
                    let ord = if sort_desc { base.reverse() } else { base };
                    if ord == std::cmp::Ordering::Equal {
                        let min_a = a.1.iter().min().copied().unwrap_or(u32::MAX);
                        let min_b = b.1.iter().min().copied().unwrap_or(u32::MAX);
                        let pid_ord = min_a.cmp(&min_b);
                        if pid_ord == std::cmp::Ordering::Equal {
                            a.0.to_lowercase().cmp(&b.0.to_lowercase())
                        } else {
                            pid_ord
                        }
                    } else {
                        ord
                    }
                });
            }
            GroupSort::Disk => {
                // Sort by total disk bytes/sec across group members (sum of read+write).
                group_list.sort_by(|a, b| {
                    let disk_a: f64 =
                        a.1.iter()
                            .filter_map(|pid| io_rate_by_pid.get(pid))
                            .map(|r| r.read_bytes_per_sec + r.write_bytes_per_sec)
                            .sum();
                    let disk_b: f64 =
                        b.1.iter()
                            .filter_map(|pid| io_rate_by_pid.get(pid))
                            .map(|r| r.read_bytes_per_sec + r.write_bytes_per_sec)
                            .sum();

                    let base = disk_a
                        .partial_cmp(&disk_b)
                        .unwrap_or(std::cmp::Ordering::Equal);
                    let ord = if sort_desc { base.reverse() } else { base };
                    if ord == std::cmp::Ordering::Equal {
                        let min_a = a.1.iter().min().copied().unwrap_or(u32::MAX);
                        let min_b = b.1.iter().min().copied().unwrap_or(u32::MAX);
                        let pid_ord = min_a.cmp(&min_b);
                        if pid_ord == std::cmp::Ordering::Equal {
                            a.0.to_lowercase().cmp(&b.0.to_lowercase())
                        } else {
                            pid_ord
                        }
                    } else {
                        ord
                    }
                });
            }
            GroupSort::GPU => {
                // Sort by max GPU % across group members.
                group_list.sort_by(|a, b| {
                    let gpu_a: f32 =
                        a.1.iter()
                            .filter_map(|pid| gpu_data.get(pid).map(|(pct, _, _, _)| *pct))
                            .fold(0.0_f32, f32::max);
                    let gpu_b: f32 =
                        b.1.iter()
                            .filter_map(|pid| gpu_data.get(pid).map(|(pct, _, _, _)| *pct))
                            .fold(0.0_f32, f32::max);

                    let base = gpu_a
                        .partial_cmp(&gpu_b)
                        .unwrap_or(std::cmp::Ordering::Equal);
                    let ord = if sort_desc { base.reverse() } else { base };
                    if ord == std::cmp::Ordering::Equal {
                        let min_a = a.1.iter().min().copied().unwrap_or(u32::MAX);
                        let min_b = b.1.iter().min().copied().unwrap_or(u32::MAX);
                        let pid_ord = min_a.cmp(&min_b);
                        if pid_ord == std::cmp::Ordering::Equal {
                            a.0.to_lowercase().cmp(&b.0.to_lowercase())
                        } else {
                            pid_ord
                        }
                    } else {
                        ord
                    }
                });
            }
            GroupSort::Name => {
                group_list.sort_by(|a, b| {
                    let ord = a.0.to_lowercase().cmp(&b.0.to_lowercase());
                    let ord = if sort_desc { ord.reverse() } else { ord };
                    if ord == std::cmp::Ordering::Equal {
                        // Fallback: minimal PID then name
                        let min_a = a.1.iter().min().copied().unwrap_or(u32::MAX);
                        let min_b = b.1.iter().min().copied().unwrap_or(u32::MAX);
                        let pid_ord = min_a.cmp(&min_b);
                        if pid_ord == std::cmp::Ordering::Equal {
                            a.0.to_lowercase().cmp(&b.0.to_lowercase())
                        } else {
                            pid_ord
                        }
                    } else {
                        ord
                    }
                });
            }
            GroupSort::Handles => {
                // Sort by aggregated handles, None-last both directions
                group_list.sort_by(|a, b| {
                    let sum_a_opt = {
                        let mut total: u32 = 0;
                        let mut saw_any = false;
                        for pid in &a.1 {
                            if let Some(summary) = handle_cache.get(*pid) {
                                total = total.saturating_add(summary.total);
                                saw_any = true;
                            }
                        }
                        if saw_any {
                            Some(total)
                        } else {
                            None
                        }
                    };
                    let sum_b_opt = {
                        let mut total: u32 = 0;
                        let mut saw_any = false;
                        for pid in &b.1 {
                            if let Some(summary) = handle_cache.get(*pid) {
                                total = total.saturating_add(summary.total);
                                saw_any = true;
                            }
                        }
                        if saw_any {
                            Some(total)
                        } else {
                            None
                        }
                    };
                    let ord = match (sum_a_opt, sum_b_opt) {
                        (Some(va), Some(vb)) => {
                            let base = va.cmp(&vb);
                            if sort_desc {
                                base.reverse()
                            } else {
                                base
                            }
                        }
                        (Some(_), None) => std::cmp::Ordering::Less, // Some before None
                        (None, Some(_)) => std::cmp::Ordering::Greater, // None last
                        (None, None) => std::cmp::Ordering::Equal,
                    };
                    if ord == std::cmp::Ordering::Equal {
                        // Fallback: minimal PID then name
                        let min_a = a.1.iter().min().copied().unwrap_or(u32::MAX);
                        let min_b = b.1.iter().min().copied().unwrap_or(u32::MAX);
                        let pid_ord = min_a.cmp(&min_b);
                        if pid_ord == std::cmp::Ordering::Equal {
                            a.0.to_lowercase().cmp(&b.0.to_lowercase())
                        } else {
                            pid_ord
                        }
                    } else {
                        ord
                    }
                });
            }
            GroupSort::PID => {
                // Sort by minimal PID in group (proxy for representative)
                group_list.sort_by(|a, b| {
                    let min_a = a.1.iter().min().copied().unwrap_or(u32::MAX);
                    let min_b = b.1.iter().min().copied().unwrap_or(u32::MAX);
                    let base = min_a.cmp(&min_b);
                    let ord = if sort_desc { base.reverse() } else { base };
                    if ord == std::cmp::Ordering::Equal {
                        a.0.to_lowercase().cmp(&b.0.to_lowercase())
                    } else {
                        ord
                    }
                });
            }
            GroupSort::Threads => {
                // Sort by aggregated thread count
                group_list.sort_by(|a, b| {
                    let threads_a: usize =
                        a.1.iter()
                            .filter_map(|pid| global_thread_counts.get(pid))
                            .sum();
                    let threads_b: usize =
                        b.1.iter()
                            .filter_map(|pid| global_thread_counts.get(pid))
                            .sum();
                    let ord = threads_a.cmp(&threads_b);
                    let ord = if sort_desc { ord.reverse() } else { ord };
                    if ord == std::cmp::Ordering::Equal {
                        // Fallback: minimal PID then name
                        let min_a = a.1.iter().min().copied().unwrap_or(u32::MAX);
                        let min_b = b.1.iter().min().copied().unwrap_or(u32::MAX);
                        let pid_ord = min_a.cmp(&min_b);
                        if pid_ord == std::cmp::Ordering::Equal {
                            a.0.to_lowercase().cmp(&b.0.to_lowercase())
                        } else {
                            pid_ord
                        }
                    } else {
                        ord
                    }
                });
            }
            GroupSort::GPUMemory => {
                // Sort by total GPU memory
                group_list.sort_by(|a, b| {
                    let mem_a: u64 =
                        a.1.iter()
                            .filter_map(|pid| gpu_data.get(pid).map(|(_, _, _, total)| total))
                            .sum();
                    let mem_b: u64 =
                        b.1.iter()
                            .filter_map(|pid| gpu_data.get(pid).map(|(_, _, _, total)| total))
                            .sum();
                    let ord = mem_a.cmp(&mem_b);
                    let ord = if sort_desc { ord.reverse() } else { ord };
                    if ord == std::cmp::Ordering::Equal {
                        let min_a = a.1.iter().min().copied().unwrap_or(u32::MAX);
                        let min_b = b.1.iter().min().copied().unwrap_or(u32::MAX);
                        let pid_ord = min_a.cmp(&min_b);
                        if pid_ord == std::cmp::Ordering::Equal {
                            a.0.to_lowercase().cmp(&b.0.to_lowercase())
                        } else {
                            pid_ord
                        }
                    } else {
                        ord
                    }
                });
            }
        }
    }

    // Build process lookup for representative selection
    let pid_to_proc: HashMap<u32, &process::Process> =
        processes.iter().map(|p| (p.pid, p)).collect();

    // Build rows
    for (name, mut pids) in group_list {
        let count = pids.len();

        // Check if group matches filter
        let group_matches = if !filter_text_lower.is_empty() {
            name.to_lowercase().contains(filter_text_lower)
        } else {
            false
        };

        // Check if any member PID matches filter
        let member_matches: HashSet<u32> = if !filter_text_lower.is_empty() {
            pids.iter()
                .filter(|&&pid| pid.to_string().contains(filter_text_lower))
                .copied()
                .collect()
        } else {
            HashSet::new()
        };

        // Skip group if filter is active and no matches
        if !filter_text_lower.is_empty() && !group_matches && member_matches.is_empty() {
            continue;
        }

        // Find representative PID (prefer root-level process, else lowest PID)
        pids.sort();
        let pids_in_group: HashSet<u32> = pids.iter().copied().collect();
        let representative_pid = pids
            .iter()
            .copied()
            .find(|&pid| {
                // Prefer process whose parent is NOT in the same group
                if let Some(proc) = pid_to_proc.get(&pid) {
                    if let Some(ppid) = proc.ppid {
                        return !pids_in_group.contains(&ppid);
                    }
                }
                true
            })
            .unwrap_or_else(|| pids[0]);

        // Check if any member is selected
        let is_selected = pids.iter().any(|&pid| selected_pid == Some(pid));

        // Aggregate handles
        let mut total_handles: u32 = 0;
        let mut handles_any_available = false;
        let mut handles_all_available = true;
        for &pid in &pids {
            if let Some(summary) = handle_cache.get(pid) {
                total_handles = total_handles.saturating_add(summary.total);
                handles_any_available = true;
            } else {
                handles_all_available = false;
            }
        }

        // Aggregate threads (from global fast count)
        let mut thread_count: usize = 0;
        for &pid in &pids {
            if let Some(&count) = global_thread_counts.get(&pid) {
                thread_count += count;
            }
        }

        // Aggregate CPU and Memory
        let mut total_cpu: f32 = 0.0;
        let mut total_memory: u64 = 0;
        let mut any_memory = false;
        for &pid in &pids {
            if let Some((cpu_pct, mem_bytes)) = cpu_memory_data.get(&pid) {
                total_cpu += cpu_pct;
                if let Some(mem_bytes) = mem_bytes {
                    total_memory = total_memory.saturating_add(*mem_bytes);
                    any_memory = true;
                }
            }
        }

        // Aggregate Disk I/O rate (read+write bytes/sec)
        let mut disk_bps: f64 = 0.0;
        for &pid in &pids {
            if let Some(r) = io_rate_by_pid.get(&pid) {
                disk_bps += r.read_bytes_per_sec + r.write_bytes_per_sec;
            }
        }

        // Aggregate GPU metrics (max GPU %, sum GPU memory)
        let mut max_gpu: f32 = 0.0;
        let mut total_gpu_dedicated: u64 = 0;
        let mut total_gpu_shared: u64 = 0;
        let mut total_gpu_total: u64 = 0;
        for &pid in &pids {
            if let Some((gpu_pct, dedicated, shared, total)) = gpu_data.get(&pid) {
                max_gpu = max_gpu.max(*gpu_pct);
                total_gpu_dedicated += dedicated;
                total_gpu_shared += shared;
                total_gpu_total += total;
            }
        }

        rows.push(GroupedRow {
            name: name.clone(),
            count,
            is_match: group_matches,
            is_selected,
            representative_pid,
            total_handles,
            handles_any_available,
            handles_all_available,
            thread_count,
            cpu_percent: total_cpu,
            memory_bytes: any_memory.then_some(total_memory),
            disk_bytes_per_sec: disk_bps,
            gpu_percent: max_gpu,
            gpu_dedicated_bytes: total_gpu_dedicated,
            gpu_shared_bytes: total_gpu_shared,
            gpu_total_bytes: total_gpu_total,
            member_pids: pids,
            // Process Explorer parity fields from representative PID
            image_path: pid_to_image_path.get(&representative_pid).cloned(),
            command_line: pid_to_command_line.get(&representative_pid).cloned(),
            company_name: pid_to_company_name.get(&representative_pid).cloned(),
            file_description: pid_to_file_description.get(&representative_pid).cloned(),
            integrity_level: pid_to_integrity_level.get(&representative_pid).cloned(),
            user: pid_to_user.get(&representative_pid).cloned(),
            session_id: pid_to_session_id.get(&representative_pid).copied(),
        });
    }

    if group_sort == GroupSort::VerifiedSigner {
        fn sig_sort_key(
            image_path: Option<&String>,
            signature_cache_by_path: &HashMap<String, pmonnt_core::SignatureInfo>,
        ) -> (u8, String) {
            let Some(path) = image_path else {
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

        rows.sort_by(|a, b| {
            let ka = sig_sort_key(a.image_path.as_ref(), signature_cache_by_path);
            let kb = sig_sort_key(b.image_path.as_ref(), signature_cache_by_path);
            let base = ka
                .cmp(&kb)
                .then(a.name.to_lowercase().cmp(&b.name.to_lowercase()));
            if sort_desc {
                base.reverse()
            } else {
                base
            }
        });
    }

    rows
}
