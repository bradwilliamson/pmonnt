use std::collections::HashSet;
use std::time::Instant;

use eframe::egui;
use pmonnt_core::diff::ProcessDiff;
use pmonnt_core::snapshot::ProcessSnapshot;
use pmonnt_core::win_process_metrics;
use pmonnt_core::win_thread;

use crate::app::PMonNTApp;
use crate::gpu_pdh::should_warn;
use crate::process_info;
use crate::util::{
    query_gpu_memory_capacity_bytes, query_physical_memory_used_total, sum_cpu_percent,
    sum_gpu_mem_bytes, sum_gpu_percent,
};

impl PMonNTApp {
    pub(super) fn refresh_snapshot_and_metrics(&mut self, ctx: &egui::Context) {
        // Update snapshot every 2 seconds
        if self.last_snapshot_update.elapsed().as_secs() >= 2 {
            if let Ok(new_snapshot) = ProcessSnapshot::new() {
                // Move current to previous
                self.previous_snapshot = Some(self.current_snapshot.clone());
                self.current_snapshot = new_snapshot;

                // Rebuild process tree
                self.process_tree.clear();
                for process in &self.current_snapshot.processes {
                    self.process_tree
                        .entry(process.ppid)
                        .or_default()
                        .push(process.clone());
                }

                // Compute diff if we have a previous snapshot
                if let Some(ref prev) = self.previous_snapshot {
                    let diff = ProcessDiff::new(prev, &self.current_snapshot);
                    self.exited_buffer.add_from_diff(&diff, prev);
                    self.last_diff = Some(diff);
                }

                // Hardening: Prune expanded_pids to only include alive processes
                let alive: HashSet<u32> = self
                    .current_snapshot
                    .processes
                    .iter()
                    .map(|p| p.pid)
                    .collect();
                self.expanded_pids.retain(|pid| alive.contains(pid));

                // Hardening: Prune expanded_groups to only include groups that still exist
                let alive_groups: HashSet<String> = self
                    .current_snapshot
                    .processes
                    .iter()
                    .map(|p| p.name.to_lowercase())
                    .collect();
                self.expanded_groups.retain(|k| alive_groups.contains(k));

                // Close perf windows for exited processes
                self.perf_windows.retain(|pid, _| alive.contains(pid));

                // Keep I/O rate state in sync with live processes.
                self.io_rate_calc.retain_pids(alive.iter().copied());
                self.io_rate_by_pid.retain(|pid, _| alive.contains(pid));

                // Hardening: Clear selection if selected process exited
                if let Some(pid) = self.selected_pid {
                    if !alive.contains(&pid) {
                        self.selected_pid = None;
                    }
                }

                // Update global thread counts (fast, ~5ms)
                if let Ok(counts) = win_thread::count_threads_global() {
                    self.global_thread_counts = counts;
                }
            }

            // Also clean up token/thread cache on snapshot refresh
            self.token_cache.cleanup();
            self.thread_cache.cleanup();

            // Calculate CPU % and fetch memory for each process in batch
            let now = Instant::now();
            let elapsed_since_last = if let Some(last_time) = self.last_cpu_calc_time {
                last_time.elapsed().as_millis() as f32 / 1000.0 // seconds
            } else {
                2.0
            };
            self.last_cpu_calc_time = Some(now);

            // Get number of CPUs for multi-core aware calculation
            let num_cpus = num_cpus::get() as f32;

            // Task Manager-like memory coverage: query all working sets in one syscall and
            // overlay results by PID. If this fails, fall back to per-PID queries.
            let working_set_map: Option<std::collections::HashMap<u32, u64>> =
                match win_process_metrics::get_working_set_bytes_map() {
                    Ok(map) => Some(map),
                    Err(e) => {
                        log::debug!(
                            "Failed to query SystemProcessInformation working sets: {}",
                            e
                        );
                        None
                    }
                };

            // Calculate CPU % and memory for each process
            self.cpu_memory_data.clear();
            self.io_rate_by_pid.clear();
            for process in &self.current_snapshot.processes {
                let pid = process.pid;
                if pid == 0 {
                    continue;
                }

                let memory_bytes: Option<u64> = if let Some(ref map) = working_set_map {
                    map.get(&pid).copied()
                } else {
                    win_process_metrics::get_process_memory_by_pid(pid)
                };

                // Calculate CPU % from time deltas
                let cpu_percent = if let Some((kernel_100ns, user_100ns)) =
                    win_process_metrics::get_process_times_by_pid(pid)
                {
                    let total_time_100ns = kernel_100ns + user_100ns;

                    let cpu_pct =
                        if let Some((prev_kernel, prev_user)) = self.previous_cpu_times.get(&pid) {
                            let prev_total = prev_kernel + prev_user;
                            let delta_100ns =
                                (total_time_100ns as i64 - prev_total as i64).max(0) as u64;

                            if elapsed_since_last > 0.0 {
                                let delta_ms = delta_100ns as f32 / 10_000.0;
                                let cpu_pct =
                                    (delta_ms / (elapsed_since_last * 1000.0)) / num_cpus * 100.0;
                                Some(cpu_pct.min(99.9))
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                    // Store current for next iteration
                    self.previous_cpu_times
                        .insert(pid, (kernel_100ns, user_100ns));
                    cpu_pct
                } else {
                    self.previous_cpu_times.remove(&pid);
                    None
                };

                if memory_bytes.is_some() || cpu_percent.is_some() {
                    let cpu_final = cpu_percent.unwrap_or(0.0);
                    self.cpu_memory_data.insert(pid, (cpu_final, memory_bytes));
                }

                if let Ok(counters) = win_process_metrics::get_io_counters(pid) {
                    let rate = self.io_rate_calc.calculate_rate(pid, counters);
                    self.io_rate_by_pid.insert(pid, rate);
                } else {
                    // Access denied or process exited between snapshot & query.
                    self.io_rate_calc.remove_pid(pid);
                }
            }

            // Task Manager-style totals (best-effort).
            self.total_cpu_percent = sum_cpu_percent(&self.cpu_memory_data);
            if let Some((used, total)) = query_physical_memory_used_total() {
                self.ram_used_bytes = used;
                self.ram_total_bytes = total;
            }

            // GPU memory capacities (best-effort).
            if cfg!(windows) && self.last_gpu_mem_capacity_refresh.elapsed().as_secs() >= 10 {
                if let Some((dedicated, shared)) = query_gpu_memory_capacity_bytes() {
                    self.gpu_dedicated_capacity_bytes = dedicated;
                    self.gpu_shared_capacity_bytes = shared;
                    self.gpu_total_capacity_bytes = dedicated.saturating_add(shared);
                }
                self.last_gpu_mem_capacity_refresh = Instant::now();
            }

            // GPU metrics via PDH sampler.
            if self.gpu_sampler_rebuild_due() {
                self.gpu_sampler.rebuild_counters();
                self.last_gpu_rebuild = Instant::now();
            }

            if let Some(snapshot) = self.gpu_sampler.sample() {
                if !snapshot.gpu_percent.is_empty()
                    || !snapshot.gpu_dedicated_bytes.is_empty()
                    || !snapshot.gpu_shared_bytes.is_empty()
                {
                    self.gpu_data.clear();
                    let all_pids: HashSet<u32> = snapshot
                        .gpu_percent
                        .keys()
                        .chain(snapshot.gpu_dedicated_bytes.keys())
                        .chain(snapshot.gpu_shared_bytes.keys())
                        .cloned()
                        .collect();

                    for pid in all_pids {
                        let pct = snapshot.gpu_percent.get(&pid).copied().unwrap_or(0.0);
                        let dedicated =
                            snapshot.gpu_dedicated_bytes.get(&pid).copied().unwrap_or(0);
                        let shared = snapshot.gpu_shared_bytes.get(&pid).copied().unwrap_or(0);
                        let total = snapshot
                            .gpu_total_bytes
                            .get(&pid)
                            .copied()
                            .unwrap_or(dedicated + shared);
                        self.gpu_data.insert(pid, (pct, dedicated, shared, total));
                    }

                    self.last_gpu_sample_timestamp = Some(snapshot.sample_timestamp);
                } else if let Some(last_ts) = self.last_gpu_sample_timestamp {
                    if last_ts.elapsed().as_secs() > 30 && should_warn() {
                        log::warn!(
                            "[GPU] No GPU data received for 30+ seconds, keeping last good sample"
                        );
                    }
                }
            }

            self.total_gpu_percent = sum_gpu_percent(&self.gpu_data);
            let (dedicated, shared, total) = sum_gpu_mem_bytes(&self.gpu_data);
            self.total_gpu_dedicated_bytes = dedicated;
            self.total_gpu_shared_bytes = shared;
            self.total_gpu_total_bytes = total;

            // Populate Process Explorer parity fields.
            // These fields are effectively static for a PID, so cache them across snapshots
            // and only drop entries for processes that exited.
            let alive: HashSet<u32> = self
                .current_snapshot
                .processes
                .iter()
                .map(|p| p.pid)
                .collect();

            self.pid_to_image_path.retain(|pid, _| alive.contains(pid));
            self.pid_to_command_line
                .retain(|pid, _| alive.contains(pid));
            self.pid_to_current_directory
                .retain(|pid, _| alive.contains(pid));
            self.pid_to_company_name.clear();
            self.pid_to_file_description.clear();
            self.pid_to_integrity_level.clear();
            self.pid_to_user.clear();
            self.pid_to_session_id.clear();
            self.pid_to_handle_count.clear();
            self.pid_to_thread_count.clear();

            for process in &self.current_snapshot.processes {
                let pid = process.pid;
                if pid == 0 {
                    continue;
                }

                if let std::collections::hash_map::Entry::Vacant(e) =
                    self.pid_to_image_path.entry(pid)
                {
                    if let Some(path) = process_info::get_image_path(pid) {
                        e.insert(path);
                    }
                }

                if let std::collections::hash_map::Entry::Vacant(e) =
                    self.pid_to_command_line.entry(pid)
                {
                    if let Some(cmd) = process_info::get_command_line(pid) {
                        e.insert(cmd);
                    }
                }

                if let std::collections::hash_map::Entry::Vacant(e) =
                    self.pid_to_current_directory.entry(pid)
                {
                    if let Some(cwd) = process_info::get_current_directory(pid) {
                        e.insert(cwd);
                    }
                }

                if let Some(path) = self.pid_to_image_path.get(&pid) {
                    let (company, description) = process_info::get_file_version_info(path);
                    if let Some(company) = company {
                        self.pid_to_company_name.insert(pid, company);
                    }
                    if let Some(description) = description {
                        self.pid_to_file_description.insert(pid, description);
                    }
                }

                if let Some(integrity) = process_info::get_integrity_level(pid) {
                    self.pid_to_integrity_level.insert(pid, integrity);
                }

                if let Some(user) = process_info::get_user(pid) {
                    self.pid_to_user.insert(pid, user);
                }

                if let Some(session_id) = process_info::get_session_id(pid) {
                    self.pid_to_session_id.insert(pid, session_id);
                }

                if let Some(handle_count) = self.handle_cache.get(pid).map(|s| s.total) {
                    self.pid_to_handle_count.insert(pid, handle_count);
                }
                if let Some(thread_count) = self.global_thread_counts.get(&pid).copied() {
                    self.pid_to_thread_count.insert(pid, thread_count);
                }
            }

            self.last_snapshot_update = Instant::now();
            ctx.request_repaint();
        }
    }
}
