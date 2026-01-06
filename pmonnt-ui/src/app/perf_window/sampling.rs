use pmonnt_core::win_process_metrics;

use super::super::PMonNTApp;
use super::PerfStats;

impl PMonNTApp {
    pub(crate) fn update_perf_windows_history(&mut self, elapsed_seconds: f32) {
        if self.perf_windows.is_empty() {
            return;
        }

        let elapsed_seconds = elapsed_seconds.max(1e-3);
        let num_cpus = num_cpus::get().max(1) as f32;

        let pids: Vec<u32> = self.perf_windows.keys().copied().collect();
        for pid in pids {
            let gpu = self
                .gpu_data
                .get(&pid)
                .map(|(pct, _, _, _)| *pct)
                .unwrap_or(0.0);

            let mem = win_process_metrics::get_process_memory_by_pid(pid).unwrap_or(0);
            let private_bytes =
                win_process_metrics::get_process_private_bytes_by_pid(pid).unwrap_or(0);

            let io_now = win_process_metrics::get_process_io_counters_by_pid(pid);
            let (mut io_read_bps, mut io_write_bps) = (0.0f32, 0.0f32);

            if let Some(w) = self.perf_windows.get_mut(&pid) {
                let mut cpu = 0.0f32;
                if let Some((kernel_100ns, user_100ns)) =
                    win_process_metrics::get_process_times_by_pid(pid)
                {
                    if let Some((prev_kernel, prev_user)) = w.last_cpu_times {
                        let prev_total = prev_kernel.saturating_add(prev_user);
                        let now_total = kernel_100ns.saturating_add(user_100ns);
                        let delta_100ns = now_total.saturating_sub(prev_total);

                        let delta_seconds = delta_100ns as f32 / 10_000_000.0;
                        cpu = (delta_seconds / (elapsed_seconds * num_cpus) * 100.0)
                            .clamp(0.0, 100.0);
                    }
                    w.last_cpu_times = Some((kernel_100ns, user_100ns));
                } else {
                    w.last_cpu_times = None;
                }

                if let Some(now) = io_now {
                    if let Some(prev) = w.last_io {
                        let read_delta = now.read_bytes.saturating_sub(prev.read_bytes);
                        let write_delta = now.write_bytes.saturating_sub(prev.write_bytes);
                        io_read_bps = read_delta as f32 / elapsed_seconds;
                        io_write_bps = write_delta as f32 / elapsed_seconds;
                    }
                    w.last_io = Some(now);
                }

                w.history
                    .push_sample(cpu, mem, private_bytes, gpu, io_read_bps, io_write_bps);
            }
        }
    }

    pub(crate) fn sample_perf_stats(
        pid: u32,
        last_stats: Option<&PerfStats>,
        elapsed_seconds: f64,
    ) -> Option<PerfStats> {
        let mut stats = PerfStats::default();

        // CPU
        if let Some(priority) = win_process_metrics::get_process_priority_class_by_pid(pid) {
            stats.priority_class = Some(match priority {
                0x00000040 => "Idle".to_string(),
                0x00004000 => "Below Normal".to_string(),
                0x00000020 => "Normal".to_string(),
                0x00008000 => "Above Normal".to_string(),
                0x00000080 => "High".to_string(),
                0x00000100 => "Realtime".to_string(),
                _ => format!("Unknown ({})", priority),
            });
        }

        if let Some((kernel, user)) = win_process_metrics::get_process_times_by_pid(pid) {
            stats.kernel_time = Some(kernel);
            stats.user_time = Some(user);
            stats.total_time = Some(kernel + user);

            if let Some(last) = last_stats {
                if let (Some(lk), Some(lu)) = (last.kernel_time, last.user_time) {
                    stats.kernel_delta = Some(kernel.saturating_sub(lk));
                    stats.user_delta = Some(user.saturating_sub(lu));
                    stats.total_delta = Some((kernel + user).saturating_sub(lk + lu));
                }
            }
        }

        if let Some(cycles) = win_process_metrics::get_process_cycle_time_by_pid(pid) {
            stats.cycles = Some(cycles);
            if let Some(last) = last_stats.and_then(|l| l.cycles) {
                stats.cycles_delta = Some(cycles.saturating_sub(last));
            }
        }

        // Memory
        if let Some(mem_info) = win_process_metrics::get_process_memory_info_by_pid(pid) {
            let current_private = mem_info.PrivateUsage;
            let current_commit = mem_info.PagefileUsage;
            let current_peak_commit = mem_info.PeakPagefileUsage;
            let current_working_set = mem_info.WorkingSetSize;
            let current_peak_working_set = mem_info.PeakWorkingSetSize;

            stats.virtual_size = Some(current_commit); // Virtual size is commit size in Process Explorer
            stats.private_bytes = Some(current_private);
            stats.commit_charge = Some(current_commit);
            stats.peak_commit_charge = Some(current_peak_commit);
            stats.page_faults = Some(mem_info.PageFaultCount);
            stats.working_set = Some(current_working_set);
            stats.peak_working_set = Some(current_peak_working_set);

            // Track peak private bytes as max over time (no OS peak available)
            stats.peak_private_bytes = last_stats
                .and_then(|l| l.peak_private_bytes)
                .map(|p| p.max(current_private))
                .or(Some(current_private));

            if let Some(last) = last_stats {
                if let Some(lp) = last.page_faults {
                    stats.page_fault_delta = Some(mem_info.PageFaultCount.saturating_sub(lp));
                }
            }
        }

        // I/O
        if let Some(io) = win_process_metrics::get_process_io_counters_by_pid(pid) {
            stats.io_reads = Some(io.read_ops);
            stats.io_writes = Some(io.write_ops);
            stats.io_other = Some(io.other_ops);
            stats.io_read_bytes = Some(io.read_bytes);
            stats.io_write_bytes = Some(io.write_bytes);
            stats.io_other_bytes = Some(io.other_bytes);

            if let Some(last) = last_stats {
                if let (Some(lr), Some(lw), Some(lo)) =
                    (last.io_reads, last.io_writes, last.io_other)
                {
                    stats.io_read_delta = Some(io.read_ops.saturating_sub(lr));
                    stats.io_write_delta = Some(io.write_ops.saturating_sub(lw));
                    stats.io_other_delta = Some(io.other_ops.saturating_sub(lo));
                }

                if let (Some(lrb), Some(lwb), Some(lob)) =
                    (last.io_read_bytes, last.io_write_bytes, last.io_other_bytes)
                {
                    stats.io_read_bytes_delta = Some(io.read_bytes.saturating_sub(lrb));
                    stats.io_write_bytes_delta = Some(io.write_bytes.saturating_sub(lwb));
                    stats.io_other_bytes_delta = Some(io.other_bytes.saturating_sub(lob));
                }
            }

            // Rates
            if elapsed_seconds > 0.0 {
                let read_ops = stats.io_read_delta.unwrap_or(0) as f64 / elapsed_seconds;
                let write_ops = stats.io_write_delta.unwrap_or(0) as f64 / elapsed_seconds;
                let total_ops = read_ops + write_ops;
                let read_bytes = stats.io_read_bytes_delta.unwrap_or(0) as f64 / elapsed_seconds;
                let write_bytes = stats.io_write_bytes_delta.unwrap_or(0) as f64 / elapsed_seconds;
                let total_bytes = read_bytes + write_bytes;

                stats.read_ops_per_sec = Some(read_ops);
                stats.write_ops_per_sec = Some(write_ops);
                stats.total_ops_per_sec = Some(total_ops);
                stats.read_bytes_per_sec = Some(read_bytes);
                stats.write_bytes_per_sec = Some(write_bytes);
                stats.total_bytes_per_sec = Some(total_bytes);

                if read_ops > 0.0 {
                    stats.avg_read_size = Some(read_bytes / read_ops);
                }
                if write_ops > 0.0 {
                    stats.avg_write_size = Some(write_bytes / write_ops);
                }
            }
        }

        // Handles
        if let Some(handles) = win_process_metrics::get_process_handle_count_by_pid(pid) {
            stats.handles = Some(handles);

            // Track peak handles
            stats.peak_handles = last_stats
                .and_then(|l| l.peak_handles)
                .map(|p| p.max(handles))
                .or(Some(handles));

            if let Some(last) = last_stats.and_then(|l| l.handles) {
                stats.handles_delta = Some(handles.saturating_sub(last));
            }
        }

        if let Some(gdi) = win_process_metrics::get_process_gdi_handles_by_pid(pid) {
            stats.gdi_handles = Some(gdi);
        }

        if let Some(user) = win_process_metrics::get_process_user_handles_by_pid(pid) {
            stats.user_handles = Some(user);
        }

        Some(stats)
    }

    /// Poll network connections and update churn monitor
    pub(super) fn poll_network_connections(
        monitor: &mut super::history::NetChurnMonitor,
        _pid: u32,
        pids_to_monitor: &[u32],
    ) {
        use pmonnt_core::network::{get_all_connections, Protocol, TcpState};
        use std::collections::HashSet;

        monitor.error = None;

        // Fetch all connections
        let conns = match get_all_connections() {
            Ok(c) => c,
            Err(e) => {
                monitor.error = Some(format!("Failed to fetch connections: {}", e));
                return;
            }
        };

        // Filter to target PIDs
        let pid_set: HashSet<u32> = pids_to_monitor.iter().copied().collect();
        let filtered: Vec<_> = conns
            .into_iter()
            .filter(|c| pid_set.contains(&c.pid))
            .collect();

        // Aggregate counts
        let mut tcp_states = super::history::TcpStateCounts::default();
        let mut total_tcp = 0u32;
        let mut total_udp = 0u32;
        let mut unique_remotes = HashSet::new();

        for conn in &filtered {
            match conn.protocol {
                Protocol::Tcp => {
                    total_tcp += 1;
                    if let Some(state) = conn.state {
                        match state {
                            TcpState::Established => tcp_states.established += 1,
                            TcpState::TimeWait => tcp_states.time_wait += 1,
                            TcpState::CloseWait => tcp_states.close_wait += 1,
                            TcpState::SynSent => tcp_states.syn_sent += 1,
                            TcpState::SynReceived => tcp_states.syn_recv += 1,
                            TcpState::Listen => tcp_states.listen += 1,
                            TcpState::FinWait1 => tcp_states.fin_wait1 += 1,
                            TcpState::FinWait2 => tcp_states.fin_wait2 += 1,
                            TcpState::Closing => tcp_states.closing += 1,
                            TcpState::LastAck => tcp_states.last_ack += 1,
                            _ => {}
                        }
                    }
                }
                Protocol::Udp => {
                    total_udp += 1;
                }
            }

            if let Some(remote) = conn.remote_address {
                unique_remotes.insert(remote);
            }
        }

        // Compute new connections/sec
        let now = std::time::Instant::now();
        let dt = now
            .duration_since(monitor.last_poll)
            .as_secs_f32()
            .max(0.001);
        let delta_total = total_tcp.saturating_sub(monitor.last_snapshot_total) as f32;
        let new_per_sec = (delta_total / dt).max(0.0);

        // Smooth new_per_sec with rolling average of last 5 samples
        let smoothed_new_per_sec = if monitor.samples.len() >= 5 {
            let recent: Vec<f32> = monitor
                .samples
                .iter()
                .rev()
                .take(5)
                .map(|s| s.new_per_sec)
                .collect();
            let sum: f32 = recent.iter().sum();
            (sum + new_per_sec) / 6.0
        } else {
            new_per_sec
        };

        // Create sample
        let sample = super::history::NetChurnSample {
            _t: now,
            total_tcp,
            tcp_states: tcp_states.clone(),
            total_udp,
            unique_remotes: unique_remotes.len() as u32,
            new_per_sec: smoothed_new_per_sec,
        };

        // Push to ring buffer
        {
            use super::history::push_with_cap;
            push_with_cap(
                &mut monitor.samples,
                sample,
                super::history::NET_HISTORY_LEN,
            );
        }

        // Update state
        monitor.last_snapshot_total = total_tcp;
        monitor.last_poll = now;
        monitor.last_counts = tcp_states;
        monitor.child_pid_count = pids_to_monitor.len().saturating_sub(1); // Exclude root PID
    }
}
