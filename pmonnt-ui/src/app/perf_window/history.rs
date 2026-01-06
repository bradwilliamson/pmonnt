use std::collections::VecDeque;
use std::time::Instant;

use crate::view::RightTab;

use super::PERF_HISTORY_LEN;

// Constants for network churn monitoring
pub(crate) const NET_HISTORY_LEN: usize = 120; // ~2 minutes at 1s sampling
pub(crate) const NET_POLL_INTERVAL_SECS: f32 = 1.0;

// Thresholds for leak/churn badges
pub(crate) const CLOSE_WAIT_THRESHOLD: u32 = 10;
pub(crate) const TIME_WAIT_THRESHOLD: u32 = 500;
pub(crate) const NEW_CONN_PER_SEC_THRESHOLD: f32 = 50.0;
pub(crate) const CLOSE_WAIT_RISING_COUNT: usize = 3; // consecutive samples

#[derive(Debug, Default, Clone)]
pub(crate) struct PerfStats {
    // CPU
    pub(crate) priority_class: Option<String>,
    pub(crate) kernel_time: Option<u64>,
    pub(crate) user_time: Option<u64>,
    pub(crate) total_time: Option<u64>,
    pub(crate) kernel_delta: Option<u64>,
    pub(crate) user_delta: Option<u64>,
    pub(crate) total_delta: Option<u64>,
    pub(crate) cycles: Option<u64>,
    pub(crate) cycles_delta: Option<u64>,
    // Virtual Memory
    pub(crate) virtual_size: Option<usize>,
    pub(crate) private_bytes: Option<usize>,
    pub(crate) peak_private_bytes: Option<usize>,
    pub(crate) commit_charge: Option<usize>,
    pub(crate) peak_commit_charge: Option<usize>,
    pub(crate) page_faults: Option<u32>,
    pub(crate) page_fault_delta: Option<u32>,
    // Physical Memory
    pub(crate) working_set: Option<usize>,
    pub(crate) ws_private: Option<usize>,
    pub(crate) ws_shareable: Option<usize>,
    pub(crate) ws_shared: Option<usize>,
    pub(crate) peak_working_set: Option<usize>,
    // I/O
    pub(crate) io_reads: Option<u64>,
    pub(crate) io_read_delta: Option<u64>,
    pub(crate) io_read_bytes: Option<u64>, // Cumulative
    pub(crate) io_read_bytes_delta: Option<u64>,
    pub(crate) io_writes: Option<u64>,
    pub(crate) io_write_delta: Option<u64>,
    pub(crate) io_write_bytes: Option<u64>, // Cumulative
    pub(crate) io_write_bytes_delta: Option<u64>,
    pub(crate) io_other: Option<u64>,
    pub(crate) io_other_delta: Option<u64>,
    pub(crate) io_other_bytes: Option<u64>, // Cumulative
    pub(crate) io_other_bytes_delta: Option<u64>,
    pub(crate) read_bytes_per_sec: Option<f64>,
    pub(crate) write_bytes_per_sec: Option<f64>,
    pub(crate) total_bytes_per_sec: Option<f64>,
    pub(crate) read_ops_per_sec: Option<f64>,
    pub(crate) write_ops_per_sec: Option<f64>,
    pub(crate) total_ops_per_sec: Option<f64>,
    pub(crate) avg_read_size: Option<f64>,
    pub(crate) avg_write_size: Option<f64>,
    // Handles
    pub(crate) handles: Option<u32>,
    pub(crate) peak_handles: Option<u32>,
    pub(crate) gdi_handles: Option<u32>,
    pub(crate) user_handles: Option<u32>,
    pub(crate) handles_delta: Option<u32>,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct ProcessPerfHistory {
    pub(crate) cpu_percent: VecDeque<f32>,
    pub(crate) memory_bytes: VecDeque<u64>,
    pub(crate) private_bytes: VecDeque<u64>,
    pub(crate) gpu_percent: VecDeque<f32>,
    pub(crate) io_read_bps: VecDeque<f32>,
    pub(crate) io_write_bps: VecDeque<f32>,
}

impl ProcessPerfHistory {
    pub(crate) fn push_sample(
        &mut self,
        cpu_percent: f32,
        memory_bytes: u64,
        private_bytes: u64,
        gpu_percent: f32,
        io_read_bps: f32,
        io_write_bps: f32,
    ) {
        push_with_cap(&mut self.cpu_percent, cpu_percent, PERF_HISTORY_LEN);
        push_with_cap(&mut self.memory_bytes, memory_bytes, PERF_HISTORY_LEN);
        push_with_cap(&mut self.private_bytes, private_bytes, PERF_HISTORY_LEN);
        push_with_cap(&mut self.gpu_percent, gpu_percent, PERF_HISTORY_LEN);
        push_with_cap(&mut self.io_read_bps, io_read_bps, PERF_HISTORY_LEN);
        push_with_cap(&mut self.io_write_bps, io_write_bps, PERF_HISTORY_LEN);
    }
}

pub(crate) fn push_with_cap<T>(deque: &mut VecDeque<T>, value: T, cap: usize) {
    if cap == 0 {
        return;
    }
    if deque.len() == cap {
        deque.pop_front();
    }
    deque.push_back(value);
}

#[derive(Debug, Default, Clone)]
pub(crate) struct ProcessPerfWindow {
    pub(crate) history: ProcessPerfHistory,
    pub(crate) last_io: Option<pmonnt_core::win_process_metrics::ProcessIoCounters>,
    pub(crate) last_cpu_times: Option<(u64, u64)>,
    pub(crate) tab: RightTab,
    pub(crate) selected_tid: Option<u32>,
    pub(crate) last_stats: Option<PerfStats>,
    pub(crate) current_stats: Option<PerfStats>,
    pub(crate) last_sample: Option<Instant>,
    pub(crate) peak_handles: Option<u32>,
    pub(crate) security_filter: String,
    // Network churn monitoring
    pub(crate) net_churn_monitor: Option<NetChurnMonitor>,
    pub(crate) include_child_pids: bool,
}

/// TCP state counts aggregated from connections
#[derive(Debug, Default, Clone)]
pub(crate) struct TcpStateCounts {
    pub(crate) established: u32,
    pub(crate) time_wait: u32,
    pub(crate) close_wait: u32,
    pub(crate) syn_sent: u32,
    pub(crate) syn_recv: u32,
    pub(crate) listen: u32,
    pub(crate) fin_wait1: u32,
    pub(crate) fin_wait2: u32,
    pub(crate) closing: u32,
    pub(crate) last_ack: u32,
}

/// A single sample of network statistics
#[derive(Debug, Clone)]
pub(crate) struct NetChurnSample {
    #[allow(dead_code)]
    pub(crate) _t: Instant,
    pub(crate) total_tcp: u32,
    pub(crate) tcp_states: TcpStateCounts,
    pub(crate) total_udp: u32,
    pub(crate) unique_remotes: u32,
    pub(crate) new_per_sec: f32,
}

impl Default for NetChurnSample {
    fn default() -> Self {
        Self {
            _t: Instant::now(),
            total_tcp: 0,
            tcp_states: TcpStateCounts::default(),
            total_udp: 0,
            unique_remotes: 0,
            new_per_sec: 0.0,
        }
    }
}

/// Socket churn monitor with rolling history
#[derive(Debug, Clone)]
pub(crate) struct NetChurnMonitor {
    pub(crate) last_snapshot_total: u32,
    pub(crate) last_poll: Instant,
    pub(crate) samples: VecDeque<NetChurnSample>,
    pub(crate) last_counts: TcpStateCounts,
    pub(crate) error: Option<String>,
    pub(crate) child_pid_count: usize,
}

impl Default for NetChurnMonitor {
    fn default() -> Self {
        Self {
            last_snapshot_total: 0,
            last_poll: Instant::now(),
            samples: VecDeque::new(),
            last_counts: TcpStateCounts::default(),
            error: None,
            child_pid_count: 0,
        }
    }
}

#[cfg(any(test, feature = "dev-tools"))]
#[allow(dead_code)]
pub(crate) fn fake_perf_stats() -> PerfStats {
    PerfStats {
        priority_class: Some("Normal".to_string()),
        kernel_time: Some(123456789),
        user_time: Some(987654321),
        total_time: Some(1111111110),
        kernel_delta: Some(12345),
        user_delta: Some(67890),
        total_delta: Some(80235),
        cycles: Some(1_000_000_000),
        cycles_delta: Some(100_000),
        virtual_size: Some(1_000_000_000),
        private_bytes: Some(500_000_000),
        peak_private_bytes: Some(600_000_000),
        commit_charge: Some(800_000_000),
        peak_commit_charge: Some(900_000_000),
        page_faults: Some(1000),
        page_fault_delta: Some(10),
        working_set: Some(200_000_000),
        ws_private: Some(150_000_000),
        ws_shareable: Some(30_000_000),
        ws_shared: Some(20_000_000),
        peak_working_set: Some(250_000_000),
        io_reads: Some(100),
        io_read_delta: Some(5),
        io_read_bytes: Some(10_000_000),
        io_read_bytes_delta: Some(1_000_000),
        io_writes: Some(50),
        io_write_delta: Some(2),
        io_write_bytes: Some(5_000_000),
        io_write_bytes_delta: Some(500_000),
        io_other: Some(20),
        io_other_delta: Some(1),
        io_other_bytes: Some(1_000_000),
        io_other_bytes_delta: Some(100_000),
        read_bytes_per_sec: Some(1000.0),
        write_bytes_per_sec: Some(500.0),
        total_bytes_per_sec: Some(1500.0),
        read_ops_per_sec: Some(10.0),
        write_ops_per_sec: Some(5.0),
        total_ops_per_sec: Some(15.0),
        avg_read_size: Some(100.0),
        avg_write_size: Some(100.0),
        handles: Some(200),
        peak_handles: Some(250),
        gdi_handles: Some(50),
        user_handles: Some(30),
        handles_delta: Some(5),
    }
}
