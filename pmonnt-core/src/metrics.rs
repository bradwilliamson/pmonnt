//! Platform-independent process metric types and calculations.
//!
//! The Windows collectors in `win::process_metrics` produce these values; keeping the types
//! and arithmetic here lets them be unit-tested and benchmarked on any platform.

use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IoCounters {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub other_bytes: u64,
    pub read_ops: u64,
    pub write_ops: u64,
    pub other_ops: u64,
}

// Back-compat for existing UI code.
pub type ProcessIoCounters = IoCounters;

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct IoRate {
    pub read_bytes_per_sec: f64,
    pub write_bytes_per_sec: f64,
}

#[derive(Debug, Default)]
pub struct IoRateCalculator {
    prev_counters: HashMap<u32, (Instant, IoCounters)>,
}

impl IoRateCalculator {
    pub fn calculate_rate(&mut self, pid: u32, current: IoCounters) -> IoRate {
        let now = Instant::now();
        let rate = if let Some((prev_time, prev_counters)) = self.prev_counters.get(&pid) {
            let elapsed = now.duration_since(*prev_time).as_secs_f64();
            compute_io_rate(prev_counters, &current, elapsed)
        } else {
            IoRate::default()
        };

        self.prev_counters.insert(pid, (now, current));
        rate
    }

    pub fn remove_pid(&mut self, pid: u32) {
        self.prev_counters.remove(&pid);
    }

    pub fn retain_pids<I>(&mut self, live_pids: I)
    where
        I: IntoIterator<Item = u32>,
    {
        let live: std::collections::HashSet<u32> = live_pids.into_iter().collect();
        self.prev_counters.retain(|pid, _| live.contains(pid));
    }
}

pub(crate) fn compute_io_rate(
    prev: &IoCounters,
    current: &IoCounters,
    elapsed_secs: f64,
) -> IoRate {
    if elapsed_secs.partial_cmp(&0.0) != Some(std::cmp::Ordering::Greater) {
        return IoRate::default();
    }

    let read_delta = current.read_bytes.saturating_sub(prev.read_bytes);
    let write_delta = current.write_bytes.saturating_sub(prev.write_bytes);

    IoRate {
        read_bytes_per_sec: read_delta as f64 / elapsed_secs,
        write_bytes_per_sec: write_delta as f64 / elapsed_secs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_io_rate_uses_saturating_sub() {
        let prev = IoCounters {
            read_bytes: 100,
            write_bytes: 100,
            other_bytes: 0,
            read_ops: 0,
            write_ops: 0,
            other_ops: 0,
        };
        let current = IoCounters {
            read_bytes: 50,
            write_bytes: 90,
            other_bytes: 0,
            read_ops: 0,
            write_ops: 0,
            other_ops: 0,
        };

        let rate = compute_io_rate(&prev, &current, 1.0);
        assert_eq!(rate.read_bytes_per_sec, 0.0);
        assert_eq!(rate.write_bytes_per_sec, 0.0);
    }

    #[test]
    fn compute_io_rate_scales_by_elapsed() {
        let prev = IoCounters {
            read_bytes: 0,
            write_bytes: 0,
            other_bytes: 0,
            read_ops: 0,
            write_ops: 0,
            other_ops: 0,
        };
        let current = IoCounters {
            read_bytes: 1000,
            write_bytes: 500,
            other_bytes: 0,
            read_ops: 0,
            write_ops: 0,
            other_ops: 0,
        };

        let rate = compute_io_rate(&prev, &current, 2.0);
        assert_eq!(rate.read_bytes_per_sec, 500.0);
        assert_eq!(rate.write_bytes_per_sec, 250.0);
    }
}
