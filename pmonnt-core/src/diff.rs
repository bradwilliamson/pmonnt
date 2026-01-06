//! Process snapshot diffing functionality

use crate::process::Process;
use crate::snapshot::ProcessSnapshot;
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Represents the differences between two process snapshots
#[derive(Debug, Clone)]
pub struct ProcessDiff {
    /// PIDs that exist in the new snapshot but not in the old one
    pub new_pids: HashSet<u32>,
    /// PIDs that existed in the old snapshot but not in the new one
    pub exited_pids: HashSet<u32>,
    /// PIDs where the process name or PPID changed
    pub changed_pids: HashSet<u32>,
    /// When the diff was computed (from new snapshot's timestamp)
    pub computed_at: Instant,
}

impl ProcessDiff {
    /// Compute the difference between two snapshots
    pub fn new(old_snapshot: &ProcessSnapshot, new_snapshot: &ProcessSnapshot) -> Self {
        let old_pids: HashSet<u32> = old_snapshot.pids().collect();
        let new_pids: HashSet<u32> = new_snapshot.pids().collect();

        let new_pids_set = &new_pids - &old_pids;
        let exited_pids_set = &old_pids - &new_pids;

        let mut changed_pids = HashSet::new();

        // Check for changes in existing processes
        for &pid in &old_pids {
            if let (Some(old_proc), Some(new_proc)) =
                (old_snapshot.get_process(pid), new_snapshot.get_process(pid))
            {
                if old_proc.name != new_proc.name || old_proc.ppid != new_proc.ppid {
                    changed_pids.insert(pid);
                }
            }
        }

        Self {
            new_pids: new_pids_set,
            exited_pids: exited_pids_set,
            changed_pids,
            computed_at: new_snapshot.taken_at,
        }
    }

    /// Check if there are any changes
    pub fn has_changes(&self) -> bool {
        !self.new_pids.is_empty() || !self.exited_pids.is_empty() || !self.changed_pids.is_empty()
    }

    /// Get the total number of changes
    pub fn change_count(&self) -> usize {
        self.new_pids.len() + self.exited_pids.len() + self.changed_pids.len()
    }
}

/// Represents an exited process with its exit time
#[derive(Debug, Clone)]
pub struct ExitedProcess {
    pub process: Process,
    pub exited_at: Instant,
}

impl ExitedProcess {
    pub fn new(process: Process, exited_at: Instant) -> Self {
        Self { process, exited_at }
    }

    /// Check if this exited process should still be shown (within max_age)
    pub fn is_recent(&self, now: Instant, max_age: Duration) -> bool {
        now.duration_since(self.exited_at) <= max_age
    }
}

/// A ring buffer for tracking recently exited processes
#[derive(Debug, Clone)]
pub struct ExitedProcessBuffer {
    processes: Vec<ExitedProcess>,
    max_age: Duration,
    max_entries: usize,
}

impl ExitedProcessBuffer {
    pub fn new(max_age: Duration) -> Self {
        Self {
            processes: Vec::new(),
            max_age,
            max_entries: 500,
        }
    }

    pub fn new_with_capacity(max_age: Duration, max_entries: usize) -> Self {
        Self {
            processes: Vec::new(),
            max_age,
            max_entries,
        }
    }

    /// Add an exited process
    pub fn add_exited(&mut self, process: Process, exited_at: Instant) {
        self.processes.push(ExitedProcess::new(process, exited_at));
        self.cleanup();
    }

    /// Add multiple exited processes from a diff
    pub fn add_from_diff(&mut self, diff: &ProcessDiff, old_snapshot: &ProcessSnapshot) {
        for &pid in &diff.exited_pids {
            if let Some(process) = old_snapshot.get_process(pid) {
                self.add_exited(process.clone(), diff.computed_at);
            }
        }
    }

    /// Get all recent exited processes
    pub fn recent_exited(&self, now: Instant) -> Vec<&ExitedProcess> {
        self.processes
            .iter()
            .filter(|ep| ep.is_recent(now, self.max_age))
            .collect()
    }

    /// Clean up old entries
    fn cleanup(&mut self) {
        let now = Instant::now();
        // First, remove entries older than max_age
        self.processes.retain(|ep| ep.is_recent(now, self.max_age));

        // Then enforce max_entries cap by dropping oldest entries first
        if self.processes.len() > self.max_entries {
            // Sort by exit time (oldest first) and keep only the most recent max_entries
            self.processes.sort_by_key(|ep| ep.exited_at);
            self.processes
                .drain(0..(self.processes.len() - self.max_entries));
        }
    }

    /// Get the count of recent exited processes
    pub fn recent_count(&self, now: Instant) -> usize {
        self.recent_exited(now).len()
    }
}

impl Default for ExitedProcessBuffer {
    fn default() -> Self {
        Self::new(Duration::from_secs(30))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Process;
    use std::time::Duration;

    fn create_test_process(pid: u32, name: &str, ppid: Option<u32>) -> Process {
        Process {
            pid,
            name: name.to_string(),
            ppid,
            cpu_percent: None,
            memory_bytes: None,
            gpu_percent: None,
            gpu_memory_bytes: None,
            path: None,
            signature: None,
        }
    }

    fn create_test_snapshot(processes: Vec<Process>) -> ProcessSnapshot {
        let taken_at = Instant::now();
        let process_map = processes.iter().map(|p| (p.pid, p.clone())).collect();
        ProcessSnapshot {
            taken_at,
            processes,
            process_map,
        }
    }

    #[test]
    fn test_diff_new_processes() {
        let old_snapshot = create_test_snapshot(vec![
            create_test_process(1, "init", None),
            create_test_process(2, "bash", Some(1)),
        ]);

        let new_snapshot = create_test_snapshot(vec![
            create_test_process(1, "init", None),
            create_test_process(2, "bash", Some(1)),
            create_test_process(3, "notepad", Some(2)),
        ]);

        let diff = ProcessDiff::new(&old_snapshot, &new_snapshot);

        assert_eq!(diff.new_pids.len(), 1);
        assert!(diff.new_pids.contains(&3));
        assert!(diff.exited_pids.is_empty());
        assert!(diff.changed_pids.is_empty());
        assert!(diff.has_changes());
        assert_eq!(diff.change_count(), 1);
    }

    #[test]
    fn test_diff_exited_processes() {
        let old_snapshot = create_test_snapshot(vec![
            create_test_process(1, "init", None),
            create_test_process(2, "bash", Some(1)),
            create_test_process(3, "notepad", Some(2)),
        ]);

        let new_snapshot = create_test_snapshot(vec![
            create_test_process(1, "init", None),
            create_test_process(2, "bash", Some(1)),
        ]);

        let diff = ProcessDiff::new(&old_snapshot, &new_snapshot);

        assert!(diff.new_pids.is_empty());
        assert_eq!(diff.exited_pids.len(), 1);
        assert!(diff.exited_pids.contains(&3));
        assert!(diff.changed_pids.is_empty());
        assert!(diff.has_changes());
        assert_eq!(diff.change_count(), 1);
    }

    #[test]
    fn test_diff_changed_processes() {
        let old_snapshot = create_test_snapshot(vec![
            create_test_process(1, "init", None),
            create_test_process(2, "bash", Some(1)),
        ]);

        let new_snapshot = create_test_snapshot(vec![
            create_test_process(1, "init", None),
            create_test_process(2, "zsh", Some(1)), // name changed
        ]);

        let diff = ProcessDiff::new(&old_snapshot, &new_snapshot);

        assert!(diff.new_pids.is_empty());
        assert!(diff.exited_pids.is_empty());
        assert_eq!(diff.changed_pids.len(), 1);
        assert!(diff.changed_pids.contains(&2));
        assert!(diff.has_changes());
        assert_eq!(diff.change_count(), 1);
    }

    #[test]
    fn test_diff_no_changes() {
        let processes = vec![
            create_test_process(1, "init", None),
            create_test_process(2, "bash", Some(1)),
        ];
        let old_snapshot = create_test_snapshot(processes.clone());
        let new_snapshot = create_test_snapshot(processes);

        let diff = ProcessDiff::new(&old_snapshot, &new_snapshot);

        assert!(diff.new_pids.is_empty());
        assert!(diff.exited_pids.is_empty());
        assert!(diff.changed_pids.is_empty());
        assert!(!diff.has_changes());
        assert_eq!(diff.change_count(), 0);
    }

    #[test]
    fn test_exited_process_buffer() {
        let mut buffer = ExitedProcessBuffer::new(Duration::from_secs(30));

        let process = create_test_process(123, "test", Some(1));
        let exited_at = Instant::now();

        buffer.add_exited(process.clone(), exited_at);

        // Should be recent
        let recent = buffer.recent_exited(Instant::now());
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].process.pid, 123);

        // Simulate time passing beyond 30 seconds
        let future_time = exited_at + Duration::from_secs(31);
        let recent_future = buffer.recent_exited(future_time);
        assert_eq!(recent_future.len(), 0);
    }

    #[test]
    fn test_exited_process_buffer_from_diff() {
        let mut buffer = ExitedProcessBuffer::new(Duration::from_secs(30));

        let old_snapshot = create_test_snapshot(vec![
            create_test_process(1, "init", None),
            create_test_process(2, "bash", Some(1)),
            create_test_process(3, "notepad", Some(2)),
        ]);

        let new_snapshot = create_test_snapshot(vec![
            create_test_process(1, "init", None),
            create_test_process(2, "bash", Some(1)),
        ]);

        let diff = ProcessDiff::new(&old_snapshot, &new_snapshot);
        buffer.add_from_diff(&diff, &old_snapshot);

        let recent = buffer.recent_exited(Instant::now());
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].process.pid, 3);
    }
}
