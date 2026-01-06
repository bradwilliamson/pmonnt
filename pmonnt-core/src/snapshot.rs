//! Process snapshot functionality

use crate::process::Process;
use anyhow;
use std::collections::HashMap;
use std::time::Instant;

/// A snapshot of processes at a specific point in time
#[derive(Debug, Clone)]
pub struct ProcessSnapshot {
    /// When the snapshot was taken
    pub taken_at: Instant,
    /// All processes in the snapshot
    pub processes: Vec<Process>,
    /// Quick lookup map: PID -> Process
    pub process_map: HashMap<u32, Process>,
}

impl ProcessSnapshot {
    /// Create a new snapshot from the current process enumeration
    pub fn new() -> anyhow::Result<Self> {
        let processes = crate::process::enumerate_processes()?;
        let taken_at = Instant::now();
        let process_map = processes.iter().map(|p| (p.pid, p.clone())).collect();

        Ok(Self {
            taken_at,
            processes,
            process_map,
        })
    }

    /// Get a process by PID
    pub fn get_process(&self, pid: u32) -> Option<&Process> {
        self.process_map.get(&pid)
    }

    /// Check if a PID exists in this snapshot
    pub fn has_pid(&self, pid: u32) -> bool {
        self.process_map.contains_key(&pid)
    }

    /// Get all PIDs in this snapshot
    pub fn pids(&self) -> impl Iterator<Item = u32> + '_ {
        self.process_map.keys().copied()
    }

    /// Get the number of processes
    pub fn len(&self) -> usize {
        self.processes.len()
    }

    /// Check if snapshot is empty
    pub fn is_empty(&self) -> bool {
        self.processes.is_empty()
    }
}

impl Default for ProcessSnapshot {
    fn default() -> Self {
        Self {
            taken_at: Instant::now(),
            processes: Vec::new(),
            process_map: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_creation() {
        let snapshot = ProcessSnapshot::new().unwrap();
        assert!(!snapshot.is_empty());
        assert_eq!(snapshot.processes.len(), snapshot.process_map.len());
    }

    #[test]
    fn test_snapshot_lookup() {
        let snapshot = ProcessSnapshot::new().unwrap();

        // Test that we can look up processes
        for process in &snapshot.processes {
            let looked_up = snapshot.get_process(process.pid);
            assert_eq!(looked_up, Some(process));
            assert!(snapshot.has_pid(process.pid));
        }

        // Test non-existent PID
        assert!(!snapshot.has_pid(u32::MAX));
        assert_eq!(snapshot.get_process(u32::MAX), None);
    }

    #[test]
    fn test_snapshot_pids() {
        let snapshot = ProcessSnapshot::new().unwrap();
        let pids: Vec<u32> = snapshot.pids().collect();
        assert_eq!(pids.len(), snapshot.len());

        for &pid in &pids {
            assert!(snapshot.has_pid(pid));
        }
    }
}
