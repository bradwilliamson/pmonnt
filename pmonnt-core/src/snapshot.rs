//! Process snapshot functionality

use crate::process::Process;
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
    #[cfg(windows)]
    pub fn new() -> anyhow::Result<Self> {
        let processes = crate::process::enumerate_processes()?;
        Ok(Self::from_processes(processes, Instant::now()))
    }

    /// Build a snapshot from an already-enumerated process list.
    pub fn from_processes(processes: Vec<Process>, taken_at: Instant) -> Self {
        let process_map = processes.iter().map(|p| (p.pid, p.clone())).collect();
        Self {
            taken_at,
            processes,
            process_map,
        }
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

    fn proc(pid: u32, ppid: u32, name: &str) -> Process {
        Process {
            pid,
            name: name.to_string(),
            ppid: Some(ppid),
            cpu_percent: None,
            memory_bytes: None,
            gpu_percent: None,
            gpu_memory_bytes: None,
            path: None,
            signature: None,
        }
    }

    #[test]
    fn from_processes_indexes_every_pid() {
        let snapshot = ProcessSnapshot::from_processes(
            vec![
                proc(4, 0, "System"),
                proc(100, 4, "smss.exe"),
                proc(200, 100, "csrss.exe"),
            ],
            Instant::now(),
        );
        assert_eq!(snapshot.len(), 3);
        assert_eq!(
            snapshot.get_process(100).map(|p| p.name.as_str()),
            Some("smss.exe")
        );
        assert!(snapshot.has_pid(200));
        assert!(!snapshot.has_pid(300));
        let mut pids: Vec<u32> = snapshot.pids().collect();
        pids.sort_unstable();
        assert_eq!(pids, vec![4, 100, 200]);
    }

    #[test]
    #[cfg(windows)]
    fn test_snapshot_creation() {
        let snapshot = ProcessSnapshot::new().unwrap();
        assert!(!snapshot.is_empty());
        assert_eq!(snapshot.processes.len(), snapshot.process_map.len());
    }

    #[test]
    #[cfg(windows)]
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
    #[cfg(windows)]
    fn test_snapshot_pids() {
        let snapshot = ProcessSnapshot::new().unwrap();
        let pids: Vec<u32> = snapshot.pids().collect();
        assert_eq!(pids.len(), snapshot.len());

        for &pid in &pids {
            assert!(snapshot.has_pid(pid));
        }
    }
}
