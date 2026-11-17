//! Process snapshot functionality

use crate::process::Process;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

/// Fast hasher for PID-keyed maps (one multiply per key, FxHash-style). PIDs are local,
/// not attacker-chosen, so SipHash's flooding resistance buys nothing here, while the
/// view model hashes PIDs thousands of times per frame.
#[derive(Default, Clone, Copy)]
pub struct PidHasher(u64);

impl Hasher for PidHasher {
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u64(u64::from(b));
        }
    }
    fn write_u32(&mut self, n: u32) {
        self.write_u64(u64::from(n));
    }
    fn write_u64(&mut self, n: u64) {
        self.0 = (self.0.rotate_left(5) ^ n).wrapping_mul(0x517c_c1b7_2722_0a95);
    }
    fn finish(&self) -> u64 {
        self.0
    }
}

/// `HashMap` keyed by PID with [`PidHasher`].
pub type PidMap<V> = HashMap<u32, V, BuildHasherDefault<PidHasher>>;

/// A snapshot of processes at a specific point in time
#[derive(Debug, Clone)]
pub struct ProcessSnapshot {
    /// When the snapshot was taken
    pub taken_at: Instant,
    /// All processes in the snapshot, in enumeration order. Treat as read-only: the lookup
    /// index below is built from it.
    pub processes: Vec<Process>,
    /// PID -> index into `processes`.
    index: PidMap<usize>,
    /// Parent/child relationships and name groups for the process list, built on first use.
    view_index: OnceLock<ViewIndex>,
}

/// Process relationships derived once per snapshot for the tree and grouped views.
#[derive(Debug, Clone)]
pub struct ViewIndex {
    /// Parent PID -> child PIDs (enumeration order). PPID 0 is never a parent.
    pub children: PidMap<Vec<u32>>,
    /// PIDs whose parent is missing, 0 or absent (excluding PID 0), in enumeration order.
    pub roots: Vec<u32>,
    /// Lowercased process names, parallel to `ProcessSnapshot::processes`.
    pub lower_names: Vec<String>,
    /// Tree-view labels ("name (pid)"), parallel to `processes`; shared with every frame's rows.
    pub labels: Vec<Arc<str>>,
    /// Processes grouped by exact executable name (PID 0 and blank names excluded).
    pub groups: Vec<NameGroup>,
}

/// All processes sharing one executable name.
#[derive(Debug, Clone)]
pub struct NameGroup {
    pub name: String,
    pub lower_name: String,
    /// Member PIDs in enumeration order.
    pub pids: Vec<u32>,
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
        let index = processes
            .iter()
            .enumerate()
            .map(|(i, p)| (p.pid, i))
            .collect();
        Self {
            taken_at,
            processes,
            index,
            view_index: OnceLock::new(),
        }
    }

    /// Get a process by PID
    pub fn get_process(&self, pid: u32) -> Option<&Process> {
        self.index.get(&pid).map(|&i| &self.processes[i])
    }

    /// Position of `pid` in `processes`.
    pub fn index_of(&self, pid: u32) -> Option<usize> {
        self.index.get(&pid).copied()
    }

    /// Check if a PID exists in this snapshot
    pub fn has_pid(&self, pid: u32) -> bool {
        self.index.contains_key(&pid)
    }

    /// Get all PIDs in this snapshot
    pub fn pids(&self) -> impl Iterator<Item = u32> + '_ {
        self.index.keys().copied()
    }

    /// Get the number of processes
    pub fn len(&self) -> usize {
        self.processes.len()
    }

    /// Check if snapshot is empty
    pub fn is_empty(&self) -> bool {
        self.processes.is_empty()
    }

    /// Tree/group structure for the process list, computed once and then shared by every
    /// frame until the next snapshot.
    pub fn view_index(&self) -> &ViewIndex {
        self.view_index
            .get_or_init(|| ViewIndex::build(&self.processes, &self.index))
    }

    /// Lowercased name of `pid`, or "" if unknown.
    pub fn lower_name(&self, pid: u32) -> &str {
        self.index
            .get(&pid)
            .map_or("", |&i| self.view_index().lower_names[i].as_str())
    }
}

/// Lowercase like `str::to_lowercase`, skipping the Unicode tables for plain ASCII.
pub(crate) fn lowercase(s: &str) -> String {
    if s.is_ascii() {
        s.to_ascii_lowercase()
    } else {
        s.to_lowercase()
    }
}

impl ViewIndex {
    fn build(processes: &[Process], index: &PidMap<usize>) -> Self {
        let mut children: PidMap<Vec<u32>> = PidMap::default();
        let mut roots = Vec::new();
        let mut group_of: HashMap<&str, usize> = HashMap::new();
        let mut groups: Vec<NameGroup> = Vec::new();
        let lower_names = processes.iter().map(|p| lowercase(&p.name)).collect();
        let labels = processes
            .iter()
            .map(|p| Arc::from(format!("{} ({})", p.name, p.pid)))
            .collect();

        for p in processes {
            if let Some(parent) = p.ppid
                && parent != 0
            {
                children.entry(parent).or_default().push(p.pid);
            }
            if p.pid != 0
                && match p.ppid {
                    None | Some(0) => true,
                    Some(parent) => !index.contains_key(&parent),
                }
            {
                roots.push(p.pid);
            }
            if p.pid != 0 && !p.name.trim().is_empty() {
                let g = *group_of.entry(p.name.as_str()).or_insert_with(|| {
                    groups.push(NameGroup {
                        name: p.name.clone(),
                        lower_name: lowercase(&p.name),
                        pids: Vec::new(),
                    });
                    groups.len() - 1
                });
                groups[g].pids.push(p.pid);
            }
        }

        Self {
            children,
            roots,
            lower_names,
            labels,
            groups,
        }
    }
}

impl Default for ProcessSnapshot {
    fn default() -> Self {
        Self::from_processes(Vec::new(), Instant::now())
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
        assert_eq!(snapshot.processes.len(), snapshot.pids().count());
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
