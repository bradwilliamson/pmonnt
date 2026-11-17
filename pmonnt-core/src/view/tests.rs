//! View-model tests (moved from pmonnt-ui so they run on every platform).

use super::*;
use crate::handles::HandleCache;
use crate::metrics::IoRate;
use crate::process;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

use crate::snapshot::ProcessSnapshot;

fn snapshot_of(processes: &[process::Process]) -> ProcessSnapshot {
    ProcessSnapshot::from_processes(processes.to_vec(), Instant::now())
}

fn proc(pid: u32, name: &str) -> process::Process {
    process::Process {
        pid,
        name: name.to_string(),
        ppid: None,
        cpu_percent: None,
        memory_bytes: None,
        gpu_percent: None,
        gpu_memory_bytes: None,
        path: None,
        signature: None,
    }
}

fn proc_with_ppid(pid: u32, ppid: Option<u32>, name: &str) -> process::Process {
    process::Process {
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

#[test]
fn grouped_sort_cpu_desc_uses_total_cpu_sum() {
    let processes = vec![
        proc(1, "chrome.exe"),
        proc(2, "chrome.exe"),
        proc(3, "notepad.exe"),
    ];

    let handle_cache = HandleCache::new(0);
    let global_thread_counts: HashMap<u32, usize> = HashMap::new();

    // Total chrome: 30 + 30 = 60; notepad: 40.
    let mut cpu_memory_data: HashMap<u32, (f32, Option<u64>)> = HashMap::new();
    cpu_memory_data.insert(1, (30.0, Some(0)));
    cpu_memory_data.insert(2, (30.0, Some(0)));
    cpu_memory_data.insert(3, (40.0, Some(0)));

    let gpu_data: HashMap<u32, (f32, u64, u64, u64)> = HashMap::new();
    let io_rate_by_pid: HashMap<u32, IoRate> = HashMap::new();

    let empty_str_map: HashMap<u32, String> = HashMap::new();
    let empty_sig_cache: HashMap<String, crate::SignatureInfo> = HashMap::new();

    let rows = build_grouped_rows(
        &snapshot_of(&processes),
        &GroupedOptions {
            selected_pid: None,
            filter_text_lower: "",
            sort: GroupSort::CPU,
            sort_desc: true,
            sort_by_leader: false,
        },
        &empty_str_map,
        &RowMetrics {
            handle_cache: &handle_cache,
            global_thread_counts: &global_thread_counts,
            cpu_memory_data: &cpu_memory_data,
            io_rate_by_pid: &io_rate_by_pid,
            gpu_data: &gpu_data,
            signature_cache_by_path: &empty_sig_cache,
        },
    );

    assert_eq!(rows[0].name, "chrome.exe");
    assert!(rows[0].cpu_percent > rows[1].cpu_percent);
}

#[test]
fn grouped_sort_cpu_leader_toggle_changes_first_group() {
    // Aggregate CPU sort vs Leader CPU sort differ:
    // - a.exe has 2 children at 5% each: sum=10, leader=5
    // - b.exe has 1 child at 9%: sum=9, leader=9
    // So with Leader sort (desc) b.exe should come first.
    let processes = vec![proc(1, "a.exe"), proc(2, "a.exe"), proc(3, "b.exe")];

    let handle_cache = HandleCache::new(0);
    let global_thread_counts: HashMap<u32, usize> = HashMap::new();

    let mut cpu_memory_data: HashMap<u32, (f32, Option<u64>)> = HashMap::new();
    cpu_memory_data.insert(1, (5.0, Some(0)));
    cpu_memory_data.insert(2, (5.0, Some(0)));
    cpu_memory_data.insert(3, (9.0, Some(0)));

    let gpu_data: HashMap<u32, (f32, u64, u64, u64)> = HashMap::new();
    let io_rate_by_pid: HashMap<u32, IoRate> = HashMap::new();

    let empty_str_map: HashMap<u32, String> = HashMap::new();
    let empty_sig_cache: HashMap<String, crate::SignatureInfo> = HashMap::new();

    let desc = build_grouped_rows(
        &snapshot_of(&processes),
        &GroupedOptions {
            selected_pid: None,
            filter_text_lower: "",
            sort: GroupSort::CPU,
            sort_desc: true,
            sort_by_leader: true,
        },
        &empty_str_map,
        &RowMetrics {
            handle_cache: &handle_cache,
            global_thread_counts: &global_thread_counts,
            cpu_memory_data: &cpu_memory_data,
            io_rate_by_pid: &io_rate_by_pid,
            gpu_data: &gpu_data,
            signature_cache_by_path: &empty_sig_cache,
        },
    );
    assert_eq!(desc[0].name, "b.exe");

    let asc = build_grouped_rows(
        &snapshot_of(&processes),
        &GroupedOptions {
            selected_pid: None,
            filter_text_lower: "",
            sort: GroupSort::CPU,
            sort_desc: false,
            sort_by_leader: true,
        },
        &empty_str_map,
        &RowMetrics {
            handle_cache: &handle_cache,
            global_thread_counts: &global_thread_counts,
            cpu_memory_data: &cpu_memory_data,
            io_rate_by_pid: &io_rate_by_pid,
            gpu_data: &gpu_data,
            signature_cache_by_path: &empty_sig_cache,
        },
    );
    assert_eq!(asc[0].name, "a.exe");
}

#[test]
fn leader_sort_falls_back_to_cpu_when_sort_is_name() {
    let processes = vec![proc(10, "a.exe"), proc(11, "a.exe"), proc(20, "b.exe")];

    let handle_cache = HandleCache::new(0);
    let global_thread_counts: HashMap<u32, usize> = HashMap::new();

    let mut cpu_memory_data: HashMap<u32, (f32, Option<u64>)> = HashMap::new();
    cpu_memory_data.insert(10, (1.0, None));
    cpu_memory_data.insert(11, (1.0, None));
    cpu_memory_data.insert(20, (3.0, None));

    let gpu_data: HashMap<u32, (f32, u64, u64, u64)> = HashMap::new();
    let io_rate_by_pid: HashMap<u32, IoRate> = HashMap::new();
    let empty_str_map: HashMap<u32, String> = HashMap::new();
    let empty_sig_cache: HashMap<String, crate::SignatureInfo> = HashMap::new();

    let desc = build_grouped_rows(
        &snapshot_of(&processes),
        &GroupedOptions {
            selected_pid: None,
            filter_text_lower: "",
            sort: GroupSort::Name,
            sort_desc: true,
            sort_by_leader: true,
        },
        &empty_str_map,
        &RowMetrics {
            handle_cache: &handle_cache,
            global_thread_counts: &global_thread_counts,
            cpu_memory_data: &cpu_memory_data,
            io_rate_by_pid: &io_rate_by_pid,
            gpu_data: &gpu_data,
            signature_cache_by_path: &empty_sig_cache,
        },
    );
    assert_eq!(desc[0].name, "b.exe");

    let asc = build_grouped_rows(
        &snapshot_of(&processes),
        &GroupedOptions {
            selected_pid: None,
            filter_text_lower: "",
            sort: GroupSort::Name,
            sort_desc: false,
            sort_by_leader: true,
        },
        &empty_str_map,
        &RowMetrics {
            handle_cache: &handle_cache,
            global_thread_counts: &global_thread_counts,
            cpu_memory_data: &cpu_memory_data,
            io_rate_by_pid: &io_rate_by_pid,
            gpu_data: &gpu_data,
            signature_cache_by_path: &empty_sig_cache,
        },
    );
    assert_eq!(asc[0].name, "a.exe");
}

#[test]
fn grouped_sort_memory_desc_uses_total_memory_sum() {
    let processes = vec![proc(1, "a.exe"), proc(2, "b.exe")];

    let handle_cache = HandleCache::new(0);
    let global_thread_counts: HashMap<u32, usize> = HashMap::new();

    let mut cpu_memory_data: HashMap<u32, (f32, Option<u64>)> = HashMap::new();
    cpu_memory_data.insert(1, (0.0, Some(10_000)));
    cpu_memory_data.insert(2, (0.0, Some(50_000)));

    let gpu_data: HashMap<u32, (f32, u64, u64, u64)> = HashMap::new();
    let io_rate_by_pid: HashMap<u32, IoRate> = HashMap::new();
    let empty_str_map: HashMap<u32, String> = HashMap::new();
    let empty_sig_cache: HashMap<String, crate::SignatureInfo> = HashMap::new();

    let rows = build_grouped_rows(
        &snapshot_of(&processes),
        &GroupedOptions {
            selected_pid: None,
            filter_text_lower: "",
            sort: GroupSort::Memory,
            sort_desc: true,
            sort_by_leader: false,
        },
        &empty_str_map,
        &RowMetrics {
            handle_cache: &handle_cache,
            global_thread_counts: &global_thread_counts,
            cpu_memory_data: &cpu_memory_data,
            io_rate_by_pid: &io_rate_by_pid,
            gpu_data: &gpu_data,
            signature_cache_by_path: &empty_sig_cache,
        },
    );

    assert_eq!(rows[0].name, "b.exe");
    assert!(rows[0].memory_bytes.unwrap() > rows[1].memory_bytes.unwrap());
}

#[test]
fn grouped_sort_gpu_desc_uses_group_max_gpu() {
    let processes = vec![
        proc(1, "group.exe"),
        proc(2, "group.exe"),
        proc(3, "solo.exe"),
    ];

    let handle_cache = HandleCache::new(0);
    let global_thread_counts: HashMap<u32, usize> = HashMap::new();
    let cpu_memory_data: HashMap<u32, (f32, Option<u64>)> = HashMap::new();

    // group.exe max GPU = 75; solo.exe GPU = 50.
    let mut gpu_data: HashMap<u32, (f32, u64, u64, u64)> = HashMap::new();
    gpu_data.insert(1, (10.0, 0, 0, 0));
    gpu_data.insert(2, (75.0, 0, 0, 0));
    gpu_data.insert(3, (50.0, 0, 0, 0));

    let io_rate_by_pid: HashMap<u32, IoRate> = HashMap::new();

    let empty_str_map: HashMap<u32, String> = HashMap::new();
    let empty_sig_cache: HashMap<String, crate::SignatureInfo> = HashMap::new();

    let rows = build_grouped_rows(
        &snapshot_of(&processes),
        &GroupedOptions {
            selected_pid: None,
            filter_text_lower: "",
            sort: GroupSort::GPU,
            sort_desc: true,
            sort_by_leader: false,
        },
        &empty_str_map,
        &RowMetrics {
            handle_cache: &handle_cache,
            global_thread_counts: &global_thread_counts,
            cpu_memory_data: &cpu_memory_data,
            io_rate_by_pid: &io_rate_by_pid,
            gpu_data: &gpu_data,
            signature_cache_by_path: &empty_sig_cache,
        },
    );

    assert_eq!(rows[0].name, "group.exe");
    assert!(rows[0].gpu_percent >= rows[1].gpu_percent);
}

#[test]
fn tree_sort_cpu_desc_sorts_siblings_by_cpu() {
    // root(1) with children [2,3]
    let p1 = proc_with_ppid(1, None, "root.exe");
    let p2 = proc_with_ppid(2, Some(1), "a.exe");
    let p3 = proc_with_ppid(3, Some(1), "b.exe");

    let processes = [p1, p2, p3];

    let expanded: HashSet<u32> = [1].into_iter().collect();
    let handle_cache = HandleCache::new(0);
    let global_thread_counts: HashMap<u32, usize> = HashMap::new();

    let mut cpu_memory_data: HashMap<u32, (f32, Option<u64>)> = HashMap::new();
    cpu_memory_data.insert(2, (10.0, Some(0)));
    cpu_memory_data.insert(3, (90.0, Some(0)));

    let io_rate_by_pid: HashMap<u32, IoRate> = HashMap::new();

    let gpu_data: HashMap<u32, (f32, u64, u64, u64)> = HashMap::new();
    let empty_sig_cache: HashMap<String, crate::SignatureInfo> = HashMap::new();

    let rows = build_process_rows(
        &snapshot_of(&processes),
        &TreeOptions {
            expanded: &expanded,
            selected_pid: None,
            visible_pids: None,
            filter_text_lower: "",
            max_depth: 16,
            sort: GroupSort::CPU,
            sort_desc: true,
        },
        &RowMetrics {
            handle_cache: &handle_cache,
            global_thread_counts: &global_thread_counts,
            cpu_memory_data: &cpu_memory_data,
            io_rate_by_pid: &io_rate_by_pid,
            gpu_data: &gpu_data,
            signature_cache_by_path: &empty_sig_cache,
        },
    );

    // rows: root, then children. Expect pid 3 first (higher CPU).
    assert_eq!(rows[0].pid, 1);
    assert_eq!(rows[1].pid, 3);
    assert_eq!(rows[2].pid, 2);
}

#[test]
fn tree_sort_memory_desc_sorts_siblings_by_memory() {
    let p1 = proc_with_ppid(1, None, "root.exe");
    let p2 = proc_with_ppid(2, Some(1), "a.exe");
    let p3 = proc_with_ppid(3, Some(1), "b.exe");

    let processes = [p1, p2, p3];

    let expanded: HashSet<u32> = [1].into_iter().collect();
    let handle_cache = HandleCache::new(0);
    let global_thread_counts: HashMap<u32, usize> = HashMap::new();

    let mut cpu_memory_data: HashMap<u32, (f32, Option<u64>)> = HashMap::new();
    cpu_memory_data.insert(2, (0.0, Some(10)));
    cpu_memory_data.insert(3, (0.0, Some(90)));

    let io_rate_by_pid: HashMap<u32, IoRate> = HashMap::new();

    let gpu_data: HashMap<u32, (f32, u64, u64, u64)> = HashMap::new();
    let empty_sig_cache: HashMap<String, crate::SignatureInfo> = HashMap::new();

    let rows = build_process_rows(
        &snapshot_of(&processes),
        &TreeOptions {
            expanded: &expanded,
            selected_pid: None,
            visible_pids: None,
            filter_text_lower: "",
            max_depth: 16,
            sort: GroupSort::Memory,
            sort_desc: true,
        },
        &RowMetrics {
            handle_cache: &handle_cache,
            global_thread_counts: &global_thread_counts,
            cpu_memory_data: &cpu_memory_data,
            io_rate_by_pid: &io_rate_by_pid,
            gpu_data: &gpu_data,
            signature_cache_by_path: &empty_sig_cache,
        },
    );

    assert_eq!(rows[0].pid, 1);
    assert_eq!(rows[1].pid, 3);
    assert_eq!(rows[2].pid, 2);
}

#[test]
fn tree_expansion_controls_child_visibility() {
    // root(1) with children [2,3]
    let p1 = proc_with_ppid(1, None, "root.exe");
    let p2 = proc_with_ppid(2, Some(1), "a.exe");
    let p3 = proc_with_ppid(3, Some(1), "b.exe");

    let processes = [p1, p2, p3];

    let handle_cache = HandleCache::new(0);
    let global_thread_counts: HashMap<u32, usize> = HashMap::new();
    let cpu_memory_data: HashMap<u32, (f32, Option<u64>)> = HashMap::new();
    let io_rate_by_pid: HashMap<u32, IoRate> = HashMap::new();
    let gpu_data: HashMap<u32, (f32, u64, u64, u64)> = HashMap::new();
    let empty_sig_cache: HashMap<String, crate::SignatureInfo> = HashMap::new();

    // Collapsed: only root is visible.
    let expanded: HashSet<u32> = HashSet::new();
    let rows = build_process_rows(
        &snapshot_of(&processes),
        &TreeOptions {
            expanded: &expanded,
            selected_pid: None,
            visible_pids: None,
            filter_text_lower: "",
            max_depth: 16,
            sort: GroupSort::Name,
            sort_desc: false,
        },
        &RowMetrics {
            handle_cache: &handle_cache,
            global_thread_counts: &global_thread_counts,
            cpu_memory_data: &cpu_memory_data,
            io_rate_by_pid: &io_rate_by_pid,
            gpu_data: &gpu_data,
            signature_cache_by_path: &empty_sig_cache,
        },
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].pid, 1);

    // Expanded: root + children are visible.
    let expanded: HashSet<u32> = [1].into_iter().collect();
    let rows = build_process_rows(
        &snapshot_of(&processes),
        &TreeOptions {
            expanded: &expanded,
            selected_pid: None,
            visible_pids: None,
            filter_text_lower: "",
            max_depth: 16,
            sort: GroupSort::Name,
            sort_desc: false,
        },
        &RowMetrics {
            handle_cache: &handle_cache,
            global_thread_counts: &global_thread_counts,
            cpu_memory_data: &cpu_memory_data,
            io_rate_by_pid: &io_rate_by_pid,
            gpu_data: &gpu_data,
            signature_cache_by_path: &empty_sig_cache,
        },
    );
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].pid, 1);
    assert!(rows.iter().any(|r| r.pid == 2));
    assert!(rows.iter().any(|r| r.pid == 3));
}

// ---------------------------------------------------------------------------------------
// Differential tests: the optimized builders must produce exactly the same rows as the
// original implementation (kept in `super::reference`) on randomized inputs.
// ---------------------------------------------------------------------------------------

mod differential {
    use super::super::reference;
    use super::*;
    use crate::handles::HandleSummary;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
        fn chance(&mut self, pct: u64) -> bool {
            self.below(100) < pct
        }
    }

    // No two names differ only by case: the original grouped sort left such ties in
    // HashMap order, which is not reproducible.
    const NAMES: &[&str] = &[
        "svchost.exe",
        "chrome.exe",
        "Code.exe",
        "explorer.exe",
        "csrss.exe",
        "RuntimeBroker.exe",
        "conhost.exe",
        "MsMpEng.exe",
        "zoom.exe",
        "Ärger.exe",
        "日本語.exe",
        " ",
        "a",
        "B",
    ];
    const SORTS: [GroupSort; 10] = [
        GroupSort::Name,
        GroupSort::VerifiedSigner,
        GroupSort::CPU,
        GroupSort::Memory,
        GroupSort::Disk,
        GroupSort::GPU,
        GroupSort::GPUMemory,
        GroupSort::Handles,
        GroupSort::PID,
        GroupSort::Threads,
    ];

    struct World {
        processes: Vec<process::Process>,
        handle_cache: HandleCache,
        threads: HashMap<u32, usize>,
        cpu_mem: HashMap<u32, (f32, Option<u64>)>,
        io: HashMap<u32, IoRate>,
        gpu: HashMap<u32, (f32, u64, u64, u64)>,
        sigs: HashMap<String, crate::SignatureInfo>,
        paths: HashMap<u32, String>,
    }

    impl World {
        fn metrics(&self) -> RowMetrics<'_> {
            RowMetrics {
                handle_cache: &self.handle_cache,
                global_thread_counts: &self.threads,
                cpu_memory_data: &self.cpu_mem,
                io_rate_by_pid: &self.io,
                gpu_data: &self.gpu,
                signature_cache_by_path: &self.sigs,
            }
        }
    }

    fn world(seed: u64) -> World {
        let mut r = Rng(seed);
        let n = 1 + r.below(60) as usize;
        let mut processes: Vec<process::Process> = Vec::new();
        let mut pids: Vec<u32> = Vec::new();
        for i in 0..n {
            // PID 0 sometimes present; occasional cycles and dangling parents.
            let pid = if i == 0 && r.chance(30) {
                0
            } else {
                4 + 4 * (i as u32) + 4 * r.below(3) as u32
            };
            if pids.contains(&pid) {
                continue;
            }
            let ppid = match r.below(10) {
                0 => None,
                1 => Some(0),
                2 => Some(9_999_000 + r.below(5) as u32), // parent not in snapshot
                3 if !pids.is_empty() => Some(pid),       // self-parent
                _ if !pids.is_empty() => Some(pids[r.below(pids.len() as u64) as usize]),
                _ => None,
            };
            let name = NAMES[r.below(NAMES.len() as u64) as usize];
            let path = r.chance(70).then(|| format!(r"C:\x\{}", r.below(6)));
            pids.push(pid);
            processes.push(process::Process {
                pid,
                name: name.to_string(),
                ppid,
                cpu_percent: None,
                memory_bytes: None,
                gpu_percent: None,
                gpu_memory_bytes: None,
                path,
                signature: None,
            });
        }
        // Occasionally make two existing processes parents of each other (a cycle).
        if processes.len() > 2 && r.chance(20) {
            let (a, b) = (processes[1].pid, processes[2].pid);
            processes[1].ppid = Some(b);
            processes[2].ppid = Some(a);
        }

        let mut threads = HashMap::new();
        let mut cpu_mem = HashMap::new();
        let mut io = HashMap::new();
        let mut gpu = HashMap::new();
        let mut summaries = HashMap::new();
        let mut paths = HashMap::new();
        for p in &processes {
            // Small value ranges so ties (and the tie-break rules) get exercised.
            if r.chance(80) {
                threads.insert(p.pid, r.below(4) as usize);
            }
            if r.chance(80) {
                let mem = r.chance(80).then(|| r.below(4) * 1024);
                cpu_mem.insert(p.pid, (r.below(4) as f32 * 0.5, mem));
            }
            if r.chance(70) {
                io.insert(
                    p.pid,
                    IoRate {
                        read_bytes_per_sec: r.below(3) as f64 * 100.0,
                        write_bytes_per_sec: r.below(3) as f64 * 10.0,
                    },
                );
            }
            if r.chance(40) {
                let d = r.below(3) * 512;
                gpu.insert(p.pid, (r.below(3) as f32 * 2.0, d, 64, d + 64));
            }
            if r.chance(70) {
                summaries.insert(
                    p.pid,
                    HandleSummary::from_entries(&[(30, r.below(5) as u32)]),
                );
            }
            if let Some(path) = &p.path {
                paths.insert(p.pid, path.clone());
            }
        }
        let mut handle_cache = HandleCache::new(3600);
        handle_cache.update(summaries);

        let mut sigs = HashMap::new();
        for i in 0..6 {
            if r.chance(70) {
                let valid = r.chance(60);
                sigs.insert(
                    format!(r"C:\x\{i}"),
                    crate::SignatureInfo {
                        is_signed: r.chance(80),
                        is_valid: valid,
                        signer_name: r
                            .chance(70)
                            .then(|| ["Microsoft", "Google LLC", "Äcme"][i % 3].to_string()),
                        issuer_name: None,
                        timestamp: None,
                        catalog_signed: r.chance(30),
                        error: [
                            None,
                            Some("Expired".to_string()),
                            Some("Untrusted".to_string()),
                        ][r.below(3) as usize]
                            .clone(),
                    },
                );
            }
        }
        World {
            processes,
            handle_cache,
            threads,
            cpu_mem,
            io,
            gpu,
            sigs,
            paths,
        }
    }

    /// The per-frame pipeline the UI ran before this optimization.
    fn reference_visible(
        processes: &[process::Process],
        filter_lower: &str,
    ) -> Option<HashSet<u32>> {
        if filter_lower.is_empty() {
            return None;
        }
        let pid_to_proc: HashMap<u32, &process::Process> =
            processes.iter().map(|p| (p.pid, p)).collect();
        let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
        for p in processes {
            if let Some(parent) = p.ppid
                && parent != 0
            {
                children_map.entry(parent).or_default().push(p.pid);
            }
        }
        let mut matching = HashSet::new();
        for p in processes {
            if p.name.to_lowercase().contains(filter_lower)
                || p.pid.to_string().contains(filter_lower)
            {
                matching.insert(p.pid);
            }
        }
        let mut expanded = matching.clone();
        for &pid in &matching {
            let mut current = pid;
            let mut visited = HashSet::new();
            let mut depth = 0;
            while depth < 128 && !visited.contains(&current) {
                visited.insert(current);
                if let Some(p) = pid_to_proc.get(&current)
                    && let Some(parent) = p.ppid
                    && parent != 0
                    && parent != current
                {
                    expanded.insert(parent);
                    current = parent;
                    depth += 1;
                    continue;
                }
                break;
            }
        }
        for &pid in &matching {
            if let Some(kids) = children_map.get(&pid) {
                expanded.extend(kids.iter().copied());
            }
        }
        Some(expanded)
    }

    #[allow(clippy::too_many_arguments)]
    fn reference_tree(
        w: &World,
        expanded: &HashSet<u32>,
        selected: Option<u32>,
        visible: Option<&HashSet<u32>>,
        filter: &str,
        sort: GroupSort,
        desc: bool,
    ) -> Vec<ProcRow> {
        let metrics = w.metrics();
        let pid_to_proc: HashMap<u32, &process::Process> =
            w.processes.iter().map(|p| (p.pid, p)).collect();
        let pid_set: HashSet<u32> = pid_to_proc.keys().copied().collect();
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        for p in &w.processes {
            if let Some(parent) = p.ppid
                && parent != 0
            {
                children.entry(parent).or_default().push(p.pid);
            }
        }
        let mut roots: Vec<u32> = w
            .processes
            .iter()
            .filter(|p| p.pid != 0)
            .filter(|p| match p.ppid {
                None | Some(0) => true,
                Some(parent) => !pid_set.contains(&parent),
            })
            .map(|p| p.pid)
            .collect();
        if let Some(v) = visible {
            roots.retain(|p| v.contains(p));
        }
        roots.sort_by(|&a, &b| {
            reference::tree::compare_tree_pids(a, b, sort, desc, &pid_to_proc, &metrics)
        });
        roots.dedup();
        reference::tree::build_process_rows(
            &roots,
            &children,
            &pid_to_proc,
            expanded,
            selected,
            visible,
            filter,
            128,
            sort,
            desc,
            &metrics,
        )
    }

    #[test]
    fn optimized_rows_match_reference_implementation() {
        let filters = ["", "s", "exe", "1", "2", "zz", "日本"];
        let mut cases = 0usize;
        for seed in 0..200u64 {
            let w = world(seed);
            let snapshot = ProcessSnapshot::from_processes(w.processes.clone(), Instant::now());
            let metrics = w.metrics();
            let mut r = Rng(seed ^ 0xABCD);
            let expanded: HashSet<u32> = w
                .processes
                .iter()
                .filter(|_| r.chance(70))
                .map(|p| p.pid)
                .collect();
            let selected = w
                .processes
                .get(r.below(w.processes.len() as u64) as usize)
                .map(|p| p.pid);

            for filter in filters {
                let visible_ref = reference_visible(&w.processes, filter);
                let visible_new = filter_visible_pids(&snapshot, filter);
                assert_eq!(
                    visible_new, visible_ref,
                    "visible pids, seed {seed}, filter {filter:?}"
                );

                for sort in SORTS {
                    for desc in [false, true] {
                        let tree_new = build_process_rows(
                            &snapshot,
                            &TreeOptions {
                                expanded: &expanded,
                                selected_pid: selected,
                                visible_pids: visible_new.as_ref(),
                                filter_text_lower: filter,
                                max_depth: 128,
                                sort,
                                sort_desc: desc,
                            },
                            &metrics,
                        );
                        let tree_ref = reference_tree(
                            &w,
                            &expanded,
                            selected,
                            visible_ref.as_ref(),
                            filter,
                            sort,
                            desc,
                        );
                        assert_eq!(
                            tree_new, tree_ref,
                            "tree, seed {seed}, filter {filter:?}, {sort:?}, desc {desc}"
                        );

                        for leader in [false, true] {
                            let grouped_new = build_grouped_rows(
                                &snapshot,
                                &GroupedOptions {
                                    selected_pid: selected,
                                    filter_text_lower: filter,
                                    sort,
                                    sort_desc: desc,
                                    sort_by_leader: leader,
                                },
                                &w.paths,
                                &metrics,
                            );
                            let grouped_ref = reference::grouped::build_grouped_rows(
                                &w.processes,
                                selected,
                                filter,
                                sort,
                                desc,
                                leader,
                                &w.paths,
                                &metrics,
                            );
                            assert_eq!(
                                grouped_new, grouped_ref,
                                "grouped, seed {seed}, filter {filter:?}, {sort:?}, desc {desc}, leader {leader}"
                            );
                            cases += 1;
                        }
                    }
                }
            }
        }
        assert!(cases > 50_000);
    }
}
