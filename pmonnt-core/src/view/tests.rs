//! View-model tests (moved from pmonnt-ui so they run on every platform).

use super::*;
use crate::handles::HandleCache;
use crate::metrics::IoRate;
use crate::process;
use std::collections::{HashMap, HashSet};

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
        &processes,
        None,
        "",
        GroupSort::CPU,
        true,
        false,
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
        &processes,
        None,
        "",
        GroupSort::CPU,
        true,
        true,
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
        &processes,
        None,
        "",
        GroupSort::CPU,
        false,
        true,
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
        &processes,
        None,
        "",
        GroupSort::Name,
        true,
        true,
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
        &processes,
        None,
        "",
        GroupSort::Name,
        false,
        true,
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
        &processes,
        None,
        "",
        GroupSort::Memory,
        true,
        false,
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
        &processes,
        None,
        "",
        GroupSort::GPU,
        true,
        false,
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
    let pid_to_proc: HashMap<u32, &process::Process> =
        processes.iter().map(|p| (p.pid, p)).collect();

    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    children.insert(1, vec![2, 3]);

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
        &[1],
        &children,
        &pid_to_proc,
        &expanded,
        None,
        None,
        "",
        16,
        GroupSort::CPU,
        true,
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
    let pid_to_proc: HashMap<u32, &process::Process> =
        processes.iter().map(|p| (p.pid, p)).collect();

    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    children.insert(1, vec![2, 3]);

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
        &[1],
        &children,
        &pid_to_proc,
        &expanded,
        None,
        None,
        "",
        16,
        GroupSort::Memory,
        true,
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
    let pid_to_proc: HashMap<u32, &process::Process> =
        processes.iter().map(|p| (p.pid, p)).collect();

    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    children.insert(1, vec![2, 3]);

    let handle_cache = HandleCache::new(0);
    let global_thread_counts: HashMap<u32, usize> = HashMap::new();
    let cpu_memory_data: HashMap<u32, (f32, Option<u64>)> = HashMap::new();
    let io_rate_by_pid: HashMap<u32, IoRate> = HashMap::new();
    let gpu_data: HashMap<u32, (f32, u64, u64, u64)> = HashMap::new();
    let empty_sig_cache: HashMap<String, crate::SignatureInfo> = HashMap::new();

    // Collapsed: only root is visible.
    let expanded: HashSet<u32> = HashSet::new();
    let rows = build_process_rows(
        &[1],
        &children,
        &pid_to_proc,
        &expanded,
        None,
        None,
        "",
        16,
        GroupSort::Name,
        false,
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
        &[1],
        &children,
        &pid_to_proc,
        &expanded,
        None,
        None,
        "",
        16,
        GroupSort::Name,
        false,
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
