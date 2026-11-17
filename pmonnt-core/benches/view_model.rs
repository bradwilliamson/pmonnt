//! Process-list view model: the work PMonNT does on every UI frame.
//!
//! Run with `cargo bench -p pmonnt-core --bench view_model` (needs Valgrind and a matching
//! `gungraun-runner`; see docs/performance.md).

mod fixtures;

use std::collections::{HashMap, HashSet};
use std::hint::black_box;

use gungraun::{Dhat, LibraryBenchmarkConfig, library_benchmark, library_benchmark_group, main};
use pmonnt_core::process::Process;
use pmonnt_core::view::{
    GroupSort, GroupedRow, ProcRow, build_grouped_rows, build_process_rows, compare_tree_pids,
};

use fixtures::{Fixture, fixture};

struct Input {
    fx: Fixture,
    sort: GroupSort,
    desc: bool,
    leader: bool,
    expanded: HashSet<u32>,
}

fn input(n: usize, sort: GroupSort, leader: bool) -> Input {
    let fx = fixture(n);
    let expanded = fx.all_parents();
    Input {
        fx,
        sort,
        desc: true,
        leader,
        expanded,
    }
}

/// Mirrors the per-frame tree work in `pmonnt-ui/src/app/update/list_panel`.
fn ui_tree_frame(i: &Input) -> Vec<ProcRow> {
    let metrics = i.fx.metrics();
    let processes = i.fx.processes.clone();
    let pid_to_proc: HashMap<u32, &Process> = processes.iter().map(|p| (p.pid, p)).collect();
    let pid_set: HashSet<u32> = pid_to_proc.keys().copied().collect();
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for p in &processes {
        if let Some(parent) = p.ppid
            && parent != 0
        {
            children.entry(parent).or_default().push(p.pid);
        }
    }
    let mut roots: Vec<u32> = processes
        .iter()
        .filter(|p| p.pid != 0)
        .filter(|p| match p.ppid {
            None | Some(0) => true,
            Some(parent) => !pid_set.contains(&parent),
        })
        .map(|p| p.pid)
        .collect();
    roots.sort_by(|&a, &b| compare_tree_pids(a, b, i.sort, i.desc, &pid_to_proc, &metrics));
    roots.dedup();
    build_process_rows(
        &roots,
        &children,
        &pid_to_proc,
        &i.expanded,
        None,
        None,
        "",
        128,
        i.sort,
        i.desc,
        &metrics,
    )
}

/// Mirrors the per-frame grouped-view work in `pmonnt-ui/src/app/update/list_panel`.
fn ui_grouped_frame(i: &Input) -> Vec<GroupedRow> {
    // The list panel clones the process list and builds the tree maps every frame,
    // whichever view is active.
    let processes = i.fx.processes.clone();
    let pid_to_proc: HashMap<u32, &Process> = processes.iter().map(|p| (p.pid, p)).collect();
    let pid_set: HashSet<u32> = pid_to_proc.keys().copied().collect();
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for p in &processes {
        if let Some(parent) = p.ppid
            && parent != 0
        {
            children.entry(parent).or_default().push(p.pid);
        }
    }
    black_box((&pid_set, &children));
    build_grouped_rows(
        &processes,
        None,
        "",
        i.sort,
        i.desc,
        i.leader,
        &i.fx.image_paths,
        &i.fx.metrics(),
    )
}

#[library_benchmark(setup = input)]
#[bench::name_400(400, GroupSort::Name, false)]
#[bench::cpu_400(400, GroupSort::CPU, false)]
#[bench::cpu_leader_400(400, GroupSort::CPU, true)]
#[bench::memory_400(400, GroupSort::Memory, false)]
#[bench::signer_400(400, GroupSort::VerifiedSigner, false)]
#[bench::cpu_1200(1200, GroupSort::CPU, false)]
fn grouped_rows(i: Input) -> Vec<GroupedRow> {
    black_box(build_grouped_rows(
        &i.fx.processes,
        None,
        "",
        i.sort,
        i.desc,
        i.leader,
        &i.fx.image_paths,
        &i.fx.metrics(),
    ))
}

#[library_benchmark(setup = input)]
#[bench::name_400(400, GroupSort::Name, false)]
#[bench::cpu_400(400, GroupSort::CPU, false)]
#[bench::handles_400(400, GroupSort::Handles, false)]
#[bench::cpu_1200(1200, GroupSort::CPU, false)]
fn tree_frame(i: Input) -> Vec<ProcRow> {
    black_box(ui_tree_frame(&i))
}

#[library_benchmark(setup = input)]
#[bench::cpu_400(400, GroupSort::CPU, false)]
#[bench::cpu_1200(1200, GroupSort::CPU, false)]
fn grouped_frame(i: Input) -> Vec<GroupedRow> {
    black_box(ui_grouped_frame(&i))
}

library_benchmark_group!(
    name = view_model;
    benchmarks = grouped_rows, tree_frame, grouped_frame
);

main!(
    config = LibraryBenchmarkConfig::default().tool(Dhat::default());
    library_benchmark_groups = view_model
);
