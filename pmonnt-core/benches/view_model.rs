//! Process-list view model: the work PMonNT does on every UI frame.
//!
//! Every benchmark returns its input and hands it to the `discard` teardown, so dropping the
//! (large) fixture happens outside the measured region.
//!
//! Run with `cargo bench -p pmonnt-core --bench view_model` (needs Valgrind and a matching
//! `gungraun-runner`; see docs/performance.md).

mod fixtures;

use std::collections::HashSet;
use std::hint::black_box;

use gungraun::{Dhat, LibraryBenchmarkConfig, library_benchmark, library_benchmark_group, main};
use pmonnt_core::snapshot::ProcessSnapshot;
use pmonnt_core::view::{
    GroupSort, GroupedOptions, GroupedRow, ProcRow, TreeOptions, build_grouped_rows,
    build_process_rows,
};

use fixtures::{Fixture, fixture};

struct Input {
    fx: Fixture,
    snapshot: ProcessSnapshot,
    sort: GroupSort,
    desc: bool,
    leader: bool,
    expanded: HashSet<u32>,
}

fn input(n: usize, sort: GroupSort, leader: bool) -> Input {
    let fx = fixture(n);
    let expanded = fx.all_parents();
    let snapshot = ProcessSnapshot::from_processes(fx.processes.clone(), fixtures::epoch());
    Input {
        fx,
        snapshot,
        sort,
        desc: true,
        leader,
        expanded,
    }
}

/// Like `input`, but with the snapshot's view index already built, as it is for every frame
/// after the first one following a refresh.
fn warm_input(n: usize, sort: GroupSort, leader: bool) -> Input {
    let i = input(n, sort, leader);
    i.snapshot.view_index();
    i
}

fn tree_options(i: &Input) -> TreeOptions<'_> {
    TreeOptions {
        expanded: &i.expanded,
        selected_pid: None,
        visible_pids: None,
        filter_text_lower: "",
        max_depth: 128,
        sort: i.sort,
        sort_desc: i.desc,
    }
}

fn grouped_options(i: &Input) -> GroupedOptions<'static> {
    GroupedOptions {
        selected_pid: None,
        filter_text_lower: "",
        sort: i.sort,
        sort_desc: i.desc,
        sort_by_leader: i.leader,
    }
}

#[library_benchmark(setup = warm_input, teardown = fixtures::discard)]
#[bench::name_400(400, GroupSort::Name, false)]
#[bench::cpu_400(400, GroupSort::CPU, false)]
#[bench::cpu_leader_400(400, GroupSort::CPU, true)]
#[bench::memory_400(400, GroupSort::Memory, false)]
#[bench::signer_400(400, GroupSort::VerifiedSigner, false)]
#[bench::cpu_1200(1200, GroupSort::CPU, false)]
fn grouped_rows(i: Input) -> (Vec<GroupedRow>, Input) {
    let rows = black_box(build_grouped_rows(
        &i.snapshot,
        &grouped_options(&i),
        &i.fx.image_paths,
        &i.fx.metrics(),
    ));
    (rows, i)
}

#[library_benchmark(setup = warm_input, teardown = fixtures::discard)]
#[bench::name_400(400, GroupSort::Name, false)]
#[bench::cpu_400(400, GroupSort::CPU, false)]
#[bench::handles_400(400, GroupSort::Handles, false)]
#[bench::cpu_1200(1200, GroupSort::CPU, false)]
fn tree_frame(i: Input) -> (Vec<ProcRow>, Input) {
    // Per frame the list panel now just builds rows from the shared snapshot.
    let rows = black_box(build_process_rows(
        &i.snapshot,
        &tree_options(&i),
        &i.fx.metrics(),
    ));
    (rows, i)
}

#[library_benchmark(setup = warm_input, teardown = fixtures::discard)]
#[bench::cpu_400(400, GroupSort::CPU, false)]
#[bench::cpu_1200(1200, GroupSort::CPU, false)]
fn grouped_frame(i: Input) -> (Vec<GroupedRow>, Input) {
    let rows = black_box(build_grouped_rows(
        &i.snapshot,
        &grouped_options(&i),
        &i.fx.image_paths,
        &i.fx.metrics(),
    ));
    (rows, i)
}

// The once-per-refresh cost the frames above no longer pay: building the snapshot's view
// index (children, roots, lowercased names, name groups).
#[library_benchmark(setup = input, teardown = fixtures::discard)]
#[bench::index_400(400, GroupSort::CPU, false)]
#[bench::index_1200(1200, GroupSort::CPU, false)]
fn view_index_build(i: Input) -> Input {
    black_box(i.snapshot.view_index());
    i
}

library_benchmark_group!(
    name = view_model;
    benchmarks = grouped_rows, tree_frame, grouped_frame, view_index_build
);

main!(
    config = LibraryBenchmarkConfig::default().tool(Dhat::default());
    library_benchmark_groups = view_model
);
