//! Every benchmark returns its inputs and hands them to the `discard` teardown, so dropping
//! them happens outside the measured region.
//!
//! Non-UI hot paths: snapshot diffing (every 2 s), handle summaries (every handle scan),
//! SHA-256 of executables (reputation lookups) and YARA buffer scanning.

mod fixtures;

use std::hint::black_box;
use std::io::Cursor;

use gungraun::{Dhat, LibraryBenchmarkConfig, library_benchmark, library_benchmark_group, main};
use pmonnt_core::diff::{ExitedProcessBuffer, ProcessDiff};
use pmonnt_core::handles::{HandleCache, HandleEntry, compute_summaries};
use pmonnt_core::hashing::sha256_hex_from_reader;
use pmonnt_core::process::Process;
use pmonnt_core::snapshot::ProcessSnapshot;
use pmonnt_core::yara::YaraEngine;

use fixtures::{epoch, fixture, handle_table, next_refresh};

/// The previous snapshot already exists when a refresh happens, so it is built in setup.
fn two_refreshes(n: usize) -> (ProcessSnapshot, Vec<Process>) {
    let prev = fixture(n).processes;
    let next = next_refresh(&prev, 7);
    (ProcessSnapshot::from_processes(prev, epoch()), next)
}

// One 2-second refresh: index the new snapshot, diff it against the previous one (which
// already exists) and record exited processes (pmonnt-ui/src/app/update/snapshot.rs).
#[library_benchmark(setup = two_refreshes, teardown = fixtures::discard)]
#[bench::desktop_400(400)]
#[bench::busy_1200(1200)]
fn snapshot_refresh(
    (prev, next): (ProcessSnapshot, Vec<Process>),
) -> (
    ProcessSnapshot,
    ProcessSnapshot,
    ProcessDiff,
    ExitedProcessBuffer,
) {
    let next = ProcessSnapshot::from_processes(next, epoch());
    let diff = ProcessDiff::new(&prev, &next);
    let mut exited = ExitedProcessBuffer::new(std::time::Duration::from_secs(30));
    exited.add_from_diff(&diff, &prev);
    black_box((prev, next, diff, exited))
}

fn handles_input(n: usize, per_process: usize) -> (Vec<HandleEntry>, HandleCache) {
    let fx = fixture(n);
    (
        handle_table(&fx.processes, per_process),
        HandleCache::new(60),
    )
}

// One handle scan: per-PID summaries plus leak-detector updates
// (pmonnt-ui/src/app/update/handles.rs). 400 x 250 = 100k handles is a typical desktop.
#[library_benchmark(setup = handles_input, teardown = fixtures::discard)]
#[bench::handles_100k(400, 250)]
fn handle_scan(
    (handles, mut cache): (Vec<HandleEntry>, HandleCache),
) -> (Vec<HandleEntry>, HandleCache) {
    let summaries = compute_summaries(&handles);
    cache.update(summaries);
    black_box((handles, cache))
}

fn file_bytes(len: usize) -> Vec<u8> {
    let mut rng = fixtures::Rng::new(len as u64);
    (0..len).map(|_| rng.next_u64() as u8).collect()
}

// SHA-256 of an executable image read through the streaming hasher.
#[library_benchmark(setup = file_bytes, teardown = fixtures::discard)]
#[bench::exe_4mib(4 * 1024 * 1024)]
fn sha256_stream(bytes: Vec<u8>) -> (String, Vec<u8>) {
    let hex = sha256_hex_from_reader(Cursor::new(bytes.as_slice())).unwrap();
    black_box((hex, bytes))
}

fn yara_input(len: usize) -> (YaraEngine, Vec<u8>) {
    let rules = r#"
rule Suspicious_Strings {
    strings:
        $a = "mimikatz" ascii wide nocase
        $b = "sekurlsa::logonpasswords" ascii
        $c = { 4D 5A 90 00 03 00 00 00 }
    condition:
        any of them
}
rule Url_Indicator {
    strings:
        $u = /https?:\/\/[a-z0-9.-]{4,40}\/(gate|panel|admin)\.php/ ascii
    condition:
        $u
}
"#;
    let engine = YaraEngine::compile(rules).expect("rules compile");
    let mut data = file_bytes(len);
    data[4096..4104].copy_from_slice(b"mimikatz");
    (engine, data)
}

// Scanning one memory region chunk (the process scanner works in 1-4 MiB chunks).
#[library_benchmark(setup = yara_input, teardown = fixtures::discard)]
#[bench::chunk_1mib(1024 * 1024)]
fn yara_scan_chunk((engine, data): (YaraEngine, Vec<u8>)) -> (usize, YaraEngine, Vec<u8>) {
    let hits = engine.scan_buffer(&data).map_or(0, |m| m.len());
    black_box((hits, engine, data))
}

library_benchmark_group!(
    name = refresh;
    config = LibraryBenchmarkConfig::default().tool(Dhat::default());
    benchmarks = snapshot_refresh, handle_scan
);

// Note: Valgrind does not expose SHA-NI, so this measures sha2's portable code path. It is a
// regression guard for the streaming loop, not a measure of real-hardware hashing speed.
library_benchmark_group!(
    name = hashing;
    config = LibraryBenchmarkConfig::default().tool(Dhat::default());
    benchmarks = sha256_stream
);

// Callgrind only: DHAT cannot parse the stack frames of yara-x's JIT-compiled wasm.
library_benchmark_group!(
    name = yara;
    benchmarks = yara_scan_chunk
);

main!(library_benchmark_groups = refresh, hashing, yara);
