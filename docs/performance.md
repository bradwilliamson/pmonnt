# Performance tooling (Gungraun / Valgrind)

PMonNT is a Windows application, but its hot, platform-independent logic lives in
`pmonnt-core` and also builds on Linux. That code can be measured precisely under
[Valgrind](https://valgrind.org/) with [Gungraun](https://github.com/gungraun/gungraun)
(formerly iai-callgrind):

- `pmonnt_core::view`: the process-list view model (tree and grouped rows: sorting,
  filtering, aggregation), which runs on every UI frame.
- `snapshot` / `diff`: the 2-second refresh.
- `handles`: per-process handle summaries and leak detection on every handle scan.
- `hashing`, `yara::engine`: SHA-256 streaming and YARA buffer scans.

The Win32 collectors themselves (`pmonnt-core/src/win`, the UI) are Windows-only and not
covered here.

## Why instruction counts

Gungraun runs each benchmark once under Callgrind and reports instructions, cache hits and
an estimated cycle count, plus DHAT heap totals (allocations, bytes). The numbers are
deterministic, so a 1% change is real, CI noise doesn't matter, and a regression shows up
in a single run. Wall-clock timing would need many repetitions on a quiet machine.

## Setup (Linux or WSL)

```bash
sudo apt-get install valgrind                         # 3.22+
cargo install gungraun-runner --version 0.20.0 --locked   # must match the `gungraun` crate
```

## Running

```bash
# All benchmarks
cargo bench -p pmonnt-core --bench view_model --bench core_paths

# Save a baseline, change code, compare against it
cargo bench -p pmonnt-core --bench view_model -- --save-baseline=before
cargo bench -p pmonnt-core --bench view_model -- --baseline=before
```

Pass the `--bench` names explicitly. A bare `cargo bench -p pmonnt-core -- <args>` would
also hand the Gungraun arguments to other targets. Baseline names may only contain
letters, digits and `_`.

Profiles land in `target/gungraun/pmonnt-core/<bench>/<group>/<benchmark>/`. To see where
the instructions go:

```bash
callgrind_annotate --inclusive=yes \
  target/gungraun/pmonnt-core/view_model/view_model/tree_frame.cpu_400/callgrind.tree_frame.cpu_400.out
# or open the .out file in KCachegrind / QCachegrind
```

### What the benchmarks measure

| Benchmark | Work | Cadence in the app |
|---|---|---|
| `view_model::tree_frame` | Build the tree view rows (sorted roots, expanded children) | every frame (>= 10/s) |
| `view_model::grouped_frame`, `grouped_rows` | Build the grouped view rows | every frame |
| `view_model::view_index_build` | Children, roots, lowercase names, groups, labels for a snapshot | once per refresh (2 s) |
| `core_paths::snapshot_refresh` | Index a new snapshot, diff it, record exited processes | every 2 s |
| `core_paths::handle_scan` | Summaries and leak-detector update for 100k handles | every 5-10 s |
| `core_paths::sha256_stream` | SHA-256 of a 4 MiB image | per reputation lookup |
| `core_paths::yara_scan_chunk` | YARA scan of a 1 MiB memory chunk | per chunk during a scan |

Inputs come from `pmonnt-core/benches/fixtures`: a deterministic synthetic Windows process
table (400 or 1200 processes, realistic name repetition and parent tree) with every metric
map populated. Each benchmark hands its inputs to a `#[inline(never)]` teardown so freeing
the fixtures is not counted.

Caveats:

- Valgrind does not expose the CPU's SHA extensions, so `sha256_stream` measures sha2's
  portable code. Treat it as a regression guard, not a speed measurement.
- DHAT cannot parse the stack frames of yara-x's JIT-compiled wasm, so the YARA benchmark is
  Callgrind-only.

## Results of the 2026-11 optimization pass

Measured against the commit before the optimizations (same benchmark code and fixtures):

| Benchmark | Instructions before | after | Speedup | Allocations before | after |
|---|---:|---:|---:|---:|---:|
| tree frame, 400 procs | 2,853,588 | 339,178 | 8.4x | 2,938 | 194 |
| tree frame, 1200 procs | 8,884,008 | 993,185 | 8.9x | 8,643 | 391 |
| grouped frame, 400 procs | 2,218,777 | 353,385 | 6.3x | 1,619 | 149 |
| grouped frame, 1200 procs | 6,198,519 | 920,837 | 6.7x | 4,416 | 160 |
| snapshot refresh + diff, 400 | 716,943 | 122,413 | 5.9x | 793 | 33 |
| snapshot refresh + diff, 1200 | 2,150,842 | 353,670 | 6.1x | 2,345 | 70 |
| handle scan, 100k handles | 34,584,808 | 4,451,532 | 7.8x | 5,617 | 4,821 |

The old grouped-view numbers vary by about ±10% between runs, because the old code sorted
groups that started in `HashMap` iteration order (randomized per process), so the number of
comparisons varied. The new code is deterministic. The refresh numbers don't count the full
deep copy of the previous snapshot that the old UI made on every refresh, so they understate
the old cost. The new view index adds about 0.88M instructions once per refresh at 400
processes (`view_index_build`), against roughly 2M saved on every frame.

Where the time went, and what changed:

- **Per-frame copies.** The list panel cloned the whole process list and rebuilt the
  PID map, PID set and parent->children map on every frame. The snapshot is now shared
  (`Arc`), indexes PIDs instead of keeping a second deep copy, and builds a `ViewIndex`
  (children, roots, lowercase names, name groups, row labels) once per snapshot.
- **Allocating comparators.** Tree sorting lowercased both names (two `String`
  allocations) on every comparison, even for numeric sorts, and the grouped view
  re-aggregated every group's metrics inside every comparison. Keys are now computed once
  per PID or group; comparisons only compare plain values. Floats are normalized so the
  order is total (`sort_by` may panic on an inconsistent comparator since Rust 1.81).
- **Clock reads.** `HandleCache::get` read the clock on every call, including inside sort
  comparators; `fresh_summaries()` reads it once per frame.
- **Hashing.** Handle summaries did two SipHash map updates per handle; they now count
  each process's contiguous run in a type-indexed array. Internal PID-keyed maps use a
  multiplicative hasher.
- **Quadratic pruning.** The exited-process buffer was pruned once per exited process.

A randomized differential test (`pmonnt-core/src/view/tests.rs`) checks over 56,000 cases
that the optimized view model produces exactly the same rows as the original
implementation, which is kept test-only in `view/reference`.

## Memcheck

```bash
tools/valgrind/memcheck-core-tests.sh            # all pmonnt-core unit tests
tools/valgrind/memcheck-core-tests.sh aligned    # a filter, like `cargo test`
```

The script exits non-zero on any invalid read or write, use of uninitialised memory, or
definite leak. `tools/valgrind/memcheck.supp` suppresses two well-known false positives in
ring/rustls TLS code. CI runs this script, the Linux core tests and the benchmarks on
every push (`.github/workflows/ci.yml`).
