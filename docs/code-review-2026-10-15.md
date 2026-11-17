# PMonNT code review (2026-10-15)

Scope: full read of `pmonnt-core` and the load-bearing parts of `pmonnt-ui`
(app state, refresh loop, background work, GPU sampler, YARA, reputation).
Line numbers refer to the tree at commit `cb9ff06`, before the dependency
upgrade. Nothing below has been fixed yet; this is the review only.

Severity key: **High** = wrong results or hang/crash in normal use.
**Medium** = incorrect in realistic edge cases, leaks, or noticeable stalls.
**Low** = hygiene, latent UB, or performance debt.

---

## High

### H1. Two metric functions loop forever once the process table exceeds 1 MB
`pmonnt-core/src/win/process_metrics.rs:418-469` and `:504-553`
(`get_process_cycle_time_by_pid`, `get_process_handle_count_by_pid`).

`buffer_size` is declared without `mut`. On `STATUS_INFO_LENGTH_MISMATCH` the
loop computes `new_size` but never assigns it (the comment at line 448 admits
this) and `continue`s with the same 1 MB buffer. `SystemProcessInformation`
includes one `SYSTEM_THREAD_INFORMATION` (80 bytes) per thread, so a machine
with roughly 10k+ threads (busy dev box, many browser tabs) exceeds 1 MB and
these functions spin forever. Both are called from
`pmonnt-ui/src/app/perf_window/sampling.rs:99,188` on the UI thread, so opening
a per-process performance window hangs the whole app on such machines.

Fix: make `buffer_size` mutable and assign `new_size` (the same loop in
`get_working_set_bytes_map` at line 225 does this correctly). Better: query the
table once per tick and look up both values, instead of re-querying the entire
system process table twice per PID (see P1).

### H2. Signature verification uses wrong HRESULT constants
`pmonnt-core/src/win/signature.rs:111-114` and
`pmonnt-core/src/win/module.rs:184-187`.

The `TRUST_E_*` / `CRYPT_E_SECURITY_SETTINGS` values are wrong (verified
numerically):

| Constant | In code | Actual |
|---|---|---|
| TRUST_E_NOSIGNATURE | 0x80090200 | 0x800B0100 |
| TRUST_E_EXPLICIT_DISTRUST | 0x80090204 | 0x800B0111 |
| TRUST_E_SUBJECT_NOT_TRUSTED | 0x80090202 | 0x800B0004 |
| CRYPT_E_SECURITY_SETTINGS | 0x80093003 | 0x80092026 |

(`CERT_E_EXPIRED` and `CERT_E_UNTRUSTEDROOT` are correct.) Consequence: the
`verify_code == TRUST_E_NOSIGNATURE` branch in `verify_signature` never matches,
so **every unsigned executable is reported as "signed but Invalid"** instead of
"Not signed". Same for the module list.

Fix: delete the hand-written constants and use
`windows::Win32::Foundation::{TRUST_E_NOSIGNATURE, ...}` (HRESULT newtypes); the
`windows` crate is already compiled with the `Win32_Security_WinTrust` feature,
so `WINTRUST_DATA`, `WINTRUST_FILE_INFO`, `WinVerifyTrust` and the `WTD_*`
constants can replace the duplicated manual FFI in both files.

### H3. "Cache-only URL retrieval" flag is the wrong bit, so signature checks can hit the network
`pmonnt-core/src/win/signature.rs:102` defines
`WTD_CACHE_ONLY_URL_RETRIEVAL = 0x4`. The real value is `0x1000` (`0x4` is
`WTD_NO_POLICY_USAGE_FLAG`). `module.rs:check_signature` passes `dwProvFlags: 0`.
So WinVerifyTrust is free to fetch CRLs/AIA over the network, and with
`fdwRevocationChecks = WTD_REVOKE_NONE` only partially suppressed, a signature
check on an offline or slow-DNS machine can block for many seconds. Signature
work is on the background worker, but module signature checks
(`module.rs:fetch_modules(pid, true)`) are not.

Fix: use `windows::Win32::Security::WinTrust::WTD_CACHE_ONLY_URL_RETRIEVAL`
and also set `WTD_REVOCATION_CHECK_NONE` in `dwProvFlags`.

### H4. Process enumeration aborts on any non-ASCII executable name
`pmonnt-core/src/win/process_enum.rs:27-62,80-91`.

The snapshot uses the ANSI `PROCESSENTRY32` and converts `szExeFile` with
`String::from_utf8`, which fails for any byte ≥ 0x80 in the system code page
(e.g. a German/Japanese/Cyrillic file name). The `?` at line 48 then aborts the
**entire** enumeration, `ProcessSnapshot::new()` returns `Err`, and
`refresh_snapshot_and_metrics` silently skips the refresh forever
(`if let Ok(new_snapshot)` at `snapshot.rs:22`). On a non-English Windows with
one such process the list never updates. The same early return also leaks the
snapshot handle, because `HandleGuard` is only created at the end (line 74).

Fix: switch to `PROCESSENTRY32W` / `Process32FirstW` / `Process32NextW` and
`String::from_utf16_lossy`; wrap the snapshot in `HandleGuard` immediately after
creation.

---

## Medium

### M1. Handle enumeration is silently capped at 100,000 handles
`pmonnt-core/src/win/handles.rs:176`. Windows 10/11 systems routinely have
60k–200k open handles. Above the cap, per-process handle counts and the leak
detector see a truncated, arbitrary subset (whichever entries the kernel put
first), so leak detection becomes unreliable exactly on the busy machines where
it matters. The buffer-growth loop already bounds memory at 100 MB; drop the
100k cap (or raise it to the buffer-derived `max_entries`).

Also in this file: `populate_type_cache` samples only every 10th of the first
1000 entries (line 224), so `TYPE_NAME_CACHE` is mostly empty and is never read
anyway (`get_type_name` is a hard-coded match). The type-index table is only
valid for recent Windows builds; `NtQueryObject(ObjectTypesInformation)` gives
the real names.

### M2. Local reputation cache panics on a future timestamp
`pmonnt-core/src/local_cache.rs:63,90,279`: `now - e.timestamp` on `u64`. The
release profile sets `overflow-checks = true`, so if the cache file contains a
timestamp in the future (clock moved back, VM snapshot restore, hand-edited
file) the app panics inside `LocalCacheProvider::new` during startup. Use
`now.saturating_sub(e.timestamp)` (or `checked_sub` and treat as expired).

### M3. Byte-index slicing of HTTP bodies can panic and kill the reputation worker
`pmonnt-core/src/providers/threatfox.rs:207`: `&text[..text.len().min(2048)]`
panics if byte 2048 is inside a multi-byte UTF-8 character. The panic happens on
the single reputation worker thread (`reputation_service/worker.rs:167`), which
is never restarted, so all later VT/MB/TF lookups stay in "Querying" forever.
Use `chars().take(2048)` as the other providers do. Same pattern at
`pmonnt-ui/src/app/state.rs` (`&src[..src.len().min(500)]`, YARA source
preview).

### M4. Reputation worker builds a new TLS client per request and is single-threaded
`vt.rs:288`, `threatfox.rs:169`, `malwarebazaar/download.rs:27`: a
`reqwest::blocking::Client` (its own tokio runtime + TLS config) is constructed
for every lookup. Build one client per provider in `new()`. Because all
providers run sequentially on one worker thread with 10–30 s timeouts, one
stalled provider blocks every other lookup; consider one thread per provider or
a small pool.

### M5. Blocking Windows calls in the UI thread refresh loop
`pmonnt-ui/src/app/update/snapshot.rs:19-325` runs every 2 s on the egui thread:
`CreateToolhelp32Snapshot`, then per process `OpenProcess` × 2–3
(`get_process_times_by_pid`, `get_io_counters`), and then per process
`get_integrity_level`, `get_user` (`LookupAccountSidW`, which can round-trip to
a domain controller), `get_session_id`, plus PEB reads for new PIDs. The
`pid_to_user/integrity/session` maps are cleared and rebuilt every refresh even
though these values never change for a live PID. The `FRAME STALL` log at
`update.rs:111` is the only safeguard.

Recommendation: move the whole "collect metrics" step onto the background
worker (it already exists) and send a `MetricsSnapshot` struct back over a
channel, as `update_handles_cache` already does; cache user/integrity/session
per PID until the PID exits; cache `LookupAccountSidW` results by SID string.

### M6. GPU PDH sampler blocks the UI thread
`pmonnt-ui/src/gpu_pdh/sampler.rs:317`: `smoke_test` sleeps 200 ms inside
`GpuPdhSampler::new()`, which runs in `try_build_app`. `rebuild_counters()`
(three `PdhExpandWildCardPathW` wildcard expansions plus adding hundreds of
counters) runs on the UI thread every 10 s (`state.rs:678`); on machines with
many GPU-using processes this is a visible hitch. Move the sampler to its own
thread that publishes `GpuSnapshot`s.

### M7. Module enumeration and PEB environment reads on the UI thread
`pmonnt-ui/src/app/update/details_panel.rs:889` calls `fetch_modules` (ToolHelp
+ PSAPI + PEB walk fallbacks, plus `get_process_protection`) synchronously when
the Modules tab is opened; `:602` reads the full remote environment block
(`get_process_details(pid, true)`) synchronously. Both are one-shot per PID but
can take 100 ms+ for large processes. Dispatch to `bg_worker` like threads and
security info already are.

### M8. Writable data goes next to the executable / into the CWD
`pmonnt-ui/src/app/state.rs`: the reputation cache is
`current_dir()/pmonnt_reputation_cache.json` and the YARA cache is
`current_exe().parent()/yara_cache`. Both fail silently (or scatter files) when
launched from a shortcut, from Program Files, or from `C:\Windows\System32`.
Dumps and layout already use `%LOCALAPPDATA%\PMonNT`; use it for these too.

### M9. YARAify ZIP extraction trusts the declared size
`pmonnt-core/src/yara/rules.rs:244-270` checks `file.size()` (the header's
declared uncompressed size) and then `read_to_string` without a limit. A
crafted or corrupted archive can expand far past the 2 MB/200 MB limits. Wrap the
entry in `.take(MAX_SINGLE_FILE_BYTES + 1)` and reject if it reads past the
limit. Also `reqwest::Client::new()` (lines 194, 350) has no timeout, so a
stalled download of the ~30 MB rules zip hangs that task forever and every
click of "YARAify rules" spawns another.

### M10. Duplicate implementations
- `RuleManager::fetch_yaraify` / `refresh_from_yaraify` and
  `fetch_threatfox_rules` / `refresh_from_threatfox` are near-identical copies
  (`rules.rs:190-395` vs `:420-620`); the H2/H3-style bugs would need fixing in
  both.
- `win/module.rs:check_signature` duplicates `win/signature.rs` (with the same
  wrong constants and *no* cache-only flag).
- `NtQuerySystemInformation` is declared in both `handles.rs` and
  `process_metrics.rs`; `LocalFree` in three files; `ProcessIdToSessionId` and
  `ConvertSidToStringSidW` are hand-bound although the `windows` crate exposes
  them (`Win32_System_RemoteDesktop`, `Win32_Security_Authorization`).
- `yara/memory.rs:is_readable_protection` and
  `ProcessScanner::is_readable` implement the same predicate differently
  (the scanner version treats `PAGE_NOACCESS == 0x01` as a bit flag).

---

## Low

### L1. Unaligned reads through `Vec<u8>`
`handles.rs:158`, `process_metrics.rs:270`, `network.rs:223`, `services.rs:247`,
`thread_stack.rs:347` (`SYMBOL_INFO`), `signature.rs:288` (`CMSG_SIGNER_INFO`)
cast a `Vec<u8>` pointer to a struct with `u64`/pointer fields and dereference
it. `Vec<u8>` only guarantees 1-byte alignment; in practice the allocator gives
16, but it is technically UB and Miri would flag it. Allocate `Vec<u64>` (or
`Vec<MaybeUninit<T>>`) for these buffers, or use `ptr::read_unaligned` as
`token_info.rs` already does.

### L2. `get_process_protection` reports exited processes as protected
`win/mod.rs:141-144`: `OpenProcess` failure (including "process exited") is
mapped to `(true, "Cannot open process")`. `token_info.rs:563-571` then reports
`is_protected_process = Some(true)`.

### L3. Error-code plumbing
- `process_control.rs:356`: an NTSTATUS from `NtSuspendProcess` is stored in
  `Win32 { code }` and rendered as "Windows error 3221225506".
- `thread_stack.rs:178`: `_last_open_error` is captured but never used; the
  final `map_last_error` reads whatever the last `OpenThread` left.
- `main.rs:44-53`: `is_elevated` is derived from whether `SeDebugPrivilege`
  could be enabled, not from `is_app_elevated()`; `can_control_services` keys
  off it.

### L4. `previous_cpu_times` grows forever
`snapshot.rs:151`: entries are only removed when `GetProcessTimes` fails, which
never happens for a PID that simply exited (it is no longer iterated). Prune
with the `alive` set like the other maps.

### L5. `process_info::get_file_version_info` is a stub
`pmonnt-ui/src/process_info.rs:85` returns `(None, None)`, so the Company and
Description columns are always empty, yet `snapshot.rs:292-300` calls it for
every process every refresh. Either implement it (`GetFileVersionInfoSizeW`,
cached by path, off the UI thread) or remove the columns.

### L6. Dead and vestigial code
`ProcessScanner::scan_region` returns `Ok(vec![])`; `perform_process_action`
is `#[allow(dead_code)]` and sleeps 200 ms (`restart_process`) on the caller's
thread; `MemoryRegionIterator`, `network::cache_get_pid`,
`credentials::{save_tf_key, delete_mb_key, ...}` are allowed-dead. The
`handles_v2` feature is a skeleton.

### L7. `ctx.input(|i| i.clone())` every frame
`update.rs:49` clones the full egui input state (events, touches, raw input)
every frame just to read a few keys; take what is needed inside the closure.

### L8. No CI
`.github/workflows` only contains the tag-triggered release build. Nothing runs
`cargo check`, clippy, fmt, tests or `cargo audit` on push. (Being added as part
of the follow-up work.)

---

## Performance notes (for the profiling work)

P1. `sample_perf_stats` (`perf_window/sampling.rs:65`) opens the target process
    six separate times per 0.5 s tick and queries the whole system process
    table twice (H1). One `OpenProcess` + one shared
    `SystemProcessInformation` query per tick would cut this ~10×.
P2. The 2 s refresh (M5) is the dominant UI-thread cost; everything in it is
    cacheable or movable off-thread.
P3. `HashComputer` reads in 8 KB chunks; 256 KB–1 MB buffers roughly double
    SHA-256 throughput on large executables.
P4. `network::get_all_connections` clones the entire connection list on every
    cache hit; return `Arc<Vec<_>>`.
P5. Thread-fetch pool spawns 4–8 OS threads at startup that are idle almost
    always; a single worker (or the existing `bg_worker`) is enough.

## What looks good

- Consistent `HandleGuard` RAII for process/thread/token handles.
- Secrets handling: API keys live in Credential Manager, are never logged
  (`tests/secrets_not_logged.rs` enforces it), and env overrides are explicit.
- PEB parsing (`process_details.rs`) uses `read_unaligned`, bounded reads,
  WoW64 handling and redacts sensitive environment keys.
- YARA scanning streams memory in chunks with overlap and dedupes matches;
  the sync scanner runs on its own thread, not the tokio runtime.
- Kill/suspend refuse PID 0, PID 4 and self.
