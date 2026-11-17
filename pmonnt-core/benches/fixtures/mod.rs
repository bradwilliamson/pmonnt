//! Deterministic, realistic-looking inputs shared by the Gungraun benchmarks.
//!
//! The process table mimics a Windows desktop: a handful of system roots, many
//! `svchost.exe` under `services.exe`, browsers with dozens of renderer children,
//! and mixed-case names. Every metric map is populated so sorts and aggregations
//! take their full code paths.

#![allow(dead_code)] // each bench binary uses a different subset

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use pmonnt_core::SignatureInfo;
use pmonnt_core::handles::{HandleCache, HandleEntry, HandleSummary};
use pmonnt_core::metrics::IoRate;
use pmonnt_core::process::Process;
use pmonnt_core::view::RowMetrics;

/// Small deterministic PRNG (SplitMix64) so fixtures are identical on every run.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// (name, relative weight) roughly matching a busy Windows 11 desktop.
const NAMES: &[(&str, u64)] = &[
    ("svchost.exe", 90),
    ("chrome.exe", 40),
    ("msedge.exe", 30),
    ("Code.exe", 20),
    ("RuntimeBroker.exe", 12),
    ("conhost.exe", 10),
    ("dllhost.exe", 8),
    ("WmiPrvSE.exe", 4),
    ("backgroundTaskHost.exe", 4),
    ("SearchHost.exe", 2),
    ("explorer.exe", 1),
    ("MsMpEng.exe", 1),
    ("NisSrv.exe", 1),
    ("spoolsv.exe", 1),
    ("lsass.exe", 1),
    ("winlogon.exe", 1),
    ("dwm.exe", 1),
    ("fontdrvhost.exe", 2),
    ("sihost.exe", 1),
    ("taskhostw.exe", 2),
    ("ctfmon.exe", 1),
    ("OneDrive.exe", 1),
    ("Teams.exe", 6),
    ("Slack.exe", 5),
    ("Discord.exe", 5),
    ("steamwebhelper.exe", 6),
    ("nvcontainer.exe", 3),
    ("NVDisplay.Container.exe", 2),
    ("audiodg.exe", 1),
    ("cargo.exe", 2),
    ("rustc.exe", 4),
    ("rust-analyzer.exe", 2),
    ("pwsh.exe", 3),
    ("WindowsTerminal.exe", 1),
    ("OpenConsole.exe", 3),
    ("Docker Desktop.exe", 2),
    ("vmmem", 1),
    ("PMonNT.exe", 1),
    ("TextInputHost.exe", 1),
    ("StartMenuExperienceHost.exe", 1),
    ("ShellExperienceHost.exe", 1),
    ("SecurityHealthService.exe", 1),
    ("smartscreen.exe", 1),
    ("WUDFHost.exe", 3),
    ("igfxEM.exe", 1),
    ("jucheck.exe", 1),
    ("Zoom.exe", 2),
    ("ollama.exe", 1),
    ("node.exe", 6),
    ("python.exe", 3),
];

/// A synthetic system: processes plus every per-PID map the view model reads.
pub struct Fixture {
    pub processes: Vec<Process>,
    pub handle_cache: HandleCache,
    pub thread_counts: HashMap<u32, usize>,
    pub cpu_memory: HashMap<u32, (f32, Option<u64>)>,
    pub io_rates: HashMap<u32, IoRate>,
    pub gpu: HashMap<u32, (f32, u64, u64, u64)>,
    pub signatures: HashMap<String, SignatureInfo>,
    pub image_paths: HashMap<u32, String>,
}

impl Fixture {
    pub fn metrics(&self) -> RowMetrics<'_> {
        RowMetrics {
            handle_cache: &self.handle_cache,
            global_thread_counts: &self.thread_counts,
            cpu_memory_data: &self.cpu_memory,
            io_rate_by_pid: &self.io_rates,
            gpu_data: &self.gpu,
            signature_cache_by_path: &self.signatures,
        }
    }

    /// Every PID that has children, i.e. "expand all" in the tree view.
    pub fn all_parents(&self) -> HashSet<u32> {
        self.processes.iter().filter_map(|p| p.ppid).collect()
    }
}

fn pick_name(rng: &mut Rng) -> &'static str {
    let total: u64 = NAMES.iter().map(|(_, w)| w).sum();
    let mut x = rng.below(total);
    for (name, w) in NAMES {
        if x < *w {
            return name;
        }
        x -= w;
    }
    NAMES[0].0
}

fn process(pid: u32, ppid: u32, name: &str, path: Option<String>) -> Process {
    Process {
        pid,
        name: name.to_string(),
        ppid: Some(ppid),
        cpu_percent: None,
        memory_bytes: None,
        gpu_percent: None,
        gpu_memory_bytes: None,
        path,
        signature: None,
    }
}

fn path_for(name: &str) -> String {
    match name {
        "chrome.exe" => r"C:\Program Files\Google\Chrome\Application\chrome.exe".to_string(),
        "msedge.exe" => r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe".to_string(),
        "Code.exe" => r"C:\Users\dev\AppData\Local\Programs\Microsoft VS Code\Code.exe".to_string(),
        n => format!(r"C:\Windows\System32\{n}"),
    }
}

/// Build a process table with roughly `n` processes and fully populated metrics.
pub fn fixture(n: usize) -> Fixture {
    let mut rng = Rng::new(0x5EED_0000 + n as u64);
    let mut processes = Vec::with_capacity(n);

    // Fixed system roots.
    processes.push(process(0, 0, "System Idle Process", None));
    processes.push(process(4, 0, "System", None));
    processes.push(process(120, 4, "Registry", None));
    processes.push(process(480, 4, "smss.exe", Some(path_for("smss.exe"))));
    processes.push(process(700, 600, "csrss.exe", Some(path_for("csrss.exe")))); // orphan root
    processes.push(process(
        800,
        600,
        "wininit.exe",
        Some(path_for("wininit.exe")),
    ));
    processes.push(process(
        900,
        800,
        "services.exe",
        Some(path_for("services.exe")),
    ));
    processes.push(process(
        5000,
        4900,
        "explorer.exe",
        Some(path_for("explorer.exe")),
    )); // orphan root

    let mut next_pid = 1000u32;
    while processes.len() < n {
        let name = pick_name(&mut rng);
        let parent = match name {
            "svchost.exe"
            | "spoolsv.exe"
            | "MsMpEng.exe"
            | "NisSrv.exe"
            | "nvcontainer.exe"
            | "SecurityHealthService.exe"
            | "WUDFHost.exe" => 900,
            "chrome.exe" | "msedge.exe" | "Code.exe" | "Teams.exe" | "Slack.exe"
            | "Discord.exe" | "steamwebhelper.exe" => {
                // Browsers/Electron: first instance under explorer, the rest under a sibling.
                match processes.iter().rev().find(|p| p.name == name) {
                    Some(p) => p.pid,
                    None => 5000,
                }
            }
            _ => {
                // Anything else hangs off a random earlier process (depth grows naturally).
                processes[rng.below(processes.len() as u64) as usize].pid
            }
        };
        let path = if rng.below(10) == 0 {
            None // inaccessible process
        } else {
            Some(path_for(name))
        };
        processes.push(process(next_pid, parent, name, path));
        next_pid += 4 + rng.below(16) as u32 * 4;
    }

    let mut thread_counts = HashMap::new();
    let mut cpu_memory = HashMap::new();
    let mut io_rates = HashMap::new();
    let mut gpu = HashMap::new();
    let mut image_paths = HashMap::new();
    let mut summaries = HashMap::new();
    for p in &processes {
        if p.pid == 0 {
            continue;
        }
        thread_counts.insert(p.pid, 1 + rng.below(120) as usize);
        let cpu = if rng.below(4) == 0 {
            (rng.unit() * 25.0) as f32
        } else {
            0.0
        };
        let mem = (rng.below(400) + 1) * 1024 * 1024;
        cpu_memory.insert(p.pid, (cpu, Some(mem)));
        io_rates.insert(
            p.pid,
            IoRate {
                read_bytes_per_sec: rng.unit() * 1e6,
                write_bytes_per_sec: rng.unit() * 1e5,
            },
        );
        if rng.below(5) == 0 {
            let d = rng.below(512) * 1024 * 1024;
            let s = rng.below(64) * 1024 * 1024;
            gpu.insert(p.pid, ((rng.unit() * 40.0) as f32, d, s, d + s));
        }
        if let Some(path) = &p.path {
            image_paths.insert(p.pid, path.clone());
        }
        let entries: Vec<(u16, u32)> = [
            (30u16, 1 + rng.below(400) as u32),
            (37, rng.below(100) as u32),
            (15, rng.below(200) as u32),
        ]
        .into_iter()
        .filter(|(_, c)| *c > 0)
        .collect();
        summaries.insert(p.pid, HandleSummary::from_entries(&entries));
    }
    let mut handle_cache = HandleCache::new(u64::MAX / 4);
    handle_cache.update(summaries);

    let mut signatures = HashMap::new();
    for path in image_paths.values() {
        if signatures.contains_key(path) || rng.below(5) == 0 {
            continue; // ~20% of paths not verified yet
        }
        let signed = !path.contains("dev");
        signatures.insert(
            path.clone(),
            SignatureInfo {
                is_signed: signed,
                is_valid: signed,
                signer_name: signed.then(|| {
                    if path.contains("Google") {
                        "Google LLC"
                    } else {
                        "Microsoft Windows"
                    }
                    .to_string()
                }),
                issuer_name: None,
                timestamp: None,
                catalog_signed: path.contains("System32"),
                error: None,
            },
        );
    }

    Fixture {
        processes,
        handle_cache,
        thread_counts,
        cpu_memory,
        io_rates,
        gpu,
        signatures,
        image_paths,
    }
}

/// The same system a refresh later: ~3% of processes exited, a few started, and some
/// renderer processes were recycled under new PIDs.
pub fn next_refresh(prev: &[Process], rng_seed: u64) -> Vec<Process> {
    let mut rng = Rng::new(rng_seed);
    let mut next: Vec<Process> = prev
        .iter()
        .filter(|p| p.pid < 1000 || rng.below(33) != 0)
        .cloned()
        .collect();
    let mut pid = prev.iter().map(|p| p.pid).max().unwrap_or(0) + 4;
    for _ in 0..(prev.len() / 25) {
        let parent = next[rng.below(next.len() as u64) as usize].pid;
        next.push(process(pid, parent, pick_name(&mut rng), None));
        pid += 4;
    }
    next
}

/// A system-wide handle table: `per_process` handles for each process.
pub fn handle_table(processes: &[Process], per_process: usize) -> Vec<HandleEntry> {
    let mut rng = Rng::new(0xA11CE);
    const TYPES: [u16; 8] = [30, 37, 15, 8, 7, 40, 17, 42];
    let mut out = Vec::with_capacity(processes.len() * per_process);
    for p in processes {
        for h in 0..per_process {
            out.push(HandleEntry {
                pid: p.pid,
                handle_value: (h + 1) * 4,
                object_type_index: TYPES[rng.below(TYPES.len() as u64) as usize],
                granted_access: 0x1F_0FFF,
            });
        }
    }
    out
}

/// Fake `Instant` so benches that construct snapshots do not depend on the clock.
pub fn epoch() -> Instant {
    Instant::now()
}

/// Teardown for every benchmark: drop the benchmark's output (and the inputs it hands back)
/// outside the measured region, so freeing fixtures is not counted.
#[inline(never)] // must stay a real symbol: Gungraun toggles measurement off by function name
pub fn discard<T>(value: T) {
    drop(std::hint::black_box(value));
}
