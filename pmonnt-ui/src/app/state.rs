use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use pmonnt_core::{
    diff::ExitedProcessBuffer,
    handles::HandleCache,
    hashing::HashComputer,
    local_cache::LocalCacheProvider,
    module::ModuleCache,
    process,
    reputation_service::ReputationService,
    snapshot::ProcessSnapshot,
    thread::{ThreadCache, ThreadInfo},
    token::TokenCache,
    vt::VirusTotalProvider,
    win_thread,
};

use crate::process_table::ProcessColumnId;
use crate::theme::Theme;
use crate::ui_state::{MbUiState, TfUiState, VtUiState, YaraScanState};
use crate::view::{GroupSort, RightTab, ViewMode};

use crate::{credentials, gpu};

use super::{CompactView, Density, PMonNTApp};

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct UiLayoutConfig {
    pub left_panel_width: f32,
    pub right_panel_width: f32,
    pub details_panel_visible: bool,
    pub density: Density,
    pub theme: Theme,
    pub perf_window_width: f32,
    pub perf_window_height: f32,
    pub process_columns_order: Vec<ProcessColumnId>,
    pub process_columns_hidden: Vec<ProcessColumnId>,
}

impl Default for UiLayoutConfig {
    fn default() -> Self {
        Self {
            left_panel_width: 420.0,
            right_panel_width: 420.0,
            details_panel_visible: true,
            density: Density::Comfortable,
            theme: Theme::Dark,
            perf_window_width: 1000.0,
            perf_window_height: 720.0,
            process_columns_order: ProcessColumnId::default_order(),
            process_columns_hidden: ProcessColumnId::default_hidden(),
        }
    }
}

fn get_ui_layout_path() -> std::path::PathBuf {
    if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
        let path = std::path::Path::new(&local_appdata)
            .join("PMonNT")
            .join("pmonnt_ui_layout.ini");
        if let Some(parent) = path.parent() {
            if std::fs::create_dir_all(parent).is_ok() {
                return path;
            }
        }
    }

    std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join("pmonnt_ui_layout.ini")
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn parse_ui_layout_config(s: &str) -> UiLayoutConfig {
    let mut cfg = UiLayoutConfig::default();

    // Backward compatibility: older layout files won't mention newly-added columns.
    // We treat those as default-hidden unless the file already knows about them.
    let mut saw_leader = false;

    for raw_line in s.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim();
        let value = v.trim();

        match key {
            "left_panel_width" => {
                if let Ok(w) = value.parse::<f32>() {
                    cfg.left_panel_width = w;
                }
            }
            "right_panel_width" => {
                if let Ok(w) = value.parse::<f32>() {
                    cfg.right_panel_width = w;
                }
            }
            "details_panel_visible" => {
                if let Ok(b) = value.parse::<bool>() {
                    cfg.details_panel_visible = b;
                }
            }
            "density" => {
                cfg.density = match value {
                    "compact" => Density::Compact,
                    "comfortable" => Density::Comfortable,
                    _ => cfg.density,
                };
            }
            "theme" => {
                if let Some(t) = Theme::from_key(value) {
                    cfg.theme = t;
                }
            }
            "perf_window_width" => {
                if let Ok(w) = value.parse::<f32>() {
                    cfg.perf_window_width = w;
                }
            }
            "perf_window_height" => {
                if let Ok(h) = value.parse::<f32>() {
                    cfg.perf_window_height = h;
                }
            }
            "process_columns_order" => {
                let mut parsed: Vec<ProcessColumnId> = value
                    .split(',')
                    .filter_map(ProcessColumnId::from_key)
                    .collect();

                if parsed.contains(&ProcessColumnId::Leader) {
                    saw_leader = true;
                }

                // Ensure required columns exist and preserve a sane ordering.
                if !parsed.contains(&ProcessColumnId::Name) {
                    parsed.insert(0, ProcessColumnId::Name);
                }
                for col in ProcessColumnId::default_order() {
                    if !parsed.contains(&col) {
                        parsed.push(col);
                    }
                }
                cfg.process_columns_order = parsed;
            }
            "process_columns_hidden" => {
                let parsed: Vec<ProcessColumnId> = value
                    .split(',')
                    .filter_map(ProcessColumnId::from_key)
                    .filter(|c| *c != ProcessColumnId::Name)
                    .collect();

                if parsed.contains(&ProcessColumnId::Leader) {
                    saw_leader = true;
                }

                cfg.process_columns_hidden = parsed;
            }
            _ => {}
        }
    }

    if !saw_leader
        && !cfg
            .process_columns_hidden
            .contains(&ProcessColumnId::Leader)
    {
        cfg.process_columns_hidden.push(ProcessColumnId::Leader);
    }

    cfg
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn serialize_ui_layout_config(cfg: &UiLayoutConfig) -> String {
    let density = match cfg.density {
        Density::Comfortable => "comfortable",
        Density::Compact => "compact",
    };

    let mut out = String::new();
    out.push_str("# PMonNT UI layout\n# Auto-generated; safe to delete\n");
    out.push_str(&format!(
        "left_panel_width={}\nright_panel_width={}\ndetails_panel_visible={}\ndensity={}\ntheme={}\nperf_window_width={}\nperf_window_height={}\n",
        cfg.left_panel_width,
        cfg.right_panel_width,
        cfg.details_panel_visible,
        density,
        cfg.theme.as_key(),
        cfg.perf_window_width,
        cfg.perf_window_height,
    ));

    out.push_str("process_columns_order=");
    for (i, col) in cfg.process_columns_order.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(col.key());
    }
    out.push('\n');

    out.push_str("process_columns_hidden=");
    for (i, col) in cfg.process_columns_hidden.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(col.key());
    }
    out.push('\n');

    out
}

fn load_ui_layout_config() -> (UiLayoutConfig, bool) {
    let path = get_ui_layout_path();
    let s = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return (UiLayoutConfig::default(), false),
    };

    // Determine whether the perf-window size was explicitly persisted.
    // (Older configs won't include these keys.)
    let mut saw_w = false;
    let mut saw_h = false;
    for raw_line in s.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("perf_window_width=") {
            saw_w = true;
        } else if line.starts_with("perf_window_height=") {
            saw_h = true;
        }
    }

    (parse_ui_layout_config(&s), saw_w && saw_h)
}

fn save_ui_layout_config(cfg: &UiLayoutConfig) {
    let path = get_ui_layout_path();
    let _ = std::fs::write(path, serialize_ui_layout_config(cfg));
}

/// Get config file path with fallback (module-level helper)
fn get_config_path() -> std::path::PathBuf {
    // Try %LOCALAPPDATA%\PMonNT first (enterprise-safe)
    if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
        let path = std::path::Path::new(&local_appdata)
            .join("PMonNT")
            .join("pmonnt_handle_leak_config.json");
        // Test writability by attempting to create parent dir
        if let Some(parent) = path.parent() {
            if std::fs::create_dir_all(parent).is_ok() {
                return path;
            }
        }
    }

    // Fallback: next to executable (portable dev build)
    std::env::current_dir()
        .unwrap_or_default()
        .join("pmonnt_handle_leak_config.json")
}

pub(super) fn try_build_app() -> anyhow::Result<PMonNTApp> {
    let tokio_rt = tokio::runtime::Runtime::new()
        .map_err(|e| anyhow::anyhow!("Failed to create Tokio runtime: {e}"))?;
    let tokio_handle = tokio_rt.handle().clone();
    let bg_worker = crate::background_worker::BackgroundWorker::new("pmonnt-ui-bg");
    let selection_hash_generation = Arc::new(std::sync::atomic::AtomicU64::new(0));

    let current_snapshot = ProcessSnapshot::new().unwrap_or_default();
    let mut process_tree: HashMap<Option<u32>, Vec<process::Process>> = HashMap::new();
    for process in &current_snapshot.processes {
        process_tree
            .entry(process.ppid)
            .or_default()
            .push(process.clone());
    }

    // Initialize reputation providers
    let cache_path = std::env::current_dir()
        .unwrap_or_default()
        .join("pmonnt_reputation_cache.json");
    let local_cache = Arc::new(LocalCacheProvider::new(cache_path));
    let vt_provider = Arc::new(VirusTotalProvider::new(local_cache.clone()));

    // API keys and reputation service will be initialized below using credential helper

    // Create channel for handle updates
    let (handle_update_tx, handle_update_rx) = std::sync::mpsc::channel();

    // Create channels for thread fetches using crossbeam for multi-consumer
    let (thread_request_tx, thread_request_rx) = crossbeam_channel::unbounded::<u32>();
    let (thread_result_tx, thread_result_rx) =
        crossbeam_channel::unbounded::<(u32, Result<Vec<ThreadInfo>, String>)>();

    // Signature verification results (background; keyed by image path)
    let (signature_result_tx, signature_result_rx) =
        crossbeam_channel::unbounded::<(String, pmonnt_core::SignatureInfo)>();

    // Service action results (background)
    let (service_action_result_tx, service_action_result_rx) =
        crossbeam_channel::unbounded::<(u32, String, String, Result<(), String>)>();

    // Kill action results (background)
    let (kill_action_result_tx, kill_action_result_rx) =
        crossbeam_channel::unbounded::<(u32, bool, bool, Result<(), String>)>();

    // Dump action results (background)
    let (dump_action_result_tx, dump_action_result_rx) =
        crossbeam_channel::unbounded::<super::DumpJobResult>();

    // Security info results (background)
    let (security_result_tx, security_result_rx) =
        crossbeam_channel::unbounded::<super::SecurityJobResult>();

    // Thread action results (background)
    let (thread_action_result_tx, thread_action_result_rx) =
        crossbeam_channel::unbounded::<super::ThreadActionJobResult>();

    // Spawn parallel worker pool (4-8 threads based on CPU count)
    let num_workers = num_cpus::get().clamp(4, 8);
    log::info!("Spawning {} thread fetch workers", num_workers);

    for worker_id in 0..num_workers {
        let rx = thread_request_rx.clone();
        let tx = thread_result_tx.clone();

        std::thread::spawn(move || {
            while let Ok(pid) = rx.recv() {
                let start = std::time::Instant::now();

                // Fetch threads
                let result = match win_thread::list_threads(pid) {
                    Ok(threads) => Ok(threads),
                    Err(e) => Err(format!("Thread fetch error: {}", e)),
                };

                let elapsed = start.elapsed().as_millis();
                if elapsed > 200 {
                    log::debug!("Worker {} fetched PID {} in {}ms", worker_id, pid, elapsed);
                }

                // Send result back
                let _ = tx.send((pid, result));
            }
        });
    }

    // Drop original tx so channel closes when all workers exit
    drop(thread_result_tx);

    // Load handle leak detector config
    let mut handle_cache = HandleCache::new(5);
    let config_path = get_config_path();
    let _ = handle_cache.load_config(&config_path);

    // Load persisted UI layout config (splitter width + density + perf window size).
    let (ui_layout, perf_window_size_persisted) = load_ui_layout_config();

    // If the perf-window size wasn't persisted (fresh install / older config),
    // leave it unset so we can compute a sensible default from the main window
    // when the first popout is opened.
    let (perf_window_width, perf_window_height) = if perf_window_size_persisted {
        (ui_layout.perf_window_width, ui_layout.perf_window_height)
    } else {
        (0.0, 0.0)
    };

    // ====== REPLACE FROM HERE ======

    // Load all API keys from Windows Credential Manager (with env var overrides)
    let api_keys = credentials::ApiKeys::load();

    // Set VT provider key if available
    if let Some(ref vt_key) = api_keys.vt {
        vt_provider.set_api_key(vt_key.clone());
    }

    // Determine initial enabled states
    let vt_has_key = api_keys.vt.is_some();
    let mb_has_key = api_keys.mb.is_some();
    let tf_has_key = api_keys.tf.is_some();

    // Create reputation service with loaded keys
    let hash_computer = HashComputer::new();
    let reputation_service = Arc::new(ReputationService::new(
        hash_computer,
        local_cache,
        vt_provider.clone(),
        api_keys.mb.clone(),
        api_keys.tf.clone(),
    ));

    // ====== TO HERE ======

    Ok(PMonNTApp {
        _tokio_rt: tokio_rt,
        bg_worker,
        selection_hash_generation,
        last_update: Instant::now(),
        tick: 0,
        current_snapshot,
        previous_snapshot: None,
        last_diff: None,
        exited_buffer: ExitedProcessBuffer::default(),
        last_snapshot_update: Instant::now(),
        process_tree,
        token_cache: TokenCache::default(),
        thread_cache: ThreadCache::new(4),
        thread_prev: HashMap::new(),
        thread_fetch_in_flight: HashSet::new(),
        thread_fetch_started: HashMap::new(),
        thread_fetch_tx: thread_request_tx,
        thread_fetch_rx: thread_result_rx,

        selected_tid_by_pid: HashMap::new(),
        thread_action_in_flight: HashSet::new(),
        thread_action_message_by_key: HashMap::new(),
        thread_permissions_cache: HashMap::new(),
        thread_stack_cache: HashMap::new(),
        thread_action_result_tx,
        thread_action_result_rx,
        hover_pid: None,
        hover_start: None,
        global_thread_counts: win_thread::count_threads_global().unwrap_or_default(),
        module_cache: ModuleCache::new(5),
        selected_pid: None,
        filter_text: String::new(),
        last_filter_text_lower: String::new(),
        cached_visible_pids: None,
        slash_focus_pending: false,
        expanded_pids: HashSet::new(),
        expanded_groups: HashSet::new(),
        expanded_groups_before_filter: None,
        grouped_filter_was_active: false,
        view_mode: ViewMode::default(),
        group_sort: GroupSort::Name,
        sort_desc: false,
        group_sort_by_leader: false,
        right_tab: RightTab::default(),
        network_sort: super::network_sort::NetworkSortState::default(),
        vt_api_key: api_keys.vt.clone().unwrap_or_default(),
        mb_api_key: api_keys.mb.clone().unwrap_or_default(),
        tf_api_key: api_keys.tf.clone().unwrap_or_default(),
        vt_enabled: vt_has_key,
        mb_enabled: mb_has_key,
        tf_enabled: tf_has_key,
        vt_provider: vt_provider.clone(),
        vt_ui_state: VtUiState {
            querying_vt_pid: None,
            querying_vt_sha: None,
            querying_started_at: None,
            last_seen_pid: None,
            current_process_sha: None,
            current_process_sha_pending: Arc::new(Mutex::new(None)),
            last_query_meta: None,
        },
        tf_ui_state: TfUiState::default(),
        reputation_service,
        pid_to_image_path: HashMap::new(),
        online_lookups_enabled: true,
        prev_online_lookups_enabled: true,
        mb_ui_state: MbUiState::default(),
        yara_state: {
            let cache_dir = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.to_path_buf()))
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("yara_cache");
            let mut rule_manager = pmonnt_core::yara::rules::RuleManager::new(cache_dir.clone());

            // Delete old bundled rules that might have corrupt content (from previous versions)
            // This ensures we always have valid default rules
            let _ = std::fs::remove_file(cache_dir.join("eicar_test.yar"));
            let _ = std::fs::remove_file(cache_dir.join("test_string.yar"));

            let rule_count = rule_manager.load_cached_rules().unwrap_or(0);
            if rule_count == 0 {
                // Bundle default YARA rules
                // Note: In raw strings, single backslash is literal
                // YARA needs \\ for a literal backslash in strings
                let eicar_rule = r#"rule EICAR_Test {
    meta:
        description = "EICAR test file"
        author = "PMonNT"
        severity = "low"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}"#;
                let test_rule = r#"rule SuspiciousStrings {
    meta:
        description = "Detects suspicious strings commonly used by malware"
        author = "PMonNT"
        severity = "medium"
    strings:
        $s1 = "mimikatz" nocase
        $s2 = "Invoke-Mimikatz" nocase
        $s3 = "sekurlsa" nocase
        $s4 = "lsadump" nocase
    condition:
        any of them
}"#;
                std::fs::write(cache_dir.join("eicar_test.yar"), eicar_rule).ok();
                std::fs::write(cache_dir.join("suspicious_strings.yar"), test_rule).ok();
                let _ = rule_manager.load_cached_rules();
            }
            log::info!("YARA rule_manager has {} rules", rule_manager.rules().len());
            log::info!(
                "YARA combined source length: {} bytes",
                rule_manager.combined_source().len()
            );
            let yara_engine =
                match pmonnt_core::yara::engine::YaraEngine::from_rule_manager(&rule_manager) {
                    Ok(engine) => {
                        log::info!("YARA engine compiled successfully");
                        Some(Arc::new(engine))
                    }
                    Err(e) => {
                        log::error!("YARA engine compilation failed: {}", e);
                        // Log first 500 chars of combined source for debugging
                        let src = rule_manager.combined_source();
                        log::error!("Combined source preview: {}", &src[..src.len().min(500)]);
                        None
                    }
                };
            YaraScanState {
                scanning: false,
                last_result: None,
                current_progress: None,
                error: None,
                scan_mode: pmonnt_core::yara::scanner::ScanMode::Quick,
                min_severity: pmonnt_core::yara::rules::Severity::High,
                rt_handle: tokio_handle,
                rule_manager: Arc::new(std::sync::Mutex::new(rule_manager)),
                yara_engine,
                progress_rx: None,
                needs_engine_rebuild: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            }
        },
        handle_cache,
        last_handle_update: Instant::now(),
        handle_scan_in_progress: false,
        handle_update_rx,
        handle_update_tx,
        last_handle_scan_duration_ms: 0,
        handle_scan_interval_secs: 10,
        is_elevated: false,
        cpu_memory_data: HashMap::new(),
        previous_cpu_times: HashMap::new(),
        last_cpu_calc_time: None,
        total_cpu_percent: 0.0,
        ram_used_bytes: 0,
        ram_total_bytes: 0,
        io_rate_calc: pmonnt_core::win_process_metrics::IoRateCalculator::default(),
        io_rate_by_pid: HashMap::new(),
        total_gpu_percent: 0.0,
        total_gpu_dedicated_bytes: 0,
        total_gpu_shared_bytes: 0,
        total_gpu_total_bytes: 0,
        gpu_dedicated_capacity_bytes: 0,
        gpu_shared_capacity_bytes: 0,
        gpu_total_capacity_bytes: 0,
        last_gpu_mem_capacity_refresh: Instant::now(),
        gpu_data: HashMap::new(),
        gpu_sampler: gpu::GpuSampler::default(),
        last_gpu_rebuild: Instant::now(),
        last_gpu_sample_timestamp: None,

        perf_windows: HashMap::new(),
        perf_last_sample: Instant::now(),
        perf_sample_accum_secs: 0.0,
        pid_to_command_line: HashMap::new(),
        pid_to_current_directory: HashMap::new(),
        pid_to_company_name: HashMap::new(),
        pid_to_file_description: HashMap::new(),
        pid_to_integrity_level: HashMap::new(),
        pid_to_user: HashMap::new(),
        pid_to_session_id: HashMap::new(),
        pid_to_handle_count: HashMap::new(),
        pid_to_thread_count: HashMap::new(),
        pid_to_environment: HashMap::new(),
        pid_env_attempted: HashSet::new(),

        signature_cache_by_path: HashMap::new(),
        signature_in_flight: HashSet::new(),
        signature_result_tx,
        signature_result_rx,

        process_columns_order: ui_layout.process_columns_order.clone(),
        process_columns_hidden: ui_layout.process_columns_hidden.iter().copied().collect(),
        process_columns_drag: None,

        services_cache_by_pid: HashMap::new(),
        services_error_by_pid: HashMap::new(),
        service_action_in_flight: HashSet::new(),
        service_action_result_tx,
        service_action_result_rx,
        last_service_action_message: None,

        kill_dialog: None,
        kill_action_in_flight: None,
        kill_action_result_tx,
        kill_action_result_rx,

        dump_action_in_flight: None,
        dump_action_result_tx,
        dump_action_result_rx,
        last_dump_path: None,
        status_line: None,
        dump_confirm_dialog: None,

        security_cache_by_pid: HashMap::new(),
        security_in_flight: HashSet::new(),
        security_result_tx,
        security_result_rx,

        pending_copy_sha_pid: None,

        priority_dialog: None,
        affinity_dialog: None,
        service_dialog: None,

        left_panel_width: ui_layout.left_panel_width,
        right_panel_width: ui_layout.right_panel_width,
        details_panel_visible: ui_layout.details_panel_visible,
        compact_view: CompactView::default(),
        was_compact_layout: false,
        density: ui_layout.density,
        theme: ui_layout.theme,
        last_applied_theme: None,

        perf_window_width,
        perf_window_height,

        main_hwnd: None,
        process_permissions_hint_by_pid: HashMap::new(),
    })
}

pub(super) fn build_app() -> PMonNTApp {
    try_build_app().expect("Failed to initialize PMonNTApp")
}

impl Default for PMonNTApp {
    fn default() -> Self {
        build_app()
    }
}

impl PMonNTApp {
    pub(crate) fn try_new() -> anyhow::Result<Self> {
        try_build_app()
    }
}

impl PMonNTApp {
    pub(crate) fn set_is_elevated(&mut self, is_elevated: bool) {
        self.is_elevated = is_elevated;
    }

    #[inline]
    pub(super) fn gpu_sampler_rebuild_due(&self) -> bool {
        // Rebuild every 10 seconds to catch new processes, but keep stable data in between
        cfg!(windows) && self.last_gpu_rebuild.elapsed().as_secs() >= 10
    }
}

impl Drop for PMonNTApp {
    fn drop(&mut self) {
        // Save handle leak detector config on shutdown
        let config_path = get_config_path();
        let _ = self.handle_cache.save_config(&config_path);

        // Save UI layout (splitter width + density + theme)
        save_ui_layout_config(&UiLayoutConfig {
            left_panel_width: self.left_panel_width,
            right_panel_width: self.right_panel_width,
            details_panel_visible: self.details_panel_visible,
            density: self.density,
            theme: self.theme,
            perf_window_width: if self.perf_window_width.is_finite()
                && self.perf_window_width >= 700.0
            {
                self.perf_window_width
            } else {
                1000.0
            },
            perf_window_height: if self.perf_window_height.is_finite()
                && self.perf_window_height >= 500.0
            {
                self.perf_window_height
            } else {
                720.0
            },
            process_columns_order: self.process_columns_order.clone(),
            process_columns_hidden: {
                let mut v: Vec<ProcessColumnId> =
                    self.process_columns_hidden.iter().copied().collect();
                v.sort_by_key(|c| c.key());
                v
            },
        });
    }
}
