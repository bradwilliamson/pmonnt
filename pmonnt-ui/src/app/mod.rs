//! Core application logic.

use anyhow::Result;
use pmonnt_core::{
    diff::{ExitedProcessBuffer, ProcessDiff},
    handles::HandleCache,
    module::ModuleCache,
    process,
    reputation_service::ReputationService,
    snapshot::ProcessSnapshot,
    thread::{ThreadCache, ThreadInfo},
    token::TokenCache,
    vt::VirusTotalProvider,
};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::theme::Theme;
use crate::ui_renderer::{
    AffinityDialogState, DumpConfirmDialogState, PriorityDialogState, ServiceDialogState,
};
use crate::ui_state::{MbUiState, TfUiState, VtUiState, YaraScanState};
use crate::view::{GroupSort, RightTab, ViewMode};

use crate::gpu;
use crate::process_table::ProcessColumnId;
use crate::process_table::ProcessTablePolicy;
use pmonnt_core::services::ServiceInfo;

#[derive(Debug, Clone)]
pub(crate) enum KillDialogStep {
    Confirm,
    Running,
    Done(Result<(), String>),
}

#[derive(Debug, Clone)]
pub(crate) struct KillDialogState {
    pub(crate) pid: u32,
    pub(crate) kill_tree: bool,
    pub(crate) group_pids: Option<Vec<u32>>,
    pub(crate) group_descendant_count: Option<usize>,
    pub(crate) name: String,
    pub(crate) step: KillDialogStep,
}

#[derive(Clone, Debug)]
pub(crate) struct DumpJobResult {
    #[allow(dead_code)]
    pub(crate) pid: u32,
    #[allow(dead_code)]
    pub(crate) process_name: String,
    #[allow(dead_code)]
    pub(crate) kind: pmonnt_core::win::dump::DumpKind,
    pub(crate) result: Result<std::path::PathBuf, String>,
}

#[derive(Clone, Debug)]
pub(crate) struct SecurityJobResult {
    pub(crate) pid: u32,
    pub(crate) result: Result<pmonnt_core::win::token_info::SecurityInfo, String>,
}

#[derive(Clone, Debug)]
pub(crate) struct CachedSecurityInfo {
    pub(crate) fetched_at: Instant,
    pub(crate) result: Result<pmonnt_core::win::token_info::SecurityInfo, String>,
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub(crate) enum ThreadActionKind {
    Stack,
    Suspend,
    Resume,
    Kill,
    Permissions,
}

#[derive(Clone, Debug)]
pub(crate) struct ThreadActionJobResult {
    pub(crate) pid: u32,
    pub(crate) tid: u32,
    pub(crate) action: ThreadActionKind,
    /// For `Permissions`, this is the SDDL string. For `Stack`, this is the stack text.
    pub(crate) payload: Option<String>,
    pub(crate) result: Result<(), String>,
}

pub(crate) struct PMonNTApp {
    _tokio_rt: tokio::runtime::Runtime,
    bg_worker: crate::background_worker::BackgroundWorker,
    selection_hash_generation: Arc<AtomicU64>,
    last_update: Instant,
    tick: u64,
    current_snapshot: ProcessSnapshot,
    previous_snapshot: Option<ProcessSnapshot>,
    last_diff: Option<ProcessDiff>,
    exited_buffer: ExitedProcessBuffer,
    last_snapshot_update: Instant,
    process_tree: HashMap<Option<u32>, Vec<process::Process>>,
    token_cache: TokenCache,
    thread_cache: ThreadCache,
    thread_prev: HashMap<u32, Vec<ThreadInfo>>,
    thread_fetch_in_flight: HashSet<u32>,
    thread_fetch_started: HashMap<u32, Instant>,
    thread_fetch_tx: crossbeam_channel::Sender<u32>,
    thread_fetch_rx: crossbeam_channel::Receiver<(u32, Result<Vec<ThreadInfo>, String>)>,

    // Threads tab selection + actions
    selected_tid_by_pid: HashMap<u32, u32>,
    thread_action_in_flight: HashSet<String>,
    thread_action_message_by_key: HashMap<(u32, u32), (String, Instant)>,
    thread_permissions_cache: HashMap<(u32, u32), (Instant, Result<String, String>)>,
    thread_stack_cache: HashMap<(u32, u32), (Instant, Result<String, String>)>,
    thread_action_result_tx: crossbeam_channel::Sender<ThreadActionJobResult>,
    thread_action_result_rx: crossbeam_channel::Receiver<ThreadActionJobResult>,
    hover_pid: Option<u32>,
    hover_start: Option<Instant>,
    global_thread_counts: HashMap<u32, usize>,
    module_cache: ModuleCache,
    selected_pid: Option<u32>,
    filter_text: String,
    last_filter_text_lower: String,
    cached_visible_pids: Option<HashSet<u32>>,
    slash_focus_pending: bool,
    expanded_pids: HashSet<u32>,
    expanded_groups: HashSet<String>,
    expanded_groups_before_filter: Option<HashSet<String>>,
    grouped_filter_was_active: bool,
    view_mode: ViewMode,
    group_sort: GroupSort,
    sort_desc: bool,
    // When true (Grouped view), sort groups by the per-group Leader for the active metric.
    // Leader = the child process within the group with the highest value for the active sort
    // metric (CPU/Memory/Disk/GPU/etc.). When false, keep the existing aggregate group sort.
    group_sort_by_leader: bool,
    right_tab: RightTab,
    network_sort: network_sort::NetworkSortState,
    vt_api_key: String,
    mb_api_key: String,
    tf_api_key: String,
    vt_enabled: bool,
    mb_enabled: bool,
    tf_enabled: bool,
    vt_provider: Arc<VirusTotalProvider>,
    vt_ui_state: VtUiState,
    tf_ui_state: TfUiState,
    reputation_service: Arc<ReputationService>,
    pid_to_image_path: HashMap<u32, String>,
    online_lookups_enabled: bool,
    prev_online_lookups_enabled: bool,
    mb_ui_state: MbUiState,
    yara_state: YaraScanState,
    handle_cache: HandleCache,
    last_handle_update: Instant,
    handle_scan_in_progress: bool,
    handle_update_rx: std::sync::mpsc::Receiver<(HandleCache, u64)>,
    handle_update_tx: std::sync::mpsc::Sender<(HandleCache, u64)>,
    last_handle_scan_duration_ms: u64,
    handle_scan_interval_secs: u64,
    is_elevated: bool,
    cpu_memory_data: HashMap<u32, (f32, Option<u64>)>,
    previous_cpu_times: HashMap<u32, (u64, u64)>,
    last_cpu_calc_time: Option<Instant>,
    total_cpu_percent: f32,
    ram_used_bytes: u64,
    ram_total_bytes: u64,
    io_rate_calc: pmonnt_core::win_process_metrics::IoRateCalculator,
    io_rate_by_pid: HashMap<u32, pmonnt_core::win_process_metrics::IoRate>,
    total_gpu_percent: f32,
    total_gpu_dedicated_bytes: u64,
    total_gpu_shared_bytes: u64,
    total_gpu_total_bytes: u64,
    gpu_dedicated_capacity_bytes: u64,
    gpu_shared_capacity_bytes: u64,
    gpu_total_capacity_bytes: u64,
    last_gpu_mem_capacity_refresh: Instant,
    gpu_data: HashMap<u32, (f32, u64, u64, u64)>,
    gpu_sampler: gpu::GpuSampler,
    last_gpu_rebuild: Instant,
    last_gpu_sample_timestamp: Option<Instant>,
    perf_windows: HashMap<u32, perf_window::ProcessPerfWindow>,
    perf_last_sample: Instant,
    perf_sample_accum_secs: f32,
    pid_to_command_line: HashMap<u32, String>,
    pid_to_current_directory: HashMap<u32, String>,
    pid_to_company_name: HashMap<u32, String>,
    pid_to_file_description: HashMap<u32, String>,
    pid_to_integrity_level: HashMap<u32, String>,
    pid_to_user: HashMap<u32, String>,
    pid_to_session_id: HashMap<u32, u32>,
    pid_to_handle_count: HashMap<u32, u32>,
    pid_to_thread_count: HashMap<u32, usize>,
    pid_to_environment: HashMap<u32, Vec<(String, String)>>,
    pid_env_attempted: HashSet<u32>,

    signature_cache_by_path: HashMap<String, pmonnt_core::SignatureInfo>,
    signature_in_flight: HashSet<String>,
    signature_result_tx: crossbeam_channel::Sender<(String, pmonnt_core::SignatureInfo)>,
    signature_result_rx: crossbeam_channel::Receiver<(String, pmonnt_core::SignatureInfo)>,

    process_columns_order: Vec<ProcessColumnId>,
    process_columns_hidden: HashSet<ProcessColumnId>,
    process_columns_drag: Option<ProcessColumnId>,

    services_cache_by_pid: HashMap<u32, (Instant, Vec<ServiceInfo>)>,
    services_error_by_pid: HashMap<u32, String>,
    service_action_in_flight: HashSet<String>,
    service_action_result_tx: crossbeam_channel::Sender<(u32, String, String, Result<(), String>)>,
    service_action_result_rx:
        crossbeam_channel::Receiver<(u32, String, String, Result<(), String>)>,
    last_service_action_message: Option<String>,

    kill_dialog: Option<KillDialogState>,
    kill_action_in_flight: Option<(u32, bool, bool)>,
    kill_action_result_tx: crossbeam_channel::Sender<(u32, bool, bool, Result<(), String>)>,
    kill_action_result_rx: crossbeam_channel::Receiver<(u32, bool, bool, Result<(), String>)>,

    dump_action_in_flight: Option<(u32, pmonnt_core::win::dump::DumpKind)>,
    dump_action_result_tx: crossbeam_channel::Sender<DumpJobResult>,
    dump_action_result_rx: crossbeam_channel::Receiver<DumpJobResult>,
    last_dump_path: Option<std::path::PathBuf>,
    status_line: Option<(String, Instant)>,
    dump_confirm_dialog: Option<DumpConfirmDialogState>,

    security_cache_by_pid: HashMap<u32, CachedSecurityInfo>,
    security_in_flight: HashSet<u32>,
    security_result_tx: crossbeam_channel::Sender<SecurityJobResult>,
    security_result_rx: crossbeam_channel::Receiver<SecurityJobResult>,

    pending_copy_sha_pid: Option<u32>,

    pub(crate) priority_dialog: Option<PriorityDialogState>,
    pub(crate) affinity_dialog: Option<AffinityDialogState>,
    pub(crate) service_dialog: Option<ServiceDialogState>,

    left_panel_width: f32,
    right_panel_width: f32,
    details_panel_visible: bool,
    compact_view: CompactView,
    was_compact_layout: bool,
    density: Density,
    theme: Theme,
    last_applied_theme: Option<Theme>,

    // Process perf popout window size persistence (egui points).
    perf_window_width: f32,
    perf_window_height: f32,
    // Native dialog integration
    main_hwnd: Option<isize>,
    process_permissions_hint_by_pid: HashMap<u32, (String, Instant)>,
}

impl PMonNTApp {
    pub(crate) fn dump_confirm_dialog_state(&self) -> Option<DumpConfirmDialogState> {
        self.dump_confirm_dialog.clone()
    }

    pub(crate) fn dismiss_dump_confirm_dialog(&mut self) {
        self.dump_confirm_dialog = None;
    }

    pub(crate) fn confirm_full_dump(&mut self, pid: u32, process_name: String) {
        self.start_dump_job(pid, process_name, pmonnt_core::win::dump::DumpKind::Full);
    }

    pub(crate) fn request_mini_dump(&mut self, pid: u32, process_name: String) {
        self.start_dump_job(pid, process_name, pmonnt_core::win::dump::DumpKind::Mini);
    }

    pub(crate) fn request_full_dump_with_confirm(&mut self, pid: u32, process_name: String) {
        // Don't stack multiple modal dialogs.
        if self.kill_dialog.is_some()
            || self.priority_dialog.is_some()
            || self.affinity_dialog.is_some()
            || self.service_dialog.is_some()
            || self.dump_confirm_dialog.is_some()
        {
            return;
        }

        self.dump_confirm_dialog = Some(DumpConfirmDialogState { pid, process_name });
    }

    pub(crate) fn set_status_line(&mut self, msg: impl Into<String>) {
        self.status_line = Some((msg.into(), Instant::now()));
    }

    pub(crate) fn current_status_line(&self) -> Option<&str> {
        let Some((msg, at)) = self.status_line.as_ref() else {
            return None;
        };
        if at.elapsed() <= Duration::from_secs(10) {
            Some(msg.as_str())
        } else {
            None
        }
    }

    pub(crate) fn last_dump_path(&self) -> Option<&std::path::PathBuf> {
        self.last_dump_path.as_ref()
    }

    fn start_dump_job(
        &mut self,
        pid: u32,
        process_name: String,
        kind: pmonnt_core::win::dump::DumpKind,
    ) {
        // Keep it simple: single dump job at a time.
        if self.dump_action_in_flight.is_some() {
            self.set_status_line("Dump already in progress...");
            return;
        }

        self.dump_action_in_flight = Some((pid, kind));
        self.last_dump_path = None;
        self.set_status_line(format!(
            "Creating {} dump for '{}' (PID {})...",
            kind.as_str(),
            process_name,
            pid
        ));

        let tx = self.dump_action_result_tx.clone();
        let out_dir = pmonnt_core::win::dump::default_dump_dir();

        self.bg_worker.spawn(move || {
            let result =
                match pmonnt_core::win::dump::write_process_dump(pid, &process_name, kind, out_dir)
                {
                    Ok(path) => Ok(path),
                    Err(e) => Err(e.to_string()),
                };

            let _ = tx.send(DumpJobResult {
                pid,
                process_name,
                kind,
                result,
            });
        });
    }

    pub(crate) fn open_service_dialog(&mut self, pid: u32) {
        // Don't stack multiple modal dialogs.
        if self.kill_dialog.is_some()
            || self.priority_dialog.is_some()
            || self.affinity_dialog.is_some()
            || self.service_dialog.is_some()
            || self.dump_confirm_dialog.is_some()
        {
            return;
        }

        let name = self
            .current_snapshot
            .get_process(pid)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| format!("PID {}", pid));

        match pmonnt_core::services::get_services_for_process(pid) {
            Ok(mut services) => {
                services.sort_by(|a, b| a.name.cmp(&b.name));
                self.service_dialog = Some(ServiceDialogState {
                    pid,
                    process_name: name,
                    services,
                    selected_service: None,
                    last_result: None,
                    last_result_time: None,
                });
            }
            Err(e) => {
                self.service_dialog = Some(ServiceDialogState {
                    pid,
                    process_name: name,
                    services: Vec::new(),
                    selected_service: None,
                    last_result: Some(format!("Failed to query services: {e}")),
                    last_result_time: Some(Instant::now()),
                });
            }
        }
    }

    pub(crate) fn can_control_services(&self) -> bool {
        self.is_elevated
    }

    pub(crate) fn is_service_action_in_flight(&self, key: &str) -> bool {
        self.service_action_in_flight.contains(key)
    }

    pub(crate) fn enqueue_service_action(
        &mut self,
        pid: u32,
        service_name: String,
        action: &'static str,
    ) {
        let key = format!("{pid}:{service_name}:{action}");
        if self.service_action_in_flight.contains(&key) {
            return;
        }
        self.service_action_in_flight.insert(key);

        let tx = self.service_action_result_tx.clone();
        self.bg_worker.spawn(move || {
            let result = match action {
                "Start" => pmonnt_core::service_control::start_service(&service_name)
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
                "Stop" => pmonnt_core::service_control::stop_service(&service_name)
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
                "Restart" => pmonnt_core::service_control::restart_service(&service_name)
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
                "Pause" => pmonnt_core::service_control::pause_service(&service_name)
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
                "Resume" => pmonnt_core::service_control::resume_service(&service_name)
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
                _ => Err(format!("Unknown action: {action}")),
            };
            let _ = tx.send((pid, service_name, action.to_string(), result));
        });
    }

    #[allow(dead_code)]
    pub(crate) fn perform_process_action(&mut self, pid: u32, action: &str) {
        let result = match action {
            "Suspend" => pmonnt_core::win::process_control::suspend_process(pid),
            "Resume" => pmonnt_core::win::process_control::resume_process(pid),
            "Restart" => {
                let cmd = self
                    .pid_to_command_line
                    .get(&pid)
                    .map(|s| s.as_str())
                    .unwrap_or("");
                let cwd = self.pid_to_current_directory.get(&pid).map(|s| s.as_str());
                if cmd.is_empty() {
                    Err(
                        pmonnt_core::win::process_control::ProcessControlError::SpawnError(
                            "No command line available".to_string(),
                        ),
                    )
                } else {
                    pmonnt_core::win::process_control::restart_process(pid, cmd, cwd)
                }
            }
            _ => Ok(()),
        };

        if let Err(e) = result {
            eprintln!("Failed to {}: {}", action, e);
            // TODO: Show in UI
        }
    }

    pub(crate) fn open_priority_dialog(&mut self, pid: u32) {
        // Don't stack multiple modal dialogs.
        if self.kill_dialog.is_some()
            || self.priority_dialog.is_some()
            || self.affinity_dialog.is_some()
            || self.service_dialog.is_some()
        {
            return;
        }

        let name = self
            .current_snapshot
            .get_process(pid)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| format!("PID {}", pid));

        match pmonnt_core::win::get_priority_class(pid) {
            Ok(priority) => {
                self.priority_dialog = Some(PriorityDialogState {
                    pid,
                    process_name: name,
                    current_priority: priority,
                    selected_priority: priority,
                    result: None,
                });
            }
            Err(e) => {
                self.priority_dialog = Some(PriorityDialogState {
                    pid,
                    process_name: name,
                    current_priority: pmonnt_core::win::PriorityClass::Normal,
                    selected_priority: pmonnt_core::win::PriorityClass::Normal,
                    result: Some(Err(e.to_string())),
                });
            }
        }
    }

    pub(crate) fn open_affinity_dialog(&mut self, pid: u32) {
        // Don't stack multiple modal dialogs.
        if self.kill_dialog.is_some()
            || self.priority_dialog.is_some()
            || self.affinity_dialog.is_some()
            || self.service_dialog.is_some()
        {
            return;
        }

        let name = self
            .current_snapshot
            .get_process(pid)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| format!("PID {}", pid));

        match pmonnt_core::win::get_affinity(pid) {
            Ok(info) => {
                self.affinity_dialog = Some(AffinityDialogState {
                    pid,
                    process_name: name,
                    selected_mask: info.process_mask,
                    affinity_info: info,
                    result: None,
                });
            }
            Err(e) => {
                self.affinity_dialog = Some(AffinityDialogState {
                    pid,
                    process_name: name,
                    affinity_info: pmonnt_core::win::AffinityInfo {
                        process_mask: 0,
                        system_mask: 0,
                        cpu_count: 0,
                    },
                    selected_mask: 0,
                    result: Some(Err(e.to_string())),
                });
            }
        }
    }

    pub(crate) fn open_kill_dialog(&mut self, pid: u32, kill_tree: bool) {
        // Don't stack multiple kill dialogs.
        if let Some(KillDialogStep::Running) = self.kill_dialog.as_ref().map(|s| &s.step) {
            return;
        }

        let name = self
            .current_snapshot
            .get_process(pid)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "<unknown>".to_string());

        self.kill_dialog = Some(KillDialogState {
            pid,
            kill_tree,
            group_pids: None,
            group_descendant_count: None,
            name,
            step: KillDialogStep::Confirm,
        });
    }

    #[allow(dead_code)]
    pub(crate) fn open_group_kill_dialog(
        &mut self,
        representative_pid: u32,
        group_name: String,
        group_pids: Vec<u32>,
        kill_tree: bool,
    ) {
        // Don't stack multiple kill dialogs.
        if let Some(KillDialogStep::Running) = self.kill_dialog.as_ref().map(|s| &s.step) {
            return;
        }

        // Pre-compute descendant count for the group-trees confirmation wording.
        let descendant_count = if kill_tree {
            let processes = &self.current_snapshot.processes;

            let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
            for p in processes {
                if let Some(ppid) = p.ppid {
                    if ppid != 0 {
                        children.entry(ppid).or_default().push(p.pid);
                    }
                }
            }

            fn visit(
                pid: u32,
                children: &HashMap<u32, Vec<u32>>,
                visited: &mut HashSet<u32>,
                depth: usize,
            ) {
                if depth > 512 {
                    return;
                }
                if !visited.insert(pid) {
                    return;
                }
                if let Some(kids) = children.get(&pid) {
                    for &c in kids {
                        visit(c, children, visited, depth + 1);
                    }
                }
            }

            let mut visited = HashSet::new();
            for &root in &group_pids {
                visit(root, &children, &mut visited, 0);
            }

            // visited includes the roots, so child count excludes them.
            visited.len().saturating_sub(group_pids.len())
        } else {
            0
        };

        self.kill_dialog = Some(KillDialogState {
            pid: representative_pid,
            kill_tree,
            group_pids: Some(group_pids),
            group_descendant_count: kill_tree.then_some(descendant_count),
            name: group_name,
            step: KillDialogStep::Confirm,
        });
    }

    pub(crate) fn kill_dialog_state(&self) -> Option<KillDialogState> {
        self.kill_dialog.clone()
    }

    pub(crate) fn dismiss_kill_dialog(&mut self) {
        self.kill_dialog = None;
    }

    pub(crate) fn confirm_kill_dialog(&mut self) {
        let Some(state) = self.kill_dialog.clone() else {
            return;
        };
        if !matches!(state.step, KillDialogStep::Confirm) {
            return;
        }

        self.kill_dialog = Some(KillDialogState {
            step: KillDialogStep::Running,
            ..state.clone()
        });

        let processes = self.current_snapshot.processes.clone();
        let pid = state.pid;
        let kill_tree = state.kill_tree;
        let is_group = state.group_pids.is_some();

        // Compute child-first kill order.
        let roots: Vec<u32> = state.group_pids.clone().unwrap_or_else(|| vec![pid]);
        let kill_list = if kill_tree {
            // Build parent -> children map
            let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
            for p in &processes {
                if let Some(ppid) = p.ppid {
                    if ppid != 0 {
                        children.entry(ppid).or_default().push(p.pid);
                    }
                }
            }

            fn visit(
                pid: u32,
                children: &HashMap<u32, Vec<u32>>,
                visited: &mut HashSet<u32>,
                out: &mut Vec<u32>,
                depth: usize,
            ) {
                if depth > 512 {
                    return;
                }
                if !visited.insert(pid) {
                    return;
                }
                if let Some(kids) = children.get(&pid) {
                    for &c in kids {
                        visit(c, children, visited, out, depth + 1);
                    }
                }
                out.push(pid);
            }

            let mut out = Vec::new();
            let mut visited = HashSet::new();
            for root in roots {
                visit(root, &children, &mut visited, &mut out, 0);
            }
            out
        } else {
            roots
        };

        self.kill_action_in_flight = Some((pid, kill_tree, is_group));
        let tx = self.kill_action_result_tx.clone();
        self.bg_worker.spawn(move || {
            for target_pid in &kill_list {
                if let Err(e) = pmonnt_core::win::process_control::kill_process(*target_pid) {
                    let _ = tx.send((
                        pid,
                        kill_tree,
                        is_group,
                        Err(format!("PID {target_pid}: {e}")),
                    ));
                    return;
                }
            }
            let _ = tx.send((pid, kill_tree, is_group, Ok(())));
        });
    }

    pub(crate) fn on_kill_action_result(
        &mut self,
        pid: u32,
        kill_tree: bool,
        is_group: bool,
        result: Result<(), String>,
    ) {
        self.kill_action_in_flight = None;

        if let Some(state) = self.kill_dialog.as_mut() {
            if state.pid == pid
                && state.kill_tree == kill_tree
                && state.group_pids.is_some() == is_group
            {
                state.step = KillDialogStep::Done(result);
            }
        }
    }

    pub(crate) fn process_columns_order(&self) -> &[ProcessColumnId] {
        &self.process_columns_order
    }

    pub(crate) fn process_column_is_hidden(&self, col: ProcessColumnId) -> bool {
        self.process_columns_hidden.contains(&col)
    }

    pub(crate) fn set_process_column_hidden(&mut self, col: ProcessColumnId, hidden: bool) {
        if col == ProcessColumnId::Name {
            return;
        }

        if hidden {
            self.process_columns_hidden.insert(col);
        } else {
            self.process_columns_hidden.remove(&col);
        }
    }

    pub(crate) fn move_process_column_up(&mut self, col: ProcessColumnId) {
        if let Some(idx) = self.process_columns_order.iter().position(|c| *c == col) {
            if idx > 0 {
                self.process_columns_order.swap(idx - 1, idx);
            }
        }
    }

    pub(crate) fn move_process_column_down(&mut self, col: ProcessColumnId) {
        if let Some(idx) = self.process_columns_order.iter().position(|c| *c == col) {
            if idx + 1 < self.process_columns_order.len() {
                self.process_columns_order.swap(idx, idx + 1);
            }
        }
    }

    pub(crate) fn move_process_column_before(
        &mut self,
        moving: ProcessColumnId,
        before: ProcessColumnId,
    ) {
        if moving == before {
            return;
        }

        let Some(from_idx) = self.process_columns_order.iter().position(|c| *c == moving) else {
            return;
        };
        let Some(to_idx) = self.process_columns_order.iter().position(|c| *c == before) else {
            return;
        };

        let col = self.process_columns_order.remove(from_idx);
        let mut insert_at = to_idx;
        if from_idx < to_idx {
            insert_at = insert_at.saturating_sub(1);
        }
        self.process_columns_order.insert(insert_at, col);
    }

    pub(crate) fn reset_process_columns_to_default(&mut self) {
        self.process_columns_order = ProcessColumnId::default_order();
        self.process_columns_hidden = ProcessColumnId::default_hidden().into_iter().collect();
    }

    pub(crate) fn effective_process_columns(
        &self,
        policy: &ProcessTablePolicy,
    ) -> Vec<ProcessColumnId> {
        let mut order = self.process_columns_order.clone();

        // Backward/forward compatibility: ensure a stable superset.
        if !order.contains(&ProcessColumnId::Name) {
            order.insert(0, ProcessColumnId::Name);
        }
        for col in ProcessColumnId::default_order() {
            if !order.contains(&col) {
                order.push(col);
            }
        }

        order
            .into_iter()
            .filter(|c| {
                *c == ProcessColumnId::Name
                    || (!self.process_columns_hidden.contains(c) && c.allowed_by_policy(policy))
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum CompactView {
    #[default]
    List,
    Details,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Density {
    #[default]
    Comfortable,
    Compact,
}

mod network_sort;

mod perf;
pub(crate) mod perf_window;
mod state;
mod update;

// Re-export for tests
#[cfg(test)]
pub use state::{parse_ui_layout_config, serialize_ui_layout_config, UiLayoutConfig};

#[cfg(test)]
mod tests;
