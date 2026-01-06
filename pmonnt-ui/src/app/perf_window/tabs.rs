use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;
use pmonnt_core::{
    module::ModuleCache,
    module::ModuleListResult,
    reputation_service::ReputationService,
    snapshot::ProcessSnapshot,
    thread::{ThreadCache, ThreadInfo},
    token::TokenCache,
    vt::VirusTotalProvider,
};

use crate::app::network_sort::{sort_connections, NetworkSortState};
use crate::background_worker::BackgroundWorker;
use crate::ui_renderer;
use crate::ui_state::{MbUiState, TfUiState, VtUiState, YaraScanState};
use crate::util::format_memory_bytes;
use crate::view::RightTab;

use super::{sparkline, PerfStats};

#[allow(clippy::too_many_arguments)]
pub(super) fn render_tab(
    ui: &mut egui::Ui,
    pid: u32,
    tab: RightTab,
    perf_window: &mut super::ProcessPerfWindow,
    security_filter: &mut String,
    _cpu_values: &[f32],
    _mem_values: &[u64],
    _priv_values: &[u64],
    _gpu_values: &[f32],
    _io_read_values: &[f32],
    _io_write_values: &[f32],
    stats: Option<&PerfStats>,
    module_result: &ModuleListResult,
    gpu_opt: Option<(f32, u64, u64, u64)>,
    image_path: &Option<String>,
    signature_info: &Option<pmonnt_core::SignatureInfo>,
    signature_in_flight: bool,
    command_line: &Option<String>,
    company_name: &Option<String>,
    file_description: &Option<String>,
    integrity_level: &Option<String>,
    user: &Option<String>,
    session_id: Option<u32>,
    current_snapshot: &ProcessSnapshot,
    pid_to_image_path_mut: &mut HashMap<u32, String>,
    token_cache: &mut TokenCache,
    thread_cache: &mut ThreadCache,
    thread_prev: &HashMap<u32, Vec<ThreadInfo>>,
    thread_fetch_in_flight: &mut HashSet<u32>,
    thread_fetch_started: &mut HashMap<u32, Instant>,
    thread_fetch_tx: &crossbeam_channel::Sender<u32>,
    module_cache: &mut ModuleCache,
    handle_cache: &mut pmonnt_core::handles::HandleCache,
    reputation_service: &Arc<ReputationService>,
    bg_worker: &BackgroundWorker,
    yara_state: &mut YaraScanState,
    mb_state: &mut MbUiState,
    vt_state: &mut VtUiState,
    tf_state: &mut TfUiState,
    tf_api_key_for_scan: &str,
    online_lookups_enabled: &mut bool,
    prev_online_lookups_enabled: &mut bool,
    vt_api_key: &mut String,
    mb_api_key: &mut String,
    tf_api_key: &mut String,
    vt_enabled: &mut bool,
    mb_enabled: &mut bool,
    tf_enabled: &mut bool,
    vt_provider: &Arc<VirusTotalProvider>,
    last_handle_scan_duration_ms: u64,
    handle_scan_interval_secs: u64,
    security_cache_by_pid: &mut HashMap<u32, crate::app::CachedSecurityInfo>,
    security_in_flight: &mut HashSet<u32>,
    security_result_tx: &crossbeam_channel::Sender<crate::app::SecurityJobResult>,
    owner_hwnd: Option<isize>,
    process_permissions_hint_by_pid: &mut HashMap<u32, (String, Instant)>,
) {
    match tab {
        RightTab::Summary => {
            if let Some(stats) = stats {
                render_performance_tab(ui, stats, pid);
            } else {
                ui.label("Loading performance data...");
            }
        }
        RightTab::PerformanceGraph => {
            render_performance_graph_tab(
                ui,
                _cpu_values,
                _mem_values,
                _priv_values,
                _io_read_values,
                _io_write_values,
                stats,
            );
        }
        RightTab::Details => {
            ui.heading("Process Details");
            ui.separator();

            egui::Grid::new(("perf_details_grid", pid))
                .num_columns(2)
                .spacing([10.0, 4.0])
                .show(ui, |ui| {
                    ui.label("Image Path:");
                    if let Some(path) = image_path {
                        ui.label(path);
                    } else {
                        ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                    }
                    ui.end_row();

                    ui.label("Verified Signer:");
                    if image_path.is_none() {
                        ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                    } else if let Some(info) = signature_info {
                        let (label, color) = match info.status() {
                            pmonnt_core::SignatureStatus::Valid => (
                                info.signer_name
                                    .clone()
                                    .unwrap_or_else(|| "Verified".to_string()),
                                egui::Color32::LIGHT_GREEN,
                            ),
                            pmonnt_core::SignatureStatus::CatalogSigned => (
                                info.signer_name
                                    .clone()
                                    .unwrap_or_else(|| "Verified (Catalog)".to_string()),
                                egui::Color32::LIGHT_GREEN,
                            ),
                            pmonnt_core::SignatureStatus::NotSigned => {
                                ("Not signed".to_string(), egui::Color32::GRAY)
                            }
                            pmonnt_core::SignatureStatus::Untrusted => {
                                ("Untrusted".to_string(), egui::Color32::YELLOW)
                            }
                            pmonnt_core::SignatureStatus::Expired => {
                                ("Expired".to_string(), egui::Color32::YELLOW)
                            }
                            pmonnt_core::SignatureStatus::Invalid => {
                                ("Invalid".to_string(), egui::Color32::LIGHT_RED)
                            }
                        };

                        let resp = ui.label(egui::RichText::new(label).color(color));
                        if let Some(err) = info.error.as_deref() {
                            if !err.trim().is_empty() {
                                resp.on_hover_text(err);
                            }
                        }
                    } else if signature_in_flight {
                        ui.label(egui::RichText::new("Checking...").color(egui::Color32::GRAY));
                    } else {
                        ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                    }
                    ui.end_row();

                    ui.label("Command Line:");
                    if let Some(cmd) = command_line {
                        ui.label(cmd);
                    } else {
                        ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                    }
                    ui.end_row();

                    ui.label("Company:");
                    if let Some(company) = company_name {
                        ui.label(company);
                    } else {
                        ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                    }
                    ui.end_row();

                    ui.label("Description:");
                    if let Some(desc) = file_description {
                        ui.label(desc);
                    } else {
                        ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                    }
                    ui.end_row();

                    ui.label("Integrity Level:");
                    if let Some(integrity) = integrity_level {
                        ui.label(integrity);
                    } else {
                        ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                    }
                    ui.end_row();

                    ui.label("User:");
                    if let Some(u) = user {
                        ui.label(u);
                    } else {
                        ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                    }
                    ui.end_row();

                    ui.label("Session ID:");
                    if let Some(session) = session_id {
                        ui.label(format!("{}", session));
                    } else {
                        ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                    }
                    ui.end_row();
                });
        }

        RightTab::Security => {
            render_security_tab(
                ui,
                pid,
                security_filter,
                security_cache_by_pid,
                security_in_flight,
                security_result_tx,
                bg_worker,
                owner_hwnd,
                process_permissions_hint_by_pid,
            );
        }

        RightTab::Services => {
            ui.heading("Services");
            ui.separator();

            match pmonnt_core::services::get_services_for_process(pid) {
                Ok(mut svcs) => {
                    svcs.sort_by(|a, b| a.name.cmp(&b.name));
                    if svcs.is_empty() {
                        ui.label(
                            egui::RichText::new("No hosted services for this process")
                                .color(ui.visuals().weak_text_color()),
                        );
                        return;
                    }

                    for s in svcs {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(&s.name).monospace());
                            ui.separator();
                            ui.label(&s.display_name);
                        });
                        if let Some(desc) = s.description.as_deref() {
                            ui.label(
                                egui::RichText::new(desc)
                                    .color(ui.visuals().weak_text_color())
                                    .small(),
                            );
                        }
                        ui.add_space(6.0);
                    }
                }
                Err(e) => {
                    ui.colored_label(egui::Color32::LIGHT_RED, format!("{e}"));
                }
            }
        }

        RightTab::Network => {
            render_network_tab_with_churn(ui, pid, perf_window, current_snapshot);
        }

        RightTab::Threads => {
            // Same behavior as main window: cache-backed + async fetch.
            if let Some(threads) = thread_cache.get(pid) {
                ui.push_id(("perf_window", pid, "threads"), |ui| {
                    ui_renderer::render_threads_panel(
                        ui,
                        pid,
                        threads,
                        thread_prev,
                        &module_result.modules,
                        &mut perf_window.selected_tid,
                        None,
                        |_| {},
                    );
                });
            } else {
                if !thread_fetch_in_flight.contains(&pid) {
                    thread_fetch_in_flight.insert(pid);
                    thread_fetch_started.insert(pid, Instant::now());
                    let _ = thread_fetch_tx.send(pid);
                }

                ui.vertical_centered(|ui| {
                    ui.add_space(40.0);
                    ui.spinner();

                    let elapsed = thread_fetch_started
                        .get(&pid)
                        .map(|start| start.elapsed())
                        .unwrap_or_default();

                    if elapsed.as_millis() > 800 {
                        ui.label(format!(
                            "Querying threads... ({:.1}s)",
                            elapsed.as_secs_f32()
                        ));
                    } else {
                        ui.label("Querying threads...");
                    }
                });
            }
        }

        RightTab::Handles => {
            ui.push_id(("perf_window", pid, "handles"), |ui| {
                let mut ctx = ui_renderer::HandlesPanelContext {
                    ui,
                    pid,
                    handle_cache,
                    pid_to_image_path: &*pid_to_image_path_mut,
                    current_snapshot,
                    token_cache,
                    thread_cache,
                    thread_prev,
                    module_cache,
                    reputation_service,
                    scan_duration_ms: last_handle_scan_duration_ms,
                    scan_interval_secs: handle_scan_interval_secs,
                };
                ui_renderer::render_handles_panel_ctx(&mut ctx);
            });
        }

        RightTab::GPU => {
            ui.heading("GPU Details");
            ui.separator();

            if let Some((gpu_pct, dedicated, shared, total)) = gpu_opt {
                ui.horizontal(|ui| {
                    ui.label("GPU Usage:");
                    ui.label(format!("{gpu_pct:.1}%"));
                });

                ui.horizontal(|ui| {
                    ui.label("Dedicated Memory:");
                    ui.label(format_memory_bytes(dedicated));
                });

                ui.horizontal(|ui| {
                    ui.label("Shared Memory:");
                    ui.label(format_memory_bytes(shared));
                });

                ui.horizontal(|ui| {
                    ui.label("Total Memory:");
                    ui.label(format_memory_bytes(total));
                });
            } else {
                ui.label("No GPU data available for this process");
            }
        }

        RightTab::Version => {
            ui.heading("Version Information");
            ui.separator();

            if let Some(path) = image_path {
                ui.horizontal(|ui| {
                    ui.label("File Path:");
                    ui.label(path);
                });

                ui.separator();

                let (company, description) = crate::process_info::get_file_version_info(path);

                ui.horizontal(|ui| {
                    ui.label("Company Name:");
                    if let Some(company) = company {
                        ui.label(&company);
                    } else {
                        ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                    }
                });

                ui.horizontal(|ui| {
                    ui.label("File Description:");
                    if let Some(description) = description {
                        ui.label(&description);
                    } else {
                        ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                    }
                });
            } else {
                ui.label("No image path available");
            }
        }

        RightTab::Reputation => {
            ui.push_id(("perf_window", pid, "reputation"), |ui| {
                let mut ctx = ui_renderer::ReputationPanelContext {
                    ui,
                    pid,
                    reputation_service,
                    pid_to_image_path: pid_to_image_path_mut,
                    online_lookups_enabled: *online_lookups_enabled,
                    vt_enabled: *vt_enabled,
                    mb_enabled: *mb_enabled,
                    tf_enabled: *tf_enabled,
                    mb_state,
                    vt_state,
                    tf_state,
                };
                ui_renderer::render_reputation_panel_ctx(&mut ctx);
            });
        }

        RightTab::Scan => {
            ui.push_id(("perf_window", pid, "scan"), |ui| {
                ui_renderer::render_scan_panel(ui, pid, yara_state, tf_api_key_for_scan);
            });
        }

        RightTab::Settings => {
            ui.push_id(("perf_window", pid, "settings"), |ui| {
                let mut ctx = ui_renderer::ReputationSettingsContext {
                    ui,
                    reputation_service,
                    mb_state,
                    bg_worker,
                    pid_to_image_path: &*pid_to_image_path_mut,
                    online_lookups_enabled,
                    prev_online_lookups_enabled,
                    vt_api_key,
                    mb_api_key,
                    tf_api_key,
                    vt_enabled,
                    mb_enabled,
                    tf_enabled,
                    vt_provider,
                };
                ui_renderer::render_reputation_settings_panel_ctx(&mut ctx);
            });
        }
    }
}

pub(super) fn render_window_header(ui: &mut egui::Ui, pid: u32, title: &str, tab: &mut RightTab) {
    ui.horizontal(|ui| {
        ui.heading(title);
        ui.separator();

        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            ui.selectable_value(tab, RightTab::Summary, "Summary");
            ui.selectable_value(tab, RightTab::PerformanceGraph, "Performance Graph");
            ui.selectable_value(tab, RightTab::Details, "Details");
            ui.selectable_value(tab, RightTab::Security, "Security");
            ui.selectable_value(tab, RightTab::Services, "Services");
            ui.selectable_value(tab, RightTab::Threads, "Threads");
            ui.selectable_value(tab, RightTab::Handles, "Handles");
            ui.selectable_value(tab, RightTab::Network, "Network");
            ui.selectable_value(tab, RightTab::GPU, "GPU");
            ui.selectable_value(tab, RightTab::Version, "Version");
            ui.selectable_value(tab, RightTab::Reputation, "Reputation");
            ui.selectable_value(tab, RightTab::Scan, "Scan");
            ui.selectable_value(tab, RightTab::Settings, "Settings");
        });
    });

    ui.label(egui::RichText::new(format!("PID: {pid}")).weak());
    ui.separator();
}

pub(super) fn render_optional_gpu_footer(ui: &mut egui::Ui, gpu_values: &[f32]) {
    if gpu_values.iter().any(|v| *v > 0.0) {
        ui.add_space(12.0);
        sparkline::draw_gpu_sparkline(ui, gpu_values);
    }
}

fn integrity_label(il: &pmonnt_core::win::token_info::IntegrityLevel) -> String {
    use pmonnt_core::win::token_info::IntegrityLevel as IL;
    match il {
        IL::Untrusted => "Untrusted".to_string(),
        IL::Low => "Low".to_string(),
        IL::Medium => "Medium".to_string(),
        IL::MediumPlus => "Medium Plus".to_string(),
        IL::High => "High".to_string(),
        IL::System => "System".to_string(),
        IL::Protected => "Protected".to_string(),
        IL::Unknown(s) => format!("Unknown ({s})"),
    }
}

fn opt_bool_label(v: Option<bool>) -> String {
    match v {
        Some(true) => "Yes".to_string(),
        Some(false) => "No".to_string(),
        None => "—".to_string(),
    }
}

fn render_security_tab(
    ui: &mut egui::Ui,
    pid: u32,
    security_filter: &mut String,
    security_cache_by_pid: &mut HashMap<u32, crate::app::CachedSecurityInfo>,
    security_in_flight: &mut HashSet<u32>,
    security_result_tx: &crossbeam_channel::Sender<crate::app::SecurityJobResult>,
    bg_worker: &BackgroundWorker,
    owner_hwnd: Option<isize>,
    process_permissions_hint_by_pid: &mut HashMap<u32, (String, Instant)>,
) {
    ui.heading("Security");
    ui.separator();

    // Transient hint/errors for the Permissions dialog.
    if let Some((msg, at)) = process_permissions_hint_by_pid.get(&pid) {
        if at.elapsed() <= Duration::from_secs(10) {
            ui.label(egui::RichText::new(msg).color(ui.visuals().weak_text_color()));
        }
    }

    // Fetch asynchronously and cache per PID.
    let ttl = Duration::from_secs(5);
    let now = Instant::now();
    let is_fresh = security_cache_by_pid
        .get(&pid)
        .is_some_and(|c| now.duration_since(c.fetched_at) <= ttl);

    if !is_fresh && !security_in_flight.contains(&pid) {
        security_in_flight.insert(pid);
        let tx = security_result_tx.clone();
        bg_worker.spawn(move || {
            let result = pmonnt_core::win::token_info::get_process_security_info(pid)
                .map_err(|e| e.to_string());
            let _ = tx.send(crate::app::SecurityJobResult { pid, result });
        });
    }

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Filter:").color(ui.visuals().weak_text_color()));
        ui.text_edit_singleline(security_filter);
        if !security_filter.trim().is_empty() && ui.small_button("Clear").clicked() {
            security_filter.clear();
        }
    });
    ui.add_space(6.0);

    let cached = security_cache_by_pid.get(&pid);

    if cached.is_none() {
        if security_in_flight.contains(&pid) {
            ui.label(egui::RichText::new("Loading security info...").color(egui::Color32::GRAY));
        } else {
            ui.label(
                egui::RichText::new("Security info not available yet").color(egui::Color32::GRAY),
            );
        }
        return;
    }

    let cached = cached.unwrap();
    match &cached.result {
        Err(e) => {
            ui.colored_label(egui::Color32::LIGHT_RED, format!("{e}"));
            ui.label(
                egui::RichText::new(
                    "Tip: normal processes should work without admin; protected/system processes may deny token query.",
                )
                .small()
                .color(ui.visuals().weak_text_color()),
            );
        }
        Ok(info) => {
            // Summary header
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("Token summary")
                        .color(ui.visuals().weak_text_color())
                        .small(),
                );

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Permissions...").clicked() {
                        // Quick access probe on the UI thread; the dialog itself is opened off-thread.
                        let access = pmonnt_core::win::aclui_process_permissions::probe_process_object_permissions(pid);
                        match access {
                            Ok(pmonnt_core::win::aclui_process_permissions::ProcessPermissionsAccess::ReadWrite) => {
                                process_permissions_hint_by_pid.insert(
                                    pid,
                                    ("Opening permissions editor...".to_string(), Instant::now()),
                                );
                            }
                            Ok(pmonnt_core::win::aclui_process_permissions::ProcessPermissionsAccess::ReadOnly) => {
                                process_permissions_hint_by_pid.insert(
                                    pid,
                                    (
                                        "Opening permissions (read-only). Editing requires elevation/WRITE_DAC.".to_string(),
                                        Instant::now(),
                                    ),
                                );
                            }
                            Ok(pmonnt_core::win::aclui_process_permissions::ProcessPermissionsAccess::Denied) => {
                                process_permissions_hint_by_pid.insert(
                                    pid,
                                    ("Access denied opening permissions (need READ_CONTROL).".to_string(), Instant::now()),
                                );
                                return;
                            }
                            Err(e) => {
                                process_permissions_hint_by_pid.insert(
                                    pid,
                                    (format!("Permissions unavailable: {e}"), Instant::now()),
                                );
                                return;
                            }
                        }

                        let owner = owner_hwnd.unwrap_or(0);
                        std::thread::spawn(move || {
                            let _ = pmonnt_core::win::aclui_process_permissions::open_process_permissions_dialog(
                                owner,
                                pid,
                                format!("Process (PID {pid})"),
                            );
                        });
                    }
                });
            });

            egui::Frame::none()
                .fill(ui.visuals().widgets.inactive.bg_fill)
                .rounding(egui::Rounding::same(8.0))
                .inner_margin(egui::Margin::symmetric(10.0, 8.0))
                .show(ui, |ui| {
                    egui::Grid::new(("security_summary_grid", pid))
                        .num_columns(2)
                        .spacing([10.0, 4.0])
                        .show(ui, |ui| {
                            ui.label("User:");
                            ui.label(&info.summary.user);
                            ui.end_row();

                            ui.label("SID:");
                            ui.horizontal(|ui| {
                                ui.label(&info.summary.user_sid);
                                if ui.small_button("Copy").clicked() {
                                    ui.output_mut(|o| {
                                        o.copied_text = info.summary.user_sid.clone()
                                    });
                                }
                            });
                            ui.end_row();

                            ui.label("Session:");
                            ui.label(format!("{}", info.summary.session_id));
                            ui.end_row();

                            ui.label("Logon Session:");
                            ui.horizontal(|ui| {
                                if let Some(luid) = info.summary.logon_luid.as_deref() {
                                    ui.label(luid);
                                    if ui.small_button("Copy").clicked() {
                                        ui.output_mut(|o| o.copied_text = luid.to_string());
                                    }
                                } else {
                                    ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                                }
                            });
                            ui.end_row();

                            ui.label("Integrity:");
                            ui.label(integrity_label(&info.summary.integrity));
                            ui.end_row();

                            ui.label("Elevation:");
                            if let Some(e) = info.summary.elevation.as_deref() {
                                ui.label(e);
                            } else {
                                ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                            }
                            ui.end_row();

                            ui.label("Virtualization:");
                            ui.label(opt_bool_label(info.summary.virtualization_enabled));
                            ui.end_row();

                            ui.label("AppContainer:");
                            ui.label(opt_bool_label(info.summary.is_app_container));
                            ui.end_row();

                            ui.label("Protected Process:");
                            ui.label(opt_bool_label(info.summary.is_protected_process));
                            ui.end_row();

                            ui.label("PPL:");
                            ui.label(opt_bool_label(info.summary.is_ppl));
                            ui.end_row();
                        });
                });

            ui.add_space(10.0);

            // Filter setup
            let filter = security_filter.trim().to_lowercase();
            let group_rows: Vec<_> = if filter.is_empty() {
                info.groups.iter().collect()
            } else {
                info.groups
                    .iter()
                    .filter(|g| {
                        g.name.to_lowercase().contains(&filter)
                            || g.sid.to_lowercase().contains(&filter)
                            || g.attributes.join(" ").to_lowercase().contains(&filter)
                    })
                    .collect()
            };

            let priv_rows: Vec<_> = if filter.is_empty() {
                info.privileges.iter().collect()
            } else {
                info.privileges
                    .iter()
                    .filter(|p| {
                        p.name.to_lowercase().contains(&filter)
                            || p.display.to_lowercase().contains(&filter)
                            || p.attributes.join(" ").to_lowercase().contains(&filter)
                    })
                    .collect()
            };

            // Groups table
            ui.separator();
            ui.heading("Groups");

            let has_group_error = info.groups_error.is_some();
            if let Some(err) = info.groups_error.as_ref() {
                ui.colored_label(
                    egui::Color32::LIGHT_RED,
                    format!("Failed to query groups: {err}"),
                );
            }

            if group_rows.is_empty() {
                if has_group_error {
                    ui.label(
                        egui::RichText::new("Groups unavailable.")
                            .color(ui.visuals().weak_text_color()),
                    );
                } else {
                    ui.label(
                        egui::RichText::new("No groups match the filter.")
                            .color(ui.visuals().weak_text_color()),
                    );
                }
            } else {
                let row_h = 18.0;
                egui_extras::TableBuilder::new(ui)
                    .striped(true)
                    .resizable(true)
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(egui_extras::Column::remainder().at_least(220.0))
                    .column(egui_extras::Column::remainder().at_least(220.0))
                    .header(row_h, |mut header| {
                        header.col(|ui| {
                            ui.label(egui::RichText::new("Group").strong());
                        });
                        header.col(|ui| {
                            ui.label(egui::RichText::new("Flags").strong());
                        });
                    })
                    .body(|body| {
                        body.rows(row_h, group_rows.len(), |mut row| {
                            let g = group_rows[row.index()];
                            row.col(|ui| {
                                ui.label(&g.name).on_hover_text(format!("SID: {}", g.sid));
                            });
                            row.col(|ui| {
                                ui.label(g.attributes.join(", "))
                                    .on_hover_text(format!("SID: {}", g.sid));
                            });
                        });
                    });
            }

            ui.add_space(10.0);

            // Privileges table
            ui.separator();
            ui.heading(format!("Privileges ({})", info.privileges.len()));

            let has_priv_error = info.privileges_error.is_some();
            if let Some(err) = info.privileges_error.as_ref() {
                ui.colored_label(
                    egui::Color32::LIGHT_RED,
                    format!("Failed to query privileges: {err}"),
                );
            }

            if priv_rows.is_empty() {
                if has_priv_error {
                    ui.label(
                        egui::RichText::new("Privileges unavailable.")
                            .color(ui.visuals().weak_text_color()),
                    );
                } else {
                    ui.label(
                        egui::RichText::new("No privileges match the filter.")
                            .color(ui.visuals().weak_text_color()),
                    );
                }
            } else {
                let row_h = 18.0;
                egui_extras::TableBuilder::new(ui)
                    .striped(true)
                    .resizable(true)
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(egui_extras::Column::remainder().at_least(220.0))
                    .column(egui_extras::Column::remainder().at_least(90.0))
                    .column(egui_extras::Column::remainder().at_least(180.0))
                    .header(row_h, |mut header| {
                        header.col(|ui| {
                            ui.label(egui::RichText::new("Privilege").strong());
                        });
                        header.col(|ui| {
                            ui.label(egui::RichText::new("State").strong());
                        });
                        header.col(|ui| {
                            ui.label(egui::RichText::new("Flags").strong());
                        });
                    })
                    .body(|body| {
                        body.rows(row_h, priv_rows.len(), |mut row| {
                            let p = priv_rows[row.index()];
                            let removed = p.attributes.iter().any(|a| a == "Removed");
                            let state = if removed {
                                "Removed"
                            } else if p.enabled {
                                "Enabled"
                            } else {
                                "Disabled"
                            };
                            row.col(|ui| {
                                ui.label(egui::RichText::new(&p.name).monospace())
                                    .on_hover_text(&p.display);
                            });
                            row.col(|ui| {
                                let color = if removed {
                                    egui::Color32::LIGHT_RED
                                } else if p.enabled {
                                    egui::Color32::LIGHT_GREEN
                                } else {
                                    egui::Color32::GRAY
                                };
                                ui.label(egui::RichText::new(state).color(color));
                            });
                            row.col(|ui| {
                                ui.label(p.attributes.join(", ")).on_hover_text(&p.display);
                            });
                        });
                    });
            }
        }
    }
}

pub(super) fn render_performance_tab(ui: &mut egui::Ui, stats: &PerfStats, _pid: u32) {
    egui::ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            // Two-column layout like Process Explorer
            ui.horizontal_top(|ui| {
                // Left column: CPU, Virtual Memory, Physical Memory
                ui.vertical(|ui| {
                    ui.set_min_width(300.0);

                    // CPU Group
                    render_group_box(ui, "CPU", |ui| {
                        stat_row(
                            ui,
                            "Priority",
                            format_optional_string(&stats.priority_class),
                        );
                        stat_row(ui, "Kernel Time", format_filetime(stats.kernel_time));
                        stat_row(ui, "User Time", format_filetime(stats.user_time));
                        stat_row(ui, "Total Time", format_filetime(stats.total_time));
                        stat_row(ui, "Cycles", format_cycles_simple(stats.cycles));
                    });

                    ui.add_space(10.0);

                    // Virtual Memory Group
                    render_group_box(ui, "Virtual Memory", |ui| {
                        stat_row(
                            ui,
                            "Private Bytes",
                            format_bytes_simple(stats.private_bytes.map(|v| v as u64)),
                        );
                        stat_row(
                            ui,
                            "Peak Private Bytes",
                            format_bytes_simple(stats.peak_private_bytes.map(|v| v as u64)),
                        );
                        stat_row(
                            ui,
                            "Virtual Size",
                            format_bytes_simple(stats.virtual_size.map(|v| v as u64)),
                        );
                        stat_row(
                            ui,
                            "Page Faults",
                            format_count_simple(stats.page_faults.map(|v| v as u64)),
                        );
                        stat_row(
                            ui,
                            "Page Fault Delta",
                            format_count_simple(stats.page_fault_delta.map(|v| v as u64)),
                        );
                    });

                    ui.add_space(10.0);

                    // Physical Memory Group
                    render_group_box(ui, "Physical Memory", |ui| {
                        stat_row(
                            ui,
                            "Memory Priority",
                            na_value_inline(NA_REASON_NOT_IMPLEMENTED),
                        );
                        stat_row(
                            ui,
                            "Working Set",
                            format_bytes_simple(stats.working_set.map(|v| v as u64)),
                        );
                        stat_row(
                            ui,
                            "WS Private",
                            format_bytes_simple(stats.ws_private.map(|v| v as u64)),
                        );
                        stat_row(
                            ui,
                            "WS Shareable",
                            format_bytes_simple(stats.ws_shareable.map(|v| v as u64)),
                        );
                        stat_row(
                            ui,
                            "WS Shared",
                            format_bytes_simple(stats.ws_shared.map(|v| v as u64)),
                        );
                        stat_row(
                            ui,
                            "Peak Working Set",
                            format_bytes_simple(stats.peak_working_set.map(|v| v as u64)),
                        );
                    });
                });

                ui.add_space(20.0);

                // Right column: I/O, Handles
                ui.vertical(|ui| {
                    ui.set_min_width(300.0);

                    // I/O Group
                    render_group_box(ui, "I/O", |ui| {
                        stat_row(
                            ui,
                            "I/O Priority",
                            na_value_inline(NA_REASON_NOT_IMPLEMENTED),
                        );
                        stat_row(ui, "Reads", format_count_simple(stats.io_reads));
                        stat_row(ui, "Read Delta", format_count_simple(stats.io_read_delta));
                        stat_row(
                            ui,
                            "Read Bytes Delta",
                            format_bytes_simple(stats.io_read_bytes_delta),
                        );
                        stat_row(ui, "Writes", format_count_simple(stats.io_writes));
                        stat_row(ui, "Write Delta", format_count_simple(stats.io_write_delta));
                        stat_row(
                            ui,
                            "Write Bytes Delta",
                            format_bytes_simple(stats.io_write_bytes_delta),
                        );
                        stat_row(ui, "Other", format_count_simple(stats.io_other));
                        stat_row(ui, "Other Delta", format_count_simple(stats.io_other_delta));
                        stat_row(
                            ui,
                            "Other Bytes Delta",
                            format_bytes_simple(stats.io_other_bytes_delta),
                        );
                    });

                    ui.add_space(10.0);

                    // Handles Group
                    render_group_box(ui, "Handles", |ui| {
                        stat_row(
                            ui,
                            "Handles",
                            format_count_simple(stats.handles.map(|v| v as u64)),
                        );
                        stat_row(
                            ui,
                            "Peak Handles",
                            format_count_simple(stats.peak_handles.map(|v| v as u64)),
                        );
                        stat_row(
                            ui,
                            "GDI Handles",
                            format_count_simple(stats.gdi_handles.map(|v| v as u64)),
                        );
                        stat_row(
                            ui,
                            "USER Handles",
                            format_count_simple(stats.user_handles.map(|v| v as u64)),
                        );
                    });
                });
            });
        });
}

fn render_group_box(ui: &mut egui::Ui, title: &str, content: impl FnOnce(&mut egui::Ui)) {
    let frame = egui::Frame::group(ui.style()).inner_margin(egui::Margin::same(10.0));

    frame.show(ui, |ui| {
        ui.label(egui::RichText::new(title).strong());
        ui.add_space(5.0);

        content(ui);
    });
}

fn stat_row(ui: &mut egui::Ui, label: &str, value: String) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(value);
        });
    });
}

fn format_filetime(time_opt: Option<u64>) -> String {
    match time_opt {
        Some(time_100ns) => {
            let seconds = time_100ns / 10_000_000;
            let hours = seconds / 3600;
            let minutes = (seconds % 3600) / 60;
            let secs = seconds % 60;
            let millis = (time_100ns / 10_000) % 1000;
            format!("{:02}:{:02}:{:02}.{:03}", hours, minutes, secs, millis)
        }
        None => "—".to_string(),
    }
}

fn format_optional_string(s: &Option<String>) -> String {
    s.as_deref().unwrap_or("—").to_string()
}

fn na_value_inline(_reason: &'static str) -> String {
    "—".to_string()
}

// Simple format helpers that return String (not ValueCell)
fn format_count_simple(val: Option<u64>) -> String {
    match val {
        Some(v) => format_count_with_commas(v),
        None => "—".to_string(),
    }
}

fn format_bytes_simple(val: Option<u64>) -> String {
    match val {
        Some(v) => {
            if v >= 1_073_741_824 {
                format!("{:.1} GiB", v as f64 / 1_073_741_824.0)
            } else if v >= 1_048_576 {
                format!("{:.1} MiB", v as f64 / 1_048_576.0)
            } else if v >= 1_024 {
                format!("{:.1} KiB", v as f64 / 1024.0)
            } else {
                format!("{} B", v)
            }
        }
        None => "—".to_string(),
    }
}

fn format_cycles_simple(val: Option<u64>) -> String {
    match val {
        Some(v) => format_count_with_commas(v),
        None => "—".to_string(),
    }
}

// Old render_performance_tab for reference - can be removed later
#[cfg(feature = "dev-tools")]
#[allow(dead_code)]
pub(super) fn render_performance_tab_old(ui: &mut egui::Ui, stats: &PerfStats, pid: u32) {
    egui::ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new("Live summary")
                    .color(ui.visuals().weak_text_color())
                    .small(),
            );

            let chip_frame = egui::Frame::none()
                .fill(ui.visuals().widgets.inactive.bg_fill)
                .rounding(egui::Rounding::same(8.0))
                .inner_margin(egui::Margin::symmetric(10.0, 8.0));

            chip_frame.show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 8.0;

                    let (cpu_val, cpu_na) = match stats.total_delta {
                        Some(delta) => (format_filetime_delta(Some(delta)), false),
                        None => ("Not available".to_string(), true),
                    };
                    perf_chip(
                        ui,
                        "CPU Δ",
                        &cpu_val,
                        cpu_na,
                        cpu_na.then_some(NA_REASON_SAMPLING),
                    );

                    let (ws_val, ws_na) = match stats.working_set {
                        Some(ws) => (format_bytes(Some(ws as u64)), false),
                        None => ("Not available".to_string(), true),
                    };
                    perf_chip(
                        ui,
                        "WS",
                        &ws_val,
                        ws_na,
                        ws_na.then_some(NA_REASON_NOT_IMPLEMENTED),
                    );

                    let (priv_val, priv_na) = match stats.private_bytes {
                        Some(pb) => (format_bytes(Some(pb as u64)), false),
                        None => ("Not available".to_string(), true),
                    };
                    perf_chip(
                        ui,
                        "Private",
                        &priv_val,
                        priv_na,
                        priv_na.then_some(NA_REASON_NOT_IMPLEMENTED),
                    );

                    let (handles_val, handles_na) = match stats.handles {
                        Some(h) => (format_count_with_commas(h as u64), false),
                        None => ("Not available".to_string(), true),
                    };
                    perf_chip(
                        ui,
                        "Handles",
                        &handles_val,
                        handles_na,
                        handles_na.then_some(NA_REASON_NOT_IMPLEMENTED),
                    );

                    let (pri_val, pri_na) = match &stats.priority_class {
                        Some(p) => (p.clone(), false),
                        None => ("Not available".to_string(), true),
                    };
                    perf_chip(
                        ui,
                        "Priority",
                        &pri_val,
                        pri_na,
                        pri_na.then_some(NA_REASON_NOT_IMPLEMENTED),
                    );

                    let (rw_val, rw_na) =
                        match (stats.read_bytes_per_sec, stats.write_bytes_per_sec) {
                            (Some(r), Some(w)) => (
                                format!(
                                    "R {} • W {}",
                                    format_rate_bytes_per_s(Some(r)),
                                    format_rate_bytes_per_s(Some(w))
                                ),
                                false,
                            ),
                            (Some(r), None) => (
                                format!("R {} • W Not available", format_rate_bytes_per_s(Some(r))),
                                true,
                            ),
                            (None, Some(w)) => (
                                format!("R Not available • W {}", format_rate_bytes_per_s(Some(w))),
                                true,
                            ),
                            _ => ("Not available".to_string(), true),
                        };
                    perf_chip(
                        ui,
                        "R/W",
                        &rw_val,
                        rw_na,
                        rw_na.then_some(NA_REASON_SAMPLING),
                    );
                });
            });

            ui.add_space(8.0);
            ui.separator();
            ui.add_space(8.0);

            let is_narrow = ui.available_width() < 900.0;
            if is_narrow {
                ui.set_min_width(ui.available_width());
                render_cpu_card(ui, stats, pid);
                ui.add_space(8.0);
                render_memory_card(ui, stats, pid);
                ui.add_space(8.0);
                render_io_card(ui, stats, pid);
                ui.add_space(8.0);
                render_handles_card(ui, stats, pid);
            } else {
                let col_width = ui.available_width() / 2.0;
                ui.columns(2, |cols| {
                    cols[0].set_min_width(col_width);
                    cols[1].set_min_width(col_width);

                    cols[0].vertical(|ui| {
                        render_cpu_card(ui, stats, pid);
                        ui.add_space(8.0);
                        render_memory_card(ui, stats, pid);
                    });

                    cols[1].vertical(|ui| {
                        render_io_card(ui, stats, pid);
                        ui.add_space(8.0);
                        render_handles_card(ui, stats, pid);
                    });
                });
            }

            ui.add_space(12.0);

            ui.collapsing("Advanced (optional)", |ui| {
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    egui::Grid::new(("advanced_grid", pid))
                        .num_columns(2)
                        .spacing([10.0, 4.0])
                        .show(ui, |ui| {
                            ui.label("Hard faults/sec:");
                            na_value(ui, NA_REASON_SAMPLING);
                            ui.end_row();

                            ui.label("Context switches/sec:");
                            na_value(ui, NA_REASON_SAMPLING);
                            ui.end_row();

                            ui.label("I/O latency (avg read/write):");
                            na_value(ui, NA_REASON_SAMPLING);
                            ui.end_row();

                            ui.label("Handle breakdown by type:");
                            na_value(ui, NA_REASON_SAMPLING);
                            ui.end_row();

                            ui.label("Power throttling/efficiency mode:");
                            na_value(ui, NA_REASON_SAMPLING);
                            ui.end_row();

                            ui.label("Per-engine GPU breakdown:");
                            na_value(ui, NA_REASON_SAMPLING);
                            ui.end_row();
                        });
                });
            });
        });
}

pub(super) fn render_performance_graph_tab(
    ui: &mut egui::Ui,
    cpu_values: &[f32],
    _mem_values: &[u64],
    priv_values: &[u64],
    io_read_values: &[f32],
    io_write_values: &[f32],
    _stats: Option<&PerfStats>,
) {
    use egui_plot::{Line, Plot, PlotPoints};

    if cpu_values.is_empty() && priv_values.is_empty() && io_read_values.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(100.0);
            ui.heading("Collecting samples…");
            ui.add_space(20.0);
            ui.label(
                egui::RichText::new("Performance graphs will appear once data is available.")
                    .color(ui.visuals().weak_text_color()),
            );
        });
        return;
    }

    let sample_interval = super::PERF_SAMPLE_INTERVAL_SECS as f64;

    egui::ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new("Performance Graphs (~4 min history)")
                    .color(ui.visuals().weak_text_color())
                    .small(),
            );
            ui.add_space(10.0);

            // CPU Usage Row
            ui.horizontal(|ui| {
                // Left: Mini bar
                render_mini_bar(
                    ui,
                    "CPU",
                    cpu_values.last().copied().unwrap_or(0.0),
                    100.0,
                    |v| format!("{:.1}%", v),
                );

                ui.add_space(10.0);

                // Right: Graph
                let cpu_points: PlotPoints = cpu_values
                    .iter()
                    .enumerate()
                    .map(|(i, &v)| [i as f64 * sample_interval, v as f64])
                    .collect();

                Plot::new("cpu_plot")
                    .height(140.0)
                    .show_axes([false, false])
                    .show_grid([true, true])
                    .include_y(0.0)
                    .include_y(100.0)
                    .allow_zoom(false)
                    .allow_drag(false)
                    .allow_scroll(false)
                    .show_x(false)
                    .show_y(false)
                    .show(ui, |plot_ui| {
                        plot_ui.line(
                            Line::new(cpu_points)
                                .color(egui::Color32::from_rgb(100, 200, 100))
                                .width(1.5),
                        );
                    });
            });

            ui.add_space(15.0);
            ui.separator();
            ui.add_space(15.0);

            // Private Bytes Row
            ui.horizontal(|ui| {
                // Left: Mini bar
                let current_priv = priv_values.last().copied().unwrap_or(0);
                let max_priv = priv_values.iter().copied().max().unwrap_or(1);
                render_mini_bar(ui, "Private", current_priv as f32, max_priv as f32, |v| {
                    format_bytes(Some(v as u64))
                });

                ui.add_space(10.0);

                // Right: Graph
                let priv_points: PlotPoints = priv_values
                    .iter()
                    .enumerate()
                    .map(|(i, &v)| [i as f64 * sample_interval, v as f64])
                    .collect();

                Plot::new("priv_plot")
                    .height(140.0)
                    .show_axes([false, false])
                    .show_grid([true, true])
                    .include_y(0.0)
                    .allow_zoom(false)
                    .allow_drag(false)
                    .allow_scroll(false)
                    .show_x(false)
                    .show_y(false)
                    .show(ui, |plot_ui| {
                        plot_ui.line(
                            Line::new(priv_points)
                                .color(egui::Color32::from_rgb(100, 150, 255))
                                .width(1.5)
                                .fill(0.0),
                        );
                    });
            });

            ui.add_space(15.0);
            ui.separator();
            ui.add_space(15.0);

            // I/O Row
            ui.horizontal(|ui| {
                // Left: Mini bar showing combined I/O
                let current_read = io_read_values.last().copied().unwrap_or(0.0);
                let current_write = io_write_values.last().copied().unwrap_or(0.0);
                let current_total = current_read + current_write;
                let max_read = io_read_values.iter().copied().fold(0.0f32, f32::max);
                let max_write = io_write_values.iter().copied().fold(0.0f32, f32::max);
                let max_io = (max_read + max_write).max(1.0);

                render_mini_bar(ui, "I/O", current_total, max_io, |v| {
                    format!("{}/s", format_bytes(Some(v as u64)))
                });

                ui.add_space(10.0);

                // Right: Graph with read and write lines
                let read_points: PlotPoints = io_read_values
                    .iter()
                    .enumerate()
                    .map(|(i, &v)| [i as f64 * sample_interval, v as f64])
                    .collect();

                let write_points: PlotPoints = io_write_values
                    .iter()
                    .enumerate()
                    .map(|(i, &v)| [i as f64 * sample_interval, v as f64])
                    .collect();

                Plot::new("io_plot")
                    .height(140.0)
                    .show_axes([false, false])
                    .show_grid([true, true])
                    .include_y(0.0)
                    .allow_zoom(false)
                    .allow_drag(false)
                    .allow_scroll(false)
                    .legend(egui_plot::Legend::default())
                    .show_x(false)
                    .show_y(false)
                    .show(ui, |plot_ui| {
                        plot_ui.line(
                            Line::new(read_points)
                                .color(egui::Color32::from_rgb(100, 255, 100))
                                .width(1.5)
                                .name("Read"),
                        );
                        plot_ui.line(
                            Line::new(write_points)
                                .color(egui::Color32::from_rgb(255, 150, 100))
                                .width(1.5)
                                .name("Write"),
                        );
                    });
            });

            ui.add_space(20.0);
        });
}

fn render_mini_bar(
    ui: &mut egui::Ui,
    label: &str,
    current: f32,
    max: f32,
    format_fn: impl Fn(f32) -> String,
) {
    ui.vertical(|ui| {
        ui.set_width(90.0);

        // Label
        ui.label(egui::RichText::new(label).strong());
        ui.add_space(5.0);

        // Bar
        let bar_height = 80.0;
        let bar_width = 40.0;
        let (rect, _response) =
            ui.allocate_exact_size(egui::Vec2::new(bar_width, bar_height), egui::Sense::hover());

        let fill_ratio = if max > 0.0 {
            (current / max).clamp(0.0, 1.0)
        } else {
            0.0
        };
        let fill_height = bar_height * fill_ratio;

        // Background
        ui.painter().rect_filled(
            rect,
            egui::Rounding::same(2.0),
            ui.visuals().extreme_bg_color,
        );

        // Fill
        if fill_height > 0.0 {
            let fill_rect = egui::Rect::from_min_size(
                egui::Pos2::new(rect.min.x, rect.max.y - fill_height),
                egui::Vec2::new(bar_width, fill_height),
            );
            ui.painter().rect_filled(
                fill_rect,
                egui::Rounding::same(2.0),
                egui::Color32::from_rgb(100, 200, 100),
            );
        }

        // Border
        ui.painter().rect_stroke(
            rect,
            egui::Rounding::same(2.0),
            egui::Stroke::new(1.0, ui.visuals().widgets.noninteractive.bg_stroke.color),
        );

        ui.add_space(5.0);

        // Value label
        ui.label(
            egui::RichText::new(format_fn(current))
                .small()
                .color(ui.visuals().text_color()),
        );
    });
}

#[cfg(feature = "dev-tools")]
#[allow(dead_code)]
#[derive(Clone, Copy)]
enum MetricKind {
    Normal,
    Badge,
}

#[cfg(feature = "dev-tools")]
#[allow(dead_code)]
#[derive(Clone)]
enum ValueCell {
    Value(String),
    ValueWithTooltip { text: String, tooltip: String },
    NotAvailable(&'static str),
}

const NA_REASON_NOT_IMPLEMENTED: &str = "Not available (not implemented yet).";
#[cfg(feature = "dev-tools")]
#[allow(dead_code)]
const NA_REASON_PRIVILEGES: &str =
    "Not available (requires elevated privileges or additional API support).";
#[cfg(feature = "dev-tools")]
#[allow(dead_code)]
const NA_REASON_SAMPLING: &str =
    "Not available (requires additional sampling; not implemented in current backend).";
#[cfg(feature = "dev-tools")]
#[allow(dead_code)]
const COMPACT_COUNT_THRESHOLD: u64 = 10_000_000_000;

#[cfg(feature = "dev-tools")]
#[allow(dead_code)]
fn format_count(val: Option<u64>) -> ValueCell {
    match val {
        Some(v) => ValueCell::Value(format_count_with_commas(v)),
        None => ValueCell::NotAvailable(NA_REASON_NOT_IMPLEMENTED),
    }
}

#[cfg(feature = "dev-tools")]
#[allow(dead_code)]
fn format_compact_count(v: u64) -> (String, String) {
    let full = format_count_with_commas(v);
    if v < COMPACT_COUNT_THRESHOLD {
        return (full.clone(), full);
    }

    let (val, suffix) = if v >= 1_000_000_000_000 {
        (v as f64 / 1_000_000_000_000.0, "T")
    } else {
        (v as f64 / 1_000_000_000.0, "B")
    };

    (format!("{val:.1}{suffix}"), full)
}

#[cfg(feature = "dev-tools")]
#[allow(dead_code)]
fn compact_value_cell(v: u64) -> ValueCell {
    let (display, full) = format_compact_count(v);
    if display == full {
        ValueCell::Value(full)
    } else {
        ValueCell::ValueWithTooltip {
            text: display,
            tooltip: full,
        }
    }
}

#[cfg(feature = "dev-tools")]
#[allow(dead_code)]
fn format_compact_optional(val: Option<u64>, reason: &'static str) -> ValueCell {
    match val {
        Some(v) => compact_value_cell(v),
        None => ValueCell::NotAvailable(reason),
    }
}

#[cfg(feature = "dev-tools")]
fn format_optional<T>(
    val: Option<T>,
    f: impl FnOnce(T) -> String,
    reason: &'static str,
) -> ValueCell {
    val.map(|v| ValueCell::Value(f(v)))
        .unwrap_or(ValueCell::NotAvailable(reason))
}

fn format_count_with_commas(v: u64) -> String {
    let mut s = v.to_string();
    let mut i = s.len();
    while i > 3 {
        i -= 3;
        s.insert(i, ',');
    }
    s
}

#[cfg(feature = "dev-tools")]
#[allow(dead_code)]
fn perf_chip(
    ui: &mut egui::Ui,
    label: &str,
    value: &str,
    value_is_na: bool,
    tooltip: Option<&str>,
) {
    let visuals = ui.visuals().clone();
    let stroke = egui::Stroke::new(1.0, visuals.strong_text_color().linear_multiply(0.25));
    let fill = visuals.panel_fill.gamma_multiply(0.05);

    let frame = egui::Frame::none()
        .stroke(stroke)
        .fill(fill)
        .rounding(egui::Rounding::same(10.0))
        .inner_margin(egui::Margin::symmetric(8.0, 4.0));

    frame.show(ui, |ui| {
        ui.spacing_mut().item_spacing.x = 6.0;

        let label_text = egui::RichText::new(label)
            .small()
            .color(visuals.weak_text_color());
        let mut value_text = egui::RichText::new(value)
            .monospace()
            .small()
            .color(visuals.strong_text_color())
            .strong();
        if value_is_na {
            value_text = value_text.color(visuals.weak_text_color());
        }

        ui.label(label_text);
        let value_resp = ui.label(value_text);
        if let Some(tip) = tooltip {
            value_resp.on_hover_text(tip);
        }
    });
}

#[cfg(test)]
thread_local! {
    static TEST_CARD_RECTS: std::cell::RefCell<Vec<(&'static str, egui::Rect)>> =
        std::cell::RefCell::new(Vec::new());
}

#[cfg(test)]
#[allow(dead_code)]
fn log_card_rect(id: &'static str, rect: egui::Rect) {
    TEST_CARD_RECTS.with(|data| data.borrow_mut().push((id, rect)));
}

#[cfg(test)]
pub(super) fn take_card_rect(id: &str) -> Option<egui::Rect> {
    TEST_CARD_RECTS.with(|data| {
        let mut data = data.borrow_mut();
        let pos = data.iter().position(|(label, _)| *label == id)?;
        Some(data.remove(pos).1)
    })
}

#[cfg(test)]
pub(super) fn clear_card_rects() {
    TEST_CARD_RECTS.with(|data| data.borrow_mut().clear());
}

#[cfg(feature = "dev-tools")]
fn metric_value(ui: &mut egui::Ui, value: &ValueCell, kind: MetricKind) {
    match kind {
        MetricKind::Normal => {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let label = match value {
                    ValueCell::Value(text) => ui.label(egui::RichText::new(text).monospace()),
                    ValueCell::ValueWithTooltip { text, tooltip } => ui
                        .label(egui::RichText::new(text).monospace())
                        .on_hover_text(tooltip),
                    ValueCell::NotAvailable(reason) => {
                        let lbl = ui.label(
                            egui::RichText::new("Not available")
                                .monospace()
                                .color(ui.visuals().weak_text_color()),
                        );
                        lbl.on_hover_text(*reason)
                    }
                };
                let _ = label;
            });
        }
        MetricKind::Badge => {
            let frame = egui::Frame::none()
                .fill(ui.visuals().widgets.noninteractive.bg_fill)
                .rounding(egui::Rounding::same(4.0))
                .inner_margin(egui::Margin::symmetric(6.0, 2.0));
            frame.show(ui, |ui| {
                let label = match value {
                    ValueCell::Value(text) => ui.label(
                        egui::RichText::new(text)
                            .small()
                            .monospace()
                            .color(ui.visuals().strong_text_color()),
                    ),
                    ValueCell::ValueWithTooltip { text, tooltip } => ui
                        .label(
                            egui::RichText::new(text)
                                .small()
                                .monospace()
                                .color(ui.visuals().strong_text_color()),
                        )
                        .on_hover_text(tooltip),
                    ValueCell::NotAvailable(reason) => ui
                        .label(
                            egui::RichText::new("Not available")
                                .small()
                                .monospace()
                                .color(ui.visuals().weak_text_color()),
                        )
                        .on_hover_text(*reason),
                };
                let _ = label;
            });
        }
    }
}

#[cfg(feature = "dev-tools")]
#[allow(dead_code)]
fn na_value(ui: &mut egui::Ui, reason: &str) {
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        let label = ui.label(
            egui::RichText::new("Not available")
                .monospace()
                .color(ui.visuals().weak_text_color()),
        );
        label.on_hover_text(reason);
    });
}

#[cfg(feature = "dev-tools")]
#[allow(dead_code)]
fn format_rate_bytes_per_s(val: Option<f64>) -> String {
    val.map(|v| {
        if v >= 1_000_000_000.0 {
            format!("{:.1} GB/s", v / 1_000_000_000.0)
        } else if v >= 1_000_000.0 {
            format!("{:.1} MB/s", v / 1_000_000.0)
        } else if v >= 1_000.0 {
            format!("{:.1} KB/s", v / 1_000.0)
        } else {
            format!("{:.1} B/s", v)
        }
    })
    .unwrap_or("N/A".to_string())
}

#[cfg(feature = "dev-tools")]
#[allow(dead_code)]
fn format_rate(val: Option<f64>) -> String {
    val.map(|v| {
        if v >= 1_000_000.0 {
            format!("{:.1}M/s", v / 1_000_000.0)
        } else if v >= 1_000.0 {
            format!("{:.1}K/s", v / 1_000.0)
        } else {
            format!("{:.1}/s", v)
        }
    })
    .unwrap_or("N/A".to_string())
}

#[cfg(feature = "dev-tools")]
#[allow(dead_code)]
fn render_row(ui: &mut egui::Ui, label: &str, value: ValueCell, kind: MetricKind) {
    ui.label(egui::RichText::new(label).monospace());
    metric_value(ui, &value, kind);
    ui.end_row();
}

#[cfg(feature = "dev-tools")]
#[allow(dead_code)]
fn render_cpu_card(ui: &mut egui::Ui, stats: &PerfStats, pid: u32) {
    ui.push_id("perf_card_cpu", |ui| {
        let response = egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.heading("CPU");

            egui::Grid::new(("cpu_card_grid", pid))
                .num_columns(2)
                .spacing([10.0, 4.0])
                .show(ui, |ui| {
                    render_row(
                        ui,
                        "Priority:",
                        format_optional(
                            stats.priority_class.clone(),
                            |v| v,
                            NA_REASON_NOT_IMPLEMENTED,
                        ),
                        MetricKind::Badge,
                    );

                    render_row(
                        ui,
                        "Kernel Time:",
                        format_optional(
                            stats.kernel_time,
                            |v| format_filetime(Some(v)),
                            NA_REASON_NOT_IMPLEMENTED,
                        ),
                        MetricKind::Normal,
                    );
                    render_row(
                        ui,
                        "User Time:",
                        format_optional(
                            stats.user_time,
                            |v| format_filetime(Some(v)),
                            NA_REASON_NOT_IMPLEMENTED,
                        ),
                        MetricKind::Normal,
                    );
                    render_row(
                        ui,
                        "Total Time:",
                        format_optional(
                            stats.total_time,
                            |v| format_filetime(Some(v)),
                            NA_REASON_NOT_IMPLEMENTED,
                        ),
                        MetricKind::Normal,
                    );

                    render_row(
                        ui,
                        "Kernel Δ:",
                        format_optional(
                            stats.kernel_delta,
                            |v| format_filetime_delta(Some(v)),
                            NA_REASON_SAMPLING,
                        ),
                        MetricKind::Badge,
                    );
                    render_row(
                        ui,
                        "User Δ:",
                        format_optional(
                            stats.user_delta,
                            |v| format_filetime_delta(Some(v)),
                            NA_REASON_SAMPLING,
                        ),
                        MetricKind::Badge,
                    );
                    render_row(
                        ui,
                        "Total Δ:",
                        format_optional(
                            stats.total_delta,
                            |v| format_filetime_delta(Some(v)),
                            NA_REASON_SAMPLING,
                        ),
                        MetricKind::Badge,
                    );

                    render_row(
                        ui,
                        "Cycles:",
                        format_compact_optional(stats.cycles, NA_REASON_NOT_IMPLEMENTED),
                        MetricKind::Normal,
                    );
                    render_row(
                        ui,
                        "Cycles Δ:",
                        format_compact_optional(
                            stats.cycles_delta.map(|v| v as u64),
                            NA_REASON_SAMPLING,
                        ),
                        MetricKind::Badge,
                    );
                });
        });

        #[cfg(test)]
        log_card_rect("perf_card_cpu", response.response.rect);
    });
}

#[cfg(feature = "dev-tools")]
#[allow(dead_code)]
fn render_memory_card(ui: &mut egui::Ui, stats: &PerfStats, pid: u32) {
    ui.push_id("perf_card_memory", |ui| {
        let response = egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.heading("Memory");

            ui.label(egui::RichText::new("Virtual Memory").strong());
            egui::Grid::new(("memory_card_grid_virtual", pid))
                .num_columns(2)
                .spacing([10.0, 4.0])
                .show(ui, |ui| {
                    render_row(
                        ui,
                        "Virtual Size:",
                        format_optional(
                            stats.virtual_size,
                            |v| format_bytes_value(v as u64),
                            NA_REASON_NOT_IMPLEMENTED,
                        ),
                        MetricKind::Normal,
                    );
                    render_row(
                        ui,
                        "Private Bytes:",
                        format_optional(
                            stats.private_bytes,
                            |v| format_bytes_value(v as u64),
                            NA_REASON_NOT_IMPLEMENTED,
                        ),
                        MetricKind::Normal,
                    );
                    render_row(
                        ui,
                        "Peak Private Bytes:",
                        format_optional(
                            stats.peak_private_bytes,
                            |v| format_bytes_value(v as u64),
                            NA_REASON_NOT_IMPLEMENTED,
                        ),
                        MetricKind::Normal,
                    );
                    render_row(
                        ui,
                        "Commit Charge:",
                        format_optional(
                            stats.commit_charge,
                            |v| format_bytes_value(v as u64),
                            NA_REASON_NOT_IMPLEMENTED,
                        ),
                        MetricKind::Normal,
                    );
                    render_row(
                        ui,
                        "Peak Commit Charge:",
                        format_optional(
                            stats.peak_commit_charge,
                            |v| format_bytes_value(v as u64),
                            NA_REASON_NOT_IMPLEMENTED,
                        ),
                        MetricKind::Normal,
                    );
                    render_row(
                        ui,
                        "Page Faults:",
                        format_optional(
                            stats.page_faults,
                            |v| format_count_with_commas(v as u64),
                            NA_REASON_NOT_IMPLEMENTED,
                        ),
                        MetricKind::Normal,
                    );
                    render_row(
                        ui,
                        "Page Fault Δ:",
                        format_optional(
                            stats.page_fault_delta,
                            |v| format_count_with_commas(v as u64),
                            NA_REASON_SAMPLING,
                        ),
                        MetricKind::Badge,
                    );
                });

            ui.add_space(6.0);
            ui.label(egui::RichText::new("Physical Memory").strong());
            egui::Grid::new(("memory_card_grid_physical", pid))
                .num_columns(2)
                .spacing([10.0, 4.0])
                .show(ui, |ui| {
                    render_row(
                        ui,
                        "Working Set:",
                        format_optional(
                            stats.working_set,
                            |v| format_bytes_value(v as u64),
                            NA_REASON_NOT_IMPLEMENTED,
                        ),
                        MetricKind::Normal,
                    );
                    render_row(
                        ui,
                        "WS Private:",
                        format_optional(
                            stats.ws_private,
                            |v| format_bytes_value(v as u64),
                            NA_REASON_NOT_IMPLEMENTED,
                        ),
                        MetricKind::Normal,
                    );
                    render_row(
                        ui,
                        "WS Shareable:",
                        format_optional(
                            stats.ws_shareable,
                            |v| format_bytes_value(v as u64),
                            NA_REASON_NOT_IMPLEMENTED,
                        ),
                        MetricKind::Normal,
                    );
                    render_row(
                        ui,
                        "WS Shared:",
                        format_optional(
                            stats.ws_shared,
                            |v| format_bytes_value(v as u64),
                            NA_REASON_NOT_IMPLEMENTED,
                        ),
                        MetricKind::Normal,
                    );
                    render_row(
                        ui,
                        "Peak Working Set:",
                        format_optional(
                            stats.peak_working_set,
                            |v| format_bytes_value(v as u64),
                            NA_REASON_NOT_IMPLEMENTED,
                        ),
                        MetricKind::Normal,
                    );
                });
        });

        #[cfg(test)]
        log_card_rect("perf_card_memory", response.response.rect);
    });
}

#[cfg(feature = "dev-tools")]
#[allow(dead_code)]
fn render_io_card(ui: &mut egui::Ui, stats: &PerfStats, pid: u32) {
    ui.push_id("perf_card_io", |ui| {
        let response = egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.heading("I/O");

            ui.vertical(|ui| {
                egui::Grid::new(("io_card_grid_counts", pid))
                    .num_columns(2)
                    .spacing([10.0, 4.0])
                    .show(ui, |ui| {
                        render_row(
                            ui,
                            "Reads:",
                            format_count(stats.io_reads.map(|v| v as u64)),
                            MetricKind::Normal,
                        );
                        render_row(
                            ui,
                            "Read Δ:",
                            format_optional(
                                stats.io_read_delta,
                                |v| format_count_with_commas(v as u64),
                                NA_REASON_SAMPLING,
                            ),
                            MetricKind::Badge,
                        );
                        render_row(
                            ui,
                            "Read Bytes Δ:",
                            format_optional(
                                stats.io_read_bytes_delta,
                                |v| format_bytes_value(v),
                                NA_REASON_SAMPLING,
                            ),
                            MetricKind::Badge,
                        );

                        render_row(
                            ui,
                            "Writes:",
                            format_count(stats.io_writes.map(|v| v as u64)),
                            MetricKind::Normal,
                        );
                        render_row(
                            ui,
                            "Write Δ:",
                            format_optional(
                                stats.io_write_delta,
                                |v| format_count_with_commas(v as u64),
                                NA_REASON_SAMPLING,
                            ),
                            MetricKind::Badge,
                        );
                        render_row(
                            ui,
                            "Write Bytes Δ:",
                            format_optional(
                                stats.io_write_bytes_delta,
                                |v| format_bytes_value(v),
                                NA_REASON_SAMPLING,
                            ),
                            MetricKind::Badge,
                        );

                        render_row(
                            ui,
                            "Other:",
                            format_count(stats.io_other.map(|v| v as u64)),
                            MetricKind::Normal,
                        );
                        render_row(
                            ui,
                            "Other Δ:",
                            format_optional(
                                stats.io_other_delta,
                                |v| format_count_with_commas(v as u64),
                                NA_REASON_SAMPLING,
                            ),
                            MetricKind::Badge,
                        );
                        render_row(
                            ui,
                            "Other Bytes Δ:",
                            format_optional(
                                stats.io_other_bytes_delta,
                                |v| format_bytes_value(v),
                                NA_REASON_SAMPLING,
                            ),
                            MetricKind::Badge,
                        );
                    });

                ui.add_space(6.0);

                egui::Grid::new(("io_card_grid_rates", pid))
                    .num_columns(2)
                    .spacing([10.0, 4.0])
                    .show(ui, |ui| {
                        render_row(
                            ui,
                            "Read bytes/sec:",
                            format_optional(
                                stats.read_bytes_per_sec,
                                |v| format_rate_bytes_per_s(Some(v)),
                                NA_REASON_SAMPLING,
                            ),
                            MetricKind::Normal,
                        );
                        render_row(
                            ui,
                            "Write bytes/sec:",
                            format_optional(
                                stats.write_bytes_per_sec,
                                |v| format_rate_bytes_per_s(Some(v)),
                                NA_REASON_SAMPLING,
                            ),
                            MetricKind::Normal,
                        );
                        render_row(
                            ui,
                            "Total bytes/sec:",
                            format_optional(
                                stats.total_bytes_per_sec,
                                |v| format_rate_bytes_per_s(Some(v)),
                                NA_REASON_SAMPLING,
                            ),
                            MetricKind::Normal,
                        );

                        render_row(
                            ui,
                            "Read ops/sec:",
                            format_optional(
                                stats.read_ops_per_sec,
                                |v| format_rate(Some(v)),
                                NA_REASON_SAMPLING,
                            ),
                            MetricKind::Normal,
                        );
                        render_row(
                            ui,
                            "Write ops/sec:",
                            format_optional(
                                stats.write_ops_per_sec,
                                |v| format_rate(Some(v)),
                                NA_REASON_SAMPLING,
                            ),
                            MetricKind::Normal,
                        );
                        render_row(
                            ui,
                            "Total ops/sec:",
                            format_optional(
                                stats.total_ops_per_sec,
                                |v| format_rate(Some(v)),
                                NA_REASON_SAMPLING,
                            ),
                            MetricKind::Normal,
                        );
                    });

                ui.add_space(6.0);

                egui::Grid::new(("io_card_grid_adv", pid))
                    .num_columns(2)
                    .spacing([10.0, 4.0])
                    .show(ui, |ui| {
                        render_row(
                            ui,
                            "Avg read size:",
                            format_optional(
                                stats.avg_read_size,
                                |v| format_bytes_value(v as u64),
                                NA_REASON_SAMPLING,
                            ),
                            MetricKind::Normal,
                        );
                        render_row(
                            ui,
                            "Avg write size:",
                            format_optional(
                                stats.avg_write_size,
                                |v| format_bytes_value(v as u64),
                                NA_REASON_SAMPLING,
                            ),
                            MetricKind::Normal,
                        );

                        render_row(
                            ui,
                            "I/O Priority:",
                            ValueCell::NotAvailable(NA_REASON_PRIVILEGES),
                            MetricKind::Normal,
                        );
                    });
            });
        });

        #[cfg(test)]
        log_card_rect("perf_card_io", response.response.rect);
    });
}

#[cfg(feature = "dev-tools")]
#[allow(dead_code)]
fn render_handles_card(ui: &mut egui::Ui, stats: &PerfStats, pid: u32) {
    ui.push_id("perf_card_handles", |ui| {
        let response = egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.heading("Handles");

            egui::Grid::new(("handles_card_grid", pid))
                .num_columns(2)
                .spacing([10.0, 4.0])
                .show(ui, |ui| {
                    render_row(
                        ui,
                        "Handles:",
                        format_count(stats.handles.map(|v| v as u64)),
                        MetricKind::Normal,
                    );
                    render_row(
                        ui,
                        "Peak Handles:",
                        format_count(stats.peak_handles.map(|v| v as u64)),
                        MetricKind::Normal,
                    );
                    render_row(
                        ui,
                        "Handles Δ:",
                        format_optional(
                            stats.handles_delta,
                            |v| format_count_with_commas(v as u64),
                            NA_REASON_SAMPLING,
                        ),
                        MetricKind::Badge,
                    );
                    render_row(
                        ui,
                        "GDI Handles:",
                        format_optional(
                            stats.gdi_handles,
                            |v| format_count_with_commas(v as u64),
                            NA_REASON_PRIVILEGES,
                        ),
                        MetricKind::Normal,
                    );
                    render_row(
                        ui,
                        "USER Handles:",
                        format_optional(
                            stats.user_handles,
                            |v| format_count_with_commas(v as u64),
                            NA_REASON_PRIVILEGES,
                        ),
                        MetricKind::Normal,
                    );
                });
        });

        #[cfg(test)]
        log_card_rect("perf_card_handles", response.response.rect);
    });
}

#[cfg(feature = "dev-tools")]
#[allow(dead_code)]
fn format_filetime_delta(delta: Option<u64>) -> String {
    delta
        .map(|d| {
            let ms = d as f64 / 10_000.0;
            if ms < 1000.0 {
                format!("{:.0} ms", ms)
            } else {
                format!("{:.1} s", ms / 1000.0)
            }
        })
        .unwrap_or("Not available".to_string())
}

fn format_bytes(val: Option<u64>) -> String {
    val.map(|v| {
        if v >= 1_073_741_824 {
            format!("{:.1} GiB", v as f64 / 1_073_741_824.0)
        } else if v >= 1_048_576 {
            format!("{:.1} MiB", v as f64 / 1_048_576.0)
        } else if v >= 1_024 {
            format!("{:.1} KiB", v as f64 / 1024.0)
        } else {
            format!("{} B", v)
        }
    })
    .unwrap_or("Not available".to_string())
}

#[cfg(feature = "dev-tools")]
#[allow(dead_code)]
fn format_bytes_value(v: u64) -> String {
    format_bytes(Some(v))
}

/// Render Network tab with socket churn monitoring
fn render_network_tab_with_churn(
    ui: &mut egui::Ui,
    pid: u32,
    perf_window: &mut super::ProcessPerfWindow,
    current_snapshot: &ProcessSnapshot,
) {
    use super::history::{
        NetChurnMonitor, CLOSE_WAIT_RISING_COUNT, CLOSE_WAIT_THRESHOLD, NET_POLL_INTERVAL_SECS,
        NEW_CONN_PER_SEC_THRESHOLD, TIME_WAIT_THRESHOLD,
    };

    ui.heading("Network Connections");
    ui.add_space(4.0);

    // Include child PIDs toggle
    ui.horizontal(|ui| {
        let checkbox_resp = ui.checkbox(
            &mut perf_window.include_child_pids,
            "Include child processes",
        );
        if checkbox_resp.changed() {
            // Reset monitor when toggling
            perf_window.net_churn_monitor = None;
        }

        if perf_window.include_child_pids {
            let child_count = perf_window
                .net_churn_monitor
                .as_ref()
                .map(|m| m.child_pid_count)
                .unwrap_or(0);
            ui.label(egui::RichText::new(format!("(+ {} children)", child_count)).weak());
        }
    });

    ui.add_space(4.0);

    // Initialize monitor if needed
    if perf_window.net_churn_monitor.is_none() {
        perf_window.net_churn_monitor = Some(NetChurnMonitor::default());
    }

    let monitor = perf_window.net_churn_monitor.as_mut().unwrap();

    // Poll if interval elapsed
    let now = std::time::Instant::now();
    let should_poll = now.duration_since(monitor.last_poll).as_secs_f32() >= NET_POLL_INTERVAL_SECS;

    if should_poll {
        let pids_to_monitor = if perf_window.include_child_pids {
            collect_descendants(pid, current_snapshot)
        } else {
            vec![pid]
        };
        super::super::PMonNTApp::poll_network_connections(monitor, pid, &pids_to_monitor);
    }

    // Get current sample or default
    let current = monitor.samples.back().cloned().unwrap_or_default();
    let tcp_states = &current.tcp_states;

    // Show error if any
    if let Some(err) = &monitor.error {
        ui.colored_label(egui::Color32::LIGHT_RED, format!("Error: {}", err));
        return;
    }

    // Summary strip - always visible
    ui.group(|ui| {
        ui.horizontal_wrapped(|ui| {
            ui.label(egui::RichText::new("Summary").strong());
            ui.separator();

            // Total sockets
            ui.label("Total:");
            ui.monospace(format!("{} TCP", current.total_tcp));
            ui.label("|");
            ui.monospace(format!("{} UDP", current.total_udp));
            ui.separator();

            // TCP states
            ui.label("TCP:");
            ui.monospace(format!("ESTAB {}", tcp_states.established));
            ui.label("|");
            ui.monospace(format!("TIME_WAIT {}", tcp_states.time_wait));
            ui.label("|");
            ui.monospace(format!("CLOSE_WAIT {}", tcp_states.close_wait));
            ui.label("|");
            ui.monospace(format!("SYN {}", tcp_states.syn_sent + tcp_states.syn_recv));
            ui.separator();

            // New connections/sec
            ui.label("New/sec:");
            ui.monospace(format!("{:.1}", current.new_per_sec));
            ui.separator();

            // Unique remotes
            ui.label("Endpoints:");
            ui.monospace(format!("{}", current.unique_remotes));
        });
    });

    ui.add_space(4.0);

    // Warning badges
    let mut badges = Vec::new();

    if tcp_states.close_wait >= CLOSE_WAIT_THRESHOLD {
        badges.push(("⚠ CLOSE_WAIT high", egui::Color32::from_rgb(255, 140, 0)));
    }

    // Check if CLOSE_WAIT is rising (last N samples)
    if monitor.samples.len() >= CLOSE_WAIT_RISING_COUNT {
        let recent: Vec<u32> = monitor
            .samples
            .iter()
            .rev()
            .take(CLOSE_WAIT_RISING_COUNT)
            .map(|s| s.tcp_states.close_wait)
            .collect();
        let is_rising = recent.windows(2).all(|w| w[0] > w[1]);
        if is_rising && recent[0] > 5 {
            badges.push(("⚠ CLOSE_WAIT rising", egui::Color32::from_rgb(255, 69, 0)));
        }
    }

    if tcp_states.time_wait >= TIME_WAIT_THRESHOLD {
        badges.push(("⚠ TIME_WAIT high", egui::Color32::from_rgb(255, 165, 0)));
    }

    if current.new_per_sec >= NEW_CONN_PER_SEC_THRESHOLD {
        badges.push(("⚠ Connect storm", egui::Color32::from_rgb(255, 0, 0)));
    }

    if !badges.is_empty() {
        ui.horizontal_wrapped(|ui| {
            for (text, color) in badges {
                ui.colored_label(color, text);
            }
        });
        ui.add_space(4.0);
    }

    // Sparkline graphs
    if monitor.samples.len() >= 2 {
        ui.group(|ui| {
            ui.label(egui::RichText::new("Socket Churn (last 2 minutes)").strong());
            ui.add_space(2.0);

            ui.columns(2, |cols| {
                // TIME_WAIT graph
                cols[0].vertical(|ui| {
                    ui.label(egui::RichText::new("TIME_WAIT").small().weak());
                    let time_wait_values: Vec<f32> = monitor
                        .samples
                        .iter()
                        .map(|s| s.tcp_states.time_wait as f32)
                        .collect();
                    super::sparkline::draw_sparkline_f32_with_label(
                        ui,
                        &time_wait_values,
                        0.0,
                        time_wait_values
                            .iter()
                            .copied()
                            .fold(0.0f32, f32::max)
                            .max(1.0),
                        48.0,
                    );
                });

                // CLOSE_WAIT graph
                cols[1].vertical(|ui| {
                    ui.label(egui::RichText::new("CLOSE_WAIT").small().weak());
                    let close_wait_values: Vec<f32> = monitor
                        .samples
                        .iter()
                        .map(|s| s.tcp_states.close_wait as f32)
                        .collect();
                    super::sparkline::draw_sparkline_f32_with_label(
                        ui,
                        &close_wait_values,
                        0.0,
                        close_wait_values
                            .iter()
                            .copied()
                            .fold(0.0f32, f32::max)
                            .max(1.0),
                        48.0,
                    );
                });
            });

            ui.add_space(2.0);

            // New connections/sec graph
            ui.label(egui::RichText::new("New Connections/sec").small().weak());
            let new_per_sec_values: Vec<f32> =
                monitor.samples.iter().map(|s| s.new_per_sec).collect();
            super::sparkline::draw_sparkline_f32_with_label(
                ui,
                &new_per_sec_values,
                0.0,
                new_per_sec_values
                    .iter()
                    .copied()
                    .fold(0.0f32, f32::max)
                    .max(1.0),
                48.0,
            );
        });

        ui.add_space(4.0);
    }

    // State filter dropdown (for future enhancement)
    ui.separator();
    ui.label(
        egui::RichText::new(
            "Tip: Watch TIME_WAIT/CLOSE_WAIT trends to spot leaks. TCP/UDP sockets only.",
        )
        .weak(),
    );
    ui.add_space(4.0);

    // Fetch connections for table
    let pids_to_show = if perf_window.include_child_pids {
        collect_descendants(pid, current_snapshot)
    } else {
        vec![pid]
    };

    match fetch_connections_for_pids(&pids_to_show) {
        Ok(mut conns) => {
            if conns.is_empty() {
                ui.label(egui::RichText::new("No active connections").color(egui::Color32::GRAY));
            } else {
                sort_connections(&mut conns, NetworkSortState::default());

                let row_h = 18.0;
                let mut builder = egui_extras::TableBuilder::new(ui)
                    .striped(true)
                    .resizable(true)
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center));

                if perf_window.include_child_pids {
                    builder = builder.column(egui_extras::Column::auto());
                }
                builder = builder
                    .column(egui_extras::Column::auto())
                    .column(egui_extras::Column::remainder().at_least(140.0))
                    .column(egui_extras::Column::remainder().at_least(140.0))
                    .column(egui_extras::Column::auto());

                builder
                    .header(row_h, |mut header| {
                        if perf_window.include_child_pids {
                            header.col(|ui| {
                                ui.label(egui::RichText::new("PID").strong());
                            });
                        }
                        header.col(|ui| {
                            ui.label(egui::RichText::new("Proto").strong());
                        });
                        header.col(|ui| {
                            ui.label(egui::RichText::new("Local").strong());
                        });
                        header.col(|ui| {
                            ui.label(egui::RichText::new("Remote").strong());
                        });
                        header.col(|ui| {
                            ui.label(egui::RichText::new("State").strong());
                        });
                    })
                    .body(|mut body| {
                        for c in conns {
                            body.row(row_h, |mut row| {
                                if perf_window.include_child_pids {
                                    row.col(|ui| {
                                        ui.monospace(format!("{}", c.pid));
                                    });
                                }
                                row.col(|ui| {
                                    ui.label(match c.protocol {
                                        pmonnt_core::network::Protocol::Tcp => "TCP",
                                        pmonnt_core::network::Protocol::Udp => "UDP",
                                    });
                                });
                                row.col(|ui| {
                                    ui.label(format!("{}:{}", c.local_address, c.local_port));
                                });
                                row.col(|ui| {
                                    if let (Some(ip), Some(port)) =
                                        (c.remote_address, c.remote_port)
                                    {
                                        ui.label(format!("{}:{}", ip, port));
                                    } else {
                                        ui.label(
                                            egui::RichText::new("-").color(egui::Color32::GRAY),
                                        );
                                    }
                                });
                                row.col(|ui| {
                                    if let Some(state) = c.state {
                                        let text = format!("{:?}", state);
                                        let color = match state {
                                            pmonnt_core::network::TcpState::TimeWait => {
                                                egui::Color32::from_rgb(255, 140, 0)
                                            }
                                            pmonnt_core::network::TcpState::CloseWait => {
                                                egui::Color32::from_rgb(255, 69, 0)
                                            }
                                            pmonnt_core::network::TcpState::Established => {
                                                egui::Color32::from_rgb(0, 200, 0)
                                            }
                                            _ => ui.visuals().text_color(),
                                        };
                                        ui.colored_label(color, text);
                                    } else {
                                        ui.label(
                                            egui::RichText::new("-").color(egui::Color32::GRAY),
                                        );
                                    }
                                });
                            });
                        }
                    });
            }
        }
        Err(e) => {
            ui.colored_label(
                egui::Color32::LIGHT_RED,
                format!("Failed to enumerate connections: {}", e),
            );
        }
    }
}

/// Collect all descendant PIDs for a root PID
fn collect_descendants(root_pid: u32, snapshot: &ProcessSnapshot) -> Vec<u32> {
    use std::collections::{HashMap, HashSet};

    // Build parent -> children map
    let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
    for proc in &snapshot.processes {
        if let Some(ppid) = proc.ppid {
            if ppid != 0 {
                children_map.entry(ppid).or_default().push(proc.pid);
            }
        }
    }

    let mut result = Vec::new();
    let mut visited = HashSet::new();
    let mut stack = vec![root_pid];

    while let Some(pid) = stack.pop() {
        if !visited.insert(pid) {
            continue; // Already visited (cycle detection)
        }
        result.push(pid);

        if let Some(children) = children_map.get(&pid) {
            for &child in children {
                stack.push(child);
            }
        }
    }

    result
}

/// Fetch connections for multiple PIDs
fn fetch_connections_for_pids(
    pids: &[u32],
) -> Result<Vec<pmonnt_core::network::NetworkConnection>, pmonnt_core::network::NetworkError> {
    use std::collections::HashSet;

    let all_conns = pmonnt_core::network::get_all_connections()?;
    let pid_set: HashSet<u32> = pids.iter().copied().collect();
    Ok(all_conns
        .into_iter()
        .filter(|c| pid_set.contains(&c.pid))
        .collect())
}
