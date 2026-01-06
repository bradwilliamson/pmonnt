use crate::ui_state::VtUiState;
use eframe::egui;
use pmonnt_core::reputation_service::ReputationService;
use std::collections::HashMap;
use std::sync::Arc;

pub fn render_virustotal_section(
    ui: &mut egui::Ui,
    vt_state: &mut VtUiState,
    reputation_service: &Arc<ReputationService>,
    pid: Option<u32>,
    pid_to_image_path: &HashMap<u32, String>,
    online_lookups_enabled: bool,
) {
    ui.heading("VirusTotal");
    ui.add_space(4.0);

    // Tunable VT UX: spinner/stuck timeout (seconds)
    const VT_QUERY_TIMEOUT_SECS: u64 = 10;

    // Reset VT UI state if selection changed
    if pid != vt_state.last_seen_pid {
        vt_state.last_seen_pid = pid;
        vt_state.querying_vt_pid = None;
        vt_state.querying_vt_sha = None;
        vt_state.current_process_sha = None;
        vt_state.last_query_meta = None;
    }

    let can_query = pid.is_some() && online_lookups_enabled;
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                can_query,
                egui::Button::new("Check this process in VirusTotal"),
            )
            .clicked()
        {
            if let Some(pid) = pid {
                match reputation_service.request_vt_lookup_for_process(pid) {
                    Ok(sha) => {
                        vt_state.current_process_sha = Some(sha.clone());
                        vt_state.querying_vt_sha = Some(sha);
                        vt_state.querying_vt_pid = Some(pid);
                        vt_state.querying_started_at = Some(std::time::Instant::now());
                    }
                    Err(e) => {
                        vt_state.last_query_meta = Some(pmonnt_core::vt::VtQueryMeta {
                            last_query: Some("request".to_string()),
                            last_http_status: None,
                            last_query_status: Some("error".to_string()),
                            last_result_count: None,
                            last_error_message: Some(e),
                        });
                    }
                }
            }
        }

        if ui
            .add_enabled(can_query, egui::Button::new("Refresh VT data"))
            .clicked()
            && vt_state
                .current_process_sha
                .as_ref()
                .or(vt_state.querying_vt_sha.as_ref())
                .is_some()
        {
            // Re-request by process - this will dedupe if in-flight
            if let Some(pid) = pid {
                let _ = reputation_service.request_vt_lookup_for_process(pid);
                vt_state.querying_vt_pid = Some(pid);
                vt_state.querying_started_at = Some(std::time::Instant::now());
            }
        }

        // Spinner logic: show only if querying for this process and no cached result yet
        if let Some(sha) = vt_state
            .current_process_sha
            .as_ref()
            .or(vt_state.querying_vt_sha.as_ref())
        {
            if vt_state.querying_vt_pid == pid
                && reputation_service.get_vt_sample_for_hash(sha).is_none()
            {
                ui.spinner();
                ui.label("Querying VirusTotal...");
            }
        }
    });

    ui.add_space(6.0);
    if pid.is_none() {
        ui.colored_label(
            egui::Color32::GRAY,
            "Select a process on the left to query VirusTotal.",
        );
        return;
    }

    // Drain pending sha
    if let Ok(mut guard) = vt_state.current_process_sha_pending.lock() {
        if let Some(sha) = guard.take() {
            vt_state.current_process_sha = Some(sha);
        }
    }

    let sha_to_show = vt_state
        .current_process_sha
        .as_ref()
        .or(vt_state.querying_vt_sha.as_ref());

    // Stuck protection
    if let Some(started) = vt_state.querying_started_at {
        if started.elapsed() > std::time::Duration::from_secs(VT_QUERY_TIMEOUT_SECS) {
            vt_state.querying_vt_pid = None;
            vt_state.querying_started_at = None;
        }
    }

    if let Some(sha) = sha_to_show {
        if let Some(pid) = pid {
            if let Some(path) = pid_to_image_path.get(&pid) {
                let filename = std::path::Path::new(path)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("");
                ui.horizontal(|ui| {
                    ui.label(format!("Process: {}", filename));
                });
                ui.horizontal(|ui| {
                    ui.label(format!("Path:    {}", path));
                });
            }
        }
        ui.horizontal(|ui| {
            ui.label("SHA-256:");
            ui.monospace(sha);
            if ui.button("📋").clicked() {
                ui.output_mut(|o| o.copied_text = sha.clone());
            }
        });

        if let Some((stats_opt, meta)) = reputation_service.get_vt_sample_for_hash(sha) {
            if vt_state.querying_vt_pid != pid {
                ui.colored_label(
                    egui::Color32::GRAY,
                    "Cached result — click Refresh to re-query (cached)",
                );
            }
            if let Some(status) = meta.last_query_status.as_deref() {
                match status {
                    "ok" => {
                        if let Some(stats) = stats_opt {
                            let detections = stats.total_detections();
                            let total = stats.total_engines();
                            let color = if detections == 0 {
                                egui::Color32::GREEN
                            } else if detections < 5 {
                                egui::Color32::YELLOW
                            } else {
                                egui::Color32::RED
                            };
                            ui.colored_label(
                                color,
                                format!("VT: {}/{} detections", detections, total),
                            );
                        } else {
                            ui.colored_label(
                                egui::Color32::GRAY,
                                "No VT sample data (recorded as not found)",
                            );
                        }
                        vt_state.querying_vt_pid = None;
                        vt_state.querying_started_at = None;
                    }
                    "not_found" => {
                        ui.colored_label(egui::Color32::GRAY, "Not found on VirusTotal");
                        vt_state.querying_vt_pid = None;
                        vt_state.querying_started_at = None;
                    }
                    _ => {
                        if let Some(err) = &meta.last_error_message {
                            if err.contains("unauthorized")
                                || err.contains("401")
                                || err.contains("403")
                            {
                                ui.colored_label(egui::Color32::RED, "API key invalid or missing");
                            } else {
                                ui.colored_label(
                                    egui::Color32::RED,
                                    "VirusTotal offline or request failed",
                                );
                            }
                        }
                        vt_state.querying_vt_pid = None;
                        vt_state.querying_started_at = None;
                    }
                }
            } else if let Some(err) = &meta.last_error_message {
                if err.contains("unauthorized") || err.contains("401") || err.contains("403") {
                    ui.colored_label(egui::Color32::RED, "API key invalid or missing");
                } else {
                    ui.colored_label(egui::Color32::RED, "VirusTotal offline or request failed");
                }
                vt_state.querying_vt_pid = None;
                vt_state.querying_started_at = None;
            }
        } else if vt_state.querying_vt_pid == pid && vt_state.querying_vt_sha.is_some() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Querying VirusTotal...");
            });
        } else {
            ui.label("No VirusTotal data for this process (click Check to query)");
        }
    } else {
        ui.label("No VirusTotal data for this process (click Check to query)");
    }
}
