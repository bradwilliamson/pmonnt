use super::sha::{PendingLookups, known_image_sha, request_check};
use crate::ui_state::{TfQueryState, TfUiState};
use eframe::egui;
use pmonnt_core::reputation_service::ReputationService;
use std::collections::HashMap;
use std::sync::Arc;

impl PendingLookups for TfUiState {
    fn pending_checks(&mut self) -> &mut HashMap<u32, bool> {
        &mut self.pending_checks
    }

    fn shown_pid(&self) -> Option<u32> {
        self.last_seen_pid
    }

    fn request(service: &ReputationService, sha: &str, force: bool) {
        service.request_tf_lookup_for_hash(sha, force);
    }

    fn track(&mut self, pid: u32, sha: String) {
        self.current_process_sha = Some(sha.clone());
        self.querying_tf_sha = Some(sha);
        self.querying_tf_pid = Some(pid);
    }

    fn show_error(&mut self, message: String) {
        set_tf_error(self, message);
    }
}

fn set_tf_error(tf_state: &mut TfUiState, message: String) {
    tf_state.last_query_state = Some(TfQueryState {
        last_query: Some("request".to_string()),
        last_http_status: None,
        last_query_status: Some("error".to_string()),
        last_result_count: None,
        last_error_message: Some(message),
    });
}

/// Queue an explicit lookup for `pid` (see [`request_check`]) or show why it cannot start.
fn request_check_or_report(
    tf_state: &mut TfUiState,
    reputation_service: &ReputationService,
    pid_to_image_path: &HashMap<u32, String>,
    pid: u32,
    force: bool,
) {
    if let Err(e) = request_check(
        reputation_service,
        pid_to_image_path,
        pid,
        force,
        &mut tf_state.pending_checks,
    ) {
        set_tf_error(tf_state, e);
    }
}

pub fn render_threatfox_section(
    ui: &mut egui::Ui,
    tf_state: &mut TfUiState,
    reputation_service: &Arc<ReputationService>,
    pid: Option<u32>,
    pid_to_image_path: &HashMap<u32, String>,
    online_lookups_enabled: bool,
) {
    ui.heading("ThreatFox");
    ui.add_space(4.0);

    if pid != tf_state.last_seen_pid {
        tf_state.last_seen_pid = pid;
        tf_state.querying_tf_pid = None;
        tf_state.querying_tf_sha = None;
        tf_state.current_process_sha = None;
        tf_state.last_query_state = None;
    }

    // Show the image hash as soon as it is known.
    if tf_state.current_process_sha.is_none()
        && let Some(sha) =
            pid.and_then(|pid| known_image_sha(reputation_service, pid_to_image_path, pid))
    {
        tf_state.current_process_sha = Some(sha);
    }

    let can_query = pid.is_some() && online_lookups_enabled;
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                can_query,
                egui::Button::new("Check this process in ThreatFox"),
            )
            .clicked()
            && let Some(pid) = pid
        {
            request_check_or_report(tf_state, reputation_service, pid_to_image_path, pid, false);
        }

        // Refresh re-validates the hash and bypasses the cached answers.
        if ui
            .add_enabled(can_query, egui::Button::new("Refresh TF data"))
            .clicked()
            && let Some(pid) = pid
        {
            request_check_or_report(tf_state, reputation_service, pid_to_image_path, pid, true);
        }

        if pid.is_some_and(|pid| tf_state.pending_checks.contains_key(&pid)) {
            ui.spinner();
            ui.label("Hashing image...");
        } else if let Some(sha) = tf_state
            .current_process_sha
            .as_ref()
            .or(tf_state.querying_tf_sha.as_ref())
            && (reputation_service.tf_lookup_in_flight(sha)
                || (tf_state.querying_tf_pid == pid
                    && reputation_service.get_tf_result_for_hash(sha).is_none()))
        {
            ui.spinner();
            ui.label("Querying ThreatFox...");
        }
    });

    ui.add_space(6.0);
    if pid.is_none() {
        ui.colored_label(
            egui::Color32::GRAY,
            "Select a process on the left to query ThreatFox.",
        );
        return;
    }

    let sha_to_show = tf_state
        .current_process_sha
        .as_ref()
        .or(tf_state.querying_tf_sha.as_ref());

    if let Some(sha) = sha_to_show {
        if let Some(pid) = pid
            && let Some(path) = pid_to_image_path.get(&pid)
        {
            let filename = std::path::Path::new(path)
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            ui.horizontal(|ui| {
                ui.label(format!("Process: {filename}"));
            });
            ui.horizontal(|ui| {
                ui.label(format!("Path:    {path}"));
            });
        }
        ui.horizontal(|ui| {
            ui.label("SHA-256:");
            ui.monospace(sha);
            if ui.button("📋").clicked() {
                ui.copy_text(sha.clone());
            }
        });

        if let Some((opt_iocs, meta)) = reputation_service.get_tf_result_for_hash(sha) {
            // Stop querying spinner for this PID now that we have a cached entry (either Some or None)
            if tf_state.querying_tf_pid == pid {
                tf_state.querying_tf_pid = None;
                tf_state.querying_tf_sha = None;
            }

            if tf_state.querying_tf_pid != pid {
                ui.colored_label(
                    egui::Color32::GRAY,
                    "Cached result — click Refresh to re-query (cached)",
                );
            }

            if let Some(status) = meta.last_query_status.as_deref() {
                match status {
                    "ok" => {
                        if let Some(iocs) = opt_iocs {
                            if !iocs.is_empty() {
                                ui.colored_label(
                                    egui::Color32::RED,
                                    format!("ThreatFox: {} IOCs", iocs.len()),
                                );
                                ui.separator();
                                ui.label("IOCs:");
                                egui::ScrollArea::vertical()
                                    .max_height(180.0)
                                    .show(ui, |ui| {
                                        for i in iocs {
                                            let typ = i
                                                .ioc_type
                                                .clone()
                                                .unwrap_or_else(|| "ioc".to_string());
                                            let val = i.ioc.clone();
                                            ui.horizontal(|ui| {
                                                ui.label(format!("[{typ}] {val}"));
                                                if ui.small_button("📋").clicked() {
                                                    ui.copy_text(val.clone());
                                                }
                                            });
                                        }
                                    });
                            } else {
                                ui.colored_label(egui::Color32::GRAY, "No IOCs found in ThreatFox");
                            }
                        } else {
                            ui.colored_label(egui::Color32::GRAY, "No IOCs found in ThreatFox");
                        }
                    }
                    "no_result" | "no_results" => {
                        ui.colored_label(
                            egui::Color32::GRAY,
                            "No threat intel found (not in ThreatFox)",
                        );
                    }
                    _ => {
                        if let Some(err) = &meta.last_error_message {
                            ui.colored_label(egui::Color32::RED, format!("Error: {err}"));
                        } else {
                            ui.colored_label(egui::Color32::RED, "ThreatFox request failed");
                        }
                    }
                }
            }
        } else if tf_state.querying_tf_pid == pid && tf_state.querying_tf_sha.is_some() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Querying ThreatFox...");
            });
        } else {
            ui.label("No ThreatFox data for this process (click Check to query)");
        }
    } else {
        ui.label("No ThreatFox data for this process (click Check to query)");
    }
}
