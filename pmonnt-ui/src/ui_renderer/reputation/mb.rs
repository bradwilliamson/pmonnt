use crate::ui_state::{MbQueryState, MbUiState};
use eframe::egui;
use pmonnt_core::reputation_service::ReputationService;
use std::collections::HashMap;
use std::sync::Arc;

pub fn render_malwarebazaar_section(
    ui: &mut egui::Ui,
    mb_state: &mut MbUiState,
    reputation_service: &Arc<ReputationService>,
    pid: Option<u32>,
    pid_to_image_path: &HashMap<u32, String>,
    online_lookups_enabled: bool,
) {
    ui.heading("MalwareBazaar");
    ui.add_space(4.0);

    // Reset MB UI state if process selection changed
    if pid != mb_state.last_seen_pid {
        mb_state.last_seen_pid = pid;
        mb_state.querying_mb_pid = None;
        mb_state.querying_mb_sha = None;
        mb_state.current_process_sha = None;
        mb_state.last_query_state = None;
    }

    // Button enable logic: only allow when a process selected and online lookups enabled.
    let can_query = pid.is_some() && online_lookups_enabled;

    // MB lookup controls
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                can_query,
                egui::Button::new("Check this process in MalwareBazaar"),
            )
            .clicked()
        {
            if let Some(pid) = pid {
                match reputation_service.request_mb_lookup_for_process(pid) {
                    Ok(sha) => {
                        mb_state.current_process_sha = Some(sha.clone());
                        mb_state.querying_mb_sha = Some(sha);
                        mb_state.querying_mb_pid = Some(pid);
                        mb_state.querying_started_at = Some(std::time::Instant::now());
                    }
                    Err(e) => {
                        mb_state.last_query_state = Some(MbQueryState {
                            last_query: Some("get_info".to_string()),
                            last_http_status: None,
                            last_query_status: None,
                            last_result_count: None,
                            last_error_message: Some(e),
                        });
                    }
                }
            }
        }

        if ui
            .add_enabled(can_query, egui::Button::new("Refresh MB data"))
            .clicked()
        {
            if let Some(sha) = mb_state
                .current_process_sha
                .as_ref()
                .or(mb_state.querying_mb_sha.as_ref())
            {
                let _ = reputation_service.request_mb_lookup_for_hash(sha, true);
                if let Some(pid) = pid {
                    mb_state.querying_mb_pid = Some(pid);
                    mb_state.querying_started_at = Some(std::time::Instant::now());
                }
            }
        }

        // Only show spinner if querying for this process, have a sha, and no cached result yet
        if let Some(sha) = mb_state
            .current_process_sha
            .as_ref()
            .or(mb_state.querying_mb_sha.as_ref())
        {
            if mb_state.querying_mb_pid == pid
                && reputation_service.get_mb_sample_for_hash(sha).is_none()
            {
                ui.spinner();
                ui.label("Querying MalwareBazaar...");
            }
        }
    });

    ui.add_space(6.0);

    // Show hint if no process selected
    if pid.is_none() {
        ui.colored_label(
            egui::Color32::GRAY,
            "Select a process on the left to query MalwareBazaar.",
        );
        return;
    }

    // Drain pending computed SHA (from background thread)
    if let Ok(mut guard) = mb_state.current_process_sha_pending.lock() {
        if let Some(sha) = guard.take() {
            mb_state.current_process_sha = Some(sha);
        }
    }

    // Prefer current_process_sha, fallback to querying_mb_sha
    let sha_to_show = mb_state
        .current_process_sha
        .as_ref()
        .or(mb_state.querying_mb_sha.as_ref());

    // Stuck protection: if a query has been running too long, clear it
    if let Some(started) = mb_state.querying_started_at {
        if started.elapsed() > std::time::Duration::from_secs(15) {
            mb_state.querying_mb_pid = None;
            mb_state.querying_started_at = None;
        }
    }
    if let Some(sha) = sha_to_show {
        // Show process file info + SHA even before MB query
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
        if let Some((sample_opt, meta)) = reputation_service.get_mb_sample_for_hash(sha) {
            // Show 'Cached result' if present and not actively querying this PID
            if mb_state.querying_mb_pid != pid {
                ui.colored_label(egui::Color32::GRAY, "Cached result");
            }
            if let Some(status) = meta.last_query_status.as_deref() {
                match status {
                    "ok" => {
                        if let Some(sample) = sample_opt {
                            ui.label(format!(
                                "Signature/family: {}",
                                sample
                                    .signature
                                    .clone()
                                    .unwrap_or_else(|| "(unknown)".to_string())
                            ));
                            if let Some(first) = sample.first_seen {
                                ui.label(format!("First seen: {}", first));
                            }
                            if !sample.tags.is_empty() {
                                ui.label(format!("Tags: {}", sample.tags.join(", ")));
                            }

                            ui.collapsing("Vendor intel", |ui| {
                                if let Some(v) = &sample.vendor_intel {
                                    ui.label(format!("{}", v));
                                }
                            })
                            .header_response
                            .clicked();
                            ui.collapsing("YARA rules", |ui| {
                                if let Some(y) = &sample.yara_rules {
                                    ui.label(format!("{}", y));
                                }
                            })
                            .header_response
                            .clicked();
                            ui.collapsing("Comments", |ui| {
                                if let Some(comments) = &sample.comments {
                                    for c in comments.iter() {
                                        ui.label(format!(
                                            "{}: {}",
                                            c.date.clone().unwrap_or_default(),
                                            c.comment.clone().unwrap_or_default()
                                        ));
                                    }
                                }
                            })
                            .header_response
                            .clicked();
                        } else {
                            ui.colored_label(
                                egui::Color32::GRAY,
                                "No sample known to MalwareBazaar for this binary.",
                            );
                        }
                        // Terminal state - clear querying indicator
                        mb_state.querying_mb_pid = None;
                        mb_state.querying_started_at = None;
                    }
                    "hash_not_found" => {
                        ui.colored_label(
                            egui::Color32::GRAY,
                            "No sample known to MalwareBazaar for this binary.",
                        );
                        mb_state.querying_mb_pid = None;
                        mb_state.querying_started_at = None;
                    }
                    "no_results" => {
                        ui.colored_label(egui::Color32::GRAY, "Query returned no results.");
                        mb_state.querying_mb_pid = None;
                        mb_state.querying_started_at = None;
                    }
                    s if s.starts_with("illegal_") => {
                        ui.colored_label(egui::Color32::RED, format!("MB error: {}", s));
                        mb_state.querying_mb_pid = None;
                        mb_state.querying_started_at = None;
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
                                    "MalwareBazaar offline or request failed",
                                );
                            }
                            mb_state.querying_mb_pid = None;
                            mb_state.querying_started_at = None;
                        }
                    }
                }
            } else if let Some(err) = &meta.last_error_message {
                if err.contains("unauthorized") || err.contains("401") || err.contains("403") {
                    ui.colored_label(egui::Color32::RED, "API key invalid or missing");
                } else {
                    ui.colored_label(
                        egui::Color32::RED,
                        "MalwareBazaar offline or request failed",
                    );
                }
                mb_state.querying_mb_pid = None;
                mb_state.querying_started_at = None;
            }
        } else if mb_state.querying_mb_pid == pid && mb_state.querying_mb_sha.is_some() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Querying MalwareBazaar...");
            });
        } else {
            ui.label("No MalwareBazaar data for this process (click Check to query)");
        }
    } else {
        ui.label("No MalwareBazaar data for this process (click Check to query)");
    }

    // MB query status (from provider)
    if let Some(meta) = reputation_service.mb_get_last_query_meta() {
        // mirror into UI state
        mb_state.last_query_state = Some(MbQueryState {
            last_query: meta.last_query.clone(),
            last_http_status: meta.last_http_status,
            last_query_status: meta.last_query_status.clone(),
            last_result_count: meta.last_result_count,
            last_error_message: meta.last_error_message.clone(),
        });

        ui.horizontal(|ui| {
            ui.label("MB status:");
            match meta.last_query_status.as_deref() {
                Some("ok") => {
                    let count = meta.last_result_count.unwrap_or(0);
                    ui.label(format!("ok ({} results)", count));
                }
                Some("hash_not_found") => {
                    ui.colored_label(egui::Color32::YELLOW, "hash_not_found (no sample known)");
                }
                Some("tag_not_found") => {
                    ui.colored_label(egui::Color32::YELLOW, "tag_not_found");
                }
                Some("no_results") => {
                    ui.colored_label(egui::Color32::YELLOW, "no_results");
                }
                Some(s) => {
                    ui.label(s);
                }
                None => {
                    ui.label("(no recent MB queries)");
                }
            }
            if let Some(code) = meta.last_http_status {
                ui.add_space(6.0);
                ui.label(format!("HTTP: {}", code));
            }
        });

        // Friendly explanatory text
        if let Some(status) = meta.last_query_status.as_deref() {
            match status {
                "hash_not_found" => {
                    ui.label("No sample known to MalwareBazaar for this hash.");
                }
                "tag_not_found" => {
                    ui.label("Tag not known to MalwareBazaar.");
                }
                "no_results" => {
                    ui.label("Tag/signature/filetype is valid, but returned no results.");
                }
                s if s.starts_with("illegal_") => {
                    ui.colored_label(egui::Color32::RED, format!("MB error: {}", s));
                }
                _ => {}
            }
        } else if let Some(err) = &meta.last_error_message {
            if err.contains("unauthorized") || err.contains("401") || err.contains("403") {
                ui.colored_label(
                    egui::Color32::RED,
                    "Invalid or blocked API key (HTTP 401/403)",
                );
            } else if !err.is_empty() {
                ui.colored_label(egui::Color32::RED, format!("MB error: {}", err));
            }
        }
    } else {
        ui.horizontal(|ui| {
            ui.label("MB status:");
            ui.label("(no queries yet)");
        });
    }
    ui.add_space(4.0);

    // Get current process hash for MB lookup
    // Feed/discovery UI moved to the collapsed "Threat Intel Feeds" section to keep
    // per-process reputation lookups prominent. See `render_threat_intel_feeds()` below.
    // This function now only shows per-process MalwareBazaar lookup results.
}
