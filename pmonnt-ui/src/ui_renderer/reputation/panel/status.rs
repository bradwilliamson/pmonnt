use eframe::egui;
use pmonnt_core::reputation::{LookupState, Verdict};
use pmonnt_core::reputation_service::ReputationService;

pub(super) struct LookupStatusRowParams<'a> {
    pub(super) online_lookups_enabled: bool,
    pub(super) sha256: &'a Option<String>,
    pub(super) in_flight: bool,
    pub(super) image_path: &'a str,
    pub(super) reputation_service: &'a ReputationService,
    pub(super) vt_enabled: bool,
    pub(super) mb_enabled: bool,
    pub(super) tf_enabled: bool,
}

pub(super) fn render_sha256_row(ui: &mut egui::Ui, sha256: &Option<String>) {
    if let Some(ref sha256) = sha256 {
        ui.horizontal(|ui| {
            ui.label("SHA-256:");
            ui.monospace(sha256);
            if ui.button("📋").clicked() {
                ui.output_mut(|o| o.copied_text = sha256.clone());
            }
        });
    }
}

pub(super) fn render_lookup_status_row(
    ui: &mut egui::Ui,
    state: &LookupState,
    params: LookupStatusRowParams<'_>,
) {
    ui.separator();
    ui.horizontal(|ui| {
        ui.label("Status:");
        match state {
            LookupState::Hashing => {
                ui.spinner();
                ui.label("Computing hash...");
            }
            LookupState::NotConfigured => {
                ui.label("Not configured");
            }
            LookupState::Disabled => {
                ui.colored_label(egui::Color32::GRAY, "Online lookups disabled");
                // Show retry button to re-enable and query
                if params.online_lookups_enabled
                    && params.sha256.is_some()
                    && ui.button("🔄 Query").clicked()
                {
                    params
                        .reputation_service
                        .request_lookup(params.image_path.to_string(), true);
                }
            }
            LookupState::Offline => {
                ui.colored_label(egui::Color32::GRAY, "Offline");
                // Show retry button
                if params.sha256.is_some() && !params.in_flight && ui.button("🔄 Retry").clicked()
                {
                    params
                        .reputation_service
                        .request_lookup(params.image_path.to_string(), true);
                }
            }
            LookupState::Querying => {
                ui.spinner();
                ui.label("Querying reputation providers...");
            }
            LookupState::Hit(stats) => {
                let detections = stats.total_detections();
                let total = stats.total_engines();

                let color = if detections == 0 {
                    egui::Color32::GREEN
                } else if detections < 5 {
                    egui::Color32::YELLOW
                } else {
                    egui::Color32::RED
                };

                ui.colored_label(color, format!("VT: {}/{} detections", detections, total));

                // Show breakdown
                if detections > 0 {
                    ui.label(format!(
                        "({} malicious, {} suspicious)",
                        stats.malicious, stats.suspicious
                    ));
                }
            }
            LookupState::NotFound => {
                ui.colored_label(egui::Color32::GRAY, "Not found in reputation databases");
            }
            LookupState::Error(e) => {
                ui.colored_label(egui::Color32::RED, format!("Error: {}", e));
                // Show retry button
                if params.sha256.is_some() && !params.in_flight && ui.button("🔄 Retry").clicked()
                {
                    params
                        .reputation_service
                        .request_lookup(params.image_path.to_string(), true);
                }
            }
            LookupState::Aggregated(agg) => {
                // Display the summary string with appropriate color based on verdict
                let color = match agg.best_verdict {
                    Verdict::NotFound => egui::Color32::GRAY,
                    Verdict::Clean => egui::Color32::GREEN,
                    Verdict::Suspicious => egui::Color32::YELLOW,
                    Verdict::Malicious => egui::Color32::RED,
                };

                // Create a clickable label for the summary
                let summary_response = ui.add(
                    egui::Label::new(egui::RichText::new(&agg.summary).color(color))
                        .sense(egui::Sense::click()),
                );

                // If clicked and we have a primary link, open it
                if summary_response.clicked() {
                    if let Some(link) = &agg.primary_link {
                        if let Err(e) = open::that(link) {
                            log::error!("Failed to open link {}: {}", link, e);
                        }
                    }
                }

                // Always show all provider statuses in tooltip
                let mut provider_statuses = vec![];
                let mut findings_map = std::collections::HashMap::new();
                for f in &agg.findings {
                    findings_map.insert(f.provider_name.as_str(), f);
                }

                // List of all supported providers
                let all_providers = ["VT", "MB", "TF"];
                for &prov in &all_providers {
                    if let Some(f) = findings_map.get(prov) {
                        let verdict_str = match f.verdict {
                            Verdict::NotFound => "Not found",
                            Verdict::Clean => "Clean",
                            Verdict::Suspicious => "Suspicious",
                            Verdict::Malicious => "Malicious",
                        };
                        let details = match (&f.family, f.confidence) {
                            (Some(family), Some(conf)) => {
                                format!(" ({}, {}% confidence)", family, conf)
                            }
                            (Some(family), None) => format!(" ({})", family),
                            (None, Some(conf)) => format!(" ({}% confidence)", conf),
                            (None, None) => "".to_string(),
                        };
                        provider_statuses.push(format!("• {}: {}{}", prov, verdict_str, details));
                    } else {
                        // Not present in findings, so must be Not configured or Error
                        let status = match prov {
                            "VT" => {
                                if !params.vt_enabled {
                                    "Disabled".to_string()
                                } else {
                                    "No result (not found or error)".to_string()
                                }
                            }
                            "MB" => {
                                if !params.mb_enabled {
                                    "Disabled".to_string()
                                } else if let Some(meta) =
                                    params.reputation_service.mb_get_last_query_meta()
                                {
                                    if let Some(s) = meta.last_query_status {
                                        s
                                    } else if let Some(err) = meta.last_error_message {
                                        err
                                    } else {
                                        "No result (not found or error)".to_string()
                                    }
                                } else {
                                    "No result (not found or error)".to_string()
                                }
                            }
                            "TF" => {
                                if !params.tf_enabled {
                                    "Disabled".to_string()
                                } else {
                                    "No result (not found or error)".to_string()
                                }
                            }
                            _ => "Not configured".to_string(),
                        };
                        provider_statuses.push(format!("• {}: {}", prov, status));
                    }
                }

                summary_response.on_hover_text(format!(
                    "Click to open primary link\n\nProvider statuses:\n{}",
                    provider_statuses.join("\n")
                ));
            }
        }
    });
}
