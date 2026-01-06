use eframe::egui;
use pmonnt_core::reputation::{LookupState, ProviderFinding, Verdict};
use pmonnt_core::reputation_service::ReputationService;
use std::collections::HashMap;
use std::sync::Arc;

use crate::ui_state::{MbUiState, TfUiState, VtUiState};

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProviderKind {
    VT,
    MB,
    TF,
}

fn cached_hint_for(
    reputation_service: &ReputationService,
    kind: ProviderKind,
    sha: &str,
) -> Option<String> {
    fn compact_cached_hint(
        last_query_status: Option<&str>,
        last_result_count: Option<usize>,
        last_error_message: Option<&str>,
    ) -> Option<String> {
        if let Some(err) = last_error_message {
            if !err.trim().is_empty() {
                return Some("cached: error".to_string());
            }
        }

        let status = last_query_status?.trim();
        if status.is_empty() {
            return None;
        }

        if let Some(count) = last_result_count {
            Some(format!("cached: {} ({})", status, count))
        } else {
            Some(format!("cached: {}", status))
        }
    }

    match kind {
        ProviderKind::VT => {
            reputation_service
                .get_vt_sample_for_hash(sha)
                .and_then(|(_stats, meta)| {
                    compact_cached_hint(
                        meta.last_query_status.as_deref(),
                        meta.last_result_count,
                        meta.last_error_message.as_deref(),
                    )
                })
        }
        ProviderKind::MB => {
            reputation_service
                .get_mb_sample_for_hash(sha)
                .and_then(|(_sample, meta)| {
                    compact_cached_hint(
                        meta.last_query_status.as_deref(),
                        meta.last_result_count,
                        meta.last_error_message.as_deref(),
                    )
                })
        }
        ProviderKind::TF => {
            reputation_service
                .get_tf_result_for_hash(sha)
                .and_then(|(_result, meta)| {
                    compact_cached_hint(
                        meta.last_query_status.as_deref(),
                        meta.last_result_count,
                        meta.last_error_message.as_deref(),
                    )
                })
        }
    }
}

fn find_aggregated_finding<'a>(
    state: &'a LookupState,
    provider: &str,
) -> Option<&'a ProviderFinding> {
    match state {
        LookupState::Aggregated(agg) => agg
            .findings
            .iter()
            .find(|f| f.provider_name.as_str() == provider),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn render_providers_section(
    ui: &mut egui::Ui,
    pid: u32,
    reputation_service: &Arc<ReputationService>,
    pid_to_image_path: &mut HashMap<u32, String>,
    online_lookups_enabled: bool,
    vt_enabled: bool,
    mb_enabled: bool,
    tf_enabled: bool,
    mb_state: &mut MbUiState,
    vt_state: &mut VtUiState,
    tf_state: &mut TfUiState,
    state: &LookupState,
    sha256: Option<&str>,
    in_flight: bool,
) {
    ui.add_space(8.0);
    ui.separator();
    ui.heading("Providers");
    ui.add_space(4.0);

    let expanded_id = ui.make_persistent_id(("reputation_expanded_provider_row", pid));
    let mut expanded: u8 = ui.data_mut(|data| data.get_temp(expanded_id).unwrap_or(0));

    let vt_finding = find_aggregated_finding(state, "VT");
    let mb_finding = find_aggregated_finding(state, "MB");
    let tf_finding = find_aggregated_finding(state, "TF");

    let mut render_provider_row =
        |ui: &mut egui::Ui,
         kind: ProviderKind,
         label: &str,
         enabled: bool,
         finding: Option<&ProviderFinding>| {
            let (is_expanded, new_code) = match kind {
                ProviderKind::VT => (expanded == 1, 1),
                ProviderKind::MB => (expanded == 2, 2),
                ProviderKind::TF => (expanded == 3, 3),
            };

            let lookup_in_progress =
                in_flight || matches!(state, LookupState::Hashing | LookupState::Querying);

            let cached_hint = sha256.and_then(|sha| cached_hint_for(reputation_service, kind, sha));

            let (status_text, status_color, mut signal_text, link) = if !enabled {
                (
                    "Disabled".to_string(),
                    egui::Color32::GRAY,
                    "".to_string(),
                    None,
                )
            } else if !online_lookups_enabled {
                (
                    "Paused".to_string(),
                    egui::Color32::GRAY,
                    "Online lookups are off".to_string(),
                    None,
                )
            } else if let Some(f) = finding {
                let color = match f.verdict {
                    Verdict::NotFound => egui::Color32::GRAY,
                    Verdict::Clean => egui::Color32::GREEN,
                    Verdict::Suspicious => egui::Color32::YELLOW,
                    Verdict::Malicious => egui::Color32::RED,
                };
                let status = match f.verdict {
                    Verdict::NotFound => "Not found",
                    Verdict::Clean => "Clean",
                    Verdict::Suspicious => "Suspicious",
                    Verdict::Malicious => "Malicious",
                };
                let signal = match (&f.family, f.confidence) {
                    (Some(family), Some(conf)) => format!("{} ({}%)", family, conf),
                    (Some(family), None) => family.clone(),
                    (None, Some(conf)) => format!("{}% confidence", conf),
                    (None, None) => "".to_string(),
                };
                (status.to_string(), color, signal, f.link.clone())
            } else if lookup_in_progress {
                (
                    "Querying".to_string(),
                    ui.visuals().weak_text_color(),
                    "".to_string(),
                    None,
                )
            } else {
                match state {
                    LookupState::NotConfigured => (
                        "Not configured".to_string(),
                        egui::Color32::GRAY,
                        "Configure API keys in Settings".to_string(),
                        None,
                    ),
                    LookupState::Disabled => (
                        "Paused".to_string(),
                        egui::Color32::GRAY,
                        "Online lookups are off".to_string(),
                        None,
                    ),
                    LookupState::Offline => (
                        "Offline".to_string(),
                        egui::Color32::GRAY,
                        "Check connectivity and retry".to_string(),
                        None,
                    ),
                    _ => (
                        "No result".to_string(),
                        ui.visuals().weak_text_color(),
                        "Expand for details".to_string(),
                        None,
                    ),
                }
            };

            if let Some(hint) = cached_hint {
                if signal_text.is_empty() {
                    signal_text = hint;
                } else {
                    signal_text = format!("{} • {}", signal_text, hint);
                }
            }

            let row_id = ui.make_persistent_id(("provider_row", new_code));
            let row_height = ui.spacing().interact_size.y;
            let (rect, row_response) = ui.allocate_exact_size(
                egui::vec2(ui.available_width(), row_height),
                egui::Sense::click(),
            );

            let mut chevron_clicked = false;
            let mut open_clicked = false;

            ui.allocate_ui_at_rect(rect, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(label).strong());
                    ui.add_space(6.0);

                    ui.colored_label(status_color, status_text);
                    if !signal_text.is_empty() {
                        ui.add(
                            egui::Label::new(egui::RichText::new(signal_text).small().weak())
                                .truncate(),
                        );
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let chevron = if is_expanded { "▾" } else { "▸" };
                        if ui.button(chevron).clicked() {
                            chevron_clicked = true;
                        }

                        let can_open = link.is_some();
                        if ui
                            .add_enabled(can_open, egui::Button::new("Open"))
                            .clicked()
                        {
                            open_clicked = true;
                            if let Some(link) = &link {
                                if let Err(e) = open::that(link) {
                                    log::error!("Failed to open link {}: {}", link, e);
                                }
                            }
                        }
                    });
                });
            });

            // Toggle expansion when clicking the row background/label area.
            // Avoid double-toggling when the chevron/Open buttons were clicked.
            let row_clicked = row_response.clicked() && !chevron_clicked && !open_clicked;
            if chevron_clicked || row_clicked {
                if is_expanded {
                    expanded = 0;
                } else {
                    expanded = new_code;
                }
            }

            ui.interact(rect, row_id, egui::Sense::hover());

            if is_expanded {
                ui.add_space(6.0);
                ui.separator();
                let selected_pid = if pid == 0 { None } else { Some(pid) };
                match kind {
                    ProviderKind::MB => {
                        super::super::render_malwarebazaar_section(
                            ui,
                            mb_state,
                            reputation_service,
                            selected_pid,
                            pid_to_image_path,
                            online_lookups_enabled,
                        );
                    }
                    ProviderKind::TF => {
                        super::super::render_threatfox_section(
                            ui,
                            tf_state,
                            reputation_service,
                            selected_pid,
                            pid_to_image_path,
                            online_lookups_enabled,
                        );
                    }
                    ProviderKind::VT => {
                        super::super::render_virustotal_section(
                            ui,
                            vt_state,
                            reputation_service,
                            selected_pid,
                            pid_to_image_path,
                            online_lookups_enabled,
                        );
                    }
                }
            }
        };

    render_provider_row(ui, ProviderKind::VT, "VirusTotal", vt_enabled, vt_finding);
    ui.add_space(4.0);
    render_provider_row(
        ui,
        ProviderKind::MB,
        "MalwareBazaar",
        mb_enabled,
        mb_finding,
    );
    ui.add_space(4.0);
    render_provider_row(ui, ProviderKind::TF, "ThreatFox", tf_enabled, tf_finding);

    ui.data_mut(|data| {
        data.insert_temp(expanded_id, expanded);
    });
}
