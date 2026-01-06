use crate::ui_state::MbUiState;
use eframe::egui;
use pmonnt_core::reputation_service::ReputationService;
use pmonnt_core::vt::VirusTotalProvider;
use std::collections::HashMap;
use std::sync::Arc;

use super::super::context::ReputationSettingsContext;

pub fn render_reputation_settings_panel_ctx(ctx: &mut ReputationSettingsContext<'_>) {
    super::render_reputation_settings_panel(
        ctx.ui,
        ctx.reputation_service,
        ctx.mb_state,
        ctx.bg_worker,
        ctx.pid_to_image_path,
        ctx.online_lookups_enabled,
        ctx.prev_online_lookups_enabled,
        ctx.vt_api_key,
        ctx.mb_api_key,
        ctx.tf_api_key,
        ctx.vt_enabled,
        ctx.mb_enabled,
        ctx.tf_enabled,
        ctx.vt_provider,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn render_reputation_settings_panel(
    ui: &mut egui::Ui,
    reputation_service: &Arc<ReputationService>,
    mb_state: &mut MbUiState,
    bg_worker: &crate::background_worker::BackgroundWorker,
    pid_to_image_path: &HashMap<u32, String>,
    online_lookups_enabled: &mut bool,
    _prev_online_lookups_enabled: &mut bool,
    vt_api_key: &mut String,
    mb_api_key: &mut String,
    tf_api_key: &mut String,
    vt_enabled: &mut bool,
    mb_enabled: &mut bool,
    tf_enabled: &mut bool,
    vt_provider: &Arc<VirusTotalProvider>,
) {
    fn push_reputation_config(
        reputation_service: &ReputationService,
        vt_api_key: &str,
        mb_api_key: &str,
        tf_api_key: &str,
        vt_enabled: bool,
        mb_enabled: bool,
        tf_enabled: bool,
    ) {
        reputation_service.update_config(
            if !vt_api_key.is_empty() {
                Some(vt_api_key.to_string())
            } else {
                None
            },
            if !mb_api_key.is_empty() {
                Some(mb_api_key.to_string())
            } else {
                None
            },
            if !tf_api_key.is_empty() {
                Some(tf_api_key.to_string())
            } else {
                None
            },
            vt_enabled,
            mb_enabled,
            tf_enabled,
        );
    }

    ui.heading("Reputation Settings");
    ui.add_space(4.0);
    ui.label(
        egui::RichText::new(
            "MalwareBazaar and ThreatFox require free API keys from https://auth.abuse.ch/",
        )
        .small()
        .color(ui.visuals().weak_text_color()),
    );

    // Check if env var override is active
    let env_override_active =
        std::env::var("PMONNT_VT_API_KEY").is_ok() || std::env::var("VT_API_KEY").is_ok();

    let on_off = if *online_lookups_enabled { "On" } else { "Off" };
    let vt_cfg = if env_override_active || !vt_api_key.is_empty() {
        "configured"
    } else {
        "missing"
    };
    let mb_cfg = if !mb_api_key.is_empty() {
        "configured"
    } else {
        "missing"
    };
    let tf_cfg = if !tf_api_key.is_empty() {
        "configured"
    } else {
        "missing"
    };

    ui.separator();
    ui.label(
        egui::RichText::new(format!(
            "Online lookups: {} • VT: {} • MB: {} • TF: {}",
            on_off, vt_cfg, mb_cfg, tf_cfg
        ))
        .small()
        .color(ui.visuals().weak_text_color()),
    );
    ui.add_space(8.0);

    ui.heading("Provider settings");
    ui.add_space(4.0);

    // Show current status - NEVER reveal the actual key
    if !vt_api_key.is_empty() {
        if env_override_active {
            ui.colored_label(
                egui::Color32::LIGHT_GREEN,
                "✓ VirusTotal API key configured (override active)",
            );
            ui.label(
                egui::RichText::new(
                    "Note: The environment variable PMONNT_VT_API_KEY overrides stored keys.",
                )
                .small()
                .italics()
                .color(ui.visuals().weak_text_color()),
            );
        } else {
            ui.colored_label(
                egui::Color32::LIGHT_GREEN,
                "✓ VirusTotal API key configured",
            );
        }
        ui.label(
            egui::RichText::new(
                "Your API key is encrypted and never shown in clear text for security.",
            )
            .small()
            .italics()
            .color(ui.visuals().weak_text_color()),
        );
    } else {
        ui.colored_label(egui::Color32::YELLOW, "⚠ No VirusTotal API key configured");
        ui.label(
            egui::RichText::new(
                "Configure a VirusTotal API key below for enhanced reputation analysis.",
            )
            .small()
            .color(ui.visuals().weak_text_color()),
        );
    }

    ui.add_space(8.0);

    // Enable/disable checkbox
    let mut enable_lookups = *online_lookups_enabled;
    if ui
        .checkbox(&mut enable_lookups, "Enable online reputation lookups")
        .changed()
    {
        *online_lookups_enabled = enable_lookups;
        *vt_enabled = enable_lookups; // Keep for backward compatibility
        push_reputation_config(
            reputation_service.as_ref(),
            vt_api_key.as_str(),
            mb_api_key.as_str(),
            tf_api_key.as_str(),
            *vt_enabled,
            *mb_enabled,
            *tf_enabled,
        );
    }

    ui.add_space(4.0);
    ui.label(
        egui::RichText::new("Providers:")
            .small()
            .color(ui.visuals().weak_text_color()),
    );

    ui.horizontal(|ui| {
        ui.label("VirusTotal");
        if ui.checkbox(vt_enabled, "Enabled").changed() {
            push_reputation_config(
                reputation_service.as_ref(),
                vt_api_key.as_str(),
                mb_api_key.as_str(),
                tf_api_key.as_str(),
                *vt_enabled,
                *mb_enabled,
                *tf_enabled,
            );
        }
    });
    ui.horizontal(|ui| {
        ui.label("MalwareBazaar");
        if ui.checkbox(mb_enabled, "Enabled").changed() {
            push_reputation_config(
                reputation_service.as_ref(),
                vt_api_key.as_str(),
                mb_api_key.as_str(),
                tf_api_key.as_str(),
                *vt_enabled,
                *mb_enabled,
                *tf_enabled,
            );
        }
    });
    ui.horizontal(|ui| {
        ui.label("ThreatFox");
        if ui.checkbox(tf_enabled, "Enabled").changed() {
            push_reputation_config(
                reputation_service.as_ref(),
                vt_api_key.as_str(),
                mb_api_key.as_str(),
                tf_api_key.as_str(),
                *vt_enabled,
                *mb_enabled,
                *tf_enabled,
            );
        }
    });

    ui.add_space(8.0);

    // VT key input and management
    if enable_lookups && vt_api_key.is_empty() {
        ui.separator();
        ui.label(egui::RichText::new("VirusTotal API key").strong());
        ui.label(
            egui::RichText::new("Stored encrypted using Windows Credential Manager.")
                .small()
                .color(ui.visuals().weak_text_color()),
        );
        ui.add_space(4.0);

        let key_input_id = ui.make_persistent_id("vt_key_input_buffer");
        let mut key_input: String =
            ui.data_mut(|data| data.get_temp_mut_or_default::<String>(key_input_id).clone());

        ui.horizontal(|ui| {
            let response = ui.add(
                egui::TextEdit::singleline(&mut key_input)
                    .password(true)
                    .hint_text("Paste key (hidden)")
                    .desired_width(300.0),
            );

            ui.data_mut(|data| {
                data.insert_temp(key_input_id, key_input.clone());
            });

            if ui.button("Save key").clicked() && !key_input.trim().is_empty() {
                match crate::credentials::save_vt_key(key_input.trim()) {
                    Ok(_) => {
                        *vt_api_key = key_input.trim().to_string();
                        vt_provider.set_api_key(key_input.trim().to_string());
                        *vt_enabled = true;
                        *online_lookups_enabled = true;
                        push_reputation_config(
                            reputation_service.as_ref(),
                            vt_api_key.as_str(),
                            mb_api_key.as_str(),
                            tf_api_key.as_str(),
                            *vt_enabled,
                            *mb_enabled,
                            *tf_enabled,
                        );

                        ui.data_mut(|data| {
                            data.insert_temp(key_input_id, String::new());
                        });
                        ui.ctx().request_repaint();
                    }
                    Err(e) => {
                        log::error!("Failed to save VT API key: {}", e);
                        ui.colored_label(egui::Color32::RED, format!("Failed to save key: {}", e));
                    }
                }
            }

            if response.changed() {
                ui.ctx().request_repaint();
            }
        });
    } else if !vt_api_key.is_empty() && !env_override_active {
        ui.separator();
        if ui.button("Clear saved key").clicked() {
            match crate::credentials::delete_vt_key() {
                Ok(_) => {
                    vt_api_key.clear();
                    *vt_enabled = false;
                    *online_lookups_enabled = false;
                    push_reputation_config(
                        reputation_service.as_ref(),
                        vt_api_key.as_str(),
                        mb_api_key.as_str(),
                        tf_api_key.as_str(),
                        *vt_enabled,
                        *mb_enabled,
                        *tf_enabled,
                    );
                    ui.ctx().request_repaint();
                }
                Err(e) => {
                    log::error!("Failed to delete VT key: {}", e);
                    ui.colored_label(egui::Color32::RED, format!("Failed to clear key: {}", e));
                }
            }
        }
        ui.label(
            egui::RichText::new("Removes the key from Windows Credential Manager.")
                .small()
                .color(ui.visuals().weak_text_color()),
        );
    } else if env_override_active {
        ui.separator();
        ui.colored_label(
            egui::Color32::YELLOW,
            "VirusTotal key is controlled by an environment variable.",
        );
        ui.label(
            egui::RichText::new("Update PMONNT_VT_API_KEY / VT_API_KEY and restart.")
                .small()
                .color(ui.visuals().weak_text_color()),
        );
    }

    // MB key input
    if enable_lookups && *mb_enabled && mb_api_key.is_empty() {
        ui.separator();
        ui.label(egui::RichText::new("MalwareBazaar API key").strong());
        ui.label(
            egui::RichText::new("Get a free API key at https://auth.abuse.ch/")
                .small()
                .color(ui.visuals().weak_text_color()),
        );
        ui.add_space(4.0);

        let mb_key_input_id = ui.make_persistent_id("mb_key_input_buffer");
        let mut mb_key_input: String = ui.data_mut(|data| {
            data.get_temp_mut_or_default::<String>(mb_key_input_id)
                .clone()
        });

        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut mb_key_input)
                    .password(true)
                    .hint_text("Paste key (hidden)")
                    .desired_width(300.0),
            );

            ui.data_mut(|data| {
                data.insert_temp(mb_key_input_id, mb_key_input.clone());
            });

            if ui.button("Set key").clicked() && !mb_key_input.trim().is_empty() {
                match crate::credentials::save_mb_key(mb_key_input.trim()) {
                    Ok(_) => {
                        *mb_api_key = mb_key_input.trim().to_string();
                        push_reputation_config(
                            reputation_service.as_ref(),
                            vt_api_key.as_str(),
                            mb_api_key.as_str(),
                            tf_api_key.as_str(),
                            *vt_enabled,
                            *mb_enabled,
                            *tf_enabled,
                        );
                        ui.data_mut(|data| {
                            data.insert_temp(mb_key_input_id, String::new());
                        });
                        ui.ctx().request_repaint();
                    }
                    Err(e) => {
                        log::error!("Failed to save MB API key: {}", e);
                        ui.colored_label(egui::Color32::RED, format!("Failed to save key: {}", e));
                    }
                }
            }
        });
    }

    // TF key input
    if enable_lookups && *tf_enabled && tf_api_key.is_empty() {
        ui.separator();
        ui.label(egui::RichText::new("ThreatFox API key").strong());
        ui.label(
            egui::RichText::new("Get a free API key at https://auth.abuse.ch/")
                .small()
                .color(ui.visuals().weak_text_color()),
        );
        ui.add_space(4.0);

        let tf_key_input_id = ui.make_persistent_id("tf_key_input_buffer");
        let mut tf_key_input: String = ui.data_mut(|data| {
            data.get_temp_mut_or_default::<String>(tf_key_input_id)
                .clone()
        });

        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut tf_key_input)
                    .password(true)
                    .hint_text("Paste key (hidden)")
                    .desired_width(300.0),
            );

            ui.data_mut(|data| {
                data.insert_temp(tf_key_input_id, tf_key_input.clone());
            });

            if ui.button("Set key").clicked() && !tf_key_input.trim().is_empty() {
                match crate::credentials::save_tf_key(tf_key_input.trim()) {
                    Ok(_) => {
                        *tf_api_key = tf_key_input.trim().to_string();
                        push_reputation_config(
                            reputation_service.as_ref(),
                            vt_api_key.as_str(),
                            mb_api_key.as_str(),
                            tf_api_key.as_str(),
                            *vt_enabled,
                            *mb_enabled,
                            *tf_enabled,
                        );
                        ui.data_mut(|data| {
                            data.insert_temp(tf_key_input_id, String::new());
                        });
                        ui.ctx().request_repaint();
                    }
                    Err(e) => {
                        log::error!("Failed to save TF API key: {}", e);
                        ui.colored_label(egui::Color32::RED, format!("Failed to save key: {}", e));
                    }
                }
            }
        });
    }

    ui.add_space(10.0);
    ui.separator();
    ui.add_space(6.0);

    // Threat Intel Feeds (collapsed by default)
    egui::CollapsingHeader::new("Threat Intel Feeds")
        .default_open(false)
        .show(ui, |ui| {
            super::render_threat_intel_feeds(
                ui,
                mb_state,
                reputation_service,
                pid_to_image_path,
                bg_worker,
            );
        });
}
