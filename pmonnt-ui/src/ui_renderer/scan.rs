use crate::ui_state::YaraScanState;
use eframe::egui;
use std::sync::Arc;

pub fn render_scan_panel(
    ui: &mut egui::Ui,
    pid: u32,
    yara_state: &mut YaraScanState,
    tf_api_key: &str,
) {
    ui.heading("Scan");
    ui.add_space(6.0);

    if pid == 0 {
        ui.colored_label(
            egui::Color32::GRAY,
            "Select a process on the left to run a memory scan.",
        );
        return;
    }

    ui.heading("Memory Scan");
    ui.add_space(4.0);
    ui.label(format!("YARA rules loaded: {}", yara_state.rule_count()));

    ui.horizontal(|ui| {
        ui.label("Mode:");
        ui.radio_value(
            &mut yara_state.scan_mode,
            pmonnt_core::yara::scanner::ScanMode::Quick,
            "Quick",
        );
        ui.radio_value(
            &mut yara_state.scan_mode,
            pmonnt_core::yara::scanner::ScanMode::Deep,
            "Deep",
        );
    });

    ui.horizontal(|ui| {
        ui.label("Min severity:");
        egui::ComboBox::from_id_source("yara_min_severity")
            .selected_text(format!("{:?}", yara_state.min_severity))
            .show_ui(ui, |ui| {
                ui.selectable_value(
                    &mut yara_state.min_severity,
                    pmonnt_core::yara::rules::Severity::Critical,
                    "Critical",
                );
                ui.selectable_value(
                    &mut yara_state.min_severity,
                    pmonnt_core::yara::rules::Severity::High,
                    "High",
                );
                ui.selectable_value(
                    &mut yara_state.min_severity,
                    pmonnt_core::yara::rules::Severity::Medium,
                    "Medium",
                );
                ui.selectable_value(
                    &mut yara_state.min_severity,
                    pmonnt_core::yara::rules::Severity::Low,
                    "Low",
                );
            });
    });

    if let Some(error) = &yara_state.error {
        ui.colored_label(egui::Color32::RED, format!("Error: {}", error));
    }

    if yara_state.scanning {
        if let Some(pmonnt_core::yara::scanner::ScanProgress::ScanningRegion {
            bytes_scanned,
            total_bytes,
            ..
        }) = yara_state.current_progress.as_ref()
        {
            let progress_val = if *total_bytes == 0 {
                0.0
            } else {
                *bytes_scanned as f32 / *total_bytes as f32
            };
            ui.add(egui::ProgressBar::new(progress_val).text(format!(
                "{:.1}MB / {:.1}MB",
                *bytes_scanned as f64 / 1_000_000.0,
                *total_bytes as f64 / 1_000_000.0
            )));
        } else {
            ui.label("Scanning...");
        }
        // Hide Cancel until implemented to avoid misleading UI.
    } else if ui.button("Scan memory with YARA").clicked() {
        if yara_state.rule_count() == 0 {
            yara_state.error = Some("No YARA rules loaded. Refresh rules first.".to_string());
        } else if let Some(engine) = &yara_state.yara_engine {
            yara_state.start_scan(pid, Arc::clone(engine));
        } else {
            yara_state.error = Some("No YARA engine available".to_string());
        }
    }

    if let Some(result) = &yara_state.last_result {
        ui.separator();

        let severity_rank = |s: pmonnt_core::yara::rules::Severity| -> u8 {
            match s {
                pmonnt_core::yara::rules::Severity::Low => 0,
                pmonnt_core::yara::rules::Severity::Medium => 1,
                pmonnt_core::yara::rules::Severity::High => 2,
                pmonnt_core::yara::rules::Severity::Critical => 3,
            }
        };

        let min_rank = severity_rank(yara_state.min_severity);
        let visible_matches: Vec<&pmonnt_core::yara::scanner::ScanMatch> = result
            .matches
            .iter()
            .filter(|m| severity_rank(m.severity) >= min_rank)
            .collect();

        if visible_matches.is_empty() {
            ui.colored_label(
                egui::Color32::GREEN,
                format!(
                    "No matches at/above {:?} ({:.1}MB scanned in {}ms)",
                    yara_state.min_severity,
                    result.bytes_scanned as f64 / 1_000_000.0,
                    result.duration_ms
                ),
            );
        } else {
            ui.colored_label(
                egui::Color32::RED,
                format!(
                    "{} matches shown ({} total)",
                    visible_matches.len(),
                    result.matches.len()
                ),
            );

            for m in visible_matches {
                let color = match m.severity {
                    pmonnt_core::yara::rules::Severity::Critical => egui::Color32::RED,
                    pmonnt_core::yara::rules::Severity::High => {
                        egui::Color32::from_rgb(255, 128, 0)
                    }
                    pmonnt_core::yara::rules::Severity::Medium => egui::Color32::YELLOW,
                    pmonnt_core::yara::rules::Severity::Low => egui::Color32::GRAY,
                };

                ui.horizontal(|ui| {
                    ui.colored_label(color, format!("● {}", m.rule_name));
                    ui.label(format!("@ {:#x}", m.memory_address));
                });

                if !m.tags.is_empty() {
                    ui.label(
                        egui::RichText::new(format!("tags: {}", m.tags.join(", ")))
                            .small()
                            .weak(),
                    );
                }
                if let Some(desc) = &m.rule_description {
                    ui.label(egui::RichText::new(desc).small().italics());
                }

                ui.push_id((m.memory_address, &m.rule_name), |ui| {
                    ui.collapsing("Matched patterns", |ui| {
                        for s in &m.matched_strings {
                            ui.monospace(format!("{}: {}", s.identifier, s.data_preview));
                        }
                    });
                });
            }
        }

        ui.label(
            egui::RichText::new(format!(
                "Scanned {} regions, {} skipped, {} errors",
                result.regions_scanned,
                result.regions_skipped,
                result.errors.len()
            ))
            .small(),
        );
    }

    ui.separator();
    ui.collapsing("YARA Rules", |ui| {
        ui.label(format!("Loaded: {} rules", yara_state.rule_count()));

        ui.horizontal(|ui| {
            if ui.button("YARAify rules").clicked() {
                yara_state.refresh_yaraify_rules();
            }

            if ui.button("ThreatFox IOCs").clicked() {
                let tf_key = if !tf_api_key.is_empty() {
                    Some(tf_api_key.to_owned())
                } else {
                    None
                };
                yara_state.refresh_threatfox_rules(tf_key);
            }

            if ui.button("Local file").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("YARA rules", &["yar", "yara"])
                    .add_filter("All files", &["*"])
                    .pick_file()
                {
                    yara_state.load_local_file(path);
                }
            }
        });

        let (yaraify_count, threatfox_count, local_count) = yara_state.rule_source_counts();
        ui.label(format!(
            "Sources: {} YARAify | {} ThreatFox | {} Local",
            yaraify_count, threatfox_count, local_count
        ));

        ui.collapsing("Rule sources", |ui| {
            let rm = yara_state
                .rule_manager
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for rule in rm.rules() {
                ui.horizontal(|ui| {
                    let icon = match &rule.source {
                        pmonnt_core::yara::rules::RuleSource::YARAify { .. } => "☁",
                        pmonnt_core::yara::rules::RuleSource::LocalFile { .. } => "📄",
                        pmonnt_core::yara::rules::RuleSource::ThreatFoxGenerated => "🔷",
                    };
                    ui.label(format!("{} {}", icon, rule.name));
                });
            }
        });
    });
}
