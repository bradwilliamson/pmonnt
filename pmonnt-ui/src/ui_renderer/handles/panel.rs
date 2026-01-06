use eframe::egui;
use pmonnt_core::handles::HandleCache;
use pmonnt_core::module::ModuleCache;
use pmonnt_core::reputation_service::ReputationService;
use pmonnt_core::snapshot::ProcessSnapshot;
use pmonnt_core::thread::{ThreadCache, ThreadInfo};
use pmonnt_core::token::TokenCache;
use pmonnt_core::win::handles::get_type_name;
use std::collections::HashMap;
use std::sync::Arc;

use super::super::context::HandlesPanelContext;

use super::report::{build_full_report, build_handles_report};

pub fn render_handles_panel_ctx(ctx: &mut HandlesPanelContext<'_>) {
    render_handles_panel(
        ctx.ui,
        ctx.pid,
        ctx.handle_cache,
        ctx.pid_to_image_path,
        ctx.current_snapshot,
        ctx.token_cache,
        ctx.thread_cache,
        ctx.thread_prev,
        ctx.module_cache,
        ctx.reputation_service,
        ctx.scan_duration_ms,
        ctx.scan_interval_secs,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn render_handles_panel(
    ui: &mut egui::Ui,
    pid: u32,
    handle_cache: &mut HandleCache,
    pid_to_image_path: &HashMap<u32, String>,
    current_snapshot: &ProcessSnapshot,
    token_cache: &mut TokenCache,
    thread_cache: &mut ThreadCache,
    thread_prev: &HashMap<u32, Vec<ThreadInfo>>,
    module_cache: &mut ModuleCache,
    reputation_service: &Arc<ReputationService>,
    scan_duration_ms: u64,
    scan_interval_secs: u64,
) {
    ui.heading("Handles");

    // Show scan info
    ui.horizontal(|ui| {
        ui.label(format!("Scan: {}ms", scan_duration_ms));
        ui.label("|");
        ui.label(format!("Interval: {}s", scan_interval_secs));
        if scan_duration_ms > 100 {
            ui.colored_label(egui::Color32::YELLOW, "(slow system, reduced frequency)");
        }
    });

    if let Some(err) = &handle_cache.last_error {
        ui.colored_label(egui::Color32::RED, format!("⚠ Error: {}", err));
    }

    ui.add_space(4.0);

    // Get handle summary from cache (clone to avoid borrow conflicts)
    let summary_opt = handle_cache.get(pid).cloned();
    let delta = handle_cache.get_delta(pid);
    let is_leaking = handle_cache.is_leaking(pid);
    let leak_explanation = handle_cache.get_leak_explanation(pid);

    if let Some(summary) = summary_opt {
        // Display total with delta
        ui.horizontal(|ui| {
            ui.label("Total:");
            ui.strong(format!("{}", summary.total));

            // Show delta if available
            if let Some(delta) = delta {
                let color = if delta > 0 {
                    egui::Color32::YELLOW
                } else if delta < 0 {
                    egui::Color32::GREEN
                } else {
                    egui::Color32::GRAY
                };

                let sign = if delta > 0 { "+" } else { "" };
                ui.colored_label(color, format!("({}{} since last)", sign, delta));
            }

            // Show leak indicator with explanation
            if is_leaking {
                ui.colored_label(egui::Color32::RED, "⚠ LEAK");

                // Show explanation
                if let Some((samples, delta, flats_used)) = leak_explanation {
                    let (_, _, flat_tol) = handle_cache.get_detector_config(pid);
                    ui.colored_label(
                        egui::Color32::LIGHT_RED,
                        format!(
                            "Triggered: {} samples, +{} handles, flats {}/{}",
                            samples, delta, flats_used, flat_tol
                        ),
                    );
                }
            }
        });

        // Copy report buttons
        ui.horizontal(|ui| {
            if ui.button("📋 Copy handles report").clicked() {
                let report = build_handles_report(
                    pid,
                    pid_to_image_path,
                    current_snapshot,
                    handle_cache,
                    scan_interval_secs,
                );
                ui.output_mut(|o| o.copied_text = report);
            }
            if ui.button("📋 Copy full report").clicked() {
                let report = build_full_report(
                    pid,
                    pid_to_image_path,
                    current_snapshot,
                    token_cache,
                    thread_cache,
                    thread_prev,
                    module_cache,
                    reputation_service,
                    handle_cache,
                    scan_interval_secs,
                );
                ui.output_mut(|o| o.copied_text = report);
            }
        });

        // Leak detection config (collapsible, hidden by default)
        ui.collapsing("⚙ Leak detection", |ui| {
            let (mut consecutive, mut delta_thresh, mut flat_tol) =
                handle_cache.get_detector_config(pid);
            let image_path = pid_to_image_path.get(&pid).map(|s| s.as_str());

            ui.horizontal(|ui| {
                ui.label("Consecutive threshold:");
                if ui
                    .add(
                        egui::DragValue::new(&mut consecutive)
                            .speed(1)
                            .range(5..=60),
                    )
                    .changed()
                {
                    handle_cache.update_detector_config(
                        pid,
                        image_path,
                        consecutive,
                        delta_thresh,
                        flat_tol,
                    );
                }
                ui.label("samples");
            });

            ui.horizontal(|ui| {
                ui.label("Min delta:");
                if ui
                    .add(
                        egui::DragValue::new(&mut delta_thresh)
                            .speed(10)
                            .range(50..=2000),
                    )
                    .changed()
                {
                    handle_cache.update_detector_config(
                        pid,
                        image_path,
                        consecutive,
                        delta_thresh,
                        flat_tol,
                    );
                }
                ui.label("handles");
            });

            ui.horizontal(|ui| {
                ui.label("Flat tolerance:");
                if ui
                    .add(egui::DragValue::new(&mut flat_tol).speed(1).range(0..=10))
                    .changed()
                {
                    handle_cache.update_detector_config(
                        pid,
                        image_path,
                        consecutive,
                        delta_thresh,
                        flat_tol,
                    );
                }
                ui.label("samples");
            });

            let reset_button = ui.button("🔄 Reset detector state");
            if reset_button
                .on_hover_text("Clear history and restart leak detection. Config unchanged.")
                .clicked()
            {
                handle_cache.reset_detector(pid);
            }

            ui.label("Default: 20 samples, 200 handles, 2 flats");
        });

        ui.separator();

        // Top growing types section
        let gaps = 5u64.saturating_sub(1); // 5 samples = 4 intervals between them
        let estimated_seconds = gaps * scan_interval_secs;
        ui.label(format!(
            "Top growing types (last 5 samples ~{}s):",
            estimated_seconds
        ));

        if let Some(growing_types) = handle_cache.get_top_growing_types(pid) {
            if growing_types.is_empty() {
                ui.colored_label(egui::Color32::GRAY, "No growth detected");
            } else {
                egui::ScrollArea::vertical()
                    .id_source("growing_types_scroll")
                    .max_height(150.0)
                    .show(ui, |ui| {
                        egui::Grid::new("growing_types_grid")
                            .striped(true)
                            .spacing([20.0, 4.0])
                            .show(ui, |ui| {
                                ui.strong("Type");
                                ui.strong("Growth");
                                ui.strong("Current");
                                ui.end_row();

                                for (type_idx, delta, current_count) in growing_types {
                                    let type_name = get_type_name(type_idx);
                                    ui.label(&type_name);
                                    ui.colored_label(egui::Color32::YELLOW, format!("+{}", delta));
                                    ui.label(format!("{}", current_count));
                                    ui.end_row();
                                }
                            });
                    });
            }
        } else {
            ui.colored_label(egui::Color32::GRAY, "Collecting history...");
        }

        ui.separator();

        // Show top handle types
        if summary.by_type.is_empty() {
            ui.colored_label(
                egui::Color32::GRAY,
                "No handles or partial (access restricted)",
            );
        } else {
            ui.label("Handle types:");

            egui::ScrollArea::vertical()
                .id_source("handles_scroll")
                .max_height(300.0)
                .show(ui, |ui| {
                    egui::Grid::new("handles_grid")
                        .striped(true)
                        .spacing([40.0, 4.0])
                        .show(ui, |ui| {
                            ui.strong("Type");
                            ui.strong("Count");
                            ui.end_row();

                            for (type_name, count) in &summary.by_type {
                                ui.label(type_name);
                                ui.label(format!("{}", count));
                                ui.end_row();
                            }
                        });
                });
        }
    } else {
        // No summary for this PID
        if handle_cache.last_error.is_some() {
            // System-wide scan failed
            ui.colored_label(egui::Color32::RED, "Handle scan failed (see error above)");
            ui.label("Try running as Administrator with SeDebugPrivilege");
        } else if handle_cache.has_data() {
            // Scan completed but this PID has no visible handles
            // Check if process is protected
            let (is_protected, protection_info) = pmonnt_core::win::get_process_protection(pid);

            if is_protected {
                ui.colored_label(
                    egui::Color32::YELLOW,
                    format!(
                        "Protected Process: {}",
                        protection_info.unwrap_or_else(|| "PPL".to_string())
                    ),
                );
                ui.label("Handles are filtered by Windows kernel - cannot be enumerated");
            } else {
                // Not protected and scan completed - process has 0 handles or just exited
                ui.colored_label(egui::Color32::GRAY, "No handles found for this process");
                ui.label("Process may have no handles or has exited");
            }
        } else {
            // Scan succeeded but this process has no handles visible
            // Check if process is protected
            let (is_protected, protection_info) = pmonnt_core::win::get_process_protection(pid);

            if is_protected {
                ui.colored_label(
                    egui::Color32::YELLOW,
                    format!(
                        "Protected Process: {}",
                        protection_info.unwrap_or_else(|| "PPL".to_string())
                    ),
                );
                ui.label("Handles are filtered by Windows kernel - cannot be enumerated");
            } else {
                // Not protected, but still no handles - might still be loading
                ui.label("Loading handle information...");
                ui.spinner();
            }
        }
    }
}
