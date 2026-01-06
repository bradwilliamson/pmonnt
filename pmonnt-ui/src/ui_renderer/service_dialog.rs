//! Services dialog for managing services hosted by a process.

use eframe::egui;
use std::time::Instant;

use pmonnt_core::services::{ServiceInfo, ServiceStartType, ServiceStatus};

use crate::app::PMonNTApp;

#[derive(Debug, Clone)]
pub(crate) struct ServiceDialogState {
    pub(crate) pid: u32,
    pub(crate) process_name: String,
    pub(crate) services: Vec<ServiceInfo>,
    pub(crate) selected_service: Option<usize>,
    pub(crate) last_result: Option<String>,
    pub(crate) last_result_time: Option<Instant>,
}

pub(crate) fn render_service_dialog(app: &mut PMonNTApp, ctx: &egui::Context) {
    let Some(mut state) = app.service_dialog.take() else {
        return;
    };

    // Clear old results after a short time so the dialog doesn't accumulate messages.
    if let Some(t) = state.last_result_time {
        if t.elapsed().as_secs() >= 5 {
            state.last_result = None;
            state.last_result_time = None;
        }
    }

    let mut open = true;
    let mut should_close = false;

    egui::Window::new("Services")
        .collapsible(false)
        .resizable(true)
        .default_width(560.0)
        .default_height(340.0)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .open(&mut open)
        .show(ctx, |ui| {
            ui.label(format!(
                "{} (PID {}) - {} service{}",
                state.process_name,
                state.pid,
                state.services.len(),
                if state.services.len() == 1 { "" } else { "s" }
            ));
            ui.separator();

            if let Some(msg) = state.last_result.as_deref() {
                ui.label(egui::RichText::new(msg).color(ui.visuals().weak_text_color()));
                ui.add_space(6.0);
                ui.separator();
            }

            if state.services.is_empty() {
                ui.label(
                    egui::RichText::new(
                        "No hosted services for this process (common for non-svchost processes).",
                    )
                    .color(ui.visuals().weak_text_color()),
                );
                ui.add_space(10.0);
            } else {
                let row_h = ui.spacing().interact_size.y;
                let table = egui_extras::TableBuilder::new(ui)
                    .striped(true)
                    .column(egui_extras::Column::auto()) // Name
                    .column(egui_extras::Column::remainder()) // Display
                    .column(egui_extras::Column::auto()) // Status
                    .column(egui_extras::Column::auto()) // Start type
                    .column(egui_extras::Column::auto()); // Actions

                table
                    .header(20.0, |mut header| {
                        header.col(|ui| {
                            ui.label("Name");
                        });
                        header.col(|ui| {
                            ui.label("Display Name");
                        });
                        header.col(|ui| {
                            ui.label("Status");
                        });
                        header.col(|ui| {
                            ui.label("Start");
                        });
                        header.col(|ui| {
                            ui.label("Actions");
                        });
                    })
                    .body(|mut body| {
                        for (idx, svc) in state.services.iter().enumerate() {
                            body.row(row_h, |mut row| {
                                row.col(|ui| {
                                    let is_selected = state.selected_service == Some(idx);
                                    let resp = ui.selectable_label(
                                        is_selected,
                                        egui::RichText::new(&svc.name).monospace(),
                                    );
                                    if resp.clicked() {
                                        state.selected_service = Some(idx);
                                    }
                                });
                                row.col(|ui| {
                                    ui.label(&svc.display_name);
                                    if let Some(desc) = svc.description.as_deref() {
                                        ui.label(
                                            egui::RichText::new(desc)
                                                .color(ui.visuals().weak_text_color())
                                                .small(),
                                        );
                                    }
                                });
                                row.col(|ui| {
                                    let (text, color) = status_display(svc.status);
                                    ui.colored_label(color, text);
                                });
                                row.col(|ui| {
                                    ui.label(start_type_label(svc.start_type));
                                });
                                row.col(|ui| {
                                    let can_control = app.can_control_services();

                                    ui.horizontal(|ui| {
                                        // Compute keys that match the existing background plumbing.
                                        let start_key = format!("{}:{}:Start", state.pid, svc.name);
                                        let stop_key = format!("{}:{}:Stop", state.pid, svc.name);
                                        let restart_key =
                                            format!("{}:{}:Restart", state.pid, svc.name);
                                        let pause_key = format!("{}:{}:Pause", state.pid, svc.name);
                                        let resume_key =
                                            format!("{}:{}:Resume", state.pid, svc.name);

                                        match svc.status {
                                            ServiceStatus::Stopped => {
                                                let enabled = can_control
                                                    && !app.is_service_action_in_flight(&start_key);
                                                if ui
                                                    .add_enabled(
                                                        enabled,
                                                        egui::Button::new("Start"),
                                                    )
                                                    .on_disabled_hover_text("Requires elevation")
                                                    .clicked()
                                                {
                                                    app.enqueue_service_action(
                                                        state.pid,
                                                        svc.name.clone(),
                                                        "Start",
                                                    );
                                                }
                                            }
                                            ServiceStatus::Running => {
                                                let stop_enabled = can_control
                                                    && !app.is_service_action_in_flight(&stop_key);
                                                let restart_enabled = can_control
                                                    && !app
                                                        .is_service_action_in_flight(&restart_key);
                                                let pause_enabled = can_control
                                                    && !app.is_service_action_in_flight(&pause_key);

                                                if ui
                                                    .add_enabled(
                                                        stop_enabled,
                                                        egui::Button::new("Stop"),
                                                    )
                                                    .on_disabled_hover_text("Requires elevation")
                                                    .clicked()
                                                {
                                                    app.enqueue_service_action(
                                                        state.pid,
                                                        svc.name.clone(),
                                                        "Stop",
                                                    );
                                                }
                                                if ui
                                                    .add_enabled(
                                                        restart_enabled,
                                                        egui::Button::new("Restart"),
                                                    )
                                                    .on_disabled_hover_text("Requires elevation")
                                                    .clicked()
                                                {
                                                    app.enqueue_service_action(
                                                        state.pid,
                                                        svc.name.clone(),
                                                        "Restart",
                                                    );
                                                }
                                                if ui
                                                    .add_enabled(
                                                        pause_enabled,
                                                        egui::Button::new("Pause"),
                                                    )
                                                    .on_disabled_hover_text("Requires elevation")
                                                    .clicked()
                                                {
                                                    app.enqueue_service_action(
                                                        state.pid,
                                                        svc.name.clone(),
                                                        "Pause",
                                                    );
                                                }
                                            }
                                            ServiceStatus::Paused => {
                                                let resume_enabled = can_control
                                                    && !app
                                                        .is_service_action_in_flight(&resume_key);
                                                let stop_enabled = can_control
                                                    && !app.is_service_action_in_flight(&stop_key);

                                                if ui
                                                    .add_enabled(
                                                        resume_enabled,
                                                        egui::Button::new("Resume"),
                                                    )
                                                    .on_disabled_hover_text("Requires elevation")
                                                    .clicked()
                                                {
                                                    app.enqueue_service_action(
                                                        state.pid,
                                                        svc.name.clone(),
                                                        "Resume",
                                                    );
                                                }
                                                if ui
                                                    .add_enabled(
                                                        stop_enabled,
                                                        egui::Button::new("Stop"),
                                                    )
                                                    .on_disabled_hover_text("Requires elevation")
                                                    .clicked()
                                                {
                                                    app.enqueue_service_action(
                                                        state.pid,
                                                        svc.name.clone(),
                                                        "Stop",
                                                    );
                                                }
                                            }
                                            _ => {
                                                ui.label(
                                                    egui::RichText::new("Busy")
                                                        .color(ui.visuals().weak_text_color()),
                                                );
                                            }
                                        }
                                    });
                                });
                            });
                        }
                    });

                ui.add_space(8.0);

                if let Some(idx) = state.selected_service {
                    if let Some(svc) = state.services.get(idx) {
                        ui.separator();
                        ui.collapsing("Details", |ui| {
                            egui::Grid::new("service_details_grid")
                                .num_columns(2)
                                .show(ui, |ui| {
                                    ui.label("Name:");
                                    ui.label(&svc.name);
                                    ui.end_row();

                                    ui.label("Display Name:");
                                    ui.label(&svc.display_name);
                                    ui.end_row();

                                    ui.label("Status:");
                                    let (t, c) = status_display(svc.status);
                                    ui.colored_label(c, t);
                                    ui.end_row();

                                    ui.label("Start Type:");
                                    ui.label(start_type_label(svc.start_type));
                                    ui.end_row();

                                    if let Some(desc) = svc.description.as_deref() {
                                        ui.label("Description:");
                                        ui.label(desc);
                                        ui.end_row();
                                    }
                                });
                        });
                    }
                }
            }

            ui.separator();
            ui.horizontal(|ui| {
                if ui.button("Refresh").clicked() {
                    // Avoid any background complexity; core has short TTL caching.
                    match pmonnt_core::services::get_services_for_process(state.pid) {
                        Ok(mut services) => {
                            services.sort_by(|a, b| a.name.cmp(&b.name));
                            state.services = services;
                        }
                        Err(e) => {
                            state.last_result = Some(format!("Refresh failed: {e}"));
                            state.last_result_time = Some(Instant::now());
                        }
                    }
                }

                if ui.button("Close").clicked() {
                    should_close = true;
                }
            });
        });

    if !open || should_close {
        app.service_dialog = None;
    } else {
        app.service_dialog = Some(state);
    }
}

fn status_display(status: ServiceStatus) -> (&'static str, egui::Color32) {
    match status {
        ServiceStatus::Running => ("Running", egui::Color32::LIGHT_GREEN),
        ServiceStatus::Stopped => ("Stopped", egui::Color32::LIGHT_RED),
        ServiceStatus::Paused => ("Paused", egui::Color32::YELLOW),
        ServiceStatus::StartPending => ("Start pending", egui::Color32::YELLOW),
        ServiceStatus::StopPending => ("Stop pending", egui::Color32::YELLOW),
        ServiceStatus::ContinuePending => ("Continue pending", egui::Color32::YELLOW),
        ServiceStatus::PausePending => ("Pause pending", egui::Color32::YELLOW),
    }
}

fn start_type_label(t: ServiceStartType) -> &'static str {
    match t {
        ServiceStartType::Automatic => "Automatic",
        ServiceStartType::AutomaticDelayed => "Automatic (Delayed)",
        ServiceStartType::Manual => "Manual",
        ServiceStartType::Disabled => "Disabled",
        ServiceStartType::Boot => "Boot",
        ServiceStartType::System => "System",
    }
}
