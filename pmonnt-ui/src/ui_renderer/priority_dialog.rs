//! Set Priority dialog.

use eframe::egui;

use pmonnt_core::win::{set_priority_class, PriorityClass};

use crate::app::PMonNTApp;

#[derive(Debug, Clone)]
pub(crate) struct PriorityDialogState {
    pub(crate) pid: u32,
    pub(crate) process_name: String,
    pub(crate) current_priority: PriorityClass,
    pub(crate) selected_priority: PriorityClass,
    pub(crate) result: Option<Result<(), String>>,
}

pub(crate) fn render_priority_dialog(app: &mut PMonNTApp, ctx: &egui::Context) {
    let Some(state) = &mut app.priority_dialog else {
        return;
    };

    let mut open = true;
    let mut should_close = false;
    let mut apply_clicked = false;
    let mut selected = state.selected_priority;
    let selection_changed = selected != state.selected_priority;

    egui::Window::new("Set Priority")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .open(&mut open)
        .show(ctx, |ui| {
            ui.label(format!("{} (PID {})", state.process_name, state.pid));
            ui.separator();

            ui.horizontal(|ui| {
                ui.label("Priority:");
                egui::ComboBox::from_id_source("priority_combo")
                    .selected_text(selected.display_name())
                    .show_ui(ui, |ui| {
                        for &p in PriorityClass::all() {
                            let label = if p == state.current_priority {
                                format!("{} (current)", p.display_name())
                            } else {
                                p.display_name().to_string()
                            };
                            ui.selectable_value(&mut selected, p, label);
                        }
                    });
            });

            if selected == PriorityClass::Realtime {
                ui.add_space(6.0);
                ui.label("Warning: Realtime priority can make the system unresponsive.");
                ui.label("It often requires administrator privileges.");
            } else if selected == PriorityClass::High {
                ui.add_space(6.0);
                ui.label("Warning: High priority may affect system responsiveness.");
            }

            ui.add_space(10.0);

            if let Some(result) = &state.result {
                match result {
                    Ok(()) => {
                        ui.label("Priority changed successfully.");
                    }
                    Err(e) => {
                        ui.label(format!("Error: {}", e));
                    }
                };
                ui.add_space(6.0);
            }

            ui.horizontal(|ui| {
                if ui.button("Cancel").clicked() {
                    should_close = true;
                }

                let can_apply = selected != state.current_priority;
                if ui
                    .add_enabled(can_apply, egui::Button::new("Apply"))
                    .clicked()
                {
                    apply_clicked = true;
                }

                if state.result.is_some() && ui.button("Close").clicked() {
                    should_close = true;
                }
            });
        });

    if let Some(state) = &mut app.priority_dialog {
        if selection_changed {
            state.result = None;
        }
        state.selected_priority = selected;

        if apply_clicked {
            let result = set_priority_class(state.pid, selected);
            match result {
                Ok(()) => {
                    state.current_priority = selected;
                    state.result = Some(Ok(()));
                }
                Err(e) => {
                    state.result = Some(Err(e.to_string()));
                }
            }
        }
    }

    if !open || should_close {
        app.priority_dialog = None;
    }
}
