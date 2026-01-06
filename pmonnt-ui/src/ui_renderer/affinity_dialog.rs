//! Set Affinity dialog.

use eframe::egui;

use pmonnt_core::win::{set_affinity, AffinityInfo};

use crate::app::PMonNTApp;

#[derive(Debug, Clone)]
pub(crate) struct AffinityDialogState {
    pub(crate) pid: u32,
    pub(crate) process_name: String,
    pub(crate) affinity_info: AffinityInfo,
    pub(crate) selected_mask: u64,
    pub(crate) result: Option<Result<(), String>>,
}

pub(crate) fn render_affinity_dialog(app: &mut PMonNTApp, ctx: &egui::Context) {
    let Some(state) = &mut app.affinity_dialog else {
        return;
    };

    let selected_mask_before_ui = state.selected_mask;

    let mut open = true;
    let mut should_close = false;
    let mut apply_clicked = false;

    egui::Window::new("Set Affinity")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .open(&mut open)
        .show(ctx, |ui| {
            ui.label(format!("{} (PID {})", state.process_name, state.pid));
            ui.separator();

            let available_cpus = state.affinity_info.available_cpus();
            let cpu_count = available_cpus.len();

            if cpu_count == 0 {
                ui.label("Unable to query CPU affinity for this process.");
                ui.add_space(10.0);
            } else {
                let all_selected = state.selected_mask == state.affinity_info.system_mask;
                let mut all_checked = all_selected;
                if ui
                    .checkbox(&mut all_checked, format!("All CPUs ({})", cpu_count))
                    .changed()
                    && all_checked
                {
                    state.selected_mask = state.affinity_info.system_mask;
                }

                ui.add_space(4.0);
                ui.separator();
                ui.add_space(4.0);

                let cpus_per_row = 8;
                egui::Grid::new("cpu_grid")
                    .num_columns(cpus_per_row)
                    .spacing([8.0, 4.0])
                    .show(ui, |ui| {
                        for (i, &cpu) in available_cpus.iter().enumerate() {
                            let mut checked = (state.selected_mask & (1u64 << cpu)) != 0;
                            let label = format!("CPU {}", cpu);

                            if ui.checkbox(&mut checked, label).changed() {
                                if checked {
                                    state.selected_mask |= 1u64 << cpu;
                                } else {
                                    state.selected_mask &= !(1u64 << cpu);
                                }
                            }

                            if (i + 1) % cpus_per_row == 0 {
                                ui.end_row();
                            }
                        }
                    });

                ui.add_space(8.0);

                if state.selected_mask == 0 {
                    ui.label("Warning: At least one CPU must be selected.");
                    ui.add_space(6.0);
                }

                ui.label(format!(
                    "Selected: {} of {} CPUs",
                    state.selected_mask.count_ones(),
                    cpu_count
                ));

                ui.add_space(10.0);
            }

            if let Some(result) = &state.result {
                match result {
                    Ok(()) => {
                        ui.label("Affinity changed successfully.");
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

                let changed = state.selected_mask != state.affinity_info.process_mask;
                let valid = state.selected_mask != 0;
                let can_apply = changed && valid;

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

    if let Some(state) = &mut app.affinity_dialog {
        if state.selected_mask != selected_mask_before_ui {
            state.result = None;
        }

        if apply_clicked {
            let result = set_affinity(state.pid, state.selected_mask);
            match result {
                Ok(()) => {
                    state.affinity_info.process_mask = state.selected_mask;
                    state.result = Some(Ok(()));
                }
                Err(e) => {
                    state.result = Some(Err(e.to_string()));
                }
            }
        }
    }

    if !open || should_close {
        app.affinity_dialog = None;
    }
}
