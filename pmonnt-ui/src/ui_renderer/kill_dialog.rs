use eframe::egui;

use crate::app::{KillDialogStep, PMonNTApp};
pub(crate) fn render_kill_dialog(app: &mut PMonNTApp, ctx: &egui::Context) {
    let Some(state) = app.kill_dialog_state() else {
        return;
    };

    let mut open = true;
    let title = if state.kill_tree {
        "Confirm Kill Process Tree"
    } else {
        "Confirm Kill Process"
    };

    egui::Window::new(title)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .open(&mut open)
        .show(ctx, |ui| {
            ui.label(format!("{} (PID {})", state.name, state.pid));
            ui.separator();
            ui.colored_label(
                egui::Color32::YELLOW,
                "Warning: Terminating a process can cause data loss.",
            );
            ui.label(egui::RichText::new("Hotkeys: Del = Kill, Shift+Del = Kill Tree").color(egui::Color32::GRAY));
            if state.kill_tree {
                ui.label(
                    "This will terminate the selected process and all descendants (children first).",
                );
            }

            ui.add_space(8.0);

            match &state.step {
                KillDialogStep::Confirm => {
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            app.dismiss_kill_dialog();
                        }

                        let kill_label = if state.kill_tree { "Kill Tree" } else { "Kill" };
                        if ui
                            .add(egui::Button::new(kill_label).fill(egui::Color32::DARK_RED))
                            .clicked()
                        {
                            app.confirm_kill_dialog();
                        }
                    });
                }
                KillDialogStep::Running => {
                    ui.label("Killing...");
                    ui.add_enabled(false, egui::Button::new("Kill"));
                    ui.horizontal(|ui| {
                        ui.add(egui::widgets::Spinner::new());
                        ui.label("Please wait");
                    });
                }
                KillDialogStep::Done(result) => {
                    match result {
                        Ok(()) => {
                            ui.colored_label(egui::Color32::LIGHT_GREEN, "Kill succeeded");
                        }
                        Err(e) => {
                            ui.colored_label(egui::Color32::LIGHT_RED, format!("Kill failed: {e}"));
                        }
                    }

                    ui.add_space(8.0);
                    if ui.button("Close").clicked() {
                        app.dismiss_kill_dialog();
                    }
                }
            }
        });

    if !open {
        app.dismiss_kill_dialog();
    }
}
