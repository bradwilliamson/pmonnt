use eframe::egui;

use crate::app::PMonNTApp;

#[derive(Clone, Debug)]
pub(crate) struct DumpConfirmDialogState {
    pub(crate) pid: u32,
    pub(crate) process_name: String,
}

pub(crate) fn render_dump_confirm_dialog(app: &mut PMonNTApp, ctx: &egui::Context) {
    let Some(state) = app.dump_confirm_dialog_state() else {
        return;
    };

    let mut open = true;

    egui::Window::new("Confirm Full Dump")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .open(&mut open)
        .show(ctx, |ui| {
            ui.label(format!(
                "Create a FULL memory dump of '{}' (PID {})?",
                state.process_name, state.pid
            ));
            ui.separator();
            ui.colored_label(
                egui::Color32::YELLOW,
                "Warning: Full dumps can be very large and may contain sensitive data.",
            );
            ui.label("If you only need stack/module info, prefer a minidump.");

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("Cancel").clicked() {
                    app.dismiss_dump_confirm_dialog();
                }

                let btn = egui::Button::new("Create full dump")
                    .fill(egui::Color32::DARK_RED)
                    .stroke(ui.visuals().widgets.inactive.fg_stroke);
                if ui.add(btn).clicked() {
                    app.confirm_full_dump(state.pid, state.process_name.clone());
                    app.dismiss_dump_confirm_dialog();
                }
            });
        });

    if !open {
        app.dismiss_dump_confirm_dialog();
    }
}
