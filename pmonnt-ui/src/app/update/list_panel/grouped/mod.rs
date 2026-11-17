use eframe::egui;

use crate::app::PMonNTApp;
use crate::process_table::ProcessTablePolicy;
use pmonnt_core::view::build_grouped_rows;

mod keyboard;
mod selection;
mod table;

impl PMonNTApp {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn show_grouped_list_panel(
        &mut self,
        ctx: &egui::Context,
        ui: &mut egui::Ui,
        input: &egui::InputState,
        row_height: f32,
        policy: ProcessTablePolicy,
        selection_changed: &mut bool,
    ) {
        // Build grouped rows (flat, Task Manager style)
        let filter_lower = self.filter_text.to_lowercase();
        let grouped_rows = build_grouped_rows(
            &self.current_snapshot.processes,
            self.selected_pid,
            &filter_lower,
            self.group_sort,
            self.sort_desc,
            self.group_sort_by_leader,
            &self.pid_to_image_path,
            &self.row_metrics(),
        );

        selection::clear_invalid_selection(self, &grouped_rows);
        keyboard::handle_grouped_keyboard_nav(self, ctx, input, &grouped_rows, selection_changed);
        table::render_grouped_table(
            self,
            ctx,
            ui,
            row_height,
            policy,
            &grouped_rows,
            selection_changed,
        );
    }
}
