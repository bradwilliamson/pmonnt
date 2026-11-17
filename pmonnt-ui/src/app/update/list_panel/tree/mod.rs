use std::collections::HashSet;

use eframe::egui;
use pmonnt_core::snapshot::ProcessSnapshot;
use pmonnt_core::view::{TreeOptions, build_process_rows};

use crate::app::PMonNTApp;

mod keyboard;
mod selection;
mod sort_controls;
mod table;

impl PMonNTApp {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn show_tree_list_panel(
        &mut self,
        ctx: &egui::Context,
        ui: &mut egui::Ui,
        input: &egui::InputState,
        row_height: f32,
        snapshot: &ProcessSnapshot,
        visible_pids: Option<&HashSet<u32>>,
        selection_changed: &mut bool,
    ) {
        // Build the flattened row list for virtualized rendering.
        let filter_lower = self.filter_text.to_lowercase();
        let rows = build_process_rows(
            snapshot,
            &TreeOptions {
                expanded: &self.expanded_pids,
                selected_pid: self.selected_pid,
                visible_pids,
                filter_text_lower: &filter_lower,
                max_depth: 128,
                sort: self.group_sort,
                sort_desc: self.sort_desc,
            },
            &self.row_metrics(),
        );

        selection::clear_invalid_selection(self, &rows);
        sort_controls::render_tree_sort_controls(self, ui);
        keyboard::handle_tree_keyboard_nav(self, ctx, input, &rows, selection_changed);
        table::render_tree_table(self, ctx, ui, row_height, &rows, selection_changed);
    }
}
