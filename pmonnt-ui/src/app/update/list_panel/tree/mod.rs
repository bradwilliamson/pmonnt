use std::collections::{HashMap, HashSet};

use eframe::egui;
use pmonnt_core::process;

use crate::app::PMonNTApp;
use crate::process_rows::build_process_rows;

mod keyboard;
mod roots;
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
        pid_set: &HashSet<u32>,
        pid_to_proc: &HashMap<u32, &process::Process>,
        children_map: &HashMap<u32, Vec<u32>>,
        visible_pids: Option<&HashSet<u32>>,
        selection_changed: &mut bool,
    ) {
        let roots = roots::compute_sorted_roots(self, pid_set, pid_to_proc, visible_pids);

        // Build flattened row list for virtualized rendering
        let filter_lower = self.filter_text.to_lowercase();
        let rows = build_process_rows(
            &roots,
            children_map,
            pid_to_proc,
            &self.expanded_pids,
            self.selected_pid,
            visible_pids,
            &filter_lower,
            128,
            self.group_sort,
            self.sort_desc,
            &self.handle_cache,
            &self.global_thread_counts,
            &self.cpu_memory_data,
            &self.io_rate_by_pid,
            &self.gpu_data,
            &self.signature_cache_by_path,
        );

        selection::clear_invalid_selection(self, &rows);
        sort_controls::render_tree_sort_controls(self, ui);
        keyboard::handle_tree_keyboard_nav(self, ctx, input, &rows, selection_changed);
        table::render_tree_table(self, ctx, ui, row_height, &rows, selection_changed);
    }
}
