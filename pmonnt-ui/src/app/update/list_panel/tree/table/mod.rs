use eframe::egui;
use egui_extras::{Column, TableBuilder};

use crate::app::PMonNTApp;
use crate::process_table::{process_table_policy, ProcessColumnId};
use crate::view::ProcRow;

mod header;
mod rows;

pub(super) fn render_tree_table(
    app: &mut PMonNTApp,
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    row_height: f32,
    rows_flat: &[ProcRow],
    selection_changed: &mut bool,
) {
    // Render tree view with aligned columns via TableBuilder
    let mut did_scroll = false;
    // Tree view uses the same responsive column policy as Grouped.
    let policy = process_table_policy(ui.available_width());
    ui.push_id("tree_process_table", |ui| {
        let columns: Vec<ProcessColumnId> = app
            .effective_process_columns(&policy)
            .into_iter()
            .filter(|c| *c != ProcessColumnId::Leader)
            .collect();

        let mut table = TableBuilder::new(ui).striped(true);
        for col in &columns {
            // Right-align numeric columns for better readability
            let layout = match col {
                ProcessColumnId::CPU
                | ProcessColumnId::Memory
                | ProcessColumnId::Disk
                | ProcessColumnId::GPU
                | ProcessColumnId::GpuDedicated
                | ProcessColumnId::GpuShared
                | ProcessColumnId::GpuTotal
                | ProcessColumnId::Handles
                | ProcessColumnId::Threads
                | ProcessColumnId::PID => egui::Layout::right_to_left(egui::Align::Center),
                _ => egui::Layout::left_to_right(egui::Align::Center),
            };
            table = table
                .column(Column::initial(col.width(&policy)).resizable(true))
                .cell_layout(layout);
        }

        table
            .header(20.0, |header_row| {
                header::render_header(app, header_row, &columns);
            })
            .body(|body| {
                rows::render_rows(
                    app,
                    ctx,
                    body,
                    row_height,
                    &columns,
                    rows_flat,
                    selection_changed,
                    &mut did_scroll,
                );
            });
    });
}
