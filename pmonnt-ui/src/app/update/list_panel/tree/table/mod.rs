use eframe::egui;
use egui_extras::{Column, TableBuilder};

use crate::app::PMonNTApp;
use crate::process_table::{ProcessColumnId, process_table_policy};
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

        // `cell_layout` applies to the whole table, not one column: setting it per column
        // left the last column's right-to-left layout on every cell, so names were
        // right-aligned and tree indentation ran the wrong way. Cells are laid out left to
        // right; numeric cells right-align themselves.
        let mut table = TableBuilder::new(ui)
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            // Cells sense clicks so `row.response()` (the union of the cells) reports a
            // click anywhere in the row, as in egui's table demo.
            .sense(egui::Sense::click());
        for col in &columns {
            table = table.column(Column::initial(col.width(&policy)).resizable(true));
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
