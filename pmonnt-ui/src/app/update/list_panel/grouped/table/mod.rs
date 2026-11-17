use eframe::egui;
use egui_extras::{Column, TableBuilder};

use crate::app::PMonNTApp;
use crate::process_table::{ProcessColumnId, ProcessTablePolicy};
use crate::view::GroupedRow;

mod header;
mod rows;

pub(super) fn render_grouped_table(
    app: &mut PMonNTApp,
    ctx: &egui::Context,
    ui: &mut egui::Ui,
    row_height: f32,
    policy: ProcessTablePolicy,
    grouped_rows: &[GroupedRow],
    selection_changed: &mut bool,
) {
    // Render grouped view with expandable/collapsible groups (Task Manager style)
    let mut did_scroll = false;
    ui.push_id("grouped_process_table", |ui| {
        let columns: Vec<ProcessColumnId> = app.effective_process_columns(&policy);

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
                header::render_header(app, header_row, policy, &columns);
            })
            .body(|body| {
                rows::render_rows(
                    app,
                    ctx,
                    body,
                    row_height,
                    policy,
                    &columns,
                    grouped_rows,
                    selection_changed,
                    &mut did_scroll,
                );
            });
    });
}
