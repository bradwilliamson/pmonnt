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
