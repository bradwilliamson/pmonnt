use eframe::egui;

use crate::app::PMonNTApp;
use crate::view::{GroupedRow, RightTab};

pub(super) fn handle_grouped_keyboard_nav(
    app: &mut PMonNTApp,
    ctx: &egui::Context,
    input: &egui::InputState,
    grouped_rows: &[GroupedRow],
    selection_changed: &mut bool,
) {
    // Keyboard navigation for grouped view (flat rows) - only when not typing
    if ctx.wants_keyboard_input() {
        return;
    }

    if input.key_pressed(egui::Key::ArrowDown) {
        if let Some(selected) = app.selected_pid {
            // Find current row by checking if selected PID is in any group
            if let Some(idx) = grouped_rows
                .iter()
                .position(|r| r.member_pids.contains(&selected) || r.representative_pid == selected)
            {
                // Select next group's representative (clamp at bottom)
                if idx + 1 < grouped_rows.len() {
                    app.selected_pid = Some(grouped_rows[idx + 1].representative_pid);
                    *selection_changed = true;
                    ctx.request_repaint();
                }
            }
        } else if !grouped_rows.is_empty() {
            // Select first group
            app.selected_pid = Some(grouped_rows[0].representative_pid);
            *selection_changed = true;
            ctx.request_repaint();
        }
    }

    if input.key_pressed(egui::Key::ArrowUp) {
        if let Some(selected) = app.selected_pid {
            if let Some(idx) = grouped_rows
                .iter()
                .position(|r| r.member_pids.contains(&selected) || r.representative_pid == selected)
            {
                if idx > 0 {
                    app.selected_pid = Some(grouped_rows[idx - 1].representative_pid);
                    *selection_changed = true;
                    ctx.request_repaint();
                }
            }
        } else if !grouped_rows.is_empty() {
            if let Some(last) = grouped_rows.last() {
                app.selected_pid = Some(last.representative_pid);
            }
            *selection_changed = true;
            ctx.request_repaint();
        }
    }

    // Enter key switches to Details tab (Process Explorer "properties" equivalent)
    if input.key_pressed(egui::Key::Enter) && app.selected_pid.is_some() {
        app.right_tab = RightTab::Details;
        ctx.request_repaint();
    }

    // Delete = Kill Process, Shift+Delete = Kill Process Tree (opens confirmation)
    if input.key_pressed(egui::Key::Delete) {
        if let Some(selected) = app.selected_pid {
            let kill_tree = input.modifiers.shift;
            app.open_kill_dialog(selected, kill_tree);
            ctx.request_repaint();
        }
    }
}
