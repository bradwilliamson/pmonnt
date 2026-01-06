use eframe::egui;

use crate::app::PMonNTApp;
use crate::view::{ProcRow, RightTab};

pub(super) fn handle_tree_keyboard_nav(
    app: &mut PMonNTApp,
    ctx: &egui::Context,
    input: &egui::InputState,
    rows: &[ProcRow],
    selection_changed: &mut bool,
) {
    // Keyboard navigation - only when not typing
    if ctx.wants_keyboard_input() {
        return;
    }

    if input.key_pressed(egui::Key::ArrowDown) {
        if let Some(selected) = app.selected_pid {
            if let Some(idx) = rows.iter().position(|r| r.pid == selected) {
                if idx + 1 < rows.len() {
                    app.selected_pid = Some(rows[idx + 1].pid);
                    *selection_changed = true;
                    ctx.request_repaint();
                }
            }
        } else if !rows.is_empty() {
            app.selected_pid = Some(rows[0].pid);
            *selection_changed = true;
            ctx.request_repaint();
        }
    }

    if input.key_pressed(egui::Key::ArrowUp) {
        if let Some(selected) = app.selected_pid {
            if let Some(idx) = rows.iter().position(|r| r.pid == selected) {
                if idx > 0 {
                    app.selected_pid = Some(rows[idx - 1].pid);
                    *selection_changed = true;
                    ctx.request_repaint();
                }
            }
        } else if !rows.is_empty() {
            app.selected_pid = Some(rows[rows.len() - 1].pid);
            *selection_changed = true;
            ctx.request_repaint();
        }
    }

    if input.key_pressed(egui::Key::Enter) && app.selected_pid.is_some() {
        app.right_tab = RightTab::Details;
        ctx.request_repaint();
    }

    // Space toggles expand/collapse in tree view (only in tree mode)
    if input.key_pressed(egui::Key::Space) {
        if let Some(selected) = app.selected_pid {
            if app.expanded_pids.contains(&selected) {
                app.expanded_pids.remove(&selected);
            } else {
                app.expanded_pids.insert(selected);
            }
            ctx.request_repaint();
        }
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
