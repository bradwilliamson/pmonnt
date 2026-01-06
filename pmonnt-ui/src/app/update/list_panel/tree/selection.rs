use crate::app::PMonNTApp;
use crate::view::ProcRow;

pub(super) fn clear_invalid_selection(app: &mut PMonNTApp, rows: &[ProcRow]) {
    // Clear selection if selected PID is no longer in the filtered results
    if let Some(selected) = app.selected_pid {
        if !rows.iter().any(|r| r.pid == selected) {
            app.selected_pid = None;
        }
    }
}
