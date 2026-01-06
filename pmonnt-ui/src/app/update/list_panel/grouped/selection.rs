use crate::app::PMonNTApp;
use crate::view::GroupedRow;

pub(super) fn clear_invalid_selection(app: &mut PMonNTApp, grouped_rows: &[GroupedRow]) {
    // Clear selection if selected PID is no longer in the filtered results
    if let Some(selected) = app.selected_pid {
        if !grouped_rows
            .iter()
            .any(|r| r.member_pids.contains(&selected) || r.representative_pid == selected)
        {
            app.selected_pid = None;
        }
    }
}
