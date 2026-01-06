use crate::app::{CompactView, PMonNTApp};

impl PMonNTApp {
    pub(super) fn compute_panel_visibility_and_splitter_bounds(
        &mut self,
        available_width: f32,
        is_compact: bool,
    ) -> (bool, bool, f32, f32) {
        let show_list_panel = !is_compact || self.compact_view == CompactView::List;
        let show_details_panel = !is_compact || self.compact_view == CompactView::Details;

        // Wide-mode splitter bounds.
        let left_min_width = 320.0;
        let left_max_width = (available_width * 0.75).max(left_min_width);
        self.left_panel_width = self.left_panel_width.clamp(left_min_width, left_max_width);

        (
            show_list_panel,
            show_details_panel,
            left_min_width,
            left_max_width,
        )
    }
}
