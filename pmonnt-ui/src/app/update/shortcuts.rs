use eframe::egui;

use crate::app::PMonNTApp;

impl PMonNTApp {
    pub(super) fn handle_filter_shortcuts(
        &mut self,
        ctx: &egui::Context,
        input: &egui::InputState,
    ) {
        // Handle global keyboard shortcuts for filter (one-shot pattern to prevent infinite loop)
        let filter_id = egui::Id::new("process_filter_input");
        let filter_has_focus = ctx.memory(|m| m.has_focus(filter_id));

        // Detect "/" key press event-based (not frame-based) - only when NOT already focused
        let slash_pressed = input
            .events
            .iter()
            .any(|e| matches!(e, egui::Event::Text(t) if t == "/"));

        // Only request focus if NOT already focused AND haven't requested yet
        // Gate slash event so it only triggers when filter is NOT focused
        if slash_pressed && !filter_has_focus && !self.slash_focus_pending {
            ctx.memory_mut(|m| m.request_focus(filter_id));
            self.slash_focus_pending = true;
        }

        // Ctrl+F always focuses the filter
        if input.modifiers.ctrl && input.key_pressed(egui::Key::F) {
            ctx.memory_mut(|m| m.request_focus(filter_id));
        }

        // Clear filter with Esc
        if input.key_pressed(egui::Key::Escape) && !self.filter_text.is_empty() {
            self.filter_text.clear();
        }
    }
}
