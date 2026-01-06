use std::time::Instant;

use eframe::egui;

use super::PMonNTApp;
use crate::theme::apply_theme;

mod background;
mod details_panel;
mod handles;
mod layout;
mod list_panel;
mod panels;
mod selection;
mod shortcuts;
mod snapshot;

impl eframe::App for PMonNTApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        // FRAME TIMING START
        let frame_start = Instant::now();

        // Best-effort: keep a cached HWND for native dialog ownership.
        self.main_hwnd = crate::util::try_get_main_hwnd(frame);

        // Apply theme only when it changes (avoids redundant ctx updates).
        if self.last_applied_theme != Some(self.theme) {
            apply_theme(ctx, self.theme);
            self.last_applied_theme = Some(self.theme);
        }

        let mut selection_changed = false;
        // Used to detect mouse-driven selection changes without touching every click site.
        let selected_pid_before_panels = self.selected_pid;

        self.service_background_work();
        self.tick_housekeeping(ctx);
        self.refresh_snapshot_and_metrics(ctx);
        self.update_handles_cache(ctx);

        // Extract needed state before closures to avoid borrow conflicts
        let tick = self.tick;
        let process_count = self.current_snapshot.len();
        let last_diff = self.last_diff.clone();
        let selected_pid = self.selected_pid;

        // Cache input state to avoid multiple ctx.input() calls.
        // This is also used later for keyboard navigation in the process list.
        let input = ctx.input(|i| i.clone());

        self.update_selection_hash_jobs();
        self.handle_filter_shortcuts(ctx, &input);
        self.show_elevation_warning(ctx);
        self.show_version_footer(ctx);

        let (available_width, is_compact) = self.compute_responsive_layout(ctx);
        self.render_main_toolbar(ctx, is_compact);

        let (show_list_panel, show_details_panel, left_min_width, left_max_width) =
            self.compute_panel_visibility_and_splitter_bounds(available_width, is_compact);

        // Render Details Panel first (SidePanel::right) if visible
        if show_details_panel && self.details_panel_visible {
            self.show_details_panel(ctx, selected_pid);
        }

        // Render List Panel (CentralPanel)
        if show_list_panel {
            self.show_list_panel(
                ctx,
                is_compact,
                available_width,
                left_min_width,
                left_max_width,
                tick,
                process_count,
                &last_diff,
                selected_pid_before_panels,
                &input,
                &mut selection_changed,
            );
        }

        self.tick_perf_windows(ctx);

        // Deferred clipboard actions (e.g., Copy SHA-256 from context menu)
        if let Some(pid) = self.pending_copy_sha_pid {
            // Only fulfill if the requested PID is still selected.
            if self.selected_pid == Some(pid) {
                if let Some(sha) = self.mb_ui_state.current_process_sha.clone() {
                    ctx.output_mut(|o| o.copied_text = sha);
                    self.pending_copy_sha_pid = None;
                }
            } else {
                // Selection changed; cancel the pending copy.
                self.pending_copy_sha_pid = None;
            }
        }

        // Global modal dialogs
        crate::ui_renderer::render_kill_dialog(self, ctx);
        crate::ui_renderer::render_priority_dialog(self, ctx);
        crate::ui_renderer::render_affinity_dialog(self, ctx);
        crate::ui_renderer::render_service_dialog(self, ctx);
        crate::ui_renderer::render_dump_confirm_dialog(self, ctx);

        self.was_compact_layout = is_compact;

        // FRAME TIMING END - log if frame exceeded thresholds
        let frame_elapsed = frame_start.elapsed().as_millis() as u64;
        if frame_elapsed > 500 {
            log::warn!(
                "FRAME STALL: total={}ms, selected_pid={:?}, filter_len={}",
                frame_elapsed,
                self.selected_pid,
                self.filter_text.len()
            );
        }

        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}
