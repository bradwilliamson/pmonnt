use eframe::egui;
use std::time::Instant;

use super::{perf_window, PMonNTApp};

impl PMonNTApp {
    pub(crate) fn tick_perf_windows(&mut self, ctx: &egui::Context) {
        // Spawn/render any per-process performance windows.
        if self.perf_windows.is_empty() {
            self.perf_last_sample = Instant::now();
            self.perf_sample_accum_secs = 0.0;
        } else {
            // Keep popout graphs responsive even if snapshot refresh is slower.
            let dt = self.perf_last_sample.elapsed().as_secs_f32();
            self.perf_last_sample = Instant::now();
            self.perf_sample_accum_secs += dt;

            if self.perf_sample_accum_secs >= perf_window::PERF_SAMPLE_INTERVAL_SECS {
                let sample_dt = self.perf_sample_accum_secs;
                self.perf_sample_accum_secs = 0.0;
                self.update_perf_windows_history(sample_dt);
            }
        }

        self.show_perf_windows(ctx);
    }
}
