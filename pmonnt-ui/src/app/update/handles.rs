use std::collections::HashMap;
use std::time::Instant;

use eframe::egui;
use pmonnt_core::handles::compute_summaries;
use pmonnt_core::win;

use crate::app::PMonNTApp;

impl PMonNTApp {
    pub(super) fn update_handles_cache(&mut self, ctx: &egui::Context) {
        // Update handles every N seconds (off UI thread, adaptive)
        if self.last_handle_update.elapsed().as_secs() >= self.handle_scan_interval_secs {
            self.last_handle_update = Instant::now();

            // Avoid piling up scans if enumeration is slow.
            if self.handle_scan_in_progress {
                return;
            }
            self.handle_scan_in_progress = true;

            // Clone cache, PIDs, and image paths for background thread
            let mut handle_cache_local = self.handle_cache.clone();
            let current_pids: Vec<u32> = self
                .current_snapshot
                .processes
                .iter()
                .map(|p| p.pid)
                .collect();
            let pid_to_path = self.pid_to_image_path.clone();
            let tx = self.handle_update_tx.clone();

            std::thread::spawn(move || {
                let scan_start = Instant::now();
                match win::handles::enumerate_handles() {
                    Ok(handles) => {
                        handle_cache_local.last_error = None;
                        win::handles::populate_type_cache(&handles);

                        let mut raw_type_counts: HashMap<u32, HashMap<u16, u32>> = HashMap::new();
                        for handle in &handles {
                            let type_counts = raw_type_counts.entry(handle.pid).or_default();
                            *type_counts.entry(handle.object_type_index).or_insert(0) += 1;
                        }

                        let summaries = compute_summaries(&handles);

                        handle_cache_local.update_with_paths(summaries, &pid_to_path);
                        handle_cache_local.update_type_history(&raw_type_counts);
                        handle_cache_local.cleanup(&current_pids);

                        let scan_duration_ms = scan_start.elapsed().as_millis() as u64;
                        let _ = tx.send((handle_cache_local, scan_duration_ms));
                    }
                    Err(e) => {
                        handle_cache_local.last_error = Some(e.to_string());
                        let scan_duration_ms = scan_start.elapsed().as_millis() as u64;
                        let _ = tx.send((handle_cache_local, scan_duration_ms));
                    }
                }
            });
        }

        // Check for handle cache updates from background thread
        if let Ok((updated_cache, scan_duration_ms)) = self.handle_update_rx.try_recv() {
            self.handle_cache = updated_cache;
            self.last_handle_scan_duration_ms = scan_duration_ms;
            self.handle_scan_in_progress = false;

            // Adaptive interval: if scan took > 100ms, back off to 10s
            if scan_duration_ms > 100 {
                self.handle_scan_interval_secs = 10;
            } else {
                self.handle_scan_interval_secs = 5;
            }

            ctx.request_repaint();
        }
    }
}
