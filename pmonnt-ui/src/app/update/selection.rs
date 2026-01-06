use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::app::PMonNTApp;

impl PMonNTApp {
    pub(super) fn update_selection_hash_jobs(&mut self) {
        let selected_pid = self.selected_pid;

        // If selected process changed, compute SHA-256 in background (non-blocking)
        if selected_pid != self.mb_ui_state.last_seen_pid {
            // Bump a generation counter so any in-flight hash computations can be ignored.
            // This prevents stale results from racing and overwriting the newly-selected PID state.
            let generation = self
                .selection_hash_generation
                .fetch_add(1, Ordering::SeqCst)
                .wrapping_add(1);

            self.mb_ui_state.last_seen_pid = selected_pid;
            self.mb_ui_state.current_process_sha = None;
            self.mb_ui_state.querying_mb_pid = None;
            self.mb_ui_state.querying_mb_sha = None;
            self.mb_ui_state.querying_started_at = None;

            if let Some(pid) = selected_pid {
                if let Some(path) = self.pid_to_image_path.get(&pid) {
                    let path_clone = path.clone();
                    let pending_mb = self.mb_ui_state.current_process_sha_pending.clone();
                    let pending_vt = self.vt_ui_state.current_process_sha_pending.clone();
                    let gen_guard = Arc::clone(&self.selection_hash_generation);
                    self.bg_worker.spawn(move || {
                        let hc = pmonnt_core::hashing::HashComputer::new();
                        if let Ok(sha) = hc.compute_sha256(&path_clone) {
                            if gen_guard.load(Ordering::SeqCst) != generation {
                                return;
                            }

                            if let Ok(mut guard) = pending_mb.lock() {
                                *guard = Some(sha.clone());
                            }
                            if let Ok(mut guard) = pending_vt.lock() {
                                *guard = Some(sha);
                            }
                        }
                    });
                }
            } else {
                // no selection, clear pending
                if let Ok(mut guard) = self.mb_ui_state.current_process_sha_pending.lock() {
                    *guard = None;
                }
                if let Ok(mut guard) = self.vt_ui_state.current_process_sha_pending.lock() {
                    *guard = None;
                }
            }
        }
    }
}
