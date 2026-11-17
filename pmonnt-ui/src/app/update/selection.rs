use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::app::{PMonNTApp, SelectionSha};

impl PMonNTApp {
    /// Start hashing the selected process's image in the background when the selection
    /// changes. The result is accepted by [`Self::accept_selection_sha`] only if it still
    /// matches the selection.
    pub(super) fn update_selection_hash_jobs(&mut self) {
        let selected_pid = self.selected_pid;
        if selected_pid == self.selection_hash_pid {
            return;
        }
        self.selection_hash_pid = selected_pid;
        self.selected_sha = None;

        // Only the UI thread bumps the generation, so a result carrying an older value is
        // stale no matter when its job finished.
        let generation = self
            .selection_hash_generation
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1);

        let Some(pid) = selected_pid else {
            return;
        };
        let known_path = self.pid_to_image_path.get(&pid).cloned();
        let pending = Arc::clone(&self.selection_sha_pending);
        let gen_guard = Arc::clone(&self.selection_hash_generation);
        // Shares the reputation worker's cache, so neither hashes the same file twice.
        let hasher = self.reputation_service.hash_computer();
        self.bg_worker.spawn(move || {
            if gen_guard.load(Ordering::SeqCst) != generation {
                return; // The selection moved on before this job started.
            }
            let path = match known_path {
                Some(path) => path,
                None => match pmonnt_core::win::process_path::get_process_image_path(pid) {
                    Ok(path) => path,
                    Err(e) => {
                        log::debug!("No image path for selected PID {pid}: {e}");
                        return;
                    }
                },
            };
            match hasher.compute_sha256(&path) {
                Ok(sha) => {
                    if let Ok(mut slot) = pending.lock() {
                        *slot = Some(SelectionSha {
                            generation,
                            pid,
                            sha,
                        });
                    }
                }
                Err(e) => log::debug!("Hashing {path} for PID {pid} failed: {e}"),
            }
        });
    }

    /// Take a finished selection hash if it belongs to the current selection.
    pub(super) fn accept_selection_sha(&mut self) {
        let Some(done) = self
            .selection_sha_pending
            .lock()
            .ok()
            .and_then(|mut slot| slot.take())
        else {
            return;
        };
        if done.generation == self.selection_hash_generation.load(Ordering::SeqCst)
            && self.selected_pid == Some(done.pid)
        {
            self.selected_sha = Some((done.pid, done.sha));
        }
    }

    /// SHA-256 of `pid`'s image if `pid` is selected and its hash is known.
    pub(crate) fn selected_sha_for(&self, pid: u32) -> Option<&str> {
        match &self.selected_sha {
            Some((p, sha)) if *p == pid => Some(sha.as_str()),
            _ => None,
        }
    }
}
