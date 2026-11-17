use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use eframe::egui;
use pmonnt_core::handles::{HandleSummary, count_handle_types, summaries_from_counts};
use pmonnt_core::snapshot::ProcessSnapshot;
use pmonnt_core::win;

use crate::app::PMonNTApp;

/// What a background handle scan produced. The scan thread only enumerates and counts; the
/// UI thread folds the result into the live `HandleCache`, so leak-detector settings changed
/// (or reset) while a scan was running are not overwritten by a stale copy.
pub(crate) struct HandleScanResult {
    outcome: Result<HandleCounts, String>,
    duration_ms: u64,
    /// The process list when the scan started. Counts are kept only for PIDs that still
    /// belong to the same process when the result is applied.
    started_with: Option<Arc<ProcessSnapshot>>,
}

struct HandleCounts {
    summaries: HashMap<u32, HandleSummary>,
    type_counts: HashMap<u32, HashMap<u16, u32>>,
}

fn scan_handles() -> HandleScanResult {
    let scan_start = Instant::now();
    let outcome = win::handles::enumerate_handles()
        .map(|handles| {
            win::handles::populate_type_cache(&handles);
            // One counting pass feeds both the summaries and the type history.
            let counts = count_handle_types(&handles);
            HandleCounts {
                summaries: summaries_from_counts(&counts),
                type_counts: counts
                    .into_iter()
                    .map(|(pid, types)| (pid, types.into_iter().collect()))
                    .collect(),
            }
        })
        .map_err(|e| e.to_string());
    HandleScanResult {
        outcome,
        duration_ms: scan_start.elapsed().as_millis() as u64,
        started_with: None,
    }
}

/// Whether `pid` is the same process instance in both snapshots.
fn same_process(before: &ProcessSnapshot, now: &ProcessSnapshot, pid: u32) -> bool {
    match (before.get_process(pid), now.get_process(pid)) {
        (Some(a), Some(b)) => a.name == b.name && a.create_time == b.create_time,
        _ => false,
    }
}

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

            let tx = self.handle_update_tx.clone();
            let started_with = Arc::clone(&self.current_snapshot);
            std::thread::spawn(move || {
                // Always answer, even if the scan panics, or no scan would ever start again.
                let mut result =
                    std::panic::catch_unwind(scan_handles).unwrap_or_else(|_| HandleScanResult {
                        outcome: Err("handle scan failed unexpectedly".to_string()),
                        duration_ms: 0,
                        started_with: None,
                    });
                result.started_with = Some(started_with);
                let _ = tx.send(result);
            });
        }

        // Fold a finished scan into the live cache.
        if let Ok(scan) = self.handle_update_rx.try_recv() {
            self.apply_handle_scan(scan);
            ctx.request_repaint();
        }
    }

    fn apply_handle_scan(&mut self, scan: HandleScanResult) {
        match scan.outcome {
            Ok(mut counts) => {
                // A PID recycled while the scan ran would otherwise receive the old process's
                // handle counts (and leak-detector samples). Recycled PIDs, and processes that
                // started during the scan, are picked up by the next one.
                if let Some(before) = &scan.started_with {
                    let now = &self.current_snapshot;
                    counts
                        .summaries
                        .retain(|&pid, _| same_process(before, now, pid));
                    counts
                        .type_counts
                        .retain(|&pid, _| same_process(before, now, pid));
                }
                let cache = &mut self.handle_cache;
                cache.last_error = None;
                cache.update_with_paths(counts.summaries, &self.pid_to_image_path);
                cache.update_type_history(&counts.type_counts);
                let live_pids: Vec<u32> = self
                    .current_snapshot
                    .processes
                    .iter()
                    .map(|p| p.pid)
                    .collect();
                cache.cleanup(&live_pids);
            }
            Err(e) => self.handle_cache.last_error = Some(e),
        }
        self.last_handle_scan_duration_ms = scan.duration_ms;
        self.handle_scan_in_progress = false;

        // Adaptive interval: if scan took > 100ms, back off to 10s
        self.handle_scan_interval_secs = if scan.duration_ms > 100 { 10 } else { 5 };
    }
}
