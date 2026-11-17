//! Image hashes for the provider sections. Nothing here hashes on the UI thread.

use pmonnt_core::reputation_service::{ImageHashState, ReputationService};
use std::collections::HashMap;

/// The image hash to display for `pid`, if known: the latest explicitly re-validated one,
/// otherwise the reputation worker's (which the reputation panel queues before the provider
/// sections render).
pub(super) fn known_image_sha(
    service: &ReputationService,
    pid_to_image_path: &HashMap<u32, String>,
    pid: u32,
) -> Option<String> {
    let path = pid_to_image_path.get(&pid)?;
    if let Some(ImageHashState::Ready(sha)) = service.image_hash_state(path) {
        return Some(sha);
    }
    service.get_result(path)?.sha256
}

/// Start an explicit lookup ("Check", or "Refresh" with `force`) for `pid`: re-validate its
/// image hash in the background and remember the request until the hash is ready.
///
/// `pending` maps PID to `force` and is not cleared when a view switches process, so a
/// request survives the main panel and a perf window sharing the provider state.
pub(super) fn request_check(
    service: &ReputationService,
    pid_to_image_path: &HashMap<u32, String>,
    pid: u32,
    force: bool,
    pending: &mut HashMap<u32, bool>,
) -> Result<(), String> {
    let path = pid_to_image_path
        .get(&pid)
        .ok_or_else(|| "image path unknown".to_string())?;
    service.rehash_image(path);
    // A pending Refresh stays a Refresh if Check is clicked meanwhile.
    *pending.entry(pid).or_insert(false) |= force;
    Ok(())
}

/// What the background dispatcher needs from one provider's panel state.
pub(super) trait PendingLookups {
    fn pending_checks(&mut self) -> &mut HashMap<u32, bool>;
    /// PID the provider section last rendered (its display state belongs to that process).
    fn shown_pid(&self) -> Option<u32>;
    /// Queue the provider lookup for `sha` on the reputation worker.
    fn request(service: &ReputationService, sha: &str, force: bool);
    /// Show a started lookup in the section's state.
    fn track(&mut self, pid: u32, sha: String);
    fn show_error(&mut self, message: String);
}

/// Start the lookups whose re-validated image hash is ready. Runs every frame from the app's
/// background work, so requests progress while their section is collapsed, scrolled away or
/// showing another process. Pending requests are dropped if online lookups were turned off.
pub(super) fn dispatch_pending<S: PendingLookups>(
    service: &ReputationService,
    pid_to_image_path: &HashMap<u32, String>,
    online_lookups_enabled: bool,
    state: &mut S,
) {
    if state.pending_checks().is_empty() {
        return;
    }
    if !online_lookups_enabled {
        state.pending_checks().clear();
        return;
    }
    let mut finished: Vec<(u32, bool, Result<String, String>)> = Vec::new();
    for (&pid, &force) in state.pending_checks().iter() {
        let Some(path) = pid_to_image_path.get(&pid) else {
            finished.push((pid, force, Err("image path unknown".to_string())));
            continue;
        };
        match service.image_hash_state(path) {
            Some(ImageHashState::Ready(sha)) => finished.push((pid, force, Ok(sha))),
            Some(ImageHashState::Failed(e)) => finished.push((pid, force, Err(e))),
            Some(ImageHashState::Pending) => {}
            // The re-hash state was trimmed away; start it again.
            None => service.rehash_image(path),
        }
    }
    for (pid, force, outcome) in finished {
        state.pending_checks().remove(&pid);
        // Only the section showing this process may display its hash or error.
        let shown = state.shown_pid() == Some(pid);
        match outcome {
            Ok(sha) => {
                S::request(service, &sha, force);
                if shown {
                    state.track(pid, sha);
                }
            }
            Err(e) if shown => state.show_error(e),
            Err(_) => {}
        }
    }
}
