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

/// For a pending request on `pid`, the hash once it is ready (with the request's `force`),
/// or the hashing error. `None` while there is nothing to do yet. Requests are dropped
/// without a lookup if online lookups were turned off meanwhile.
pub(super) fn take_ready_check(
    service: &ReputationService,
    pid_to_image_path: &HashMap<u32, String>,
    pid: u32,
    online_lookups_enabled: bool,
    pending: &mut HashMap<u32, bool>,
) -> Option<Result<(String, bool), String>> {
    let &force = pending.get(&pid)?;
    if !online_lookups_enabled {
        pending.remove(&pid);
        return None;
    }
    let Some(path) = pid_to_image_path.get(&pid) else {
        pending.remove(&pid);
        return Some(Err("image path unknown".to_string()));
    };
    match service.image_hash_state(path) {
        Some(ImageHashState::Ready(sha)) => {
            pending.remove(&pid);
            Some(Ok((sha, force)))
        }
        Some(ImageHashState::Failed(e)) => {
            pending.remove(&pid);
            Some(Err(e))
        }
        Some(ImageHashState::Pending) => None,
        // The re-hash state was trimmed away; start it again.
        None => {
            service.rehash_image(path);
            None
        }
    }
}
