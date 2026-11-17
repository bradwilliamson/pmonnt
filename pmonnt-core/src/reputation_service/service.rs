use crate::hashing::HashComputer;
use crate::local_cache::LocalCacheProvider;
use crate::providers::MalwareBazaarProvider;

use super::types::{ImageHashState, Job, MbCacheType, VtCacheType};

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};

/// Background service managing all reputation operations
pub struct ReputationService {
    pub(super) job_tx: std::sync::mpsc::Sender<Job>,
    pub(super) command_tx: std::sync::mpsc::Sender<super::types::ReputationCommand>,
    pub(super) results: Arc<RwLock<HashMap<String, super::types::ReputationResult>>>,
    pub(super) in_flight: Arc<Mutex<HashSet<String>>>,
    pub(super) mb_provider: Arc<MalwareBazaarProvider>,
    pub(super) hash_computer: HashComputer,
    // Use type aliases to reduce clippy type-complexity warnings
    pub(super) mb_cache: MbCacheType,
    pub(super) mb_in_flight: Arc<Mutex<HashSet<String>>>,
    #[allow(clippy::type_complexity)]
    pub(super) tf_cache: Arc<
        RwLock<
            HashMap<
                String,
                (
                    Option<crate::providers::TfResult>,
                    crate::providers::TfQueryMeta,
                ),
            >,
        >,
    >,
    pub(super) tf_in_flight: Arc<Mutex<HashSet<String>>>,
    pub(super) vt_cache: VtCacheType,
    pub(super) vt_in_flight: Arc<Mutex<HashSet<String>>>,
    /// Hashes re-validated for explicit "Check"/"Refresh" requests, by image path.
    pub(super) image_hashes: Arc<Mutex<HashMap<String, ImageHashState>>>,
    // Keep local_cache owned by MB/TF providers; service only needs it for construction
    pub(super) _local_cache: Arc<LocalCacheProvider>,
}

impl ReputationService {
    /// The service's SHA-256 computer. Clones share one cache, so hashing a file elsewhere
    /// (for example for the selected process) saves the worker from hashing it again.
    pub fn hash_computer(&self) -> HashComputer {
        self.hash_computer.clone()
    }

    /// Number of image paths with a hash/lookup result.
    pub fn cached_path_count(&self) -> usize {
        self.results
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Forget results for image paths `keep` rejects, and provider answers for hashes no
    /// remaining path has. Work that is still in flight is kept.
    pub fn retain_paths(&self, keep: impl Fn(&str) -> bool) {
        // Every lock is taken on its own, never nested, so this cannot deadlock with the
        // worker or the request paths. A path that becomes in flight after the copy may lose
        // its placeholder result; the worker writes the real one.
        let in_flight = copy_set(&self.in_flight);
        let mut live_shas: HashSet<String> = {
            let mut results = self
                .results
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            results.retain(|path, _| keep(path) || in_flight.contains(path));
            results.values().filter_map(|r| r.sha256.clone()).collect()
        };
        {
            let mut hashes = self
                .image_hashes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            hashes.retain(|path, state| keep(path) || *state == ImageHashState::Pending);
            // A re-validated hash can differ from the path result (upgraded binary).
            live_shas.extend(hashes.values().filter_map(|state| match state {
                ImageHashState::Ready(sha) => Some(sha.clone()),
                _ => None,
            }));
        }

        let mb_busy = copy_set(&self.mb_in_flight);
        self.mb_cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|sha, _| live_shas.contains(sha) || mb_busy.contains(sha));
        let tf_busy = copy_set(&self.tf_in_flight);
        self.tf_cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|sha, _| live_shas.contains(sha) || tf_busy.contains(sha));
        let vt_busy = copy_set(&self.vt_in_flight);
        self.vt_cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|sha, _| live_shas.contains(sha) || vt_busy.contains(sha));
    }

    /// Re-hash `path` on a background thread for an explicit lookup.
    ///
    /// The path-keyed results above can predate an upgrade of the binary at that path, and
    /// remember a failed hash. This goes through the shared [`HashComputer`], which re-reads
    /// the file only if its modification time or size changed, so it is cheap when nothing
    /// changed. Does nothing while a re-hash of `path` is already running.
    pub fn rehash_image(&self, path: &str) {
        {
            let mut hashes = self
                .image_hashes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if hashes.get(path) == Some(&ImageHashState::Pending) {
                return;
            }
            hashes.insert(path.to_string(), ImageHashState::Pending);
        }
        let hashes = Arc::clone(&self.image_hashes);
        let results = Arc::clone(&self.results);
        let in_flight = Arc::clone(&self.in_flight);
        let hasher = self.hash_computer.clone();
        let path = path.to_string();
        std::thread::spawn(move || {
            // AssertUnwindSafe: the hash cache only gains an entry after a hash completes,
            // so a panic part-way through leaves it consistent.
            let hash = std::panic::AssertUnwindSafe(|| hasher.compute_sha256(&path));
            let state = match std::panic::catch_unwind(hash) {
                Ok(Ok(sha)) => ImageHashState::Ready(sha),
                Ok(Err(e)) => ImageHashState::Failed(format!("Hash error: {e}")),
                Err(_) => ImageHashState::Failed("hashing failed".to_string()),
            };
            // If the file changed since the path result was computed, that result (and its
            // aggregate verdict) describes the old binary: drop it so the next request
            // rebuilds it. Locks are taken one at a time.
            if let ImageHashState::Ready(sha) = &state {
                let stale = results
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&path)
                    .is_some_and(|r| r.sha256.as_deref() != Some(sha.as_str()));
                if stale && !set_contains(&in_flight, &path) {
                    results
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&path);
                }
            }
            hashes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(path, state);
        });
    }

    /// State of the last [`Self::rehash_image`] for `path`, if any.
    pub fn image_hash_state(&self, path: &str) -> Option<ImageHashState> {
        self.image_hashes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(path)
            .cloned()
    }

    /// Whether a VirusTotal lookup for `sha` is queued or running.
    pub fn vt_lookup_in_flight(&self, sha: &str) -> bool {
        set_contains(&self.vt_in_flight, sha)
    }

    /// Whether a MalwareBazaar lookup for `sha` is queued or running.
    pub fn mb_lookup_in_flight(&self, sha: &str) -> bool {
        set_contains(&self.mb_in_flight, sha)
    }

    /// Whether a ThreatFox lookup for `sha` is queued or running.
    pub fn tf_lookup_in_flight(&self, sha: &str) -> bool {
        set_contains(&self.tf_in_flight, sha)
    }
}

fn copy_set(set: &Mutex<HashSet<String>>) -> HashSet<String> {
    set.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn set_contains(set: &Mutex<HashSet<String>>, key: &str) -> bool {
    set.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(key)
}
