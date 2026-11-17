use crate::hashing::HashComputer;
use crate::local_cache::LocalCacheProvider;
use crate::providers::MalwareBazaarProvider;

use super::types::{Job, MbCacheType, VtCacheType};

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
        let live_shas: HashSet<String> = {
            let in_flight = self
                .in_flight
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut results = self
                .results
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            results.retain(|path, _| keep(path) || in_flight.contains(path));
            results.values().filter_map(|r| r.sha256.clone()).collect()
        };
        let keep_sha = |sha: &String, in_flight: &Mutex<HashSet<String>>| {
            live_shas.contains(sha) || set_contains(in_flight, sha)
        };
        self.mb_cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|sha, _| keep_sha(sha, &self.mb_in_flight));
        self.tf_cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|sha, _| keep_sha(sha, &self.tf_in_flight));
        self.vt_cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|sha, _| keep_sha(sha, &self.vt_in_flight));
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

fn set_contains(set: &Mutex<HashSet<String>>, key: &str) -> bool {
    set.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains(key)
}
