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
