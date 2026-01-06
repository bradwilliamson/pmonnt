use super::service::ReputationService;
use super::sync::{lock_or_recover, read_or_recover, write_or_recover};
use super::types::{Job, ReputationCommand, ReputationResult};

use crate::hashing::HashComputer;
use crate::local_cache::LocalCacheProvider;
use crate::providers::{AggregatorProvider, MalwareBazaarProvider, ThreatFoxProvider};
use crate::reputation::{LookupState, ReputationProvider};
use crate::vt::VirusTotalProvider;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

fn apply_update_config_command(
    vt_provider: &VirusTotalProvider,
    mb_provider: &MalwareBazaarProvider,
    tf_provider: &ThreatFoxProvider,
    aggregator: &AggregatorProvider,
    cmd: ReputationCommand,
) {
    match cmd {
        ReputationCommand::UpdateConfig {
            vt_api_key,
            mb_api_key,
            tf_api_key,
            vt_enabled,
            mb_enabled,
            tf_enabled,
        } => {
            if let Some(key) = vt_api_key {
                vt_provider.set_api_key(key);
            }

            mb_provider.update_api_key(mb_api_key.clone());
            let tf_effective = tf_api_key.or_else(|| mb_api_key.clone());
            tf_provider.update_api_key(tf_effective);

            aggregator.update_provider_enabled(vt_enabled, mb_enabled, tf_enabled);
        }
    }
}

fn handle_hash_and_lookup_job(
    results: &Arc<RwLock<HashMap<String, ReputationResult>>>,
    in_flight: &Arc<Mutex<HashSet<String>>>,
    hash_computer: &HashComputer,
    aggregator: &dyn ReputationProvider,
    image_path: String,
    lookup_enabled: bool,
) {
    // Update state to Hashing
    {
        let mut results = write_or_recover(results);
        results.insert(
            image_path.clone(),
            ReputationResult {
                image_path: image_path.clone(),
                sha256: None,
                state: LookupState::Hashing,
            },
        );
    }

    // Compute hash directly (we're already in a background thread)
    let sha256 = match hash_computer.compute_sha256(&image_path) {
        Ok(hash) => hash,
        Err(e) => {
            log::warn!("Hash computation failed for {}: {}", image_path, e);
            let mut results = write_or_recover(results);
            results.insert(
                image_path.clone(),
                ReputationResult {
                    image_path: image_path.clone(),
                    sha256: None,
                    state: LookupState::Error(format!("Hash error: {}", e)),
                },
            );
            lock_or_recover(in_flight).remove(&image_path);
            return;
        }
    };

    let state = if !lookup_enabled {
        LookupState::Disabled
    } else {
        {
            let mut results = write_or_recover(results);
            results.insert(
                image_path.clone(),
                ReputationResult {
                    image_path: image_path.clone(),
                    sha256: Some(sha256.clone()),
                    state: LookupState::Querying,
                },
            );
        }

        aggregator.lookup_hash(&sha256)
    };

    {
        let mut results = write_or_recover(results);
        results.insert(
            image_path.clone(),
            ReputationResult {
                image_path: image_path.clone(),
                sha256: Some(sha256),
                state,
            },
        );
    }

    lock_or_recover(in_flight).remove(&image_path);
}

impl ReputationService {
    /// Create a new reputation service with background worker
    pub fn new(
        hash_computer: HashComputer,
        local_cache: Arc<LocalCacheProvider>,
        vt_provider: Arc<VirusTotalProvider>,
        mb_api_key: Option<String>,
        tf_api_key: Option<String>,
    ) -> Self {
        // Create individual providers
        let mb_provider = Arc::new(MalwareBazaarProvider::new(local_cache.clone(), mb_api_key));
        let tf_provider = Arc::new(ThreatFoxProvider::new(local_cache.clone(), tf_api_key));
        let vt_provider_for_thread = vt_provider.clone();

        // Create aggregator with all providers
        let providers: Vec<Arc<dyn crate::reputation::ReputationProvider>> = vec![
            vt_provider.clone(),
            mb_provider.clone(),
            tf_provider.clone(),
        ];

        let aggregator = Arc::new(AggregatorProvider::new(providers));

        let (job_tx, job_rx) = std::sync::mpsc::channel::<Job>();
        let (command_tx, command_rx) = std::sync::mpsc::channel::<ReputationCommand>();
        let results = Arc::new(RwLock::new(HashMap::new()));
        let in_flight = Arc::new(Mutex::new(HashSet::new()));

        let results_clone = results.clone();
        let in_flight_clone = in_flight.clone();
        let aggregator_clone = Arc::clone(&aggregator);
        let mb_provider_clone = Arc::clone(&mb_provider);
        let tf_provider_clone = Arc::clone(&tf_provider);
        let mb_cache = Arc::new(RwLock::new(HashMap::new()));
        let mb_in_flight = Arc::new(Mutex::new(HashSet::new()));
        let tf_cache = Arc::new(RwLock::new(HashMap::new()));
        let tf_in_flight = Arc::new(Mutex::new(HashSet::new()));
        let vt_cache = Arc::new(RwLock::new(HashMap::new()));
        let vt_in_flight = Arc::new(Mutex::new(HashSet::new()));

        let mb_cache_for_thread = Arc::clone(&mb_cache);
        let mb_in_flight_for_thread = Arc::clone(&mb_in_flight);
        let tf_cache_for_thread = Arc::clone(&tf_cache);
        let tf_in_flight_for_thread = Arc::clone(&tf_in_flight);
        let vt_cache_for_thread = Arc::clone(&vt_cache);
        let vt_in_flight_for_thread = Arc::clone(&vt_in_flight);

        // Clone hash_computer for thread
        let hash_computer_clone = hash_computer.clone();
        thread::spawn(move || {
            let drain_commands = || {
                while let Ok(command) = command_rx.try_recv() {
                    apply_update_config_command(
                        &vt_provider_for_thread,
                        &mb_provider_clone,
                        &tf_provider_clone,
                        &aggregator_clone,
                        command,
                    );
                }
            };

            // Process jobs and commands
            loop {
                // Always drain config commands promptly (even when idle)
                drain_commands();

                // Process jobs (blocking with timeout so commands can be handled while idle)
                match job_rx.recv_timeout(Duration::from_millis(200)) {
                    Ok(Job::HashAndLookup {
                        image_path,
                        lookup_enabled,
                    }) => {
                        handle_hash_and_lookup_job(
                            &results_clone,
                            &in_flight_clone,
                            &hash_computer_clone,
                            aggregator_clone.as_ref(),
                            image_path,
                            lookup_enabled,
                        );
                    }

                    Ok(Job::MbLookupHash { sha256 }) => {
                        struct InFlightRemover {
                            set: Arc<Mutex<HashSet<String>>>,
                            sha: String,
                        }
                        impl Drop for InFlightRemover {
                            fn drop(&mut self) {
                                if let Ok(mut guard) = self.set.lock() {
                                    let _ = guard.remove(&self.sha);
                                }
                            }
                        }

                        let _guard = InFlightRemover {
                            set: Arc::clone(&mb_in_flight_for_thread),
                            sha: sha256.clone(),
                        };

                        match mb_provider_clone.get_info_verbose(&sha256) {
                            Ok((sample_opt, meta)) => {
                                let mut guard = mb_cache_for_thread
                                    .write()
                                    .unwrap_or_else(|p| p.into_inner());
                                guard.insert(sha256, (sample_opt, meta));
                            }
                            Err(e) => {
                                let meta = crate::providers::MbQueryMeta {
                                    last_query: Some("get_info".to_string()),
                                    last_http_status: None,
                                    last_query_status: None,
                                    last_result_count: None,
                                    last_error_message: Some(format!("{}", e)),
                                };
                                let mut guard = mb_cache_for_thread
                                    .write()
                                    .unwrap_or_else(|p| p.into_inner());
                                guard.insert(sha256, (None, meta));
                            }
                        }
                    }

                    Ok(Job::TfLookupHash { sha256 }) => {
                        struct InFlightRemover {
                            set: Arc<Mutex<HashSet<String>>>,
                            sha: String,
                        }
                        impl Drop for InFlightRemover {
                            fn drop(&mut self) {
                                if let Ok(mut guard) = self.set.lock() {
                                    let _ = guard.remove(&self.sha);
                                }
                            }
                        }

                        let _guard = InFlightRemover {
                            set: Arc::clone(&tf_in_flight_for_thread),
                            sha: sha256.clone(),
                        };

                        match tf_provider_clone.search_hash_verbose(&sha256) {
                            Ok((iocs, meta)) => {
                                let mut guard = tf_cache_for_thread
                                    .write()
                                    .unwrap_or_else(|p| p.into_inner());
                                guard.insert(sha256, (Some(iocs), meta));
                            }
                            Err(e) => {
                                let meta = crate::providers::TfQueryMeta {
                                    last_query: Some("search_hash".to_string()),
                                    last_http_status: None,
                                    last_query_status: None,
                                    last_result_count: None,
                                    last_error_message: Some(e.to_string()),
                                };
                                let mut guard = tf_cache_for_thread
                                    .write()
                                    .unwrap_or_else(|p| p.into_inner());
                                guard.insert(sha256, (None, meta));
                            }
                        }
                    }

                    Ok(Job::VtLookupHash { sha256 }) => {
                        use crate::vt::VtQueryMeta;

                        struct InFlightRemover {
                            set: Arc<Mutex<HashSet<String>>>,
                            sha: String,
                        }
                        impl Drop for InFlightRemover {
                            fn drop(&mut self) {
                                if let Ok(mut guard) = self.set.lock() {
                                    let _ = guard.remove(&self.sha);
                                }
                            }
                        }

                        let _guard = InFlightRemover {
                            set: Arc::clone(&vt_in_flight_for_thread),
                            sha: sha256.clone(),
                        };

                        let res = vt_provider_for_thread.lookup_hash_sync(&sha256);
                        let (stats_opt, meta) = match res {
                            LookupState::Hit(stats) => {
                                let engine_count = stats.total_engines() as usize;
                                (
                                    Some(stats),
                                    VtQueryMeta {
                                        last_query: Some("lookup".to_string()),
                                        last_http_status: None,
                                        last_query_status: Some("ok".to_string()),
                                        last_result_count: Some(engine_count),
                                        last_error_message: None,
                                    },
                                )
                            }
                            LookupState::NotFound => (
                                None,
                                VtQueryMeta {
                                    last_query: Some("lookup".to_string()),
                                    last_http_status: None,
                                    last_query_status: Some("not_found".to_string()),
                                    last_result_count: Some(0),
                                    last_error_message: None,
                                },
                            ),
                            LookupState::Offline => (
                                None,
                                VtQueryMeta {
                                    last_query: Some("lookup".to_string()),
                                    last_http_status: None,
                                    last_query_status: Some("offline".to_string()),
                                    last_result_count: None,
                                    last_error_message: None,
                                },
                            ),
                            LookupState::NotConfigured => (
                                None,
                                VtQueryMeta {
                                    last_query: Some("lookup".to_string()),
                                    last_http_status: None,
                                    last_query_status: Some("not_configured".to_string()),
                                    last_result_count: None,
                                    last_error_message: None,
                                },
                            ),
                            LookupState::Error(e) => (
                                None,
                                VtQueryMeta {
                                    last_query: Some("lookup".to_string()),
                                    last_http_status: None,
                                    last_query_status: Some("error".to_string()),
                                    last_result_count: None,
                                    last_error_message: Some(e),
                                },
                            ),
                            _ => (
                                None,
                                VtQueryMeta {
                                    last_query: Some("lookup".to_string()),
                                    last_http_status: None,
                                    last_query_status: Some("unknown".to_string()),
                                    last_result_count: None,
                                    last_error_message: None,
                                },
                            ),
                        };

                        let mut guard = vt_cache_for_thread
                            .write()
                            .unwrap_or_else(|p| p.into_inner());
                        guard.insert(sha256, (stats_opt, meta));
                    }

                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // No jobs right now; loop back to drain commands.
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        });

        Self {
            job_tx,
            command_tx,
            results,
            in_flight,
            mb_provider,
            hash_computer,
            mb_cache,
            mb_in_flight,
            tf_cache,
            tf_in_flight,
            vt_cache,
            vt_in_flight,
            _local_cache: local_cache,
        }
    }

    #[cfg(test)]
    fn new_without_worker_for_tests(
        hash_computer: HashComputer,
        local_cache: Arc<LocalCacheProvider>,
    ) -> (
        Self,
        std::sync::mpsc::Receiver<Job>,
        std::sync::mpsc::Receiver<ReputationCommand>,
    ) {
        let (job_tx, job_rx) = std::sync::mpsc::channel::<Job>();
        let (command_tx, command_rx) = std::sync::mpsc::channel::<ReputationCommand>();

        let results = Arc::new(RwLock::new(HashMap::new()));
        let in_flight = Arc::new(Mutex::new(HashSet::new()));

        let mb_provider = Arc::new(MalwareBazaarProvider::new(local_cache.clone(), None));
        let mb_cache = Arc::new(RwLock::new(HashMap::new()));
        let mb_in_flight = Arc::new(Mutex::new(HashSet::new()));
        let tf_cache = Arc::new(RwLock::new(HashMap::new()));
        let tf_in_flight = Arc::new(Mutex::new(HashSet::new()));
        let vt_cache = Arc::new(RwLock::new(HashMap::new()));
        let vt_in_flight = Arc::new(Mutex::new(HashSet::new()));

        let svc = Self {
            job_tx,
            command_tx,
            results,
            in_flight,
            mb_provider,
            hash_computer,
            mb_cache,
            mb_in_flight,
            tf_cache,
            tf_in_flight,
            vt_cache,
            vt_in_flight,
            _local_cache: local_cache,
        };

        (svc, job_rx, command_rx)
    }

    /// Request hashing and optional lookup for a process image
    /// Returns true if a new job was submitted, false if skipped
    pub fn request_lookup(&self, image_path: String, lookup_enabled: bool) -> bool {
        // Check if already in-flight
        {
            let in_flight = lock_or_recover(&self.in_flight);
            if in_flight.contains(&image_path) {
                return false;
            }
        }

        // Check if result already exists and decide if re-query is needed
        {
            let results = read_or_recover(&self.results);
            if let Some(result) = results.get(&image_path) {
                // Re-query if:
                // 1. Previous state was Disabled and now lookups are enabled
                // 2. Previous state was Error/Offline (user can retry)
                let should_retry = match &result.state {
                    LookupState::Disabled if lookup_enabled => true,
                    LookupState::Error(_) => true,
                    LookupState::Offline => true,
                    _ => false,
                };

                if !should_retry {
                    return false;
                }
            }
        }

        // Mark in-flight BEFORE enqueueing to prevent race condition
        {
            let mut in_flight = lock_or_recover(&self.in_flight);
            in_flight.insert(image_path.clone());
        }

        // Insert placeholder result with Hashing state
        {
            let mut results = write_or_recover(&self.results);
            results.insert(
                image_path.clone(),
                ReputationResult {
                    image_path: image_path.clone(),
                    sha256: None,
                    state: LookupState::Hashing,
                },
            );
        }

        // Submit job
        let _ = self.job_tx.send(Job::HashAndLookup {
            image_path,
            lookup_enabled,
        });

        true
    }

    /// Request VT lookup for an already-hashed file (retry scenario)
    pub fn request_vt_lookup(&self, image_path: String, sha256: String) -> bool {
        // Check if already in-flight
        {
            let in_flight = lock_or_recover(&self.in_flight);
            if in_flight.contains(&image_path) {
                return false;
            }
        }

        // Mark in-flight
        {
            let mut in_flight = lock_or_recover(&self.in_flight);
            in_flight.insert(image_path.clone());
        }

        // Update result to Querying state
        {
            let mut results = write_or_recover(&self.results);
            results.insert(
                image_path.clone(),
                ReputationResult {
                    image_path: image_path.clone(),
                    sha256: Some(sha256),
                    state: LookupState::Querying,
                },
            );
        }

        // Submit job with lookup enabled
        let _ = self.job_tx.send(Job::HashAndLookup {
            image_path,
            lookup_enabled: true,
        });

        true
    }

    /// Get result for an image path
    pub fn get_result(&self, image_path: &str) -> Option<ReputationResult> {
        let results = read_or_recover(&self.results);
        results.get(image_path).cloned()
    }

    /// Check if a job is in-flight
    pub fn is_in_flight(&self, image_path: &str) -> bool {
        let in_flight = lock_or_recover(&self.in_flight);
        in_flight.contains(image_path)
    }

    /// Update configuration at runtime (non-blocking)
    pub fn update_config(
        &self,
        vt_api_key: Option<String>,
        mb_api_key: Option<String>,
        tf_api_key: Option<String>,
        vt_enabled: bool,
        mb_enabled: bool,
        tf_enabled: bool,
    ) {
        let _ = self.command_tx.send(ReputationCommand::UpdateConfig {
            vt_api_key,
            mb_api_key,
            tf_api_key,
            vt_enabled,
            mb_enabled,
            tf_enabled,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingProvider {
        calls: AtomicUsize,
        state: LookupState,
    }
    impl CountingProvider {
        fn new(state: LookupState) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                state,
            }
        }
        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }
    impl ReputationProvider for CountingProvider {
        fn name(&self) -> &'static str {
            "counting"
        }

        fn lookup_hash(&self, _sha256: &str) -> LookupState {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.state.clone()
        }
    }

    fn temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let unique = format!(
            "pmonnt_test_{}_{}_{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        p.push(unique);
        p
    }

    #[test]
    fn update_config_tf_key_falls_back_to_mb_key() {
        let cache_path = temp_path("cache");
        let local_cache = Arc::new(LocalCacheProvider::new(cache_path));
        let mb = MalwareBazaarProvider::new(local_cache.clone(), None);
        let tf = ThreatFoxProvider::new(local_cache, None);

        // Aggregator is only needed for enable-flag update; providers list can be empty for this test.
        let agg = AggregatorProvider::new(Vec::new());

        let vt = VirusTotalProvider::new(Arc::new(LocalCacheProvider::new(temp_path("cache_vt"))));

        apply_update_config_command(
            &vt,
            &mb,
            &tf,
            &agg,
            ReputationCommand::UpdateConfig {
                vt_api_key: None,
                mb_api_key: Some("mb_key".to_string()),
                tf_api_key: None,
                vt_enabled: true,
                mb_enabled: true,
                tf_enabled: true,
            },
        );

        assert_eq!(mb.get_api_key(), Some("mb_key".to_string()));
        assert_eq!(tf.get_api_key(), Some("mb_key".to_string()));
    }

    #[test]
    fn request_lookup_dedupes_in_flight() {
        let cache_path = temp_path("cache_req");
        let local_cache = Arc::new(LocalCacheProvider::new(cache_path));
        let (service, job_rx, _cmd_rx) =
            ReputationService::new_without_worker_for_tests(HashComputer::new(), local_cache);

        let path = "C:/fake/image.exe".to_string();
        assert!(service.request_lookup(path.clone(), true));
        assert!(!service.request_lookup(path.clone(), true));

        let queued = job_rx.try_iter().count();
        assert_eq!(queued, 1);
    }

    #[test]
    fn handle_hash_and_lookup_job_clears_in_flight_on_hash_error() {
        let results: Arc<RwLock<HashMap<String, ReputationResult>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let in_flight: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let hash_computer = HashComputer::new();
        let aggregator = CountingProvider::new(LookupState::NotFound);

        let image_path = "C:/does/not/exist.exe".to_string();
        in_flight.lock().unwrap().insert(image_path.clone());

        handle_hash_and_lookup_job(
            &results,
            &in_flight,
            &hash_computer,
            &aggregator,
            image_path.clone(),
            true,
        );

        assert!(!in_flight.lock().unwrap().contains(&image_path));
        let r = results
            .read()
            .unwrap()
            .get(&image_path)
            .cloned()
            .expect("result");
        match r.state {
            LookupState::Error(msg) => assert!(msg.starts_with("Hash error:")),
            other => panic!("unexpected state: {other:?}"),
        }
        assert!(r.sha256.is_none());
        assert_eq!(aggregator.call_count(), 0);
    }

    #[test]
    fn handle_hash_and_lookup_job_calls_aggregator_once() {
        let results: Arc<RwLock<HashMap<String, ReputationResult>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let in_flight: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let hash_computer = HashComputer::new();
        let aggregator = CountingProvider::new(LookupState::NotFound);

        let file_path = temp_path("hash_file");
        fs::write(&file_path, b"hello").unwrap();
        let image_path = file_path.to_string_lossy().to_string();
        in_flight.lock().unwrap().insert(image_path.clone());

        handle_hash_and_lookup_job(
            &results,
            &in_flight,
            &hash_computer,
            &aggregator,
            image_path.clone(),
            true,
        );

        assert_eq!(aggregator.call_count(), 1);
        assert!(!in_flight.lock().unwrap().contains(&image_path));
        let r = results
            .read()
            .unwrap()
            .get(&image_path)
            .cloned()
            .expect("result");
        assert!(matches!(r.state, LookupState::NotFound));
        assert!(r.sha256.is_some());

        let _ = fs::remove_file(&file_path);
    }

    #[test]
    fn handle_hash_and_lookup_job_sets_disabled_when_lookup_disabled() {
        let results: Arc<RwLock<HashMap<String, ReputationResult>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let in_flight: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let hash_computer = HashComputer::new();
        let aggregator = CountingProvider::new(LookupState::NotFound);

        let file_path = temp_path("hash_file_disabled");
        fs::write(&file_path, b"hello").unwrap();
        let image_path = file_path.to_string_lossy().to_string();
        in_flight.lock().unwrap().insert(image_path.clone());

        handle_hash_and_lookup_job(
            &results,
            &in_flight,
            &hash_computer,
            &aggregator,
            image_path.clone(),
            false,
        );

        assert_eq!(aggregator.call_count(), 0);
        let r = results
            .read()
            .unwrap()
            .get(&image_path)
            .cloned()
            .expect("result");
        assert!(matches!(r.state, LookupState::Disabled));
        assert!(r.sha256.is_some());

        let _ = fs::remove_file(&file_path);
    }

    // Regression test: requesting the same image twice should enqueue only one job,
    // the aggregator should be called once, and the service should store a single result
    // that satisfies both requesters (dedupe behavior).
    #[test]
    fn request_lookup_dedup_calls_provider_once_and_both_get_result() {
        let cache_path = temp_path("cache_req_2");
        let local_cache = Arc::new(LocalCacheProvider::new(cache_path));
        let (service, job_rx, _cmd_rx) =
            ReputationService::new_without_worker_for_tests(HashComputer::new(), local_cache);

        let file_path = temp_path("hash_file_dedup");
        fs::write(&file_path, b"hello").unwrap();
        let image_path = file_path.to_string_lossy().to_string();

        // First request enqueues job, second is deduped
        assert!(service.request_lookup(image_path.clone(), true));
        assert!(!service.request_lookup(image_path.clone(), true));
        assert_eq!(job_rx.try_iter().count(), 1);

        // Process the single job manually using a counting provider
        let aggregator = CountingProvider::new(LookupState::NotFound);
        handle_hash_and_lookup_job(
            &service.results,
            &service.in_flight,
            &HashComputer::new(),
            &aggregator,
            image_path.clone(),
            true,
        );

        // Provider called once and result stored for both requesters to see
        assert_eq!(aggregator.call_count(), 1);
        assert!(!service.is_in_flight(&image_path));
        let r = service.get_result(&image_path).expect("result");
        assert!(matches!(r.state, LookupState::NotFound));
        assert!(r.sha256.is_some());

        let _ = fs::remove_file(&file_path);
    }

    // Regression test: during the lookup phase the state must be set to Querying
    // before providers are invoked (so UI can reflect "Querying" state). This test
    // ensures the provider observes Querying when called.
    #[test]
    fn provider_sees_querying_state_during_lookup() {
        use std::sync::atomic::Ordering;

        struct InspectingProvider {
            calls: AtomicUsize,
            results: Arc<RwLock<HashMap<String, ReputationResult>>>,
        }
        impl InspectingProvider {
            fn new(results: Arc<RwLock<HashMap<String, ReputationResult>>>) -> Self {
                Self {
                    calls: AtomicUsize::new(0),
                    results,
                }
            }
            fn call_count(&self) -> usize {
                self.calls.load(Ordering::SeqCst)
            }
        }
        impl ReputationProvider for InspectingProvider {
            fn name(&self) -> &'static str {
                "inspecting"
            }

            fn lookup_hash(&self, sha256: &str) -> LookupState {
                self.calls.fetch_add(1, Ordering::SeqCst);

                // Provider should observe Querying state for the entry whose sha matches
                let guard = self.results.read().unwrap();
                let found = guard
                    .values()
                    .find(|r| r.sha256.as_deref() == Some(sha256))
                    .cloned();

                if let Some(r) = found {
                    assert!(matches!(r.state, LookupState::Querying));
                } else {
                    panic!("provider couldn't find matching entry in results");
                }

                LookupState::NotFound
            }
        }

        let results: Arc<RwLock<HashMap<String, ReputationResult>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let in_flight: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

        let file_path = temp_path("hash_file_inspect");
        fs::write(&file_path, b"hello").unwrap();
        let image_path = file_path.to_string_lossy().to_string();

        in_flight.lock().unwrap().insert(image_path.clone());

        let provider = InspectingProvider::new(results.clone());

        handle_hash_and_lookup_job(
            &results,
            &in_flight,
            &HashComputer::new(),
            &provider,
            image_path.clone(),
            true,
        );

        assert_eq!(provider.call_count(), 1);
        let r = results.read().unwrap().get(&image_path).cloned().unwrap();
        assert!(matches!(r.state, LookupState::NotFound));

        let _ = fs::remove_file(&file_path);
    }

    #[test]
    fn aggregator_respects_enable_flags() {
        use std::sync::atomic::Ordering;

        struct NamedCountingProvider {
            calls: AtomicUsize,
            state: LookupState,
            name_static: &'static str,
        }
        impl NamedCountingProvider {
            fn new(name: &'static str, state: LookupState) -> Self {
                Self {
                    calls: AtomicUsize::new(0),
                    state,
                    name_static: name,
                }
            }
            fn call_count(&self) -> usize {
                self.calls.load(Ordering::SeqCst)
            }
        }
        impl ReputationProvider for NamedCountingProvider {
            fn name(&self) -> &'static str {
                self.name_static
            }

            fn lookup_hash(&self, _sha256: &str) -> LookupState {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.state.clone()
            }
        }

        // Valid SHA so aggregator will attempt to query enabled providers
        let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        let vt = Arc::new(NamedCountingProvider::new("VT", LookupState::NotFound));
        let mb = Arc::new(NamedCountingProvider::new("MB", LookupState::NotFound));
        let tf = Arc::new(NamedCountingProvider::new("TF", LookupState::NotFound));

        let agg = AggregatorProvider::new(vec![vt.clone(), mb.clone(), tf.clone()]);

        // Disable VT and TF; only MB should be queried
        agg.update_provider_enabled(false, true, false);
        let _ = agg.lookup_hash(sha);

        assert_eq!(vt.call_count(), 0);
        assert_eq!(mb.call_count(), 1);
        assert_eq!(tf.call_count(), 0);
    }

    #[test]
    fn handle_hash_and_lookup_job_sets_error_on_provider_error_and_clears_in_flight() {
        struct ErrorProvider;
        impl ReputationProvider for ErrorProvider {
            fn name(&self) -> &'static str {
                "err"
            }

            fn lookup_hash(&self, _sha256: &str) -> LookupState {
                LookupState::Error("boom".to_string())
            }
        }

        let results: Arc<RwLock<HashMap<String, ReputationResult>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let in_flight: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

        let file_path = temp_path("hash_file_err");
        fs::write(&file_path, b"hello").unwrap();
        let image_path = file_path.to_string_lossy().to_string();

        in_flight.lock().unwrap().insert(image_path.clone());

        let provider = ErrorProvider;

        handle_hash_and_lookup_job(
            &results,
            &in_flight,
            &HashComputer::new(),
            &provider,
            image_path.clone(),
            true,
        );

        assert!(!in_flight.lock().unwrap().contains(&image_path));
        let r = results.read().unwrap().get(&image_path).cloned().unwrap();
        match r.state {
            LookupState::Error(msg) => assert!(
                msg.contains("boom")
                    || msg.contains("All providers failed")
                    || msg.contains("error")
            ),
            other => panic!("unexpected state: {other:?}"),
        }

        let _ = fs::remove_file(&file_path);
    }
}
