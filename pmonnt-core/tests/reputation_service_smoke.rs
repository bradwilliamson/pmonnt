use std::sync::Arc;
use std::time::{Duration, Instant};

use pmonnt_core::hashing::HashComputer;
use pmonnt_core::local_cache::LocalCacheProvider;
use pmonnt_core::reputation::LookupState;
use pmonnt_core::reputation_service::ReputationService;
use pmonnt_core::vt::VirusTotalProvider;

fn wait_for_terminal_state(svc: &ReputationService, path: &str, timeout: Duration) -> LookupState {
    let start = Instant::now();
    loop {
        if let Some(r) = svc.get_result(path) {
            match r.state.clone() {
                LookupState::Hashing | LookupState::Querying => {}
                other => return other,
            }
        }
        if start.elapsed() > timeout {
            panic!("timed out waiting for result");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn request_lookup_dedupes_in_flight_and_completes_offline_when_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("cache.json");
    let local_cache = Arc::new(LocalCacheProvider::new(cache_path));

    let vt = Arc::new(VirusTotalProvider::new(local_cache.clone()));
    let svc = ReputationService::new(HashComputer::new(), local_cache, vt, None, None);

    let target_file = dir.path().join("sample.bin");
    std::fs::write(&target_file, b"hello").unwrap();
    let target_path = target_file.to_string_lossy().to_string();

    assert!(svc.request_lookup(target_path.clone(), false));
    assert!(!svc.request_lookup(target_path.clone(), false));

    let state = wait_for_terminal_state(&svc, &target_path, Duration::from_secs(3));
    assert!(matches!(state, LookupState::Disabled));

    // Once complete, a second request with the same params should not re-run.
    assert!(!svc.request_lookup(target_path.clone(), false));
}

#[test]
fn request_lookup_allows_retry_after_hash_error() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("cache.json");
    let local_cache = Arc::new(LocalCacheProvider::new(cache_path));

    let vt = Arc::new(VirusTotalProvider::new(local_cache.clone()));
    let svc = ReputationService::new(HashComputer::new(), local_cache, vt, None, None);

    let missing_path = dir.path().join("does_not_exist.exe");
    let missing_str = missing_path.to_string_lossy().to_string();

    assert!(svc.request_lookup(missing_str.clone(), false));
    let state = wait_for_terminal_state(&svc, &missing_str, Duration::from_secs(3));
    assert!(matches!(state, LookupState::Error(_)));

    // Error states are retryable.
    assert!(svc.request_lookup(missing_str.clone(), false));
}

#[test]
fn update_config_can_disable_all_providers_for_offline_notfound() {
    let dir = tempfile::tempdir().unwrap();
    let cache_path = dir.path().join("cache.json");
    let local_cache = Arc::new(LocalCacheProvider::new(cache_path));

    let vt = Arc::new(VirusTotalProvider::new(local_cache.clone()));
    let svc = ReputationService::new(HashComputer::new(), local_cache, vt, None, None);

    // Disable all providers so lookups don't attempt network.
    svc.update_config(
        Some("supersecret".to_string()),
        Some("mbsecret".to_string()),
        Some("tfsecret".to_string()),
        false,
        false,
        false,
    );

    // Give worker a moment to drain the command channel.
    std::thread::sleep(Duration::from_millis(300));

    let target_file = dir.path().join("sample2.bin");
    std::fs::write(&target_file, b"hello2").unwrap();
    let target_path = target_file.to_string_lossy().to_string();

    assert!(svc.request_lookup(target_path.clone(), true));
    let state = wait_for_terminal_state(&svc, &target_path, Duration::from_secs(3));

    // With all providers disabled, aggregator returns NotFound deterministically.
    assert!(matches!(state, LookupState::NotFound));
}
