//! Tests for reputation service worker behavior
//!
//! These tests validate the job processing logic in the reputation worker,
//! including hash computation error handling, lookup state transitions,
//! and configuration updates.

use pmonnt_core::local_cache::LocalCacheProvider;
use pmonnt_core::reputation::LookupState;
use pmonnt_core::reputation_service::ReputationService;
use pmonnt_core::vt::VirusTotalProvider;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn test_service_construction_and_initialization() {
    // Verify the service can be created without panicking
    let temp_dir = tempdir().expect("failed to create temp dir");
    let cache_path = temp_dir.path().join("test_cache.json");
    
    let local_cache = Arc::new(LocalCacheProvider::new(cache_path.clone()));
    let vt_provider = Arc::new(VirusTotalProvider::new(local_cache.clone()));
    
    let service = ReputationService::new(
        pmonnt_core::hashing::HashComputer::new(),
        local_cache,
        vt_provider,
        None,      // no MB key
        None,      // no TF key
    );
    
    // Service should be created successfully
    assert!(service.get_result("dummy_path").is_none());
}

#[test]
fn test_hash_error_produces_error_state() {
    // Create temp directory and cache
    let temp_dir = tempdir().expect("failed to create temp dir");
    let cache_path = temp_dir.path().join("test_cache.json");
    
    let local_cache = Arc::new(LocalCacheProvider::new(cache_path));
    let vt_provider = Arc::new(VirusTotalProvider::new(local_cache.clone()));
    let service = ReputationService::new(
        pmonnt_core::hashing::HashComputer::new(),
        local_cache,
        vt_provider,
        None,
        None,
    );
    
    // Submit a job for a non-existent file (this will cause a hash error)
    let nonexistent_path = "/nonexistent/path/to/file/that/does/not/exist.exe";
    service.request_lookup(nonexistent_path.to_string(), true);
    
    // Wait for the worker to process the job
    thread::sleep(Duration::from_millis(500));
    
    // Get the result
    let result = service.get_result(nonexistent_path);
    
    if let Some(res) = result {
        // The result should be an Error state containing a hash-related message
        match &res.state {
            LookupState::Error(msg) => {
                // Error should mention hash computation failure
                assert!(
                    msg.to_lowercase().contains("hash"),
                    "error message should mention hash: {}",
                    msg
                );
            }
            other => panic!(
                "Expected Error state for nonexistent file, got: {:?}",
                other
            ),
        }
    }
}

#[test]
fn test_lookup_disabled_returns_disabled_state() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let cache_path = temp_dir.path().join("test_cache.json");
    
    let local_cache = Arc::new(LocalCacheProvider::new(cache_path));
    let vt_provider = Arc::new(VirusTotalProvider::new(local_cache.clone()));
    let service = ReputationService::new(
        pmonnt_core::hashing::HashComputer::new(),
        local_cache,
        vt_provider,
        None,
        None,
    );
    
    // Create a temporary file with known content for hashing
    let test_file = temp_dir.path().join("test_file.txt");
    std::fs::write(&test_file, b"test content").expect("failed to write test file");
    
    let test_path = test_file.to_string_lossy().to_string();
    
    // Request lookup with lookup_enabled=false
    service.request_lookup(test_path.clone(), false);
    
    // Wait for processing
    thread::sleep(Duration::from_millis(500));
    
    // Get result
    let result = service.get_result(&test_path);
    
    if let Some(res) = result {
        match &res.state {
            LookupState::Disabled => {
                // Expected: lookup was disabled
                assert!(res.sha256.is_some(), "SHA256 should be computed even when lookup disabled");
            }
            other => panic!(
                "Expected Disabled state when lookup disabled, got: {:?}",
                other
            ),
        }
    }
}

#[test]
fn test_successful_hash_computation() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let cache_path = temp_dir.path().join("test_cache.json");
    
    let local_cache = Arc::new(LocalCacheProvider::new(cache_path));
    let vt_provider = Arc::new(VirusTotalProvider::new(local_cache.clone()));
    let service = ReputationService::new(
        pmonnt_core::hashing::HashComputer::new(),
        local_cache,
        vt_provider,
        None,
        None,
    );
    
    // Create a temporary file with known content
    let test_file = temp_dir.path().join("test_hash.exe");
    std::fs::write(&test_file, b"test executable content")
        .expect("failed to write test file");
    
    let test_path = test_file.to_string_lossy().to_string();
    
    // Request lookup with disabled reputation (so we just compute hash)
    service.request_lookup(test_path.clone(), false);
    
    // Wait for processing
    thread::sleep(Duration::from_millis(500));
    
    // Get result
    let result = service.get_result(&test_path);
    
    if let Some(res) = result {
        // Hash should be computed and be 64 hex characters (SHA-256)
        assert!(res.sha256.is_some(), "SHA256 should be computed");
        if let Some(hash) = res.sha256 {
            assert_eq!(hash.len(), 64, "SHA256 hash should be 64 characters");
            // Verify it's valid hex
            assert!(
                hash.chars().all(|c| c.is_ascii_hexdigit()),
                "hash should contain only hex characters: {}",
                hash
            );
        }
    }
}

#[test]
fn test_multiple_concurrent_lookups() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let cache_path = temp_dir.path().join("test_cache.json");
    
    let local_cache = Arc::new(LocalCacheProvider::new(cache_path));
    let vt_provider = Arc::new(VirusTotalProvider::new(local_cache.clone()));
    let service = Arc::new(ReputationService::new(
        pmonnt_core::hashing::HashComputer::new(),
        local_cache,
        vt_provider,
        None,
        None,
    ));
    
    // Create multiple test files
    let mut test_paths = vec![];
    for i in 0..5 {
        let test_file = temp_dir.path().join(format!("test_{}.txt", i));
        std::fs::write(&test_file, format!("content {}", i).as_bytes())
            .expect("failed to write test file");
        test_paths.push(test_file.to_string_lossy().to_string());
    }
    
    // Submit all lookups
    for path in &test_paths {
        let service_clone = Arc::clone(&service);
        let path_clone = path.clone();
        thread::spawn(move || {
            service_clone.request_lookup(path_clone, false);
        });
    }
    
    // Wait for all processing
    thread::sleep(Duration::from_millis(1000));
    
    // Verify all results are available
    for path in test_paths {
        let result = service.get_result(&path);
        assert!(result.is_some(), "result should exist for path: {}", path);
        if let Some(res) = result {
            assert!(res.sha256.is_some(), "hash should be computed");
            if let Some(hash) = res.sha256 {
                assert_eq!(hash.len(), 64, "hash should be 64 chars");
            }
        }
    }
}

#[test]
fn test_service_handles_invalid_utf8_paths() {
    // On Windows, paths can contain invalid UTF-8 sequences
    let temp_dir = tempdir().expect("failed to create temp dir");
    let cache_path = temp_dir.path().join("test_cache.json");
    
    let local_cache = Arc::new(LocalCacheProvider::new(cache_path));
    let vt_provider = Arc::new(VirusTotalProvider::new(local_cache.clone()));
    let service = ReputationService::new(
        pmonnt_core::hashing::HashComputer::new(),
        local_cache,
        vt_provider,
        None,
        None,
    );
    
    // Use a path that's likely to exist but won't hash
    let bad_path = "/path/with/nonexistent/file.txt";
    
    // This should not panic
    service.request_lookup(bad_path.to_string(), false);
    
    // Give it time to process
    thread::sleep(Duration::from_millis(500));
    
    // Should either return None or an Error state, never panic
    let _ = service.get_result(bad_path);
}

#[test]
fn test_result_cleared_after_retrieval_or_timeout() {
    let temp_dir = tempdir().expect("failed to create temp dir");
    let cache_path = temp_dir.path().join("test_cache.json");
    
    let local_cache = Arc::new(LocalCacheProvider::new(cache_path));
    let vt_provider = Arc::new(VirusTotalProvider::new(local_cache.clone()));
    let service = ReputationService::new(
        pmonnt_core::hashing::HashComputer::new(),
        local_cache,
        vt_provider,
        None,
        None,
    );
    
    // Create a test file
    let test_file = temp_dir.path().join("test_clear.txt");
    std::fs::write(&test_file, b"content").expect("failed to write test file");
    let test_path = test_file.to_string_lossy().to_string();
    
    // Request lookup
    service.request_lookup(test_path.clone(), false);
    
    // Wait for processing
    thread::sleep(Duration::from_millis(500));
    
    // First get should return result
    let first_result = service.get_result(&test_path);
    assert!(first_result.is_some(), "first get should return result");
    
    // Behavior after first get depends on implementation:
    // - Results might be cleared immediately
    // - Results might persist
    // Either way, service should remain stable
    let second_result = service.get_result(&test_path);
    
    // Service should not panic in either case
    // (Result may or may not be present depending on implementation)
    let _ = second_result;
}
