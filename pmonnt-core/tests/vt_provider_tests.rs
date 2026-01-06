//! Tests for VirusTotal provider behavior

use pmonnt_core::vt::VirusTotalProvider;
use pmonnt_core::local_cache::LocalCacheProvider;
use pmonnt_core::reputation::{LookupState, ReputationProvider};
use std::sync::Arc;
use tempfile::tempdir;

#[test]
fn test_invalid_hash_returns_error() {
    let temp = tempdir().unwrap();
    let cache = Arc::new(LocalCacheProvider::new(temp.path().join("cache.json")));
    let provider = VirusTotalProvider::new(cache);
    
    let result = provider.lookup_hash("not-valid");
    assert!(matches!(result, LookupState::Error(e) if e.contains("Invalid")));
}

#[test]
fn test_short_hash_returns_error() {
    let temp = tempdir().unwrap();
    let cache = Arc::new(LocalCacheProvider::new(temp.path().join("cache.json")));
    let provider = VirusTotalProvider::new(cache);
    
    let result = provider.lookup_hash("deadbeef");
    assert!(matches!(result, LookupState::Error(_)));
}

#[test]
fn test_no_api_key_returns_not_configured() {
    let temp = tempdir().unwrap();
    let cache = Arc::new(LocalCacheProvider::new(temp.path().join("cache.json")));
    let provider = VirusTotalProvider::new(cache);
    // Ensure no API key is set
    provider.set_api_key(String::new());
    
    let result = provider.lookup_hash(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert!(matches!(result, LookupState::NotConfigured));
}

#[test]
fn test_set_api_key_persists() {
    let temp = tempdir().unwrap();
    let cache = Arc::new(LocalCacheProvider::new(temp.path().join("cache.json")));
    let provider = VirusTotalProvider::new(cache);
    
    provider.set_api_key("test_key_12345".to_string());
    assert_eq!(provider.get_api_key(), Some("test_key_12345".to_string()));
}

#[test]
fn test_empty_api_key_clears_config() {
    let temp = tempdir().unwrap();
    let cache = Arc::new(LocalCacheProvider::new(temp.path().join("cache.json")));
    let provider = VirusTotalProvider::new(cache);
    
    provider.set_api_key("initial_key".to_string());
    provider.set_api_key(String::new());
    assert!(provider.get_api_key().is_none());
}

#[test]
fn test_valid_hash_format_accepted() {
    let temp = tempdir().unwrap();
    let cache = Arc::new(LocalCacheProvider::new(temp.path().join("cache.json")));
    let provider = VirusTotalProvider::new(cache);
    provider.set_api_key(String::new()); // No key -> NotConfigured
    
    // This is a valid SHA256, should not return error about invalid format
    let result = provider.lookup_hash(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    // Should be NotConfigured, not an error about hash format
    assert!(matches!(result, LookupState::NotConfigured));
}

#[test]
fn test_uppercase_hash_accepted() {
    let temp = tempdir().unwrap();
    let cache = Arc::new(LocalCacheProvider::new(temp.path().join("cache.json")));
    let provider = VirusTotalProvider::new(cache);
    provider.set_api_key(String::new());
    
    let result = provider.lookup_hash(
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    );
    assert!(matches!(result, LookupState::NotConfigured));
}

#[test]
fn test_mixed_case_hash_accepted() {
    let temp = tempdir().unwrap();
    let cache = Arc::new(LocalCacheProvider::new(temp.path().join("cache.json")));
    let provider = VirusTotalProvider::new(cache);
    provider.set_api_key(String::new());
    
    let result = provider.lookup_hash(
        "E3b0c44298FC1c149AfBf4C8996fb92427Ae41E4649b934cA495991b7852B855"
    );
    assert!(matches!(result, LookupState::NotConfigured));
}

#[test]
fn test_hash_with_non_hex_chars_returns_error() {
    let temp = tempdir().unwrap();
    let cache = Arc::new(LocalCacheProvider::new(temp.path().join("cache.json")));
    let provider = VirusTotalProvider::new(cache);
    
    let result = provider.lookup_hash(
        "g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert!(matches!(result, LookupState::Error(_)));
}

#[test]
fn test_api_key_updates_multiple_times() {
    let temp = tempdir().unwrap();
    let cache = Arc::new(LocalCacheProvider::new(temp.path().join("cache.json")));
    let provider = VirusTotalProvider::new(cache);
    
    provider.set_api_key("key1".to_string());
    assert_eq!(provider.get_api_key(), Some("key1".to_string()));
    
    provider.set_api_key("key2".to_string());
    assert_eq!(provider.get_api_key(), Some("key2".to_string()));
    
    provider.set_api_key("key3".to_string());
    assert_eq!(provider.get_api_key(), Some("key3".to_string()));
}
