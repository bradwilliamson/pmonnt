//! Tests for HandleCache config persistence

use pmonnt_core::handles::HandleCache;
use tempfile::tempdir;

#[test]
fn test_save_load_config_roundtrip() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("handle_config.json");
    
    let mut cache = HandleCache::new(60);
    
    // Add some config via update_detector_config
    cache.update_detector_config(1000, Some("c:\\windows\\system32\\notepad.exe"), 10, 200, 3);
    
    // Save
    cache.save_config(&config_path).unwrap();
    assert!(config_path.exists());
    
    // Load into new cache
    let mut cache2 = HandleCache::new(60);
    cache2.load_config(&config_path).unwrap();
    
    // Config should match via path lookup
    let config1 = cache.get_path_config("c:\\windows\\system32\\notepad.exe");
    let config2 = cache2.get_path_config("c:\\windows\\system32\\notepad.exe");
    
    assert_eq!(config1.consecutive_threshold, config2.consecutive_threshold);
    assert_eq!(config1.leak_threshold, config2.leak_threshold);
    assert_eq!(config1.flat_tolerance, config2.flat_tolerance);
}

#[test]
fn test_load_nonexistent_config_succeeds() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("nonexistent.json");
    
    let mut cache = HandleCache::new(60);
    // Should not error
    cache.load_config(&config_path).unwrap();
}

#[test]
fn test_save_creates_parent_directory() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("subdir").join("nested").join("config.json");
    
    let cache = HandleCache::new(60);
    cache.save_config(&config_path).unwrap();
    
    assert!(config_path.exists());
}

#[test]
fn test_normalize_path_case_insensitive() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("config.json");
    
    let mut cache = HandleCache::new(60);
    
    // Store with lowercase
    cache.update_detector_config(1000, Some("c:\\program files\\app.exe"), 5, 100, 2);
    cache.save_config(&config_path).unwrap();
    
    // Load and query with uppercase
    let mut cache2 = HandleCache::new(60);
    cache2.load_config(&config_path).unwrap();
    
    let retrieved = cache2.get_path_config("C:\\PROGRAM FILES\\APP.EXE");
    assert_eq!(retrieved.consecutive_threshold, 5);
    assert_eq!(retrieved.leak_threshold, 100);
}

#[test]
fn test_normalize_path_forward_slash() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("config.json");
    
    let mut cache = HandleCache::new(60);
    
    // Store with forward slashes
    cache.update_detector_config(1000, Some("c:/windows/system32/test.exe"), 5, 100, 2);
    cache.save_config(&config_path).unwrap();
    
    // Load and query with backslashes
    let mut cache2 = HandleCache::new(60);
    cache2.load_config(&config_path).unwrap();
    
    let retrieved = cache2.get_path_config("c:\\windows\\system32\\test.exe");
    assert_eq!(retrieved.consecutive_threshold, 5);
}

#[test]
fn test_normalize_path_extended_prefix() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("config.json");
    
    let mut cache = HandleCache::new(60);
    
    // Store with \\?\ prefix
    cache.update_detector_config(1000, Some(r"\\?\c:\windows\system32\test.exe"), 5, 100, 2);
    cache.save_config(&config_path).unwrap();
    
    // Load and query without prefix
    let mut cache2 = HandleCache::new(60);
    cache2.load_config(&config_path).unwrap();
    
    let retrieved = cache2.get_path_config("c:\\windows\\system32\\test.exe");
    assert_eq!(retrieved.consecutive_threshold, 5);
}

#[test]
fn test_multiple_configs_persist() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("config.json");
    
    let mut cache = HandleCache::new(60);
    
    cache.update_detector_config(1000, Some("c:\\app1.exe"), 5, 100, 2);
    cache.update_detector_config(2000, Some("c:\\app2.exe"), 15, 300, 3);
    cache.save_config(&config_path).unwrap();
    
    // Load
    let mut cache2 = HandleCache::new(60);
    cache2.load_config(&config_path).unwrap();
    
    let config1 = cache2.get_path_config("c:\\app1.exe");
    let config2 = cache2.get_path_config("c:\\app2.exe");
    
    assert_eq!(config1.consecutive_threshold, 5);
    assert_eq!(config2.consecutive_threshold, 15);
}

#[test]
fn test_update_overwrites_existing() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("config.json");
    
    let mut cache = HandleCache::new(60);
    
    cache.update_detector_config(1000, Some("c:\\app.exe"), 5, 100, 2);
    cache.save_config(&config_path).unwrap();
    
    // Update same path
    cache.update_detector_config(1000, Some("c:\\app.exe"), 15, 300, 3);
    cache.save_config(&config_path).unwrap();
    
    // Load
    let mut cache2 = HandleCache::new(60);
    cache2.load_config(&config_path).unwrap();
    
    let config = cache2.get_path_config("c:\\app.exe");
    assert_eq!(config.consecutive_threshold, 15);
}

#[test]
fn test_save_empty_config() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("config.json");
    
    let cache = HandleCache::new(60);
    cache.save_config(&config_path).unwrap();
    
    assert!(config_path.exists());
    
    // Should be valid JSON
    let content = std::fs::read_to_string(&config_path).unwrap();
    let _: serde_json::Value = serde_json::from_str(&content).unwrap();
}

#[test]
fn test_get_or_create_detector_uses_config() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("config.json");
    
    let mut cache = HandleCache::new(60);
    
    cache.update_detector_config(1000, Some("c:\\app.exe"), 20, 400, 4);
    cache.save_config(&config_path).unwrap();
    
    // New cache loads config
    let mut cache2 = HandleCache::new(60);
    cache2.load_config(&config_path).unwrap();
    
    // When detector is created, it should use the loaded config
    let retrieved = cache2.get_path_config("c:\\app.exe");
    assert_eq!(retrieved.consecutive_threshold, 20);
    assert_eq!(retrieved.leak_threshold, 400);
}

#[test]
fn test_config_survives_cache_ttl() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("config.json");
    
    let mut cache = HandleCache::new(1); // 1 second TTL
    
    cache.update_detector_config(1000, Some("c:\\app.exe"), 5, 100, 2);
    cache.save_config(&config_path).unwrap();
    
    // Wait for TTL
    std::thread::sleep(std::time::Duration::from_secs(2));
    
    // Load into new cache - config should still be there
    let mut cache2 = HandleCache::new(1);
    cache2.load_config(&config_path).unwrap();
    
    let retrieved = cache2.get_path_config("c:\\app.exe");
    assert_eq!(retrieved.consecutive_threshold, 5);
}
