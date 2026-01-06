//! Comprehensive HandleCache feature tests
//! Tests the persistence, leak detection, and type-history features

use pmonnt_core::handles::{HandleCache, HandleSummary};
use std::collections::HashMap;
use tempfile::tempdir;

// ============================================================================
// Config Persistence & Path Normalization Tests
// ============================================================================

#[test]
fn test_update_detector_config_persists_by_path() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("config.json");

    let mut cache = HandleCache::new(60);

    // Update config for a specific image path
    cache.update_detector_config(1000, Some("c:\\windows\\system32\\notepad.exe"), 15, 300, 3);

    // Save to disk
    cache.save_config(&config_path).unwrap();

    // Load into new cache
    let mut cache2 = HandleCache::new(60);
    cache2.load_config(&config_path).unwrap();

    // Verify config is loaded for that path
    let config = cache2.get_path_config("c:\\windows\\system32\\notepad.exe");
    assert_eq!(config.consecutive_threshold, 15);
    assert_eq!(config.leak_threshold, 300);
    assert_eq!(config.flat_tolerance, 3);
}

#[test]
fn test_path_normalization_case_insensitive() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("config.json");

    let mut cache = HandleCache::new(60);

    // Store with lowercase
    cache.update_detector_config(1000, Some("c:\\program files\\app.exe"), 10, 150, 2);
    cache.save_config(&config_path).unwrap();

    // Load and query with different casing
    let mut cache2 = HandleCache::new(60);
    cache2.load_config(&config_path).unwrap();

    let config1 = cache2.get_path_config("C:\\PROGRAM FILES\\APP.EXE");
    let config2 = cache2.get_path_config("c:\\Program Files\\App.exe");
    let config3 = cache2.get_path_config("c:\\program files\\app.exe");

    // All should return same config
    assert_eq!(config1.consecutive_threshold, 10);
    assert_eq!(config2.consecutive_threshold, 10);
    assert_eq!(config3.consecutive_threshold, 10);
}

#[test]
fn test_path_normalization_forward_slash() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("config.json");

    let mut cache = HandleCache::new(60);

    // Store with forward slashes
    cache.update_detector_config(1000, Some("c:/windows/system32/test.exe"), 12, 250, 1);
    cache.save_config(&config_path).unwrap();

    // Load and query with backslashes
    let mut cache2 = HandleCache::new(60);
    cache2.load_config(&config_path).unwrap();

    let config = cache2.get_path_config("c:\\windows\\system32\\test.exe");
    assert_eq!(config.consecutive_threshold, 12);
}

#[test]
fn test_path_normalization_extended_prefix() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("config.json");

    let mut cache = HandleCache::new(60);

    // Store with \\?\\ prefix
    cache.update_detector_config(1000, Some(r"\\?\c:\windows\test.exe"), 8, 120, 1);
    cache.save_config(&config_path).unwrap();

    // Load and query without prefix
    let mut cache2 = HandleCache::new(60);
    cache2.load_config(&config_path).unwrap();

    let config = cache2.get_path_config("c:\\windows\\test.exe");
    assert_eq!(config.consecutive_threshold, 8);
}

#[test]
fn test_save_config_creates_parent_directory() {
    let temp = tempdir().unwrap();
    let nested_path = temp.path().join("subdir").join("nested").join("config.json");

    let mut cache = HandleCache::new(60);
    cache.update_detector_config(1000, Some("c:\\test.exe"), 5, 100, 2);

    // Should create all parent directories
    cache.save_config(&nested_path).unwrap();

    assert!(nested_path.exists());
}

#[test]
fn test_save_config_atomic_write() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("config.json");

    let mut cache = HandleCache::new(60);
    cache.update_detector_config(1000, Some("c:\\app1.exe"), 5, 100, 2);
    cache.save_config(&config_path).unwrap();

    // Overwrite with new config
    cache.update_detector_config(2000, Some("c:\\app2.exe"), 10, 200, 3);
    cache.save_config(&config_path).unwrap();

    // Load should get the second config
    let mut cache2 = HandleCache::new(60);
    cache2.load_config(&config_path).unwrap();

    let config1 = cache2.get_path_config("c:\\app1.exe");
    let config2 = cache2.get_path_config("c:\\app2.exe");

    assert_eq!(config1.consecutive_threshold, 5);
    assert_eq!(config2.consecutive_threshold, 10);
}

#[test]
fn test_load_config_missing_file() {
    let temp = tempdir().unwrap();
    let nonexistent = temp.path().join("does_not_exist.json");

    let mut cache = HandleCache::new(60);
    // Should succeed (no-op for missing file)
    cache.load_config(&nonexistent).unwrap();
}

#[test]
fn test_load_config_invalid_json() {
    let temp = tempdir().unwrap();
    let bad_json_path = temp.path().join("bad.json");
    std::fs::write(&bad_json_path, "not valid json {[}").unwrap();

    let mut cache = HandleCache::new(60);
    // Should return error for invalid JSON
    let result = cache.load_config(&bad_json_path);
    assert!(result.is_err());
}

// ============================================================================
// update_with_paths Tests (Config → Detector Wiring)
// ============================================================================

#[test]
fn test_update_with_paths_applies_config_to_detector() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("config.json");

    let mut cache = HandleCache::new(60);

    // Configure a more sensitive detector for notepad.exe
    cache.update_detector_config(0, Some("c:\\windows\\notepad.exe"), 5, 50, 1);
    cache.save_config(&config_path).unwrap();

    // New cache loads config
    let mut cache2 = HandleCache::new(60);
    cache2.load_config(&config_path).unwrap();

    // Create summaries with PID → path mapping
    let mut summaries = HashMap::new();
    summaries.insert(
        1234,
        HandleSummary {
            total: 100,
            by_type: Vec::new(), timestamp: std::time::Instant::now(),
        },
    );

    let mut pid_to_path = HashMap::new();
    pid_to_path.insert(1234, "c:\\windows\\notepad.exe".to_string());

    // Update with paths - should wire config to detector
    cache2.update_with_paths(summaries, &pid_to_path);

    // Verify detector got the custom config
    let (consecutive, delta, flat) = cache2.get_detector_config(1234);
    assert_eq!(consecutive, 5);
    assert_eq!(delta, 50);
    assert_eq!(flat, 1);
}

#[test]
fn test_update_with_paths_defaults_without_config() {
    let mut cache = HandleCache::new(60);

    // No config loaded
    let mut summaries = HashMap::new();
    summaries.insert(
        5678,
        HandleSummary {
            total: 50,
            by_type: Vec::new(), timestamp: std::time::Instant::now(),
        },
    );

    let mut pid_to_path = HashMap::new();
    pid_to_path.insert(5678, "c:\\unknown.exe".to_string());

    cache.update_with_paths(summaries, &pid_to_path);

    // Should use defaults (20, 200, 2)
    let (consecutive, delta, flat) = cache.get_detector_config(5678);
    assert_eq!(consecutive, 20);
    assert_eq!(delta, 200);
    assert_eq!(flat, 2);
}

// ============================================================================
// Leak Detection Tests (is_leaking, get_delta, reset_detector)
// ============================================================================

#[test]
fn test_is_leaking_detects_sustained_increase() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("config.json");

    let mut cache = HandleCache::new(60);

    // Configure very sensitive detector (3 samples, 10 handle delta, 0 flats)
    cache.update_detector_config(1000, Some("c:\\test.exe"), 3, 10, 0);
    cache.save_config(&config_path).unwrap();

    // Reload
    let mut cache2 = HandleCache::new(60);
    cache2.load_config(&config_path).unwrap();

    let mut pid_to_path = HashMap::new();
    pid_to_path.insert(1000, "c:\\test.exe".to_string());

    // Feed increasing samples
    for count in [100, 105, 110, 115].iter() {
        let mut summaries = HashMap::new();
        summaries.insert(
            1000,
            HandleSummary {
                total: *count,
                by_type: Vec::new(), timestamp: std::time::Instant::now(),
            },
        );
        cache2.update_with_paths(summaries, &pid_to_path);
    }

    // Should be leaking now (3+ consecutive increases, 15 delta > 10 threshold)
    assert!(cache2.is_leaking(1000));
}

#[test]
fn test_is_leaking_false_before_threshold() {
    let mut cache = HandleCache::new(60);

    cache.update_detector_config(1000, Some("c:\\test.exe"), 5, 20, 0);

    let mut pid_to_path = HashMap::new();
    pid_to_path.insert(1000, "c:\\test.exe".to_string());

    // Feed only 3 samples (threshold is 5)
    for count in [100, 105, 110].iter() {
        let mut summaries = HashMap::new();
        summaries.insert(
            1000,
            HandleSummary {
                total: *count,
                by_type: Vec::new(), timestamp: std::time::Instant::now(),
            },
        );
        cache.update_with_paths(summaries, &pid_to_path);
    }

    // Should NOT be leaking yet
    assert!(!cache.is_leaking(1000));
}

#[test]
fn test_get_delta_returns_handle_difference() {
    let mut cache = HandleCache::new(60);

    let mut pid_to_path = HashMap::new();
    pid_to_path.insert(2000, "c:\\app.exe".to_string());

    // First sample: 100 handles
    let mut summaries = HashMap::new();
    summaries.insert(
        2000,
        HandleSummary {
            total: 100,
            by_type: Vec::new(), timestamp: std::time::Instant::now(),
        },
    );
    cache.update_with_paths(summaries.clone(), &pid_to_path);

    // Second sample: 125 handles
    summaries.insert(
        2000,
        HandleSummary {
            total: 125,
            by_type: Vec::new(), timestamp: std::time::Instant::now(),
        },
    );
    cache.update_with_paths(summaries, &pid_to_path);

    // Delta should be 25
    let delta = cache.get_delta(2000);
    assert_eq!(delta, Some(25));
}

#[test]
fn test_get_leak_explanation_returns_metrics() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("config.json");

    let mut cache = HandleCache::new(60);
    cache.update_detector_config(3000, Some("c:\\leaky.exe"), 3, 10, 0);
    cache.save_config(&config_path).unwrap();

    let mut cache2 = HandleCache::new(60);
    cache2.load_config(&config_path).unwrap();

    let mut pid_to_path = HashMap::new();
    pid_to_path.insert(3000, "c:\\leaky.exe".to_string());

    // Feed leak pattern
    for count in [100, 110, 120, 130].iter() {
        let mut summaries = HashMap::new();
        summaries.insert(
            3000,
            HandleSummary {
                total: *count,
                by_type: Vec::new(), timestamp: std::time::Instant::now(),
            },
        );
        cache2.update_with_paths(summaries, &pid_to_path);
    }

    // Should have explanation (window_len, leak_delta, flats_used)
    let explanation = cache2.get_leak_explanation(3000);
    assert!(explanation.is_some());

    let (window_len, delta, flats_used) = explanation.unwrap();
    assert!(window_len >= 3); // At least threshold samples
    assert!(delta >= 10); // Above leak threshold (started at 100, now 130 = +30)
    assert_eq!(flats_used, 0); // No flats in our pattern
}

#[test]
fn test_reset_detector_clears_leak_state() {
    let mut cache = HandleCache::new(60);
    cache.update_detector_config(4000, Some("c:\\test.exe"), 2, 5, 0);

    let mut pid_to_path = HashMap::new();
    pid_to_path.insert(4000, "c:\\test.exe".to_string());

    // Feed leak pattern
    for count in [100, 110, 120].iter() {
        let mut summaries = HashMap::new();
        summaries.insert(
            4000,
            HandleSummary {
                total: *count,
                by_type: Vec::new(), timestamp: std::time::Instant::now(),
            },
        );
        cache.update_with_paths(summaries, &pid_to_path);
    }

    // Should be leaking
    assert!(cache.is_leaking(4000));

    // Reset
    cache.reset_detector(4000);

    // Should no longer be leaking
    assert!(!cache.is_leaking(4000));
}

// ============================================================================
// Type History Tests (update_type_history, get_top_growing_types)
// ============================================================================

#[test]
fn test_update_type_history_tracks_growth() {
    let mut cache = HandleCache::new(60);

    // Simulate 3 samples for PID 5000
    let mut sample1 = HashMap::new();
    sample1.insert(1u16, 10u32); // Type 1: 10 handles
    sample1.insert(2u16, 20u32); // Type 2: 20 handles

    let mut sample2 = HashMap::new();
    sample2.insert(1u16, 15u32); // Type 1: +5
    sample2.insert(2u16, 25u32); // Type 2: +5

    let mut sample3 = HashMap::new();
    sample3.insert(1u16, 25u32); // Type 1: +10 more (total +15 from start)
    sample3.insert(2u16, 30u32); // Type 2: +5 more (total +10 from start)

    let mut pid_data = HashMap::new();
    pid_data.insert(5000u32, sample1);
    cache.update_type_history(&pid_data);

    pid_data.clear();
    pid_data.insert(5000u32, sample2);
    cache.update_type_history(&pid_data);

    pid_data.clear();
    pid_data.insert(5000u32, sample3);
    cache.update_type_history(&pid_data);

    // Check growth
    let growing = cache.get_top_growing_types(5000).unwrap();

    // Should show Type 1: +15, Type 2: +10
    assert_eq!(growing.len(), 2);
    assert_eq!(growing[0].0, 1); // Type 1 first (larger delta)
    assert_eq!(growing[0].1, 15); // Delta of 15
    assert_eq!(growing[1].0, 2); // Type 2 second
    assert_eq!(growing[1].1, 10); // Delta of 10
}

#[test]
fn test_get_top_growing_types_respects_cap() {
    let mut cache = HandleCache::new(60);

    // Create 10 types, all growing
    let mut sample1 = HashMap::new();
    let mut sample2 = HashMap::new();
    for i in 1u16..=10u16 {
        sample1.insert(i, 10u32);
        sample2.insert(i, 10 + (i as u32) * 5); // Each type grows by different amount
    }

    let mut pid_data = HashMap::new();
    pid_data.insert(6000u32, sample1);
    cache.update_type_history(&pid_data);

    pid_data.clear();
    pid_data.insert(6000u32, sample2);
    cache.update_type_history(&pid_data);

    // Should return max 6 types (TOP_K constant)
    let growing = cache.get_top_growing_types(6000).unwrap();
    assert!(growing.len() <= 6);

    // Should be sorted by delta descending
    for i in 1..growing.len() {
        assert!(growing[i - 1].1 >= growing[i].1);
    }
}

#[test]
fn test_get_top_growing_types_returns_none_insufficient_samples() {
    let mut cache = HandleCache::new(60);

    // Only 1 sample
    let mut sample1 = HashMap::new();
    sample1.insert(1u16, 10u32);

    let mut pid_data = HashMap::new();
    pid_data.insert(7000u32, sample1);
    cache.update_type_history(&pid_data);

    // Should return None (need at least 2 samples)
    assert!(cache.get_top_growing_types(7000).is_none());
}

#[test]
fn test_type_history_only_includes_positive_deltas() {
    let mut cache = HandleCache::new(60);

    let mut sample1 = HashMap::new();
    sample1.insert(1u16, 100u32);
    sample1.insert(2u16, 50u32);

    let mut sample2 = HashMap::new();
    sample2.insert(1u16, 110u32); // +10 (growth)
    sample2.insert(2u16, 30u32); // -20 (decrease)

    let mut pid_data = HashMap::new();
    pid_data.insert(8000u32, sample1);
    cache.update_type_history(&pid_data);

    pid_data.clear();
    pid_data.insert(8000u32, sample2);
    cache.update_type_history(&pid_data);

    let growing = cache.get_top_growing_types(8000).unwrap();

    // Should only include Type 1 (positive delta)
    assert_eq!(growing.len(), 1);
    assert_eq!(growing[0].0, 1);
}

#[test]
fn test_type_history_handles_new_types() {
    let mut cache = HandleCache::new(60);

    let mut sample1 = HashMap::new();
    sample1.insert(1u16, 10u32);

    let mut sample2 = HashMap::new();
    sample2.insert(1u16, 15u32);
    sample2.insert(99u16, 50u32); // New type appears

    let mut pid_data = HashMap::new();
    pid_data.insert(9000u32, sample1);
    cache.update_type_history(&pid_data);

    pid_data.clear();
    pid_data.insert(9000u32, sample2);
    cache.update_type_history(&pid_data);

    let growing = cache.get_top_growing_types(9000).unwrap();

    // Should include both: Type 99: +50 (new), Type 1: +5
    assert_eq!(growing.len(), 2);
    assert_eq!(growing[0].0, 99); // New type has larger delta
    assert_eq!(growing[0].1, 50);
}

#[test]
fn test_type_history_caps_at_window_size() {
    let mut cache = HandleCache::new(60);

    // Add 10 samples (window is 5)
    for i in 0..10 {
        let mut sample = HashMap::new();
        sample.insert(1u16, 10 + i);

        let mut pid_data = HashMap::new();
        pid_data.insert(10000u32, sample);
        cache.update_type_history(&pid_data);
    }

    // Delta should be between sample 5 and 9 (oldest kept is sample 5)
    // Not between sample 0 and 9
    let growing = cache.get_top_growing_types(10000).unwrap();
    assert_eq!(growing[0].1, 4); // Delta of 4 (5 samples kept)
}
