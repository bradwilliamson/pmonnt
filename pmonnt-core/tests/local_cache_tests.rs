use pmonnt_core::local_cache::LocalCacheProvider;
use pmonnt_core::reputation::{LookupState, ReputationProvider, VtStats};
use std::fs;
use std::sync::Arc;
use std::thread;
use tempfile::tempdir;

#[test]
fn test_local_cache_persistence() {
    let temp_dir = tempdir().unwrap();
    let cache_path = temp_dir.path().join("test_cache.json");

    // Create provider and store entry
    {
        let provider = LocalCacheProvider::new(cache_path.clone());
        let stats = VtStats {
            malicious: 1,
            suspicious: 0,
            harmless: 0,
            undetected: 0,
            last_analysis_date: None,
        };
        provider.store(
            "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3".to_string(),
            Some(stats),
            false,
            Some("VT"),
        );
    } // Provider dropped here, should flush

    // Recreate provider and check persistence
    let provider = LocalCacheProvider::new(cache_path);
    let result =
        provider.lookup_hash("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3");

    match result {
        LookupState::Hit(stats) => {
            assert_eq!(stats.malicious, 1);
        }
        _ => panic!("Expected Hit result"),
    }
}

#[test]
fn test_local_cache_eviction_over_max_entries() {
    let temp_dir = tempdir().unwrap();
    let cache_path = temp_dir.path().join("test_cache.json");

    let provider = LocalCacheProvider::new(cache_path.clone());

    // Store 1001 entries
    for i in 0..1001 {
        let hash = format!("{:064x}", i);
        let stats = VtStats {
            malicious: 1,
            suspicious: 0,
            harmless: 0,
            undetected: 0,
            last_analysis_date: None,
        };
        provider.store(hash, Some(stats), false, Some("VT"));
    }

    // Force flush
    provider.flush();

    // Recreate provider to reload from disk
    let _provider = LocalCacheProvider::new(cache_path.clone());

    // Check that we have at most 1000 entries
    if let Ok(content) = fs::read_to_string(&cache_path) {
        if let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&content) {
            assert!(entries.len() <= 1000);
        }
    }
}

#[test]
fn test_local_cache_ttl_expiration() {
    let temp_dir = tempdir().unwrap();
    let cache_path = temp_dir.path().join("test_cache.json");

    // Write JSON directly with old timestamp
    let old_entry = r#"[{
        "sha256": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
        "stats": {"malicious": 1, "suspicious": 0, "harmless": 0, "undetected": 0},
        "not_found": false,
        "timestamp": 0,
        "provider": "VT"
    }]"#;

    fs::write(&cache_path, old_entry).unwrap();

    // Create provider - should filter out expired entries
    let provider = LocalCacheProvider::new(cache_path);

    let result =
        provider.lookup_hash("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3");

    assert!(matches!(result, LookupState::NotFound));
}

#[test]
fn test_local_cache_concurrent_access() {
    let temp_dir = tempdir().unwrap();
    let cache_path = temp_dir.path().join("test_cache.json");

    let provider = Arc::new(LocalCacheProvider::new(cache_path));

    let mut handles = vec![];

    // Spawn multiple threads doing lookups and stores
    for i in 0..10 {
        let provider_clone = Arc::clone(&provider);
        let handle = thread::spawn(move || {
            let hash = format!("{:064x}", i);
            let stats = VtStats {
                malicious: 1,
                suspicious: 0,
                harmless: 0,
                undetected: 0,
                last_analysis_date: None,
            };
            provider_clone.store(hash.clone(), Some(stats), false, Some("VT"));

            // Lookup the stored value
            let result = provider_clone.lookup_hash(&hash);
            matches!(result, LookupState::Hit(_))
        });
        handles.push(handle);
    }

    // All threads should complete without panicking
    for handle in handles {
        assert!(handle.join().unwrap());
    }
}

#[test]
fn test_local_cache_flush() {
    let temp_dir = tempdir().unwrap();
    let cache_path = temp_dir.path().join("test_cache.json");

    let provider = LocalCacheProvider::new(cache_path.clone());

    let stats = VtStats {
        malicious: 1,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
        last_analysis_date: None,
    };
    provider.store(
        "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3".to_string(),
        Some(stats),
        false,
        Some("VT"),
    );

    // Force immediate flush
    provider.flush();

    // Check file exists and contains data
    assert!(cache_path.exists());
    let content = fs::read_to_string(&cache_path).unwrap();
    assert!(content.contains("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"));
}

#[test]
fn test_local_cache_get_with_provider() {
    let temp_dir = tempdir().unwrap();
    let cache_path = temp_dir.path().join("test_cache.json");

    let provider = LocalCacheProvider::new(cache_path);

    let stats = VtStats {
        malicious: 1,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
        last_analysis_date: None,
    };
    provider.store(
        "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3".to_string(),
        Some(stats),
        false,
        Some("VT"),
    );

    let result = provider
        .get_with_provider("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3");

    assert!(result.is_some());
    let (state, provider_name) = result.unwrap();
    assert!(matches!(state, LookupState::Hit(_)));
    assert_eq!(provider_name, Some("VT".to_string()));
}
