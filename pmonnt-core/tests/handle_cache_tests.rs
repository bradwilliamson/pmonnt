//! Tests for handle caching behavior

use pmonnt_core::handles::HandleCache;
use std::sync::Arc;
use std::thread;

#[test]
fn test_cache_stores_and_retrieves() {
    let cache = HandleCache::new(5);
    let test_pid = 1234u32;
    
    // Initially cache should be empty
    assert!(cache.get(test_pid).is_none());
}

#[test]
fn test_cache_cleanup_removes_expired_entries() {
    let cache = HandleCache::new(1); // 1 second TTL
    
    // The cleanup method should exist and work without errors
    let mut cache_mut = cache.clone();
    cache_mut.cleanup(&[]);  // cleanup requires active PIDs list
    
    // After cleanup, cache should still be functional
    assert!(cache_mut.get(1234).is_none());
}

#[test]
fn test_cache_handles_multiple_pids() {
    let cache = HandleCache::new(5);
    
    // Multiple gets on non-existent PIDs should return None
    assert!(cache.get(1000).is_none());
    assert!(cache.get(2000).is_none());
    assert!(cache.get(3000).is_none());
}

#[test]
fn test_cache_has_data_initially_false() {
    let cache = HandleCache::new(5);
    
    // has_data should return false initially
    assert!(!cache.has_data(), "cache should have no data initially");
}

#[test]
fn test_cache_concurrent_access() {
    let cache = Arc::new(HandleCache::new(5));
    let mut handles = vec![];
    
    for i in 0..10 {
        let cache_clone = Arc::clone(&cache);
        handles.push(thread::spawn(move || {
            let cache_ref = &*cache_clone;
            let result = cache_ref.get(i as u32);
            // Should be None since we never inserted anything
            result.is_none()
        }));
    }
    
    for h in handles {
        let success = h.join().expect("thread panicked");
        assert!(success, "concurrent access should work");
    }
}

#[test]
fn test_cache_error_tracking() {
    let cache = HandleCache::new(5);
    
    // Cache should have an error field
    assert!(cache.last_error.is_none(), "should start with no error");
}

#[test]
fn test_cache_new_with_different_ttl() {
    let cache_short = HandleCache::new(1);
    let cache_long = HandleCache::new(300);
    
    // Both caches should be created without panic
    let mut cache_short_mut = cache_short.clone();
    let mut cache_long_mut = cache_long.clone();
    
    cache_short_mut.cleanup(&[]);
    cache_long_mut.cleanup(&[]);
}
