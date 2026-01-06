//! Tests for thread parsing and sorting (not OS-dependent)
use pmonnt_core::thread::{ThreadCache, ThreadInfo};
use std::time::{Duration, SystemTime};

#[test]
fn test_thread_cache_insert_and_cleanup() {
    let mut cache = ThreadCache::new(2);
    let threads = vec![ThreadInfo {
        tid: 1,
        owner_pid: 42,
        base_priority: 8,
        priority: Some(8),
        kernel_time_100ns: 1000,
        user_time_100ns: 2000,
        created_at: Some(SystemTime::now()),
        name: Some("main".to_string()),
        start_address: None,
        error: None,
        suspend_count: None,
        context_switches: None,
        cycle_time: None,
        wait_reason: None,
        state: None,
        ideal_processor: None,
    }];
    cache.insert(42, threads.clone());
    assert_eq!(cache.get(42).unwrap().len(), 1);
    // Simulate time passing
    std::thread::sleep(Duration::from_secs(3));
    cache.cleanup();
    assert!(cache.get(42).is_none() || cache.get(42).unwrap().is_empty());
}

#[test]
fn test_threadinfo_sort_by_cpu() {
    let mut threads = [
        ThreadInfo {
            tid: 1,
            owner_pid: 1,
            base_priority: 8,
            priority: Some(8),
            kernel_time_100ns: 100,
            user_time_100ns: 200,
            created_at: None,
            name: None,
            start_address: None,
            error: None,
            suspend_count: None,
            context_switches: None,
            cycle_time: None,
            wait_reason: None,
            state: None,
            ideal_processor: None,
        },
        ThreadInfo {
            tid: 2,
            owner_pid: 1,
            base_priority: 8,
            priority: Some(8),
            kernel_time_100ns: 300,
            user_time_100ns: 100,
            created_at: None,
            name: None,
            start_address: None,
            error: None,
            suspend_count: None,
            context_switches: None,
            cycle_time: None,
            wait_reason: None,
            state: None,
            ideal_processor: None,
        },
        ThreadInfo {
            tid: 3,
            owner_pid: 1,
            base_priority: 8,
            priority: Some(8),
            kernel_time_100ns: 50,
            user_time_100ns: 50,
            created_at: None,
            name: None,
            start_address: None,
            error: None,
            suspend_count: None,
            context_switches: None,
            cycle_time: None,
            wait_reason: None,
            state: None,
            ideal_processor: None,
        },
    ];
    threads.sort_by(|a, b| {
        (b.kernel_time_100ns + b.user_time_100ns).cmp(&(a.kernel_time_100ns + a.user_time_100ns))
    });
    assert_eq!(threads[0].tid, 2);
    assert_eq!(threads[1].tid, 1);
    assert_eq!(threads[2].tid, 3);
}
