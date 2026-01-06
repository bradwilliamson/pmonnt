//! ThreadInfo data model and cache for per-process thread inspection
use std::collections::HashMap;
use std::time::{Instant, SystemTime};

#[derive(Debug, Clone)]
pub struct ThreadInfo {
    pub tid: u32,
    pub owner_pid: u32,
    pub base_priority: i32,
    pub priority: Option<i32>,
    pub kernel_time_100ns: u64,
    pub user_time_100ns: u64,
    pub created_at: Option<SystemTime>,
    pub name: Option<String>,
    pub start_address: Option<u64>,
    pub error: Option<String>,

    // Additional fields like Process Explorer
    pub suspend_count: Option<u32>,
    pub context_switches: Option<u64>,
    pub cycle_time: Option<u64>,
    pub wait_reason: Option<u32>,
    pub state: Option<u32>,
    pub ideal_processor: Option<u8>,
}

pub type ThreadList = Vec<ThreadInfo>;

#[derive(Default)]
pub struct ThreadCache {
    ttl_secs: u64,
    map: HashMap<u32, (Instant, ThreadList)>,
}

impl ThreadCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            ttl_secs,
            map: HashMap::new(),
        }
    }
    pub fn get(&mut self, pid: u32) -> Option<&ThreadList> {
        let now = Instant::now();
        if let Some((fetched, threads)) = self.map.get(&pid) {
            if now.duration_since(*fetched).as_secs() < self.ttl_secs {
                return Some(threads);
            }
        }
        None
    }
    pub fn peek(&self, pid: u32) -> Option<&ThreadList> {
        self.map.get(&pid).map(|(_, threads)| threads)
    }
    pub fn insert(&mut self, pid: u32, threads: ThreadList) {
        self.map.insert(pid, (Instant::now(), threads));
    }
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.map
            .retain(|_, (fetched, _)| now.duration_since(*fetched).as_secs() < self.ttl_secs * 2);
    }
}
