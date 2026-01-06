//! Local JSON-based cache for reputation lookups

use crate::reputation::{LookupState, ReputationProvider, VtStats};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CACHE_TTL_DAYS: u64 = 7;
const MAX_CACHE_ENTRIES: usize = 1000;
const CACHE_DEBOUNCE_SECS: u64 = 5; // Only save to disk every 5 seconds

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    sha256: String,
    stats: Option<VtStats>,
    not_found: bool,
    timestamp: u64,
    #[serde(default)]
    provider: Option<String>,
}

/// Local cache provider that stores results in a JSON file
pub struct LocalCacheProvider {
    cache_path: PathBuf,
    entries: Arc<RwLock<HashMap<String, CacheEntry>>>,
    last_save: Arc<RwLock<Instant>>,
    dirty: Arc<RwLock<bool>>,
    flush_scheduled: Arc<AtomicBool>,
}

impl LocalCacheProvider {
    /// Create a new local cache provider
    pub fn new(cache_path: PathBuf) -> Self {
        let entries = Self::load_from_disk(&cache_path);
        Self {
            cache_path,
            entries: Arc::new(RwLock::new(entries)),
            last_save: Arc::new(RwLock::new(Instant::now())),
            dirty: Arc::new(RwLock::new(false)),
            flush_scheduled: Arc::new(AtomicBool::new(false)),
        }
    }

    fn now_unix_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn load_from_disk(path: &PathBuf) -> HashMap<String, CacheEntry> {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(entries) = serde_json::from_str::<Vec<CacheEntry>>(&content) {
                let now = Self::now_unix_secs();
                let ttl_secs = CACHE_TTL_DAYS * 24 * 60 * 60;

                // Filter out expired entries
                return entries
                    .into_iter()
                    .filter(|e| now - e.timestamp < ttl_secs)
                    .map(|e| (e.sha256.clone(), e))
                    .collect();
            }
        }
        HashMap::new()
    }

    fn save_to_disk_shared(
        cache_path: &PathBuf,
        entries: &Arc<RwLock<HashMap<String, CacheEntry>>>,
        last_save: &Arc<RwLock<Instant>>,
        dirty: &Arc<RwLock<bool>>,
        flush_scheduled: &Arc<AtomicBool>,
    ) {
        // Handle lock poisoning gracefully - recover the inner guard
        let entries = match entries.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let now = Self::now_unix_secs();
        let ttl_secs = CACHE_TTL_DAYS * 24 * 60 * 60;

        // Filter expired entries and enforce size cap
        let mut vec: Vec<CacheEntry> = entries
            .values()
            .filter(|e| now - e.timestamp < ttl_secs)
            .cloned()
            .collect();

        // Sort by timestamp (newest first) and keep only MAX_CACHE_ENTRIES
        vec.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        vec.truncate(MAX_CACHE_ENTRIES);

        let mut saved_ok = false;
        if let Ok(json) = serde_json::to_string_pretty(&vec) {
            // Best-effort "atomic" replace for Windows: write temp, then rename over.
            let tmp_path = cache_path.with_extension("json.tmp");
            if fs::write(&tmp_path, json).is_ok() {
                // rename can fail on Windows if destination exists.
                if fs::rename(&tmp_path, cache_path).is_ok() {
                    saved_ok = true;
                } else {
                    let _ = fs::remove_file(cache_path);
                    if fs::rename(&tmp_path, cache_path).is_ok() {
                        saved_ok = true;
                    } else {
                        // Leave tmp in place for diagnostics; do not clear dirty.
                        let _ = fs::remove_file(&tmp_path);
                    }
                }
            }
        }

        if saved_ok {
            // Update last_save timestamp and clear dirty flag - handle poisoning
            match last_save.write() {
                Ok(mut guard) => *guard = Instant::now(),
                Err(poison) => {
                    let mut guard = poison.into_inner();
                    *guard = Instant::now();
                }
            }
            match dirty.write() {
                Ok(mut guard) => *guard = false,
                Err(poison) => {
                    let mut guard = poison.into_inner();
                    *guard = false;
                }
            }
        }

        // Allow future scheduling regardless of outcome.
        flush_scheduled.store(false, Ordering::Release);
    }

    fn save_to_disk(&self) {
        Self::save_to_disk_shared(
            &self.cache_path,
            &self.entries,
            &self.last_save,
            &self.dirty,
            &self.flush_scheduled,
        );
    }

    fn save_to_disk_debounced(&self) {
        // Check if enough time has elapsed since last save - handle lock poisoning
        let should_save = match self.last_save.read() {
            Ok(last_save) => last_save.elapsed().as_secs() >= CACHE_DEBOUNCE_SECS,
            Err(poisoned) => poisoned.into_inner().elapsed().as_secs() >= CACHE_DEBOUNCE_SECS,
        };

        if should_save {
            self.save_to_disk();
        } else {
            // Mark as dirty for later save - handle lock poisoning
            match self.dirty.write() {
                Ok(mut guard) => *guard = true,
                Err(poison) => {
                    let mut guard = poison.into_inner();
                    *guard = true;
                }
            }

            // Guarantee an eventual flush even if no further writes occur.
            // This is bounded: at most one scheduled timer thread per provider at a time.
            if !self.flush_scheduled.swap(true, Ordering::AcqRel) {
                let cache_path = self.cache_path.clone();
                let entries = Arc::clone(&self.entries);
                let last_save = Arc::clone(&self.last_save);
                let dirty = Arc::clone(&self.dirty);
                let flush_scheduled = Arc::clone(&self.flush_scheduled);

                std::thread::spawn(move || {
                    // Wait until the debounce window has elapsed since last disk save.
                    let elapsed = match last_save.read() {
                        Ok(guard) => guard.elapsed(),
                        Err(poison) => poison.into_inner().elapsed(),
                    };

                    let remaining =
                        Duration::from_secs(CACHE_DEBOUNCE_SECS).saturating_sub(elapsed);
                    if !remaining.is_zero() {
                        std::thread::sleep(remaining);
                    }

                    let is_dirty = match dirty.read() {
                        Ok(guard) => *guard,
                        Err(poison) => *poison.into_inner(),
                    };

                    if is_dirty {
                        Self::save_to_disk_shared(
                            &cache_path,
                            &entries,
                            &last_save,
                            &dirty,
                            &flush_scheduled,
                        );
                    } else {
                        flush_scheduled.store(false, Ordering::Release);
                    }
                });
            }
        }
    }

    /// Force an immediate save to disk (flushes any pending changes)
    pub fn flush(&self) {
        // Handle lock poisoning gracefully
        let dirty = match self.dirty.read() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        };

        if dirty {
            self.save_to_disk();
        }
    }

    /// Store a result in the cache
    pub fn store(
        &self,
        sha256: String,
        stats: Option<VtStats>,
        not_found: bool,
        provider: Option<&str>,
    ) {
        let timestamp = Self::now_unix_secs();

        // Recover from lock poisoning and persist update.
        match self.entries.write() {
            Ok(mut entries) => {
                entries.insert(
                    sha256.clone(),
                    CacheEntry {
                        sha256,
                        stats,
                        not_found,
                        timestamp,
                        provider: provider.map(|s| s.to_string()),
                    },
                );
            }
            Err(poisoned) => {
                let mut entries = poisoned.into_inner();
                entries.insert(
                    sha256.clone(),
                    CacheEntry {
                        sha256,
                        stats,
                        not_found,
                        timestamp,
                        provider: provider.map(|s| s.to_string()),
                    },
                );
            }
        }
        self.save_to_disk_debounced();
    }

    /// Get cached result if available (respects TTL)
    /// Returns (LookupState, Option<provider_name>)
    pub fn get_with_provider(&self, sha256: &str) -> Option<(LookupState, Option<String>)> {
        let entries = match self.entries.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        if let Some(entry) = entries.get(sha256) {
            let now = Self::now_unix_secs();
            let ttl_secs = CACHE_TTL_DAYS * 24 * 60 * 60;

            // Check if expired
            if now - entry.timestamp >= ttl_secs {
                return None;
            }

            let state = if entry.not_found {
                LookupState::NotFound
            } else if let Some(ref stats) = entry.stats {
                LookupState::Hit(stats.clone())
            } else {
                LookupState::NotFound
            };

            return Some((state, entry.provider.clone()));
        }
        None
    }

    /// Get cached result if available (respects TTL)
    /// Legacy method for backward compatibility
    pub fn get(&self, sha256: &str) -> Option<LookupState> {
        self.get_with_provider(sha256).map(|(state, _)| state)
    }
}

impl ReputationProvider for LocalCacheProvider {
    fn name(&self) -> &'static str {
        "LocalCache"
    }

    fn lookup_hash(&self, sha256: &str) -> LookupState {
        if !crate::hashing::is_valid_sha256(sha256) {
            return LookupState::Error("Invalid SHA256 hash".to_string());
        }
        self.get(sha256).unwrap_or(LookupState::NotFound)
    }
}

impl Drop for LocalCacheProvider {
    fn drop(&mut self) {
        // Flush any pending writes on shutdown
        // flush() is no-panic by construction (handles lock poisoning gracefully)
        self.flush();
    }
}
