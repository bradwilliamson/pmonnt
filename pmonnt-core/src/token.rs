//! Process token inspection functionality

use crate::process::Process;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Information about a process token
#[derive(Debug, Clone)]
pub struct TokenInfo {
    /// User account (DOMAIN\User or SID string)
    pub user: Option<String>,
    /// Integrity level
    pub integrity: Option<String>,
    /// Whether the process is elevated
    pub elevated: Option<bool>,
    /// Whether the process is in an app container
    pub is_app_container: Option<bool>,
    /// List of privileges
    pub privileges: Vec<PrivilegeInfo>,
    /// Error message if token inspection failed
    pub error: Option<String>,
}

impl TokenInfo {
    /// Create a TokenInfo from a process
    pub fn from_process(process: &Process) -> Self {
        crate::win::token::inspect_process_token(process.pid)
    }

    /// Check if the token inspection succeeded
    pub fn is_success(&self) -> bool {
        self.error.is_none() && self.user.is_some() && self.integrity.is_some()
    }
}

impl Default for TokenInfo {
    fn default() -> Self {
        Self {
            user: None,
            integrity: None,
            elevated: None,
            is_app_container: None,
            privileges: Vec::new(),
            error: Some("Not inspected".to_string()),
        }
    }
}

/// Information about a privilege
#[derive(Debug, Clone)]
pub struct PrivilegeInfo {
    /// Privilege name (e.g., "SeDebugPrivilege")
    pub name: String,
    /// Whether the privilege is currently enabled
    pub enabled: bool,
}

impl PrivilegeInfo {
    pub fn new(name: String, enabled: bool) -> Self {
        Self { name, enabled }
    }
}

/// Cache for token information with expiration
#[derive(Debug)]
pub struct TokenCache {
    cache: HashMap<u32, (TokenInfo, Instant)>,
    ttl: Duration,
}

impl TokenCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: HashMap::new(),
            ttl,
        }
    }

    /// Get token info for a PID, using cache if available and fresh
    pub fn get_token_info(&mut self, pid: u32) -> &TokenInfo {
        let now = Instant::now();

        match self.cache.entry(pid) {
            Entry::Occupied(mut occupied) => {
                let timestamp = occupied.get().1;
                if now.duration_since(timestamp) < self.ttl {
                    return &occupied.into_mut().0;
                }

                // Cache expired - fetch new info
                let process = Process {
                    pid,
                    name: String::new(), // We don't need the name for token inspection
                    ppid: None,
                    cpu_percent: None,
                    memory_bytes: None,
                    gpu_percent: None,
                    gpu_memory_bytes: None,
                    path: None,
                    signature: None,
                };
                let info = TokenInfo::from_process(&process);

                occupied.insert((info, now));
                &occupied.into_mut().0
            }
            Entry::Vacant(vacant) => {
                // Cache miss - fetch new info
                let process = Process {
                    pid,
                    name: String::new(), // We don't need the name for token inspection
                    ppid: None,
                    cpu_percent: None,
                    memory_bytes: None,
                    gpu_percent: None,
                    gpu_memory_bytes: None,
                    path: None,
                    signature: None,
                };
                let info = TokenInfo::from_process(&process);
                &vacant.insert((info, now)).0
            }
        }
    }

    /// Clear expired entries
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.cache
            .retain(|_, (_, timestamp)| now.duration_since(*timestamp) < self.ttl);
    }

    /// Get cache size
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

impl Default for TokenCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(5))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_info_default() {
        let info = TokenInfo::default();
        assert!(!info.is_success());
        assert_eq!(info.error, Some("Not inspected".to_string()));
    }

    #[test]
    fn test_privilege_info() {
        let priv_info = PrivilegeInfo::new("SeDebugPrivilege".to_string(), true);
        assert_eq!(priv_info.name, "SeDebugPrivilege");
        assert!(priv_info.enabled);
    }

    #[test]
    fn test_token_cache() {
        let mut cache = TokenCache::new(Duration::from_secs(5));

        // Initially empty
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        // Get info for a PID (this will fail but create cache entry)
        let error1 = cache.get_token_info(123).error.clone();
        assert!(!cache.get_token_info(123).is_success());
        assert_eq!(cache.len(), 1);

        // Get same PID again - should return cached
        let error2 = cache.get_token_info(123).error.clone();
        assert_eq!(error2, error1);
        assert_eq!(cache.len(), 1);
    }
}
