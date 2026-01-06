//! VirusTotal reputation provider

use crate::hashing::is_valid_sha256;
use crate::local_cache::LocalCacheProvider;
use crate::reputation::{LookupState, ReputationProvider, VtStats};
use log::{debug, warn};
use serde::Deserialize;
use std::env;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const DEFAULT_VT_BASE_URL: &str = "https://www.virustotal.com/api/v3";
const RATE_LIMIT_COOLDOWN_SECS: u64 = 60;

#[derive(Debug, Deserialize)]
struct VtResponse {
    data: VtData,
}

#[derive(Debug, Deserialize)]
struct VtData {
    attributes: VtAttributes,
}

#[derive(Debug, Deserialize)]
struct VtAttributes {
    last_analysis_stats: VtAnalysisStats,
    last_analysis_date: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct VtAnalysisStats {
    malicious: u32,
    suspicious: u32,
    harmless: u32,
    undetected: u32,
}

/// Test-support helper: parse a VirusTotal JSON response into `VtStats`.
///
/// This is intentionally `#[doc(hidden)]` so integration tests can validate
/// deserialization + mapping without requiring a live HTTP call.
#[doc(hidden)]
pub fn parse_vt_stats_from_json(json: &str) -> Result<VtStats, serde_json::Error> {
    let vt_resp: VtResponse = serde_json::from_str(json)?;
    Ok(VtStats {
        malicious: vt_resp.data.attributes.last_analysis_stats.malicious,
        suspicious: vt_resp.data.attributes.last_analysis_stats.suspicious,
        harmless: vt_resp.data.attributes.last_analysis_stats.harmless,
        undetected: vt_resp.data.attributes.last_analysis_stats.undetected,
        last_analysis_date: vt_resp.data.attributes.last_analysis_date,
    })
}

/// VirusTotal provider with rate limiting and offline detection
pub struct VirusTotalProvider {
    api_key: Arc<Mutex<Option<String>>>,
    base_url: String,
    local_cache: Arc<LocalCacheProvider>,
    rate_limit_until: Arc<Mutex<Option<Instant>>>,
}

/// Metadata about the last VirusTotal query (UI-friendly)
#[derive(Debug, Clone)]
pub struct VtQueryMeta {
    pub last_query: Option<String>,
    pub last_http_status: Option<u16>,
    pub last_query_status: Option<String>,
    pub last_result_count: Option<usize>,
    pub last_error_message: Option<String>,
}

impl VirusTotalProvider {
    /// Create a new VirusTotal provider
    pub fn new(local_cache: Arc<LocalCacheProvider>) -> Self {
        let api_key = env::var("VT_API_KEY").ok();
        let base_url = env::var("VT_BASE_URL").unwrap_or_else(|_| DEFAULT_VT_BASE_URL.to_string());

        Self {
            api_key: Arc::new(Mutex::new(api_key)),
            base_url,
            local_cache,
            rate_limit_until: Arc::new(Mutex::new(None)),
        }
    }

    /// Update the API key at runtime
    pub fn set_api_key(&self, key: String) {
        if let Ok(mut api_key) = self.api_key.lock() {
            if key.is_empty() {
                *api_key = None;
            } else {
                *api_key = Some(key);
            }
        }
    }

    /// Get the current API key
    pub fn get_api_key(&self) -> Option<String> {
        self.api_key.lock().ok().and_then(|ak| ak.clone())
    }

    /// Check if rate limited
    fn is_rate_limited(&self) -> bool {
        if let Ok(rate_limit) = self.rate_limit_until.lock() {
            if let Some(until) = *rate_limit {
                if Instant::now() < until {
                    return true;
                }
            }
        }
        false
    }

    /// Set rate limit cooldown
    fn set_rate_limited(&self) {
        if let Ok(mut rate_limit) = self.rate_limit_until.lock() {
            *rate_limit = Some(Instant::now() + Duration::from_secs(RATE_LIMIT_COOLDOWN_SECS));
        }
    }

    /// Perform async lookup (for use with tokio runtime)
    pub async fn lookup_hash_async(&self, sha256: &str) -> LookupState {
        if !is_valid_sha256(sha256) {
            return LookupState::Error("Invalid SHA256 hash".to_string());
        }
        // Check cache first
        if let Some(cached) = self.local_cache.get(sha256) {
            return cached;
        }

        // Check if configured
        let api_key = match self.api_key.lock() {
            Ok(guard) => match guard.clone() {
                Some(key) => key,
                None => return LookupState::NotConfigured,
            },
            Err(_) => return LookupState::Error("Configuration lock failed".to_string()),
        };

        // Check rate limit
        if self.is_rate_limited() {
            return LookupState::Error("Rate limited".to_string());
        }

        // Build request
        let url = format!("{}/files/{}", self.base_url, sha256);
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
        {
            Ok(c) => c,
            Err(_) => return LookupState::Offline,
        };

        let start = Instant::now();
        let response = client.get(&url).header("x-apikey", &api_key).send().await;

        match response {
            Ok(resp) => {
                let status = resp.status();
                let elapsed_ms = start.elapsed().as_millis();
                debug!(
                    "VirusTotal lookup HTTP {} for {} ({} ms)",
                    status.as_u16(),
                    sha256,
                    elapsed_ms
                );
                // Log a few helpful response headers (redact anything sensitive)
                let headers = resp.headers();
                let rate_rem = headers
                    .get("x-rate-limit-remaining")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("");
                let rate_limit = headers
                    .get("x-rate-limit-limit")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("");
                debug!(
                    "VT headers: x-rate-limit-remaining={} x-rate-limit-limit={}",
                    rate_rem, rate_limit
                );

                if status == 404 {
                    // Not found in VT database
                    self.local_cache
                        .store(sha256.to_string(), None, true, Some("VT"));
                    return LookupState::NotFound;
                }

                if status == 429 {
                    // Rate limited
                    let body = resp.text().await.unwrap_or_default();
                    warn!(
                        "VirusTotal lookup rate limited ({}). elapsed={}ms body: {}",
                        status.as_u16(),
                        elapsed_ms,
                        body.chars().take(1024).collect::<String>()
                    );
                    self.set_rate_limited();
                    return LookupState::Error("Rate limited".to_string());
                }

                if !status.is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    warn!(
                        "VirusTotal lookup HTTP {}. elapsed={}ms body: {}",
                        status.as_u16(),
                        elapsed_ms,
                        body.chars().take(1024).collect::<String>()
                    );
                    return LookupState::Error(format!("HTTP {}", status));
                }

                // Parse response
                match resp.json::<VtResponse>().await {
                    Ok(vt_resp) => {
                        let stats = VtStats {
                            malicious: vt_resp.data.attributes.last_analysis_stats.malicious,
                            suspicious: vt_resp.data.attributes.last_analysis_stats.suspicious,
                            harmless: vt_resp.data.attributes.last_analysis_stats.harmless,
                            undetected: vt_resp.data.attributes.last_analysis_stats.undetected,
                            last_analysis_date: vt_resp.data.attributes.last_analysis_date,
                        };

                        // Store in cache
                        self.local_cache.store(
                            sha256.to_string(),
                            Some(stats.clone()),
                            false,
                            Some("VT"),
                        );

                        LookupState::Hit(stats)
                    }
                    Err(e) => LookupState::Error(format!("Parse error: {}", e)),
                }
            }
            Err(e) => {
                // Network errors = offline, not permanent errors
                if e.is_timeout() || e.is_connect() || e.is_request() {
                    LookupState::Offline
                } else {
                    LookupState::Error(format!("Request error: {}", e))
                }
            }
        }
    }
}

impl ReputationProvider for VirusTotalProvider {
    fn name(&self) -> &'static str {
        "VT"
    }

    fn lookup_hash(&self, sha256: &str) -> LookupState {
        self.lookup_hash_sync(sha256)
    }
}

impl VirusTotalProvider {
    /// Synchronous lookup using blocking reqwest client
    pub fn lookup_hash_sync(&self, sha256: &str) -> LookupState {
        if !is_valid_sha256(sha256) {
            return LookupState::Error("Invalid SHA256 hash".to_string());
        }
        // Check cache first
        if let Some(cached) = self.local_cache.get(sha256) {
            return cached;
        }

        // Check if configured
        let api_key = match self.api_key.lock() {
            Ok(guard) => match guard.clone() {
                Some(key) => key,
                None => return LookupState::NotConfigured,
            },
            Err(_) => return LookupState::Error("Configuration lock failed".to_string()),
        };

        // Check rate limit
        if self.is_rate_limited() {
            return LookupState::Error("Rate limited".to_string());
        }

        // Build blocking request
        let url = format!("{}/files/{}", self.base_url, sha256);
        let client = match reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
        {
            Ok(c) => c,
            Err(_) => return LookupState::Offline,
        };

        let start = Instant::now();
        let response = client.get(&url).header("x-apikey", &api_key).send();

        match response {
            Ok(resp) => {
                let status = resp.status();
                let elapsed_ms = start.elapsed().as_millis();
                debug!(
                    "VirusTotal lookup (sync) HTTP {} for {} ({} ms)",
                    status.as_u16(),
                    sha256,
                    elapsed_ms
                );
                let headers = resp.headers();
                let rate_rem = headers
                    .get("x-rate-limit-remaining")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("");
                let rate_limit = headers
                    .get("x-rate-limit-limit")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("");
                debug!(
                    "VT sync headers: x-rate-limit-remaining={} x-rate-limit-limit={}",
                    rate_rem, rate_limit
                );

                if status == reqwest::StatusCode::NOT_FOUND {
                    // Not found in VT database
                    self.local_cache
                        .store(sha256.to_string(), None, true, Some("VT"));
                    return LookupState::NotFound;
                }

                if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                    // Rate limited
                    let body = resp.text().unwrap_or_default();
                    warn!(
                        "VirusTotal lookup (sync) rate limited ({}). elapsed={}ms body: {}",
                        status.as_u16(),
                        elapsed_ms,
                        body.chars().take(1024).collect::<String>()
                    );
                    self.set_rate_limited();
                    return LookupState::Error("Rate limited".to_string());
                }

                if !status.is_success() {
                    let body = resp.text().unwrap_or_default();
                    warn!(
                        "VirusTotal lookup (sync) HTTP {}. elapsed={}ms body: {}",
                        status.as_u16(),
                        elapsed_ms,
                        body.chars().take(1024).collect::<String>()
                    );
                    return LookupState::Error(format!("HTTP {}", status));
                }

                // Parse response
                match resp.json::<VtResponse>() {
                    Ok(vt_resp) => {
                        let stats = VtStats {
                            malicious: vt_resp.data.attributes.last_analysis_stats.malicious,
                            suspicious: vt_resp.data.attributes.last_analysis_stats.suspicious,
                            harmless: vt_resp.data.attributes.last_analysis_stats.harmless,
                            undetected: vt_resp.data.attributes.last_analysis_stats.undetected,
                            last_analysis_date: vt_resp.data.attributes.last_analysis_date,
                        };

                        // Store in cache
                        self.local_cache.store(
                            sha256.to_string(),
                            Some(stats.clone()),
                            false,
                            Some("VT"),
                        );

                        LookupState::Hit(stats)
                    }
                    Err(e) => LookupState::Error(format!("Parse error: {}", e)),
                }
            }
            Err(e) => {
                // Network errors = offline, not permanent errors
                if e.is_timeout() || e.is_connect() || e.is_request() {
                    LookupState::Offline
                } else {
                    LookupState::Error(format!("Request error: {}", e))
                }
            }
        }
    }
}
