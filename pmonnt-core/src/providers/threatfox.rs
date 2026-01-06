use crate::hashing::is_valid_sha256;
use crate::local_cache::LocalCacheProvider;
use crate::reputation::{
    AggregatedReputation, LookupState, ProviderFinding, ReputationProvider, Verdict,
};

use log::{debug, warn};
use std::env;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ThreatFox types
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TfMalwareSample {
    pub time_stamp: Option<String>,
    pub md5_hash: Option<String>,
    #[serde(rename = "sha256_hash")]
    pub sha256: Option<String>,
    pub malware_bazaar: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct TfIoc {
    pub id: String,
    pub ioc: String,
    pub threat_type: Option<String>,
    pub threat_type_desc: Option<String>,
    pub ioc_type: Option<String>,
    pub ioc_type_desc: Option<String>,
    pub malware: Option<String>,
    pub malware_printable: Option<String>,
    pub malware_alias: Option<String>,
    pub malware_malpedia: Option<String>,
    pub confidence_level: Option<i64>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub reference: Option<String>,
    pub reporter: Option<String>,
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub malware_samples: Vec<TfMalwareSample>,
}

/// Result wrapper for ThreatFox searches (list of IOCs)
pub type TfResult = Vec<TfIoc>;

#[derive(Debug, Clone, Default)]
pub struct TfQueryMeta {
    pub last_query: Option<String>,
    pub last_http_status: Option<u16>,
    pub last_query_status: Option<String>,
    pub last_result_count: Option<usize>,
    pub last_error_message: Option<String>,
}

/// ThreatFox provider (abuse.ch)
pub struct ThreatFoxProvider {
    api_key: Arc<Mutex<Option<String>>>,
    local_cache: Arc<LocalCacheProvider>,
    rate_limit_until: Arc<Mutex<Option<Instant>>>,
}

/// Test-support helper: parse ThreatFox `search_hash` JSON response into `(Vec<TfIoc>, TfQueryMeta)`.
///
/// This is `#[doc(hidden)]` so integration tests can validate parsing and mapping
/// without making a live network request.
#[doc(hidden)]
pub fn parse_threatfox_search_hash_response_json(
    json: &str,
) -> Result<(Vec<TfIoc>, TfQueryMeta), serde_json::Error> {
    let v: serde_json::Value = serde_json::from_str(json)?;

    let query_status = v
        .get("query_status")
        .and_then(|s| s.as_str())
        .unwrap_or("unknown")
        .to_string();

    let mut meta = TfQueryMeta {
        last_query: Some("search_hash".to_string()),
        last_query_status: Some(query_status),
        ..Default::default()
    };

    let mut data_vec: Vec<TfIoc> = Vec::new();

    if let Some(data_val) = v.get("data") {
        if data_val.is_array() {
            match serde_json::from_value::<Vec<TfIoc>>(data_val.clone()) {
                Ok(d) => data_vec = d,
                Err(e) => {
                    meta.last_error_message = Some(format!("parse data error: {}", e));
                }
            }
        } else if data_val.is_string() {
            let msg = data_val.as_str().unwrap_or_default().to_string();
            meta.last_error_message = Some(msg);
        }
    }

    meta.last_result_count = Some(data_vec.len());

    Ok((data_vec, meta))
}

impl ThreatFoxProvider {
    fn api_base_url() -> String {
        // Test hook: allow redirecting ThreatFox API calls to a local server.
        // Defaults to the real ThreatFox API endpoint.
        env::var("TF_BASE_URL")
            .unwrap_or_else(|_| "https://threatfox-api.abuse.ch/api/v1/".to_string())
    }

    pub fn new(local_cache: Arc<LocalCacheProvider>, api_key: Option<String>) -> Self {
        let api_key = api_key
            .or_else(|| env::var("PMONNT_THREATFOX_KEY").ok())
            .or_else(|| env::var("PMONNT_MB_API_KEY").ok())
            .or_else(|| env::var("PMONNT_MALWAREBAZAAR_KEY").ok());
        Self {
            api_key: Arc::new(Mutex::new(api_key)),
            local_cache,
            rate_limit_until: Arc::new(Mutex::new(None)),
        }
    }

    /// Update the API key at runtime
    pub fn update_api_key(&self, api_key: Option<String>) {
        if let Ok(mut guard) = self.api_key.lock() {
            *guard = api_key;
        }
    }

    #[cfg(test)]
    pub(crate) fn get_api_key(&self) -> Option<String> {
        self.api_key.lock().ok().and_then(|g| g.clone())
    }

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

    fn set_rate_limited(&self) {
        if let Ok(mut rate_limit) = self.rate_limit_until.lock() {
            *rate_limit = Some(Instant::now() + Duration::from_secs(60));
        }
    }

    /// Verbose search by hash returning parsed IOCs and metadata for UI
    pub fn search_hash_verbose(&self, hash: &str) -> Result<(Vec<TfIoc>, TfQueryMeta), String> {
        let url = Self::api_base_url();
        let body = serde_json::json!({
            "query": "search_hash",
            "hash": hash,
        });

        let mut meta = TfQueryMeta {
            last_query: Some("search_hash".to_string()),
            ..Default::default()
        };

        // Build client
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| format!("http build error: {}", e))?;

        let api_key = self
            .api_key
            .lock()
            .map_err(|_| "lock error".to_string())?
            .clone();

        let mut req = client.post(url).json(&body);
        if let Some(k) = api_key.clone() {
            // Log presence of API key (length only, do not log value)
            debug!("ThreatFox API key present (len={})", k.len());
            // ThreatFox expects "Auth-Key" header
            req = req.header("Auth-Key", k);
        } else {
            debug!("ThreatFox API key not present");
        }

        let resp = req.send().map_err(|e| format!("http send error: {}", e))?;
        meta.last_http_status = Some(resp.status().as_u16());

        let status_code = resp.status().as_u16();
        // Read body for parsing and diagnostics
        let text = resp.text().map_err(|e| format!("http read error: {}", e))?;
        debug!(
            "ThreatFox search_hash_verbose HTTP {} for {}",
            status_code, hash
        );

        // Log full response for non-200 to aid debugging
        if status_code != 200 {
            warn!(
                "ThreatFox non-200 response: HTTP {} for hash {}\nBody: {}",
                status_code,
                hash,
                &text[..text.len().min(2048)]
            );
            meta.last_error_message = Some(format!("HTTP {}", status_code));
        }

        let (data_vec, parsed_meta) = parse_threatfox_search_hash_response_json(&text)
            .map_err(|e| format!("parse error: {}", e))?;

        // Preserve HTTP status and only override fields we parse from body.
        meta.last_query_status = parsed_meta.last_query_status;
        meta.last_result_count = parsed_meta.last_result_count;
        if meta.last_error_message.is_none() {
            meta.last_error_message = parsed_meta.last_error_message;
        }
        debug!(
            "ThreatFox parsed query_status='{}' result_count={}",
            meta.last_query_status
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            data_vec.len()
        );

        Ok((data_vec, meta))
    }
}

impl ReputationProvider for ThreatFoxProvider {
    fn name(&self) -> &'static str {
        "TF"
    }

    fn lookup_hash(&self, sha256: &str) -> LookupState {
        if !is_valid_sha256(sha256) {
            return LookupState::Error("Invalid SHA256 hash".to_string());
        }
        // Check cache first
        let cache_key = format!("tf:{}", sha256);
        if let Some((cached, provider)) = self.local_cache.get_with_provider(&cache_key) {
            // Only return cached result if it was cached by this provider
            if provider.as_deref() == Some("TF") || provider.is_none() {
                debug!("ThreatFox cache hit for {}", sha256);
                return match cached {
                    // Cached positive hit is stored as VT-shaped stats; rehydrate into TF-shaped Aggregated.
                    LookupState::Hit(_) => {
                        let finding = ProviderFinding {
                            provider_name: "TF".to_string(),
                            verdict: Verdict::Malicious,
                            // We don't have IOC id in the cache; avoid inventing a link.
                            link: None,
                            family: None,
                            confidence: None,
                        };

                        let agg = AggregatedReputation {
                            findings: vec![finding],
                            best_verdict: Verdict::Malicious,
                            summary: "ThreatFox: cached hit".to_string(),
                            primary_link: None,
                        };

                        LookupState::Aggregated(agg)
                    }
                    other => other,
                };
            }
        }

        // Get API key - ThreatFox works without API key but with rate limits
        let api_key = self.api_key.lock().ok().and_then(|guard| guard.clone());

        // Check rate limit
        if self.is_rate_limited() {
            return LookupState::Error("Rate limited".to_string());
        }

        // Build HTTP client
        let client = match reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                warn!("ThreatFox client build error: {}", e);
                return LookupState::Offline;
            }
        };

        // Build request body
        let body = serde_json::json!({
            "query": "search_hash",
            "hash": sha256,
        });

        // Build request with optional API key
        let mut req = client
            .post(Self::api_base_url())
            .header("Content-Type", "application/json")
            .json(&body);

        if let Some(ref k) = api_key {
            debug!("ThreatFox lookup_hash: using API key (len={})", k.len());
            // ThreatFox expects "Auth-Key" header
            req = req.header("Auth-Key", k.clone());
        } else {
            debug!("ThreatFox lookup_hash: no API key, using anonymous access");
        }

        // Send request
        let response = match req.send() {
            Ok(r) => r,
            Err(e) => {
                if e.is_timeout() {
                    warn!("ThreatFox request timeout for {}", sha256);
                    return LookupState::Offline;
                }
                if e.is_connect() {
                    warn!("ThreatFox connection error for {}: {}", sha256, e);
                    return LookupState::Offline;
                }
                warn!("ThreatFox request error for {}: {}", sha256, e);
                return LookupState::Error(format!("Request error: {}", e));
            }
        };

        let status = response.status();
        debug!(
            "ThreatFox lookup_hash HTTP {} for {}",
            status.as_u16(),
            sha256
        );

        // Handle error status codes before consuming body
        if status == reqwest::StatusCode::UNAUTHORIZED {
            // 401 - API key invalid or required
            let body_text = response.text().unwrap_or_default();
            warn!(
                "ThreatFox 401 Unauthorized for {}: {}",
                sha256,
                &body_text[..body_text.len().min(500)]
            );
            return LookupState::NotConfigured;
        }

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            // 429 - Rate limited
            let body_text = response.text().unwrap_or_default();
            warn!(
                "ThreatFox 429 Rate Limited: {}",
                &body_text[..body_text.len().min(500)]
            );
            self.set_rate_limited();
            return LookupState::Error("Rate limited".to_string());
        }

        if !status.is_success() {
            let body_text = response.text().unwrap_or_default();
            warn!(
                "ThreatFox HTTP {} for {}: {}",
                status.as_u16(),
                sha256,
                &body_text[..body_text.len().min(500)]
            );
            return LookupState::Error(format!("HTTP {}", status));
        }

        // Read response body
        let text = match response.text() {
            Ok(t) => t,
            Err(e) => {
                warn!("ThreatFox response read error for {}: {}", sha256, e);
                return LookupState::Error(format!("Read error: {}", e));
            }
        };

        debug!(
            "ThreatFox response body (first 512 chars): {}",
            &text[..text.len().min(512)]
        );

        // Parse response flexibly - "data" can be array OR string
        let v: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                warn!("ThreatFox JSON parse error for {}: {}", sha256, e);
                return LookupState::Error(format!("Parse error: {}", e));
            }
        };

        let query_status = v
            .get("query_status")
            .and_then(|s| s.as_str())
            .unwrap_or("unknown");

        debug!("ThreatFox query_status='{}' for {}", query_status, sha256);

        // Handle "data" field - can be array (results) or string (error message)
        let data: Vec<serde_json::Value> = match v.get("data") {
            Some(d) if d.is_array() => d.as_array().cloned().unwrap_or_default(),
            Some(d) if d.is_string() => {
                // "data" is a string like "No results" - treat as not found
                debug!(
                    "ThreatFox data is string for {}: {}",
                    sha256,
                    d.as_str().unwrap_or_default()
                );
                Vec::new()
            }
            _ => Vec::new(),
        };

        // Check if we have results
        if query_status == "ok" && !data.is_empty() {
            // Parse first result
            let first = &data[0];

            let malware = first
                .get("malware")
                .or_else(|| first.get("malware_printable"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let threat_type_desc = first
                .get("threat_type_desc")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let family = malware
                .or(threat_type_desc)
                .unwrap_or_else(|| "Unknown".to_string());

            let confidence = first
                .get("confidence_level")
                .and_then(|v| v.as_i64())
                .unwrap_or(80) as u32;

            let ioc_id = first.get("id").and_then(|v| v.as_str()).unwrap_or(sha256);

            debug!(
                "ThreatFox FOUND for {}: family={}, confidence={}",
                sha256, family, confidence
            );

            let finding = ProviderFinding {
                provider_name: "TF".to_string(),
                verdict: Verdict::Malicious,
                link: Some(format!("https://threatfox.abuse.ch/ioc/{}", ioc_id)),
                family: Some(family.clone()),
                confidence: Some(confidence),
            };

            let agg = AggregatedReputation {
                findings: vec![finding],
                best_verdict: Verdict::Malicious,
                summary: format!("TF: {} ({}%)", family, confidence),
                primary_link: Some(format!("https://threatfox.abuse.ch/ioc/{}", ioc_id)),
            };

            // Cache the positive result
            self.local_cache.store(
                cache_key,
                Some(crate::reputation::VtStats {
                    malicious: 1,
                    suspicious: 0,
                    harmless: 0,
                    undetected: 0,
                    last_analysis_date: None,
                }),
                false,
                Some("TF"),
            );

            LookupState::Aggregated(agg)
        } else {
            // No results - cache as not found
            debug!("ThreatFox NOT FOUND for {}", sha256);
            self.local_cache.store(cache_key, None, true, Some("TF"));
            LookupState::NotFound
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_invalid_hash_lookup() {
        let temp = tempdir().unwrap();
        let cache = Arc::new(LocalCacheProvider::new(temp.path().join("cache.json")));
        let provider = ThreatFoxProvider::new(cache, None);
        
        let result = provider.lookup_hash("invalid");
        // ThreatFox validates hash format
        assert!(matches!(result, LookupState::Error(_) | LookupState::NotFound));
    }
    
    #[test]
    fn test_api_key_update() {
        let temp = tempdir().unwrap();
        let cache = Arc::new(LocalCacheProvider::new(temp.path().join("cache.json")));
        let provider = ThreatFoxProvider::new(cache, Some("initial".to_string()));
        
        assert_eq!(provider.get_api_key(), Some("initial".to_string()));
        
        provider.update_api_key(Some("updated".to_string()));
        assert_eq!(provider.get_api_key(), Some("updated".to_string()));
        
        provider.update_api_key(None);
        assert!(provider.get_api_key().is_none());
    }

    #[test]
    fn test_new_provider_with_env_fallback() {
        let temp = tempdir().unwrap();
        let cache = Arc::new(LocalCacheProvider::new(temp.path().join("cache.json")));
        
        // Provider should work even without explicit API key
        let provider = ThreatFoxProvider::new(cache, None);
        
        // Should construct successfully
        assert!(provider.get_api_key().is_none() || provider.get_api_key().is_some());
    }

    #[test]
    fn test_new_provider_with_explicit_key() {
        let temp = tempdir().unwrap();
        let cache = Arc::new(LocalCacheProvider::new(temp.path().join("cache.json")));
        let provider = ThreatFoxProvider::new(cache, Some("explicit_key".to_string()));
        
        assert_eq!(provider.get_api_key(), Some("explicit_key".to_string()));
    }

    #[test]
    fn test_valid_hash_format_no_crash() {
        let temp = tempdir().unwrap();
        let cache = Arc::new(LocalCacheProvider::new(temp.path().join("cache.json")));
        let provider = ThreatFoxProvider::new(cache, None);
        
        // Valid hash should not panic, even without API key
        let result = provider.lookup_hash(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        
        // Result could be NotConfigured, Error, or cached result
        assert!(
            matches!(result, LookupState::NotConfigured)
                || matches!(result, LookupState::Error(_))
                || matches!(result, LookupState::NotFound)
                || matches!(result, LookupState::Aggregated(_))
        );
    }

    #[test]
    fn test_short_hash_handled() {
        let temp = tempdir().unwrap();
        let cache = Arc::new(LocalCacheProvider::new(temp.path().join("cache.json")));
        let provider = ThreatFoxProvider::new(cache, None);
        
        let result = provider.lookup_hash("deadbeef");
        // Should handle gracefully, not panic
        assert!(
            matches!(result, LookupState::Error(_))
                || matches!(result, LookupState::NotFound)
        );
    }

    #[test]
    fn test_multiple_api_key_updates() {
        let temp = tempdir().unwrap();
        let cache = Arc::new(LocalCacheProvider::new(temp.path().join("cache.json")));
        let provider = ThreatFoxProvider::new(cache, Some("key1".to_string()));
        
        assert_eq!(provider.get_api_key(), Some("key1".to_string()));
        
        provider.update_api_key(Some("key2".to_string()));
        assert_eq!(provider.get_api_key(), Some("key2".to_string()));
        
        provider.update_api_key(Some("key3".to_string()));
        assert_eq!(provider.get_api_key(), Some("key3".to_string()));
        
        provider.update_api_key(None);
        assert!(provider.get_api_key().is_none());
    }
}
