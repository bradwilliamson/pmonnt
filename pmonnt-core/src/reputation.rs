//! Reputation data model and provider interface for hash lookups

use serde::{Deserialize, Serialize};
use std::fmt;

/// Statistics from VirusTotal analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtStats {
    pub malicious: u32,
    pub suspicious: u32,
    pub harmless: u32,
    pub undetected: u32,
    pub last_analysis_date: Option<i64>,
}

impl VtStats {
    pub fn total_detections(&self) -> u32 {
        self.malicious.saturating_add(self.suspicious)
    }

    pub fn total_engines(&self) -> u32 {
        self.malicious
            .saturating_add(self.suspicious)
            .saturating_add(self.harmless)
            .saturating_add(self.undetected)
    }
}

/// Finding from a single reputation provider
#[derive(Debug, Clone)]
pub struct ProviderFinding {
    pub provider_name: String,
    pub verdict: Verdict,
    pub link: Option<String>,
    pub family: Option<String>,
    pub confidence: Option<u32>, // 0-100
}

/// Verdict from a provider
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    NotFound,
    Clean,
    Suspicious,
    Malicious,
}

impl Verdict {
    /// Get the "worst" verdict from a list (Malicious > Suspicious > Clean > NotFound)
    pub fn worst_verdict(verdicts: &[Verdict]) -> Verdict {
        verdicts
            .iter()
            .max_by_key(|v| match v {
                Verdict::NotFound => 0,
                Verdict::Clean => 1,
                Verdict::Suspicious => 2,
                Verdict::Malicious => 3,
            })
            .cloned()
            .unwrap_or(Verdict::NotFound)
    }
}

/// Aggregated reputation result from multiple providers
#[derive(Debug, Clone)]
pub struct AggregatedReputation {
    pub findings: Vec<ProviderFinding>,
    pub best_verdict: Verdict,
    pub summary: String,
    pub primary_link: Option<String>,
}

/// Current state of a reputation lookup
#[derive(Debug, Clone)]
pub enum LookupState {
    /// Computing file hash (off UI thread)
    Hashing,
    /// No API key configured
    NotConfigured,
    /// Online lookups disabled by user
    Disabled,
    /// Network unavailable or blocked
    Offline,
    /// Currently querying remote provider
    Querying,
    /// Found result (may be cached or live)
    Hit(VtStats),
    /// Hash not found in provider database
    NotFound,
    /// Error occurred (transient or permanent)
    Error(String),
    /// Multi-provider aggregated result
    Aggregated(AggregatedReputation),
}

impl fmt::Display for LookupState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LookupState::Hashing => write!(f, "Hashing..."),
            LookupState::NotConfigured => write!(f, "Not configured"),
            LookupState::Disabled => write!(f, "Disabled"),
            LookupState::Offline => write!(f, "Offline"),
            LookupState::Querying => write!(f, "Querying..."),
            LookupState::Hit(stats) => write!(
                f,
                "{}/{} detections",
                stats.total_detections(),
                stats.total_engines()
            ),
            LookupState::NotFound => write!(f, "Not found"),
            LookupState::Error(e) => write!(f, "Error: {}", e),
            LookupState::Aggregated(agg) => write!(f, "{}", agg.summary),
        }
    }
}

/// Trait for reputation providers (local cache, VirusTotal, etc.)
///
/// # Thread Safety
/// All implementations MUST be `Send + Sync` as they are accessed from background
/// reputation service threads and the UI thread concurrently. The implementation
/// is responsible for proper synchronization (mutexes, atomics, etc.).
///
/// # Cancellation
/// If implementing online lookups, use a timeout mechanism to avoid blocking
/// the reputation service thread indefinitely.
pub trait ReputationProvider: Send + Sync {
    /// Provider name for display
    fn name(&self) -> &'static str;

    /// Look up a SHA-256 hash and return current state
    fn lookup_hash(&self, sha256: &str) -> LookupState;
}
