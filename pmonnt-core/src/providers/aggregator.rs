use crate::hashing::is_valid_sha256;
use crate::reputation::{
    AggregatedReputation, LookupState, ProviderFinding, ReputationProvider, Verdict,
};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Aggregator provider that queries multiple providers and merges results
pub struct AggregatorProvider {
    providers: Vec<Arc<dyn ReputationProvider>>,
    vt_enabled: AtomicBool,
    mb_enabled: AtomicBool,
    tf_enabled: AtomicBool,
}

impl AggregatorProvider {
    pub fn new(providers: Vec<Arc<dyn ReputationProvider>>) -> Self {
        Self {
            providers,
            vt_enabled: AtomicBool::new(true),
            mb_enabled: AtomicBool::new(true),
            tf_enabled: AtomicBool::new(true),
        }
    }

    /// Update provider enable flags at runtime
    pub fn update_provider_enabled(&self, vt_enabled: bool, mb_enabled: bool, tf_enabled: bool) {
        self.vt_enabled.store(vt_enabled, Ordering::Relaxed);
        self.mb_enabled.store(mb_enabled, Ordering::Relaxed);
        self.tf_enabled.store(tf_enabled, Ordering::Relaxed);
    }
}

impl ReputationProvider for AggregatorProvider {
    fn name(&self) -> &'static str {
        "AGG"
    }

    fn lookup_hash(&self, sha256: &str) -> LookupState {
        if !is_valid_sha256(sha256) {
            return LookupState::Error("Invalid SHA256 hash".to_string());
        }
        let mut findings = Vec::new();
        let mut errors = Vec::new();

        // Get enable flags
        let vt_enabled = self.vt_enabled.load(Ordering::Relaxed);
        let mb_enabled = self.mb_enabled.load(Ordering::Relaxed);
        let tf_enabled = self.tf_enabled.load(Ordering::Relaxed);

        for provider in &self.providers {
            let provider_name = provider.name();
            let should_query = match provider_name {
                "VT" => vt_enabled,
                "MB" => mb_enabled,
                "TF" => tf_enabled,
                _ => true, // Unknown providers enabled by default
            };

            if !should_query {
                continue;
            }

            match provider.lookup_hash(sha256) {
                LookupState::Aggregated(agg) => {
                    findings.extend(agg.findings);
                }
                LookupState::Hit(stats) => {
                    // Convert VT Hit to finding
                    // SAFETY: Use provider.name() to avoid hardcoding "VT"
                    let verdict = if stats.total_detections() == 0 {
                        Verdict::Clean
                    } else if stats.malicious > 0 {
                        Verdict::Malicious
                    } else if stats.suspicious > 0 {
                        Verdict::Suspicious
                    } else {
                        Verdict::Clean
                    };

                    let provider_name = provider.name();
                    let link = if provider_name == "VT" {
                        Some(format!(
                            "https://www.virustotal.com/gui/file/{}/detection",
                            sha256
                        ))
                    } else {
                        None // Non-VT providers shouldn't use VT link
                    };

                    let finding = ProviderFinding {
                        provider_name: provider_name.to_string(),
                        verdict,
                        link,
                        family: Some(format!(
                            "{}/{} detections",
                            stats.total_detections(),
                            stats.total_engines()
                        )),
                        confidence: None,
                    };
                    findings.push(finding);
                }
                LookupState::NotFound => {} // Not found, continue
                LookupState::Error(e) => errors.push(format!("{}: {}", provider.name(), e)),
                LookupState::NotConfigured => {} // Not configured, skip without error
                LookupState::Disabled => {}      // Disabled, skip without error
                LookupState::Offline => errors.push(format!("{}: offline", provider.name())),
                LookupState::Querying => {} // Skip if querying
                LookupState::Hashing => {}  // Skip
            }
        }

        if findings.is_empty() {
            if errors.is_empty() {
                return LookupState::NotFound;
            } else {
                return LookupState::Error(format!("All providers failed: {}", errors.join(", ")));
            }
        }

        // Merge findings
        let best_verdict = Verdict::worst_verdict(
            &findings
                .iter()
                .map(|f| f.verdict.clone())
                .collect::<Vec<_>>(),
        );

        // Build summary string
        let mut summary_parts = Vec::new();
        for finding in &findings {
            let part = match finding.verdict {
                Verdict::Malicious => {
                    if let Some(ref family) = finding.family {
                        if let Some(conf) = finding.confidence {
                            format!("{}: found ({}, {}%)", finding.provider_name, family, conf)
                        } else {
                            format!("{}: found ({})", finding.provider_name, family)
                        }
                    } else {
                        format!("{}: found", finding.provider_name)
                    }
                }
                Verdict::Suspicious => format!("{}: suspicious", finding.provider_name),
                Verdict::Clean => format!("{}: clean", finding.provider_name),
                Verdict::NotFound => continue,
            };
            summary_parts.push(part);
        }

        let summary = if summary_parts.is_empty() {
            "Not found".to_string()
        } else {
            summary_parts.join(" | ")
        };

        // Choose primary link (prefer VT, then MB, then TF)
        let primary_link = findings
            .iter()
            .find(|f| f.provider_name == "VT")
            .or_else(|| findings.iter().find(|f| f.provider_name == "MB"))
            .or_else(|| findings.iter().find(|f| f.provider_name == "TF"))
            .and_then(|f| f.link.clone());

        let agg = AggregatedReputation {
            findings,
            best_verdict,
            summary,
            primary_link,
        };

        LookupState::Aggregated(agg)
    }
}
