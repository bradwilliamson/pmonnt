use pmonnt_core::providers::aggregator::AggregatorProvider;
use pmonnt_core::reputation::{LookupState, ReputationProvider, Verdict, VtStats};
use std::sync::Arc;

struct MockProvider {
    name: &'static str,
    result: LookupState,
}

impl MockProvider {
    fn new(name: &'static str, result: LookupState) -> Self {
        Self { name, result }
    }
}

impl ReputationProvider for MockProvider {
    fn name(&self) -> &'static str {
        self.name
    }

    fn lookup_hash(&self, _sha256: &str) -> LookupState {
        self.result.clone()
    }
}

fn make_mock_provider(name: &'static str, result: LookupState) -> Arc<dyn ReputationProvider> {
    Arc::new(MockProvider::new(name, result))
}

#[test]
fn test_aggregator_single_provider_hit() {
    let mock = make_mock_provider(
        "VT",
        LookupState::Hit(VtStats {
            malicious: 1,
            suspicious: 0,
            harmless: 0,
            undetected: 0,
            last_analysis_date: None,
        }),
    );
    let aggregator = AggregatorProvider::new(vec![mock]);

    let result =
        aggregator.lookup_hash("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3");

    match result {
        LookupState::Aggregated(agg) => {
            assert_eq!(agg.findings.len(), 1);
            assert_eq!(agg.findings[0].provider_name, "VT");
            assert_eq!(agg.findings[0].verdict, Verdict::Malicious);
            assert_eq!(agg.best_verdict, Verdict::Malicious);
        }
        _ => panic!("Expected Aggregated result"),
    }
}

#[test]
fn test_aggregator_single_provider_not_found() {
    let mock = make_mock_provider("VT", LookupState::NotFound);
    let aggregator = AggregatorProvider::new(vec![mock]);

    let result =
        aggregator.lookup_hash("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3");

    assert!(matches!(result, LookupState::NotFound));
}

#[test]
fn test_aggregator_multiple_providers_worst_verdict_wins() {
    let clean_provider = make_mock_provider(
        "VT",
        LookupState::Hit(VtStats {
            malicious: 0,
            suspicious: 0,
            harmless: 1,
            undetected: 0,
            last_analysis_date: None,
        }),
    );
    let malicious_provider = make_mock_provider(
        "MB",
        LookupState::Hit(VtStats {
            malicious: 1,
            suspicious: 0,
            harmless: 0,
            undetected: 0,
            last_analysis_date: None,
        }),
    );

    let aggregator = AggregatorProvider::new(vec![clean_provider, malicious_provider]);

    let result =
        aggregator.lookup_hash("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3");

    match result {
        LookupState::Aggregated(agg) => {
            assert_eq!(agg.findings.len(), 2);
            assert_eq!(agg.best_verdict, Verdict::Malicious);
        }
        _ => panic!("Expected Aggregated result"),
    }
}

#[test]
fn test_aggregator_provider_disable_flags() {
    let vt_provider = make_mock_provider(
        "VT",
        LookupState::Hit(VtStats {
            malicious: 1,
            suspicious: 0,
            harmless: 0,
            undetected: 0,
            last_analysis_date: None,
        }),
    );
    let mb_provider = make_mock_provider(
        "MB",
        LookupState::Hit(VtStats {
            malicious: 0,
            suspicious: 0,
            harmless: 1,
            undetected: 0,
            last_analysis_date: None,
        }),
    );

    let aggregator = AggregatorProvider::new(vec![vt_provider, mb_provider]);
    aggregator.update_provider_enabled(false, true, true); // Disable VT

    let result =
        aggregator.lookup_hash("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3");

    match result {
        LookupState::Aggregated(agg) => {
            assert_eq!(agg.findings.len(), 1);
            assert_eq!(agg.findings[0].provider_name, "MB");
            assert_eq!(agg.best_verdict, Verdict::Clean);
        }
        _ => panic!("Expected Aggregated result"),
    }
}

#[test]
fn test_aggregator_all_providers_error() {
    let error_provider1 = make_mock_provider("VT", LookupState::Error("Network error".to_string()));
    let error_provider2 = make_mock_provider("MB", LookupState::Error("API error".to_string()));

    let aggregator = AggregatorProvider::new(vec![error_provider1, error_provider2]);

    let result =
        aggregator.lookup_hash("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3");

    match result {
        LookupState::Error(msg) => {
            assert!(msg.contains("All providers failed"));
        }
        _ => panic!("Expected Error result"),
    }
}

#[test]
fn test_aggregator_invalid_sha256() {
    let mock = make_mock_provider(
        "VT",
        LookupState::Hit(VtStats {
            malicious: 1,
            suspicious: 0,
            harmless: 0,
            undetected: 0,
            last_analysis_date: None,
        }),
    );
    let aggregator = AggregatorProvider::new(vec![mock]);

    let result = aggregator.lookup_hash("not-a-hash");

    match result {
        LookupState::Error(msg) => {
            assert!(msg.contains("Invalid SHA256 hash"));
        }
        _ => panic!("Expected Error result"),
    }
}

#[test]
fn test_aggregator_link_priority_vt_preferred() {
    let vt_provider = make_mock_provider(
        "VT",
        LookupState::Hit(VtStats {
            malicious: 1,
            suspicious: 0,
            harmless: 0,
            undetected: 0,
            last_analysis_date: None,
        }),
    );
    let mb_provider = make_mock_provider(
        "MB",
        LookupState::Hit(VtStats {
            malicious: 1,
            suspicious: 0,
            harmless: 0,
            undetected: 0,
            last_analysis_date: None,
        }),
    );

    let aggregator = AggregatorProvider::new(vec![vt_provider, mb_provider]);

    let result =
        aggregator.lookup_hash("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3");

    match result {
        LookupState::Aggregated(agg) => {
            assert!(agg.primary_link.is_some());
            let link = agg.primary_link.unwrap();
            assert!(link.contains("virustotal.com"));
        }
        _ => panic!("Expected Aggregated result"),
    }
}

#[test]
fn test_aggregator_empty_providers_list() {
    let aggregator = AggregatorProvider::new(vec![]);

    let result =
        aggregator.lookup_hash("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3");

    assert!(matches!(result, LookupState::NotFound));
}
