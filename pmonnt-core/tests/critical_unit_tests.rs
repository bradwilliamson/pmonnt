use pmonnt_core::hashing::is_valid_sha256;
use pmonnt_core::reputation::{Verdict, VtStats};

// Verdict tests

#[test]
fn test_worst_verdict_single_element() {
    assert_eq!(
        Verdict::worst_verdict(&[Verdict::Malicious]),
        Verdict::Malicious
    );
    assert_eq!(Verdict::worst_verdict(&[Verdict::Clean]), Verdict::Clean);
    assert_eq!(
        Verdict::worst_verdict(&[Verdict::NotFound]),
        Verdict::NotFound
    );
}

#[test]
fn test_worst_verdict_duplicates() {
    let verdicts = vec![Verdict::Malicious, Verdict::Malicious];
    assert_eq!(Verdict::worst_verdict(&verdicts), Verdict::Malicious);
}

// VtStats tests

#[test]
fn test_vt_stats_all_zeros() {
    let stats = VtStats {
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
        last_analysis_date: None,
    };

    assert_eq!(stats.total_detections(), 0);
    assert_eq!(stats.total_engines(), 0);
}

#[test]
fn test_vt_stats_large_numbers() {
    let stats = VtStats {
        malicious: u32::MAX,
        suspicious: u32::MAX,
        harmless: u32::MAX,
        undetected: u32::MAX,
        last_analysis_date: None,
    };

    // Should not panic with overflow
    let _total_detections = stats.total_detections();
    let _total_engines = stats.total_engines();
}

// Hashing tests

#[test]
fn test_is_valid_sha256_empty_string() {
    assert!(!is_valid_sha256(""));
}

#[test]
fn test_is_valid_sha256_wrong_length() {
    assert!(!is_valid_sha256("deadbeef"));
}

#[test]
fn test_is_valid_sha256_with_spaces() {
    assert!(!is_valid_sha256(
        "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3 "
    ));
}

#[test]
fn test_is_valid_sha256_exactly_64_hex_with_newline() {
    let mut hash = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3".to_string();
    hash.push('\n');
    assert!(!is_valid_sha256(&hash));
}
