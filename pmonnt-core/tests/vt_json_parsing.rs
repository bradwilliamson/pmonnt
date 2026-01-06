use pmonnt_core::reputation::VtStats;

#[test]
fn vt_fixture_clean_parses_and_maps() {
    let stats: VtStats =
        pmonnt_core::vt::parse_vt_stats_from_json(include_str!("data/vt_hit_clean.json"))
            .expect("fixture should parse");

    assert_eq!(stats.malicious, 0);
    assert_eq!(stats.suspicious, 0);
    assert!(stats.total_detections() == 0);
    assert!(stats.total_engines() > 0);
    assert_eq!(stats.last_analysis_date, Some(1700000000));
}

#[test]
fn vt_fixture_malicious_parses_and_maps() {
    let stats: VtStats =
        pmonnt_core::vt::parse_vt_stats_from_json(include_str!("data/vt_hit_malicious.json"))
            .expect("fixture should parse");

    assert!(stats.malicious > 0);
    assert!(stats.total_detections() >= stats.malicious);
    assert!(stats.total_engines() >= stats.total_detections());
}

#[test]
fn vt_fixture_not_found_body_does_not_parse_as_vt_response() {
    let err =
        pmonnt_core::vt::parse_vt_stats_from_json(include_str!("data/vt_not_found_error.json"))
            .expect_err("error response is not a VT file lookup response");

    // Avoid locking to serde_json's exact error text.
    let msg = err.to_string();
    assert!(!msg.is_empty());
}

#[test]
fn vt_rate_limited_response_is_error() {
    let result =
        pmonnt_core::vt::parse_vt_stats_from_json(include_str!("data/vt_rate_limited.json"));
    
    // Rate limited response should not parse as a valid VT stats response
    assert!(result.is_err(), "rate limited response should fail to parse as VT stats");
}

#[test]
fn vt_unauthorized_response_is_error() {
    let result =
        pmonnt_core::vt::parse_vt_stats_from_json(include_str!("data/vt_unauthorized.json"));
    
    // Unauthorized response should not parse as a valid VT stats response
    assert!(result.is_err(), "unauthorized response should fail to parse as VT stats");
}
