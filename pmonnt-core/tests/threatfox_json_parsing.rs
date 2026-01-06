use pmonnt_core::providers::{parse_threatfox_search_hash_response_json, TfIoc};

#[test]
fn threatfox_fixture_ok_parses() {
    let (iocs, meta) = parse_threatfox_search_hash_response_json(include_str!(
        "data/threatfox_search_hash_ok.json"
    ))
    .expect("fixture should parse");

    assert_eq!(meta.last_query.as_deref(), Some("search_hash"));
    assert_eq!(meta.last_query_status.as_deref(), Some("ok"));
    assert_eq!(meta.last_result_count, Some(1));

    let ioc: &TfIoc = &iocs[0];
    assert_eq!(ioc.id, "123456");
    assert_eq!(ioc.ioc.len(), 64);
    assert_eq!(ioc.ioc_type.as_deref(), Some("sha256_hash"));
    assert_eq!(ioc.malware.as_deref(), Some("Emotet"));
    assert_eq!(ioc.confidence_level, Some(85));
    assert_eq!(ioc.malware_samples.len(), 1);
}

#[test]
fn threatfox_fixture_no_results_string_maps_to_empty_list() {
    let (iocs, meta) = parse_threatfox_search_hash_response_json(include_str!(
        "data/threatfox_search_hash_no_results.json"
    ))
    .expect("fixture should parse");

    assert!(iocs.is_empty());
    assert_eq!(meta.last_query_status.as_deref(), Some("no_results"));
    assert_eq!(meta.last_result_count, Some(0));
    assert_eq!(meta.last_error_message.as_deref(), Some("no_results"));
}

#[test]
fn tf_rate_limited_recognized() {
    let json = include_str!("data/tf_rate_limited.json");
    let v: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(
        v.get("query_status").and_then(|s| s.as_str()),
        Some("rate_limit_exceeded")
    );
    let data = v.get("data").and_then(|d| d.as_array()).unwrap();
    assert_eq!(data.len(), 0);
}
