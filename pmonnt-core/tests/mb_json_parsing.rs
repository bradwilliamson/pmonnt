use pmonnt_core::providers::{MbRecentDetection, MbSampleInfo, MbTagInfoSample};
use serde_json::json;

#[test]
fn parse_get_info_ok_single_sample() {
    let j = r#"
    {
        "query_status": "ok",
        "data": [
            {
                "sha256_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "signature": "TrickBot",
                "tags": ["banking", "trickbot"],
                "first_seen": "2025-12-01",
                "last_seen": "2025-12-02",
                "file_name": "evil.exe",
                "file_type_mime": "application/x-msdos-program",
                "file_size": 12345,
                "vendor_intel": {"vendor": "ACME"},
                "yara_rules": [],
                "comments": []
            }
        ]
    }
    "#;

    let v: serde_json::Value = serde_json::from_str(j).unwrap();
    let data = v.get("data").and_then(|d| d.as_array()).unwrap();
    let sample: MbSampleInfo = serde_json::from_value(data[0].clone()).unwrap();
    assert_eq!(sample.sha256.len(), 64);
    assert_eq!(sample.signature.unwrap(), "TrickBot");
    assert_eq!(sample.tags.len(), 2);
}

#[test]
fn parse_get_info_hash_not_found() {
    let j = json!({"query_status": "hash_not_found", "data": []}).to_string();
    let v: serde_json::Value = serde_json::from_str(&j).unwrap();
    let qs = v.get("query_status").and_then(|s| s.as_str()).unwrap();
    assert_eq!(qs, "hash_not_found");
}

#[test]
fn parse_recent_detections_ok() {
    let j = r#"
    {
        "query_status": "ok",
        "data": [
            {"sha256_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "signature": "Foo", "first_seen": "2025-12-25"}
        ]
    }
    "#;
    let v: serde_json::Value = serde_json::from_str(j).unwrap();
    let data = v.get("data").and_then(|d| d.as_array()).unwrap();
    let dets: Vec<MbRecentDetection> = data
        .iter()
        .filter_map(|i| serde_json::from_value(i.clone()).ok())
        .collect();
    assert_eq!(dets.len(), 1);
    assert_eq!(dets[0].sha256_hash.len(), 64);
}

#[test]
fn parse_get_taginfo_variants() {
    // build a proper ok sample with two entries
    let ok_json = json!({
        "query_status": "ok",
        "data": [
            {"sha256_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "signature": "A", "first_seen": "2025-01-01"},
            {"sha256_hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "signature": "B", "first_seen": "2025-01-02"}
        ]
    }).to_string();

    let v: serde_json::Value = serde_json::from_str(&ok_json).unwrap();
    let data = v.get("data").and_then(|d| d.as_array()).unwrap();
    let samples: Vec<MbTagInfoSample> = data
        .iter()
        .filter_map(|i| serde_json::from_value(i.clone()).ok())
        .collect();
    assert_eq!(samples.len(), 2);

    let tn = json!({"query_status": "tag_not_found", "data": []}).to_string();
    let v2: serde_json::Value = serde_json::from_str(&tn).unwrap();
    assert_eq!(
        v2.get("query_status").and_then(|s| s.as_str()).unwrap(),
        "tag_not_found"
    );

    let nr = json!({"query_status": "no_results", "data": []}).to_string();
    let v3: serde_json::Value = serde_json::from_str(&nr).unwrap();
    assert_eq!(
        v3.get("query_status").and_then(|s| s.as_str()).unwrap(),
        "no_results"
    );
}

// ThreatFox parsing tests

#[test]
fn parse_threatfox_valid_response() {
    let j = r#"
    {
        "query_status": "ok",
        "data": [
            {
                "ioc_value": "evil.com",
                "ioc_type": "domain",
                "malware": "Emotet",
                "confidence_level": 85
            }
        ]
    }
    "#;

    let v: serde_json::Value = serde_json::from_str(j).unwrap();
    let qs = v.get("query_status").and_then(|s| s.as_str()).unwrap();
    assert_eq!(qs, "ok");

    let data = v.get("data").and_then(|d| d.as_array()).unwrap();
    assert_eq!(data.len(), 1);

    let ioc = &data[0];
    assert_eq!(
        ioc.get("ioc_value").and_then(|v| v.as_str()).unwrap(),
        "evil.com"
    );
    assert_eq!(
        ioc.get("ioc_type").and_then(|v| v.as_str()).unwrap(),
        "domain"
    );
    assert_eq!(
        ioc.get("malware").and_then(|v| v.as_str()).unwrap(),
        "Emotet"
    );
    assert_eq!(
        ioc.get("confidence_level")
            .and_then(|v| v.as_i64())
            .unwrap(),
        85
    );
}

#[test]
fn parse_threatfox_empty_data_array() {
    let j = json!({"query_status": "ok", "data": []}).to_string();
    let v: serde_json::Value = serde_json::from_str(&j).unwrap();
    let data = v.get("data").and_then(|d| d.as_array()).unwrap();
    assert_eq!(data.len(), 0);
}

#[test]
fn parse_threatfox_missing_data_field() {
    let j = json!({"query_status": "no_results"}).to_string();
    let v: serde_json::Value = serde_json::from_str(&j).unwrap();
    let qs = v.get("query_status").and_then(|s| s.as_str()).unwrap();
    assert_eq!(qs, "no_results");
    assert!(v.get("data").is_none());
}

#[test]
fn mb_malicious_hit_parses_correctly() {
    let json = include_str!("data/mb_hit_malicious.json");
    let v: serde_json::Value = serde_json::from_str(json).unwrap();
    let data = v.get("data").and_then(|d| d.as_array()).unwrap();
    let sample: MbSampleInfo = serde_json::from_value(data[0].clone()).unwrap();
    
    assert_eq!(sample.signature.as_deref(), Some("Emotet"));
    assert!(sample.tags.contains(&"emotet".to_string()));
    assert!(sample.tags.contains(&"trojan".to_string()));
    assert_eq!(sample.file_name.as_deref(), Some("emotet.exe"));
}

#[test]
fn mb_not_found_recognized() {
    let json = include_str!("data/mb_not_found.json");
    let v: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(
        v.get("query_status").and_then(|s| s.as_str()),
        Some("hash_not_found")
    );
    let data = v.get("data").and_then(|d| d.as_array()).unwrap();
    assert_eq!(data.len(), 0);
}

#[test]
fn mb_unauthorized_recognized() {
    let json = include_str!("data/mb_unauthorized.json");
    let v: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(
        v.get("query_status").and_then(|s| s.as_str()),
        Some("auth_error")
    );
}
