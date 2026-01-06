//! Tests for IOC to YARA rule generator

use pmonnt_core::yara::ioc_generator::{
    escape_yara_string, sanitize_rule_name, severity_from_confidence, IocToYaraGenerator,
    ThreatFoxIoc,
};
use pmonnt_core::yara::rules::Severity;

#[test]
fn test_escape_yara_string_backslash() {
    assert_eq!(escape_yara_string(r"C:\Windows"), r"C:\\Windows");
}

#[test]
fn test_escape_yara_string_quotes() {
    assert_eq!(escape_yara_string(r#"say "hi""#), r#"say \"hi\""#);
}

#[test]
fn test_escape_yara_string_both() {
    assert_eq!(escape_yara_string(r#""C:\test""#), r#"\"C:\\test\""#);
}

#[test]
fn test_escape_yara_string_no_special_chars() {
    assert_eq!(escape_yara_string("normal_string"), "normal_string");
}

#[test]
fn test_sanitize_rule_name_spaces() {
    assert_eq!(sanitize_rule_name("Cobalt Strike"), "Cobalt_Strike");
}

#[test]
fn test_sanitize_rule_name_special_chars() {
    assert_eq!(sanitize_rule_name("Agent.Tesla/v2"), "Agent_Tesla_v2");
}

#[test]
fn test_sanitize_rule_name_consecutive_underscores() {
    assert_eq!(sanitize_rule_name("Mal---ware"), "Mal_ware");
}

#[test]
fn test_sanitize_rule_name_trailing_underscore() {
    assert_eq!(sanitize_rule_name("Test_"), "Test");
}

#[test]
fn test_sanitize_rule_name_empty() {
    assert_eq!(sanitize_rule_name(""), "unknown");
}

#[test]
fn test_sanitize_rule_name_all_invalid() {
    assert_eq!(sanitize_rule_name("!@#$%^&*()"), "unknown");
}

#[test]
fn test_sanitize_rule_name_starts_with_number() {
    assert_eq!(sanitize_rule_name("123mal"), "_123mal");
}

#[test]
fn test_severity_from_confidence_critical() {
    assert_eq!(severity_from_confidence(90), Severity::Critical);
    assert_eq!(severity_from_confidence(100), Severity::Critical);
}

#[test]
fn test_severity_from_confidence_high() {
    assert_eq!(severity_from_confidence(75), Severity::High);
    assert_eq!(severity_from_confidence(89), Severity::High);
}

#[test]
fn test_severity_from_confidence_medium() {
    assert_eq!(severity_from_confidence(50), Severity::Medium);
    assert_eq!(severity_from_confidence(74), Severity::Medium);
}

#[test]
fn test_severity_from_confidence_low() {
    assert_eq!(severity_from_confidence(49), Severity::Low);
    assert_eq!(severity_from_confidence(0), Severity::Low);
}

#[test]
fn test_generate_empty_iocs() {
    let rules = IocToYaraGenerator::generate_from_threatfox_iocs(&[]);
    assert!(rules.is_empty());
}

fn make_ioc(value: &str, ioc_type: &str, malware: Option<&str>, conf: i32) -> ThreatFoxIoc {
    ThreatFoxIoc {
        ioc_value: value.to_string(),
        ioc_type: ioc_type.to_string(),
        malware: malware.map(|s| s.to_string()),
        confidence_level: Some(conf),
    }
}

#[test]
fn test_generate_filters_low_confidence() {
    let iocs = vec![make_ioc("evil.com", "domain", Some("Emotet"), 30)];
    let rules = IocToYaraGenerator::generate_from_threatfox_iocs(&iocs);
    assert!(rules.is_empty()); // conf 30 < threshold 50
}

#[test]
fn test_generate_groups_by_malware_family() {
    let iocs = vec![
        make_ioc("evil1.com", "domain", Some("Emotet"), 80),
        make_ioc("evil2.com", "domain", Some("Emotet"), 85),
        make_ioc("bad.com", "domain", Some("TrickBot"), 90),
    ];
    let rules = IocToYaraGenerator::generate_from_threatfox_iocs(&iocs);
    assert_eq!(rules.len(), 2); // Two families
    let emotet_rule = rules.iter().find(|r| r.name.contains("Emotet")).unwrap();
    let trickbot_rule = rules.iter().find(|r| r.name.contains("TrickBot")).unwrap();
    assert!(emotet_rule.content.contains("$dom0"));
    assert!(emotet_rule.content.contains("$dom1"));
    assert!(trickbot_rule.content.contains("$dom0"));
}

#[test]
fn test_generate_max_strings_per_rule() {
    let mut iocs = Vec::new();
    for i in 0..60 {
        iocs.push(make_ioc(
            &format!("evil{}.com", i),
            "domain",
            Some("Emotet"),
            80,
        ));
    }
    let rules = IocToYaraGenerator::generate_from_threatfox_iocs(&iocs);
    assert_eq!(rules.len(), 1);
    let rule = &rules[0];
    // Should contain exactly 50 strings (max per rule)
    let string_count = rule.content.matches("$dom").count();
    assert_eq!(string_count, 50);
}

#[test]
fn test_generate_defanging_normalized() {
    let iocs = vec![make_ioc("evil[.]com", "domain", Some("Emotet"), 80)];
    let rules = IocToYaraGenerator::generate_from_threatfox_iocs(&iocs);
    assert_eq!(rules.len(), 1);
    assert!(rules[0].content.contains(r#"$dom0 = "evil[.]com" nocase"#));
}
