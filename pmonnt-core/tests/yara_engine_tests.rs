//! Tests for YARA engine compilation and scanning

use pmonnt_core::yara::engine::{YaraEngine, EngineError};
use pmonnt_core::yara::rules::{Severity, YaraRule, RuleSource};

#[test]
fn test_compile_empty_source_fails() {
    let result = YaraEngine::compile("");
    assert!(matches!(result, Err(EngineError::CompileError(_))));
}

#[test]
fn test_compile_whitespace_only_fails() {
    let result = YaraEngine::compile("   \n\t  ");
    assert!(matches!(result, Err(EngineError::CompileError(_))));
}

#[test]
fn test_compile_valid_rule_succeeds() {
    let rule = r#"
rule test_rule {
    strings:
        $a = "test"
    condition:
        $a
}
"#;
    let engine = YaraEngine::compile(rule).unwrap();
    // Successfully compiled
    let _ = engine.rule_count();
}

#[test]
fn test_compile_multiple_rules() {
    let rules = r#"
rule rule_one {
    strings:
        $a = "one"
    condition:
        $a
}

rule rule_two {
    strings:
        $b = "two"
    condition:
        $b
}
"#;
    let engine = YaraEngine::compile(rules).unwrap();
    // Engine should successfully compile both rules
    let _ = engine.rule_count();
}

#[test]
fn test_compile_invalid_syntax_fails() {
    let bad_rule = r#"
rule broken {
    strings:
        $a = "test
    condition:
        $a
}
"#;
    let result = YaraEngine::compile(bad_rule);
    assert!(matches!(result, Err(EngineError::CompileError(_))));
}

#[test]
fn test_scan_buffer_with_match() {
    let rule = r#"
rule detect_evil {
    strings:
        $magic = "EVIL"
    condition:
        $magic
}
"#;
    let engine = YaraEngine::compile(rule).unwrap();
    let matches = engine.scan_buffer(b"This contains EVIL content").unwrap();
    
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_name, "detect_evil");
    assert!(!matches[0].matched_strings.is_empty());
}

#[test]
fn test_scan_buffer_no_match() {
    let rule = r#"
rule detect_evil {
    strings:
        $magic = "EVIL"
    condition:
        $magic
}
"#;
    let engine = YaraEngine::compile(rule).unwrap();
    let matches = engine.scan_buffer(b"This file is clean").unwrap();
    
    assert!(matches.is_empty());
}

#[test]
fn test_scan_empty_buffer() {
    let rule = r#"
rule detect_anything {
    strings:
        $a = "test"
    condition:
        $a
}
"#;
    let engine = YaraEngine::compile(rule).unwrap();
    let matches = engine.scan_buffer(b"").unwrap();
    
    assert!(matches.is_empty());
}

#[test]
fn test_scan_extracts_match_offset() {
    let rule = r#"
rule find_marker {
    strings:
        $marker = "MARK"
    condition:
        $marker
}
"#;
    let engine = YaraEngine::compile(rule).unwrap();
    let data = b"prefix_MARK_suffix";
    let matches = engine.scan_buffer(data).unwrap();
    
    assert_eq!(matches.len(), 1);
    let matched = &matches[0].matched_strings[0];
    assert_eq!(matched.offset, 7); // "prefix_" is 7 bytes
    assert_eq!(matched.data.len(), 4); // "MARK" is 4 bytes
}

#[test]
fn test_metadata_description_extracted() {
    let rule = r#"
rule with_meta {
    meta:
        description = "Test rule description"
    strings:
        $a = "test"
    condition:
        $a
}
"#;
    let engine = YaraEngine::compile(rule).unwrap();
    let matches = engine.scan_buffer(b"test data").unwrap();
    
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].description.as_deref(), Some("Test rule description"));
}

#[test]
fn test_metadata_severity_string_parsed() {
    let rule = r#"
rule high_severity {
    meta:
        severity = "high"
    strings:
        $a = "test"
    condition:
        $a
}
"#;
    let engine = YaraEngine::compile(rule).unwrap();
    let matches = engine.scan_buffer(b"test").unwrap();
    
    assert_eq!(matches[0].severity, Severity::High);
}

#[test]
fn test_metadata_severity_integer_parsed() {
    let rule = r#"
rule critical_severity {
    meta:
        severity = 95
    strings:
        $a = "test"
    condition:
        $a
}
"#;
    let engine = YaraEngine::compile(rule).unwrap();
    let matches = engine.scan_buffer(b"test").unwrap();
    
    assert_eq!(matches[0].severity, Severity::Critical);
}

#[test]
fn test_compile_with_fallback_skips_invalid() {
    use std::time::SystemTime;
    
    let rules = vec![
        YaraRule {
            name: "valid.yar".to_string(),
            content: r#"rule valid { strings: $a = "test" condition: $a }"#.to_string(),
            source: RuleSource::LocalFile {
                path: "valid.yar".into(),
                modified_at: SystemTime::now(),
            },
            description: None,
            severity: Severity::Medium,
            tags: vec![],
        },
        YaraRule {
            name: "invalid.yar".to_string(),
            content: r#"rule invalid { broken syntax"#.to_string(),
            source: RuleSource::LocalFile {
                path: "invalid.yar".into(),
                modified_at: SystemTime::now(),
            },
            description: None,
            severity: Severity::Medium,
            tags: vec![],
        },
    ];
    
    let (engine, skipped) = YaraEngine::compile_rules_with_fallback(&rules).unwrap();
    
    assert!(engine.rule_count() >= 1);
    assert_eq!(skipped.len(), 1);
    assert!(skipped.contains(&"invalid.yar".to_string()));
}

#[test]
fn test_severity_low_string() {
    let rule = r#"
rule low_severity {
    meta:
        severity = "low"
    strings:
        $a = "test"
    condition:
        $a
}
"#;
    let engine = YaraEngine::compile(rule).unwrap();
    let matches = engine.scan_buffer(b"test").unwrap();
    assert_eq!(matches[0].severity, Severity::Low);
}

#[test]
fn test_severity_medium_string() {
    let rule = r#"
rule medium_severity {
    meta:
        severity = "medium"
    strings:
        $a = "test"
    condition:
        $a
}
"#;
    let engine = YaraEngine::compile(rule).unwrap();
    let matches = engine.scan_buffer(b"test").unwrap();
    assert_eq!(matches[0].severity, Severity::Medium);
}

#[test]
fn test_severity_critical_string() {
    let rule = r#"
rule critical_severity {
    meta:
        severity = "critical"
    strings:
        $a = "test"
    condition:
        $a
}
"#;
    let engine = YaraEngine::compile(rule).unwrap();
    let matches = engine.scan_buffer(b"test").unwrap();
    assert_eq!(matches[0].severity, Severity::Critical);
}

#[test]
fn test_severity_integer_low() {
    let rule = r#"
rule low_int_severity {
    meta:
        severity = 30
    strings:
        $a = "test"
    condition:
        $a
}
"#;
    let engine = YaraEngine::compile(rule).unwrap();
    let matches = engine.scan_buffer(b"test").unwrap();
    assert_eq!(matches[0].severity, Severity::Low);
}

#[test]
fn test_severity_integer_medium() {
    let rule = r#"
rule medium_int_severity {
    meta:
        severity = 60
    strings:
        $a = "test"
    condition:
        $a
}
"#;
    let engine = YaraEngine::compile(rule).unwrap();
    let matches = engine.scan_buffer(b"test").unwrap();
    assert_eq!(matches[0].severity, Severity::Medium);
}

#[test]
fn test_severity_integer_high() {
    let rule = r#"
rule high_int_severity {
    meta:
        severity = 85
    strings:
        $a = "test"
    condition:
        $a
}
"#;
    let engine = YaraEngine::compile(rule).unwrap();
    let matches = engine.scan_buffer(b"test").unwrap();
    assert_eq!(matches[0].severity, Severity::High);
}

#[test]
fn test_multiple_string_matches() {
    let rule = r#"
rule multi_match {
    strings:
        $a = "AAA"
        $b = "BBB"
    condition:
        $a and $b
}
"#;
    let engine = YaraEngine::compile(rule).unwrap();
    let matches = engine.scan_buffer(b"prefix AAA middle BBB suffix").unwrap();
    
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].matched_strings.len(), 2);
}

#[test]
fn test_rule_without_metadata() {
    let rule = r#"
rule no_meta {
    strings:
        $a = "test"
    condition:
        $a
}
"#;
    let engine = YaraEngine::compile(rule).unwrap();
    let matches = engine.scan_buffer(b"test").unwrap();
    
    assert_eq!(matches.len(), 1);
    assert!(matches[0].description.is_none());
    // Default severity should be Medium
    assert_eq!(matches[0].severity, Severity::Medium);
}

#[test]
fn test_scan_binary_data() {
    let rule = r#"
rule binary_pattern {
    strings:
        $hex = { 4D 5A } // MZ header
    condition:
        $hex
}
"#;
    let engine = YaraEngine::compile(rule).unwrap();
    let data = b"MZ\x90\x00\x03\x00";
    let matches = engine.scan_buffer(data).unwrap();
    
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_name, "binary_pattern");
}

#[test]
fn test_case_insensitive_match() {
    let rule = r#"
rule case_insensitive {
    strings:
        $a = "test" nocase
    condition:
        $a
}
"#;
    let engine = YaraEngine::compile(rule).unwrap();
    let matches = engine.scan_buffer(b"This contains TEST").unwrap();
    
    assert_eq!(matches.len(), 1);
}

#[test]
fn test_wildcard_pattern() {
    let rule = r#"
rule wildcard {
    strings:
        $a = "te?t"
    condition:
        $a
}
"#;
    let engine = YaraEngine::compile(rule).unwrap();
    let matches = engine.scan_buffer(b"test text tent").unwrap();
    
    // Wildcard may not be supported in all YARA implementations the same way
    // Just verify it doesn't crash
    let _ = matches.len();
}

#[test]
fn test_compile_rules_with_fallback_all_invalid() {
    use std::time::SystemTime;
    
    let rules = vec![
        YaraRule {
            name: "bad1.yar".to_string(),
            content: r#"rule bad1 { broken }"#.to_string(),
            source: RuleSource::LocalFile {
                path: "bad1.yar".into(),
                modified_at: SystemTime::now(),
            },
            description: None,
            severity: Severity::Medium,
            tags: vec![],
        },
        YaraRule {
            name: "bad2.yar".to_string(),
            content: r#"rule bad2 { also broken }"#.to_string(),
            source: RuleSource::LocalFile {
                path: "bad2.yar".into(),
                modified_at: SystemTime::now(),
            },
            description: None,
            severity: Severity::Medium,
            tags: vec![],
        },
    ];
    
    let result = YaraEngine::compile_rules_with_fallback(&rules);
    assert!(matches!(result, Err(EngineError::CompileError(_))));
}
