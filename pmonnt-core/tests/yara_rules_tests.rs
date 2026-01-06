use pmonnt_core::yara::rules::{has_unsupported_modules, RuleManager};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_yara_rules_skip_unsupported_module_magic() {
    let rule_content = r#"
import "magic"

rule test_rule {
    strings:
        $a = "test"
    condition:
        $a
}
"#;

    assert!(has_unsupported_modules(rule_content));
}

#[test]
fn test_yara_rules_skip_unsupported_module_cuckoo() {
    let rule_content = r#"
import "cuckoo"

rule test_rule {
    strings:
        $a = "test"
    condition:
        $a
}
"#;

    assert!(has_unsupported_modules(rule_content));
}

#[test]
fn test_yara_rules_load_supported_module_pe() {
    let rule_content = r#"
import "pe"

rule test_rule {
    strings:
        $a = "test"
    condition:
        $a
}
"#;

    assert!(!has_unsupported_modules(rule_content));
}

#[test]
fn test_yara_rules_false_positive_import_in_string() {
    let rule_content = r#"
rule test_rule {
    strings:
        $a = "import magic"
    condition:
        $a
}
"#;

    assert!(!has_unsupported_modules(rule_content));
}

#[test]
fn test_yara_rules_skip_syntactically_invalid() {
    let temp_dir = tempdir().unwrap();
    let rule_file = temp_dir.path().join("invalid.yar");

    let invalid_rule = r#"
rule invalid_rule {
    strings:
        $a = "test"
    condition:
        $a and undefined_var
}
"#;

    fs::write(&rule_file, invalid_rule).unwrap();

    let mut manager = RuleManager::new(temp_dir.path().to_path_buf());
    let count = manager.load_cached_rules().unwrap();

    // Should skip the invalid rule
    assert_eq!(count, 0);
}

#[test]
fn test_yara_rules_ignore_non_yar_files() {
    let temp_dir = tempdir().unwrap();
    let txt_file = temp_dir.path().join("notarule.txt");
    let yar_file = temp_dir.path().join("valid.yar");

    fs::write(&txt_file, "not a rule").unwrap();

    let valid_rule = r#"
rule valid_rule {
    strings:
        $a = "test"
    condition:
        $a
}
"#;
    fs::write(&yar_file, valid_rule).unwrap();

    let mut manager = RuleManager::new(temp_dir.path().to_path_buf());
    let count = manager.load_cached_rules().unwrap();

    // Should load only the .yar file, ignore .txt
    assert_eq!(count, 1);
}

#[test]
fn test_yara_rules_filename_sanitization() {
    let temp_dir = tempdir().unwrap();
    let rule_file = temp_dir.path().join("test_rule.yar");

    let valid_rule = r#"
rule test_rule {
    strings:
        $a = "test"
    condition:
        $a
}
"#;

    fs::write(&rule_file, valid_rule).unwrap();

    let mut manager = RuleManager::new(temp_dir.path().to_path_buf());
    let count = manager.load_cached_rules().unwrap();

    // Should load the rule
    assert_eq!(count, 1);
    assert_eq!(manager.rules[0].name, "test_rule.yar");
}

#[test]
fn test_yara_rules_combined_source() {
    let temp_dir = tempdir().unwrap();
    let rule_file1 = temp_dir.path().join("rule1.yar");
    let rule_file2 = temp_dir.path().join("rule2.yar");

    let rule1 = r#"
rule rule1 {
    strings:
        $a = "test1"
    condition:
        $a
}
"#;

    let rule2 = r#"
rule rule2 {
    strings:
        $a = "test2"
    condition:
        $a
}
"#;

    fs::write(&rule_file1, rule1).unwrap();
    fs::write(&rule_file2, rule2).unwrap();

    let mut manager = RuleManager::new(temp_dir.path().to_path_buf());
    manager.load_cached_rules().unwrap();

    let combined = manager.combined_source();
    assert!(combined.contains(rule1.trim()));
    assert!(combined.contains(rule2.trim()));
    assert!(combined.contains("\n\n")); // Should join with \n\n
}
