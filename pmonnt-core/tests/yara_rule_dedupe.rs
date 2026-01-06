use pmonnt_core::yara::rules::{RuleManager, RuleSource, Severity, YaraRule};

#[test]
fn threatfox_apply_rules_is_idempotent_per_refresh() {
    let dir = tempfile::tempdir().unwrap();
    let mut mgr = RuleManager::new(dir.path().to_path_buf());

    let rules = vec![
        YaraRule {
            name: "tf_rule_a.yar".to_string(),
            source: RuleSource::ThreatFoxGenerated,
            content: "rule tf_a { condition: true }".to_string(),
            description: None,
            severity: Severity::High,
            tags: vec![],
        },
        YaraRule {
            name: "tf_rule_b.yar".to_string(),
            source: RuleSource::ThreatFoxGenerated,
            content: "rule tf_b { condition: true }".to_string(),
            description: None,
            severity: Severity::High,
            tags: vec![],
        },
    ];

    let applied_1 = mgr.apply_threatfox_rules(rules.clone());
    assert_eq!(applied_1, 2);
    assert_eq!(
        mgr.rules()
            .iter()
            .filter(|r| matches!(r.source, RuleSource::ThreatFoxGenerated))
            .count(),
        2
    );

    // Apply same refresh again; should not accumulate duplicates.
    let applied_2 = mgr.apply_threatfox_rules(rules);
    assert_eq!(applied_2, 2);
    assert_eq!(
        mgr.rules()
            .iter()
            .filter(|r| matches!(r.source, RuleSource::ThreatFoxGenerated))
            .count(),
        2
    );

    // Ordering stays stable (rules are replaced then extended in input order).
    let combined = mgr.combined_source();
    assert!(combined.contains("rule tf_a"));
    assert!(combined.contains("rule tf_b"));
    assert!(combined.find("rule tf_a") < combined.find("rule tf_b"));
}
