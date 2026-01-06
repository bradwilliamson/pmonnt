//! IOC to YARA rule generator
//! Converts ThreatFox IOCs into scannable YARA rules

use crate::yara::rules::{RuleSource, Severity, YaraRule};
use std::collections::HashMap;

/// Generate YARA rules from ThreatFox IOCs
pub struct IocToYaraGenerator;

impl IocToYaraGenerator {
    /// Convert ThreatFox IOCs to YARA rules
    pub fn generate_from_threatfox_iocs(iocs: &[ThreatFoxIoc]) -> Vec<YaraRule> {
        let mut rules = Vec::new();

        // Group IOCs by malware family
        let mut by_family: HashMap<String, Vec<&ThreatFoxIoc>> = HashMap::new();
        for ioc in iocs {
            if let Some(family) = &ioc.malware {
                // Filter out low confidence IOCs
                if ioc.confidence_level.unwrap_or(0) >= 50 {
                    by_family.entry(family.clone()).or_default().push(ioc);
                }
            }
        }

        // Generate one rule per malware family
        for (family, family_iocs) in by_family {
            let mut strings = Vec::new();

            for (idx, ioc) in family_iocs.iter().enumerate().take(50) {
                // Limit to 50 strings per rule for performance
                match ioc.ioc_type.as_str() {
                    "ip:port" => {
                        // Extract just the IP
                        if let Some(ip) = ioc.ioc_value.split(':').next() {
                            strings.push(format!("$ip{} = \"{}\"", idx, ip));
                        }
                    }
                    "domain" => {
                        strings.push(format!("$dom{} = \"{}\" nocase", idx, ioc.ioc_value));
                    }
                    "url" => {
                        // Extract domain from URL
                        if let Ok(url) = url::Url::parse(&ioc.ioc_value) {
                            if let Some(host) = url.host_str() {
                                strings.push(format!("$url{} = \"{}\" nocase", idx, host));
                            }
                        }
                    }
                    _ => {} // Skip hashes - not useful for memory scanning
                }
            }

            if !strings.is_empty() {
                let rule_name = sanitize_rule_name(&family);
                let rule_content = format!(
                    r#"rule TF_{rule_name} {{
    meta:
        description = "ThreatFox IOCs for {family}"
        author = "PMonNT Auto-Generated"
        source = "ThreatFox"
        generated = "{timestamp}"
        severity = "high"
    strings:
{strings}
    condition:
        any of them
}}"#,
                    rule_name = rule_name,
                    family = family,
                    timestamp = chrono::Utc::now().format("%Y-%m-%d"),
                    strings = strings
                        .iter()
                        .map(|s| format!("        {}", s))
                        .collect::<Vec<_>>()
                        .join("\n")
                );

                rules.push(YaraRule {
                    name: format!("TF_{}.yar", rule_name),
                    source: RuleSource::ThreatFoxGenerated,
                    content: rule_content,
                    description: Some(format!("Auto-generated from ThreatFox IOCs for {}", family)),
                    severity: Severity::High,
                    tags: vec![family.clone()],
                });
            }
        }

        rules
    }
}

pub fn sanitize_rule_name(name: &str) -> String {
    if name.is_empty() {
        return "unknown".to_string();
    }

    let mut result: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect();

    // Remove consecutive underscores
    let chars: Vec<char> = result.chars().collect();
    result.clear();
    let mut prev_underscore = false;
    for &c in &chars {
        if c == '_' {
            if !prev_underscore {
                result.push(c);
            }
            prev_underscore = true;
        } else {
            result.push(c);
            prev_underscore = false;
        }
    }

    // Remove trailing underscores
    while result.ends_with('_') && !result.is_empty() {
        result.pop();
    }

    // Handle empty result after sanitization
    if result.is_empty() {
        return "unknown".to_string();
    }

    // If starts with digit, prefix with underscore
    if result.chars().next().unwrap().is_ascii_digit() {
        format!("_{}", result)
    } else {
        result
    }
}

pub fn escape_yara_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

pub fn severity_from_confidence(conf: i32) -> Severity {
    match conf {
        c if c >= 90 => Severity::Critical,
        c if c >= 75 => Severity::High,
        c if c >= 50 => Severity::Medium,
        _ => Severity::Low,
    }
}

#[derive(Debug, Clone)]
pub struct ThreatFoxIoc {
    pub ioc_value: String,
    pub ioc_type: String,
    pub malware: Option<String>,
    pub confidence_level: Option<i32>,
}
