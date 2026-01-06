//! YARA compilation and scanning engine using yara-x

use crate::yara::rules::{RuleManager, Severity};
use std::time::Duration;
use thiserror::Error;
use yara_x;

#[derive(Debug)]
pub struct YaraEngine {
    rules: yara_x::Rules,
    rule_count: usize,
}

#[derive(Debug, Clone)]
pub struct YaraMatch {
    pub rule_name: String,
    pub rule_tags: Vec<String>,
    pub description: Option<String>,
    pub severity: Severity,
    pub matched_strings: Vec<MatchedString>,
}

#[derive(Debug, Clone)]
pub struct MatchedString {
    pub identifier: String,
    pub offset: usize,
    pub match_length: usize,
    pub data: Vec<u8>,
    pub data_preview: String,
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("Failed to compile rules: {0}")]
    CompileError(String),
    #[error("Scan error: {0}")]
    ScanError(String),
}

const MAX_MATCH_BYTES: usize = 128;
const PREVIEW_BYTES: usize = 32;

impl YaraEngine {
    pub fn compile(source: &str) -> Result<Self, EngineError> {
        if source.trim().is_empty() {
            return Err(EngineError::CompileError("No rules provided".into()));
        }

        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(source)
            .map_err(|e| EngineError::CompileError(e.to_string()))?;

        let rules = compiler.build();
        let rule_count = rules.iter().count();

        Ok(Self { rules, rule_count })
    }

    pub fn compile_rules_with_fallback(
        rules: &[crate::yara::rules::YaraRule],
    ) -> Result<(Self, Vec<String>), EngineError> {
        let mut compiler = yara_x::Compiler::new();
        let mut skipped = Vec::new();

        for rule in rules {
            if let Err(e) = compiler.add_source(rule.content.as_str()) {
                log::warn!("Skipping rule '{}': {}", rule.name, e);
                skipped.push(rule.name.clone());
            }
        }

        let rules_compiled = compiler.build();
        let rule_count = rules_compiled.iter().count();

        if rule_count == 0 {
            return Err(EngineError::CompileError(
                "No valid rules to compile".into(),
            ));
        }

        Ok((
            Self {
                rules: rules_compiled,
                rule_count,
            },
            skipped,
        ))
    }

    pub fn from_rule_manager(manager: &RuleManager) -> Result<Self, EngineError> {
        let (engine, skipped) = Self::compile_rules_with_fallback(manager.rules())?;
        if !skipped.is_empty() {
            log::info!(
                "Compiled {} rules successfully, skipped {} with unsupported modules",
                engine.rule_count,
                skipped.len()
            );
        }
        Ok(engine)
    }

    /// Convenience wrapper: scan without a timeout.
    pub fn scan_buffer(&self, data: &[u8]) -> Result<Vec<YaraMatch>, EngineError> {
        self.scan_buffer_with_timeout(data, None)
    }

    /// Scan a buffer and return detailed matches for all matching rules.
    ///
    /// If `timeout` is `Some(d)`, the underlying yara-x Scanner will be configured
    /// with that timeout. A timeout will surface as a `ScanError` from yara-x.
    pub fn scan_buffer_with_timeout(
        &self,
        data: &[u8],
        timeout: Option<Duration>,
    ) -> Result<Vec<YaraMatch>, EngineError> {
        let mut scanner = yara_x::Scanner::new(&self.rules);

        if let Some(d) = timeout {
            scanner.set_timeout(d);
        }

        let results = scanner
            .scan(data)
            .map_err(|e| EngineError::ScanError(e.to_string()))?;

        let mut matches = Vec::new();

        for rule in results.matching_rules() {
            let mut description = None;
            let mut severity = Severity::Medium;

            for (k, v) in rule.metadata() {
                match k {
                    "description" => {
                        if let yara_x::MetaValue::String(s) = v {
                            description = Some(s.to_string());
                        }
                    }
                    "severity" => {
                        severity = parse_severity(&v);
                    }
                    _ => {}
                }
            }

            let rule_tags = rule
                .tags()
                .map(|t| t.identifier().to_string())
                .collect::<Vec<_>>();

            let mut matched_strings = Vec::new();

            for pattern in rule.patterns() {
                let ident = pattern.identifier().to_string();

                for m in pattern.matches() {
                    let range = m.range();
                    let match_len = range.len();

                    if range.start >= data.len() {
                        log::debug!(
                            "YARA match start {} out of bounds (len {})",
                            range.start,
                            data.len()
                        );
                        continue;
                    }

                    let stored_len = match_len.min(MAX_MATCH_BYTES);
                    let stored_end = range.start.saturating_add(stored_len).min(data.len());

                    if stored_end <= range.start {
                        continue;
                    }

                    let stored = data[range.start..stored_end].to_vec();
                    let preview_len = stored.len().min(PREVIEW_BYTES);
                    let mut data_preview =
                        String::from_utf8_lossy(&stored[..preview_len]).into_owned();

                    if match_len > preview_len {
                        data_preview.push('…');
                    }

                    matched_strings.push(MatchedString {
                        identifier: ident.clone(),
                        offset: range.start,
                        match_length: match_len,
                        data: stored,
                        data_preview,
                    });
                }
            }

            matches.push(YaraMatch {
                rule_name: rule.identifier().to_string(),
                rule_tags,
                description,
                severity,
                matched_strings,
            });
        }

        Ok(matches)
    }

    pub fn rule_count(&self) -> usize {
        self.rule_count
    }
}

/// Helper for cleaner severity parsing logic.
fn parse_severity(val: &yara_x::MetaValue) -> Severity {
    match val {
        yara_x::MetaValue::String(s) => match s.to_ascii_lowercase().as_str() {
            "low" | "info" | "informational" => Severity::Low,
            "medium" | "med" => Severity::Medium,
            "high" => Severity::High,
            "critical" | "crit" => Severity::Critical,
            _ => Severity::Medium,
        },
        yara_x::MetaValue::Integer(i) => {
            if *i >= 90 {
                Severity::Critical
            } else if *i >= 75 {
                Severity::High
            } else if *i >= 50 {
                Severity::Medium
            } else {
                Severity::Low
            }
        }
        _ => Severity::Medium,
    }
}
