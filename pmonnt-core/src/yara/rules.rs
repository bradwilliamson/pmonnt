//! YARA rule fetching, caching, and management

use log;
use reqwest;
use serde;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use yara_x;

#[derive(Debug, Clone)]
pub enum RuleSource {
    YARAify {
        rule_name: String,
        downloaded_at: SystemTime,
    },
    LocalFile {
        path: PathBuf,
        modified_at: SystemTime,
    },
    ThreatFoxGenerated,
}

#[derive(Debug, Clone)]
pub struct YaraRule {
    pub name: String,
    pub source: RuleSource,
    pub content: String,
    pub description: Option<String>,
    pub severity: Severity,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct RuleManager {
    pub cache_dir: PathBuf,
    pub rules: Vec<YaraRule>,
    pub last_yaraify_refresh: Option<SystemTime>,
    pub yaraify_refresh_interval: Duration,
    yaraify_etag: Option<String>,
    yaraify_last_modified: Option<String>,
}

#[derive(Debug, Clone)]
pub struct YaraifyRefreshContext {
    cache_dir: PathBuf,
    etag: Option<String>,
    last_modified: Option<String>,
}

#[derive(Debug, Clone)]
pub struct YaraifyRefreshResult {
    pub rules: Vec<YaraRule>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub not_modified: bool,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
struct YaraifyMeta {
    etag: Option<String>,
    last_modified: Option<String>,
}

fn yaraify_meta_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join("yaraify_meta.json")
}

fn load_yaraify_meta(cache_dir: &Path) -> YaraifyMeta {
    let p = yaraify_meta_path(cache_dir);
    let Ok(s) = fs::read_to_string(&p) else {
        return YaraifyMeta::default();
    };
    serde_json::from_str(&s).unwrap_or_default()
}

fn save_yaraify_meta(cache_dir: &Path, meta: &YaraifyMeta) {
    let p = yaraify_meta_path(cache_dir);
    if let Ok(s) = serde_json::to_string_pretty(meta) {
        let _ = fs::write(p, s);
    }
}

const UNSUPPORTED_MODULES: &[&str] = &["magic", "cuckoo", "dotnet", "dex", "macho"];

pub fn has_unsupported_modules(content: &str) -> bool {
    // Avoid false positives by only matching import statements at the start of a line.
    // This won't be perfect (YARA has block comments), but it removes most accidental matches in strings.
    for line in content.lines() {
        let l = line.trim_start();
        if !l.starts_with("import") {
            continue;
        }
        // Accept: import "module"
        let rest = l.strip_prefix("import").unwrap_or("").trim_start();
        if let Some(module) = rest.strip_prefix('"').and_then(|s| s.split('"').next()) {
            if UNSUPPORTED_MODULES
                .iter()
                .any(|m| m.eq_ignore_ascii_case(module))
            {
                return true;
            }
        }
    }
    false
}

fn is_rule_compilable(content: &str) -> bool {
    let mut compiler = yara_x::Compiler::new();
    compiler.add_source(content).is_ok()
}

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("Failed to fetch from YARAify: {0}")]
    YaraifyFetchFailed(String),
    #[error("Failed to parse YARA rule: {0}")]
    ParseError(String),
    #[error("Failed to read rule file {path}: {reason}")]
    FileReadError { path: PathBuf, reason: String },
    #[error("Cache directory error: {0}")]
    CacheError(String),
}

impl RuleManager {
    pub fn new(cache_dir: PathBuf) -> Self {
        std::fs::create_dir_all(&cache_dir).ok();

        let meta = load_yaraify_meta(&cache_dir);
        let yaraify_refresh_interval = std::env::var("PMONNT_YARAIFY_REFRESH_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(60 * 60 * 24));

        Self {
            cache_dir,
            rules: Vec::new(),
            last_yaraify_refresh: None,
            yaraify_refresh_interval,
            yaraify_etag: meta.etag,
            yaraify_last_modified: meta.last_modified,
        }
    }

    pub fn load_cached_rules(&mut self) -> Result<usize, RuleError> {
        let mut count = 0usize;
        match fs::read_dir(&self.cache_dir) {
            Ok(entries) => {
                for e in entries.flatten() {
                    let p = e.path();
                    if p.extension()
                        .and_then(|s| s.to_str())
                        .map(|s| s.eq_ignore_ascii_case("yar") || s.eq_ignore_ascii_case("yara"))
                        .unwrap_or(false)
                    {
                        if let Ok(content) = fs::read_to_string(&p) {
                            if has_unsupported_modules(&content) {
                                log::warn!("Skipping rule {:?} - uses unsupported module", p);
                                continue;
                            }

                            if !is_rule_compilable(&content) {
                                log::warn!("Skipping rule {:?} - failed to compile", p);
                                continue;
                            }

                            let metadata = fs::metadata(&p).ok();
                            let modified = metadata
                                .and_then(|m| m.modified().ok())
                                .unwrap_or(SystemTime::now());
                            self.rules.push(YaraRule {
                                name: p
                                    .file_name()
                                    .and_then(|s| s.to_str())
                                    .unwrap_or("local")
                                    .to_string(),
                                source: RuleSource::LocalFile {
                                    path: p.clone(),
                                    modified_at: modified,
                                },
                                content,
                                description: None,
                                severity: Severity::Medium,
                                tags: Vec::new(),
                            });
                            count += 1;
                        }
                    }
                }
            }
            Err(e) => return Err(RuleError::CacheError(format!("read dir failed: {}", e))),
        }
        Ok(count)
    }

    pub fn yaraify_refresh_context(&self) -> YaraifyRefreshContext {
        YaraifyRefreshContext {
            cache_dir: self.cache_dir.clone(),
            etag: self.yaraify_etag.clone(),
            last_modified: self.yaraify_last_modified.clone(),
        }
    }

    pub async fn fetch_yaraify(
        ctx: YaraifyRefreshContext,
    ) -> Result<YaraifyRefreshResult, RuleError> {
        // YARAify provides a ZIP package of all public YARA rules
        let client = reqwest::Client::new();

        let mut request = client.get("https://yaraify.abuse.ch/yarahub/yaraify-rules.zip");
        if let Some(etag) = &ctx.etag {
            request = request.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        if let Some(lm) = &ctx.last_modified {
            request = request.header(reqwest::header::IF_MODIFIED_SINCE, lm);
        }

        let response = request
            .send()
            .await
            .map_err(|e| RuleError::YaraifyFetchFailed(e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            log::info!("YARAify rules not modified (304); keeping cached rules");
            return Ok(YaraifyRefreshResult {
                rules: Vec::new(),
                etag: ctx.etag,
                last_modified: ctx.last_modified,
                not_modified: true,
            });
        }

        if !response.status().is_success() {
            return Err(RuleError::YaraifyFetchFailed(format!(
                "HTTP {}",
                response.status()
            )));
        }

        // Capture caching headers for next refresh.
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let last_modified = response
            .headers()
            .get(reqwest::header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let bytes = response
            .bytes()
            .await
            .map_err(|e| RuleError::YaraifyFetchFailed(e.to_string()))?;

        // Extract zip to cache directory
        let reader = std::io::Cursor::new(bytes);
        let mut archive = zip::ZipArchive::new(reader)
            .map_err(|e| RuleError::YaraifyFetchFailed(format!("Invalid zip: {}", e)))?;

        let mut rules = Vec::new();
        let mut count = 0usize;

        // Basic ZIP safety limits.
        const MAX_ZIP_ENTRIES: usize = 20_000;
        const MAX_SINGLE_FILE_BYTES: u64 = 2 * 1024 * 1024; // 2MB per rule file
        const MAX_TOTAL_EXTRACTED_BYTES: u64 = 200 * 1024 * 1024; // 200MB total
        let mut total_uncompressed: u64 = 0;

        let entries = archive.len().min(MAX_ZIP_ENTRIES);
        for i in 0..entries {
            let mut file = archive
                .by_index(i)
                .map_err(|e| RuleError::YaraifyFetchFailed(e.to_string()))?;

            let name = file.name().to_string();
            if !(name.ends_with(".yar") || name.ends_with(".yara")) {
                continue;
            }

            let uncompressed_size = file.size();
            if uncompressed_size > MAX_SINGLE_FILE_BYTES {
                log::warn!(
                    "Skipping rule {} - too large ({} bytes)",
                    name,
                    uncompressed_size
                );
                continue;
            }
            if total_uncompressed.saturating_add(uncompressed_size) > MAX_TOTAL_EXTRACTED_BYTES {
                log::warn!(
                    "Stopping ZIP extraction - exceeded {} bytes total",
                    MAX_TOTAL_EXTRACTED_BYTES
                );
                break;
            }

            let mut content = String::new();
            use std::io::Read;
            file.read_to_string(&mut content)
                .map_err(|e| RuleError::YaraifyFetchFailed(e.to_string()))?;

            total_uncompressed = total_uncompressed.saturating_add(uncompressed_size);

            if has_unsupported_modules(&content) {
                log::warn!("Skipping rule {} - uses unsupported module", name);
                continue;
            }

            if !is_rule_compilable(&content) {
                log::warn!("Skipping rule {} - failed to compile", name);
                continue;
            }

            // Save to cache
            let safe_name = name.replace("/", "_").replace("\\", "_");
            let cache_path = ctx.cache_dir.join(&safe_name);
            std::fs::write(&cache_path, &content)
                .map_err(|e| RuleError::CacheError(e.to_string()))?;

            rules.push(YaraRule {
                name: safe_name,
                source: RuleSource::YARAify {
                    rule_name: name,
                    downloaded_at: SystemTime::now(),
                },
                content,
                description: None,
                severity: Severity::High,
                tags: Vec::new(),
            });
            count += 1;
        }

        log::info!("YARAify refresh fetched {} rule(s)", count);
        Ok(YaraifyRefreshResult {
            rules,
            etag,
            last_modified,
            not_modified: false,
        })
    }

    pub fn apply_yaraify_refresh(&mut self, result: YaraifyRefreshResult) -> usize {
        self.last_yaraify_refresh = Some(SystemTime::now());
        self.yaraify_etag = result.etag.clone();
        self.yaraify_last_modified = result.last_modified.clone();

        save_yaraify_meta(
            &self.cache_dir,
            &YaraifyMeta {
                etag: self.yaraify_etag.clone(),
                last_modified: self.yaraify_last_modified.clone(),
            },
        );

        if result.not_modified {
            return 0;
        }

        // Prevent duplicates if refresh is called multiple times.
        self.rules
            .retain(|r| !matches!(r.source, RuleSource::YARAify { .. }));
        let count = result.rules.len();
        self.rules.extend(result.rules);
        count
    }

    pub async fn fetch_threatfox_rules(
        cache_dir: PathBuf,
        api_key: Option<&str>,
    ) -> Result<Vec<YaraRule>, RuleError> {
        use crate::yara::ioc_generator::IocToYaraGenerator;

        #[derive(serde::Deserialize)]
        struct ThreatFoxIocData {
            ioc: String,
            ioc_type: String,
            malware: Option<String>,
            confidence_level: Option<i32>,
        }

        #[derive(serde::Deserialize)]
        struct ThreatFoxResponse {
            query_status: String,
            data: Option<Vec<ThreatFoxIocData>>,
        }

        let client = reqwest::Client::new();
        let mut request =
            client
                .post("https://threatfox-api.abuse.ch/api/v1/")
                .json(&serde_json::json!({
                    "query": "get_iocs",
                    "days": 7
                }));

        if let Some(key) = api_key {
            request = request.header("Auth-Key", key);
        }

        let response = request
            .send()
            .await
            .map_err(|e| RuleError::YaraifyFetchFailed(e.to_string()))?;

        let data: ThreatFoxResponse = response
            .json()
            .await
            .map_err(|e| RuleError::YaraifyFetchFailed(e.to_string()))?;

        if data.query_status != "ok" {
            return Err(RuleError::YaraifyFetchFailed(format!(
                "ThreatFox query failed: {}",
                data.query_status
            )));
        }

        // Filter low-confidence IOCs to reduce noise/false-positives.
        const MIN_CONFIDENCE: i32 = 50;
        let iocs: Vec<crate::yara::ioc_generator::ThreatFoxIoc> = data
            .data
            .unwrap_or_default()
            .into_iter()
            .filter(|d| d.confidence_level.unwrap_or(0) >= MIN_CONFIDENCE)
            .map(|d| crate::yara::ioc_generator::ThreatFoxIoc {
                ioc_value: d.ioc,
                ioc_type: d.ioc_type,
                malware: d.malware,
                confidence_level: d.confidence_level,
            })
            .collect();

        let generated_rules = IocToYaraGenerator::generate_from_threatfox_iocs(&iocs);

        // Save generated rules to cache
        for rule in &generated_rules {
            let path = cache_dir.join(&rule.name);
            std::fs::write(&path, &rule.content).ok();
        }

        Ok(generated_rules)
    }

    pub fn apply_threatfox_rules(&mut self, rules: Vec<YaraRule>) -> usize {
        // Prevent duplicates if refresh is called multiple times.
        self.rules
            .retain(|r| !matches!(r.source, RuleSource::ThreatFoxGenerated));
        let count = rules.len();
        self.rules.extend(rules);
        count
    }

    pub async fn refresh_from_yaraify(&mut self) -> Result<usize, RuleError> {
        // YARAify provides a ZIP package of all public YARA rules
        let client = reqwest::Client::new();

        let mut request = client.get("https://yaraify.abuse.ch/yarahub/yaraify-rules.zip");
        if let Some(etag) = &self.yaraify_etag {
            request = request.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        if let Some(lm) = &self.yaraify_last_modified {
            request = request.header(reqwest::header::IF_MODIFIED_SINCE, lm);
        }

        let response = request
            .send()
            .await
            .map_err(|e| RuleError::YaraifyFetchFailed(e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            self.last_yaraify_refresh = Some(SystemTime::now());
            log::info!("YARAify rules not modified (304); keeping cached rules");
            return Ok(0);
        }

        if !response.status().is_success() {
            return Err(RuleError::YaraifyFetchFailed(format!(
                "HTTP {}",
                response.status()
            )));
        }

        // Capture caching headers for next refresh.
        self.yaraify_etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        self.yaraify_last_modified = response
            .headers()
            .get(reqwest::header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let bytes = response
            .bytes()
            .await
            .map_err(|e| RuleError::YaraifyFetchFailed(e.to_string()))?;

        // Extract zip to cache directory
        let reader = std::io::Cursor::new(bytes);
        let mut archive = zip::ZipArchive::new(reader)
            .map_err(|e| RuleError::YaraifyFetchFailed(format!("Invalid zip: {}", e)))?;

        // Prevent duplicates if refresh is called multiple times.
        self.rules
            .retain(|r| !matches!(r.source, RuleSource::YARAify { .. }));

        let mut count = 0;

        // Basic ZIP safety limits.
        const MAX_ZIP_ENTRIES: usize = 20_000;
        const MAX_SINGLE_FILE_BYTES: u64 = 2 * 1024 * 1024; // 2MB per rule file
        const MAX_TOTAL_EXTRACTED_BYTES: u64 = 200 * 1024 * 1024; // 200MB total
        let mut total_uncompressed: u64 = 0;

        let entries = archive.len().min(MAX_ZIP_ENTRIES);
        for i in 0..entries {
            let mut file = archive
                .by_index(i)
                .map_err(|e| RuleError::YaraifyFetchFailed(e.to_string()))?;

            let name = file.name().to_string();
            if name.ends_with(".yar") || name.ends_with(".yara") {
                let uncompressed_size = file.size();
                if uncompressed_size > MAX_SINGLE_FILE_BYTES {
                    log::warn!(
                        "Skipping rule {} - too large ({} bytes)",
                        name,
                        uncompressed_size
                    );
                    continue;
                }
                if total_uncompressed.saturating_add(uncompressed_size) > MAX_TOTAL_EXTRACTED_BYTES
                {
                    log::warn!(
                        "Stopping ZIP extraction - exceeded {} bytes total",
                        MAX_TOTAL_EXTRACTED_BYTES
                    );
                    break;
                }

                let mut content = String::new();
                use std::io::Read;
                file.read_to_string(&mut content)
                    .map_err(|e| RuleError::YaraifyFetchFailed(e.to_string()))?;

                total_uncompressed = total_uncompressed.saturating_add(uncompressed_size);

                if has_unsupported_modules(&content) {
                    log::warn!("Skipping rule {} - uses unsupported module", name);
                    continue;
                }

                if !is_rule_compilable(&content) {
                    log::warn!("Skipping rule {} - failed to compile", name);
                    continue;
                }

                // Save to cache
                let safe_name = name.replace("/", "_").replace("\\", "_");
                let cache_path = self.cache_dir.join(&safe_name);
                std::fs::write(&cache_path, &content)
                    .map_err(|e| RuleError::CacheError(e.to_string()))?;

                // Add to rules list
                self.rules.push(YaraRule {
                    name: safe_name,
                    source: RuleSource::YARAify {
                        rule_name: name,
                        downloaded_at: SystemTime::now(),
                    },
                    content,
                    description: None,
                    severity: Severity::High,
                    tags: Vec::new(),
                });
                count += 1;
            }
        }

        self.last_yaraify_refresh = Some(SystemTime::now());

        save_yaraify_meta(
            &self.cache_dir,
            &YaraifyMeta {
                etag: self.yaraify_etag.clone(),
                last_modified: self.yaraify_last_modified.clone(),
            },
        );

        Ok(count)
    }

    pub async fn refresh_from_threatfox(
        &mut self,
        api_key: Option<&str>,
    ) -> Result<usize, RuleError> {
        use crate::yara::ioc_generator::IocToYaraGenerator;

        #[derive(serde::Deserialize)]
        struct ThreatFoxIocData {
            ioc: String,
            ioc_type: String,
            malware: Option<String>,
            confidence_level: Option<i32>,
        }

        #[derive(serde::Deserialize)]
        struct ThreatFoxResponse {
            query_status: String,
            data: Option<Vec<ThreatFoxIocData>>,
        }

        let client = reqwest::Client::new();
        let mut request =
            client
                .post("https://threatfox-api.abuse.ch/api/v1/")
                .json(&serde_json::json!({
                    "query": "get_iocs",
                    "days": 7
                }));

        if let Some(key) = api_key {
            request = request.header("Auth-Key", key);
        }

        let response = request
            .send()
            .await
            .map_err(|e| RuleError::YaraifyFetchFailed(e.to_string()))?;

        let data: ThreatFoxResponse = response
            .json()
            .await
            .map_err(|e| RuleError::YaraifyFetchFailed(e.to_string()))?;

        if data.query_status != "ok" {
            return Err(RuleError::YaraifyFetchFailed(format!(
                "ThreatFox query failed: {}",
                data.query_status
            )));
        }

        // Filter low-confidence IOCs to reduce noise/false-positives.
        // ThreatFox confidence is commonly 0..=100.
        const MIN_CONFIDENCE: i32 = 50;
        let iocs: Vec<crate::yara::ioc_generator::ThreatFoxIoc> = data
            .data
            .unwrap_or_default()
            .into_iter()
            .filter(|d| d.confidence_level.unwrap_or(0) >= MIN_CONFIDENCE)
            .map(|d| crate::yara::ioc_generator::ThreatFoxIoc {
                ioc_value: d.ioc,
                ioc_type: d.ioc_type,
                malware: d.malware,
                confidence_level: d.confidence_level,
            })
            .collect();

        let generated_rules = IocToYaraGenerator::generate_from_threatfox_iocs(&iocs);
        let count = generated_rules.len();

        // Prevent duplicates if refresh is called multiple times.
        self.rules
            .retain(|r| !matches!(r.source, RuleSource::ThreatFoxGenerated));

        // Save generated rules to cache
        for rule in generated_rules {
            let path = self.cache_dir.join(&rule.name);
            std::fs::write(&path, &rule.content).ok();
            self.rules.push(rule);
        }

        Ok(count)
    }

    pub fn load_local_file(&mut self, path: PathBuf) -> Result<usize, RuleError> {
        match fs::read_to_string(&path) {
            Ok(content) => {
                if has_unsupported_modules(&content) {
                    log::warn!("Skipping rule {:?} - uses unsupported module", path);
                    return Ok(0);
                }

                if !is_rule_compilable(&content) {
                    log::warn!("Skipping rule {:?} - failed to compile", path);
                    return Ok(0);
                }
                let modified = fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .unwrap_or(SystemTime::now());
                self.rules.push(YaraRule {
                    name: path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("local")
                        .to_string(),
                    source: RuleSource::LocalFile {
                        path: path.clone(),
                        modified_at: modified,
                    },
                    content,
                    description: None,
                    severity: Severity::Medium,
                    tags: Vec::new(),
                });
                Ok(1)
            }
            Err(e) => Err(RuleError::FileReadError {
                path,
                reason: e.to_string(),
            }),
        }
    }

    pub fn load_local_directory(&mut self, dir: PathBuf) -> Result<usize, RuleError> {
        let mut total = 0usize;
        for entry in fs::read_dir(dir).map_err(|e| RuleError::CacheError(e.to_string()))? {
            let p = entry
                .map_err(|e| RuleError::CacheError(e.to_string()))?
                .path();
            if p.extension()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case("yar") || s.eq_ignore_ascii_case("yara"))
                .unwrap_or(false)
                && self.load_local_file(p.clone()).is_ok()
            {
                total += 1;
            }
        }
        Ok(total)
    }

    pub fn rules(&self) -> &[YaraRule] {
        &self.rules
    }

    pub fn combined_source(&self) -> String {
        self.rules
            .iter()
            .map(|r| r.content.clone())
            .collect::<Vec<_>>()
            .join("\n\n")
    }

    pub fn needs_refresh(&self) -> bool {
        match self.last_yaraify_refresh {
            Some(t) => {
                t.elapsed().unwrap_or(Duration::from_secs(0)) > self.yaraify_refresh_interval
            }
            None => true,
        }
    }

    pub fn last_refresh(&self) -> Option<SystemTime> {
        self.last_yaraify_refresh
    }
}
