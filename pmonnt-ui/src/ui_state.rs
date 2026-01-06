use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// UI state for MalwareBazaar interactions
#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct MbUiState {
    pub(crate) status: Option<String>,
    pub(crate) last_query_state: Option<MbQueryState>,
    pub(crate) download_in_progress: bool,
    pub(crate) download_error: Option<String>,
    pub(crate) last_download_path: Option<String>,
    pub(crate) recent_detections: Vec<pmonnt_core::providers::MbRecentDetection>,
    pub(crate) recent_fetch_in_progress: bool,
    pub(crate) recent_error: Option<String>,
    pub(crate) recent_hours: u32,
    pub(crate) recent_status: Option<String>,
    pub(crate) recent_additions: Vec<pmonnt_core::providers::MbRecentSample>,
    pub(crate) recent_additions_selector: String,
    pub(crate) recent_additions_fetch_in_progress: bool,
    pub(crate) recent_additions_error: Option<String>,
    pub(crate) recent_additions_pending:
        Arc<Mutex<Option<Vec<pmonnt_core::providers::MbRecentSample>>>>,
    pub(crate) recent_additions_page: usize,
    pub(crate) recent_additions_per_page: usize,
    pub(crate) tag_search_text: String,
    pub(crate) tag_search_limit: u32,
    pub(crate) tag_search_results: Vec<pmonnt_core::providers::MbTagInfoSample>,
    pub(crate) tag_search_in_progress: bool,
    pub(crate) tag_search_error: Option<String>,
    pub(crate) tag_search_status: Option<String>,
    // Collapsible sections
    pub(crate) show_vendor_intel: bool,
    pub(crate) show_yara_rules: bool,
    pub(crate) show_comments: bool,
    // Per-process MB query state
    pub(crate) querying_mb_pid: Option<u32>,
    pub(crate) querying_mb_sha: Option<String>,
    pub(crate) querying_started_at: Option<Instant>,
    pub(crate) last_seen_pid: Option<u32>,
    pub(crate) current_process_sha: Option<String>,
    pub(crate) current_process_sha_pending: Arc<Mutex<Option<String>>>,
    // CSCB cache
    pub(crate) cscb_entries: Vec<pmonnt_core::providers::MbCscbEntry>,
    pub(crate) cscb_fetch_in_progress: bool,
    pub(crate) cscb_error: Option<String>,
    // Pending CSCB results
    pub(crate) cscb_pending: Arc<Mutex<Option<Vec<pmonnt_core::providers::MbCscbEntry>>>>,
    // Paging for CSCB
    pub(crate) cscb_page: usize,
    pub(crate) cscb_per_page: usize,
}

impl Default for MbUiState {
    fn default() -> Self {
        Self {
            status: None,
            last_query_state: None,
            download_in_progress: false,
            download_error: None,
            last_download_path: None,
            recent_detections: Vec::new(),
            recent_fetch_in_progress: false,
            recent_error: None,
            recent_hours: 1,
            recent_status: None,
            recent_additions: Vec::new(),
            recent_additions_selector: "100".to_string(),
            recent_additions_fetch_in_progress: false,
            recent_additions_error: None,
            recent_additions_pending: Arc::new(Mutex::new(None)),
            recent_additions_page: 0,
            recent_additions_per_page: 10,
            tag_search_text: String::new(),
            tag_search_limit: 100,
            tag_search_results: Vec::new(),
            tag_search_in_progress: false,
            tag_search_error: None,
            tag_search_status: None,
            show_vendor_intel: false,
            show_yara_rules: false,
            show_comments: false,
            querying_mb_pid: None,
            querying_mb_sha: None,
            querying_started_at: None,
            last_seen_pid: None,
            current_process_sha: None,
            current_process_sha_pending: Arc::new(Mutex::new(None)),
            cscb_entries: Vec::new(),
            cscb_fetch_in_progress: false,
            cscb_error: None,
            cscb_pending: Arc::new(Mutex::new(None)),
            cscb_page: 0,
            cscb_per_page: 10,
        }
    }
}

/// Light-weight query state for UI display
#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct MbQueryState {
    pub(crate) last_query: Option<String>,
    pub(crate) last_http_status: Option<u16>,
    pub(crate) last_query_status: Option<String>,
    pub(crate) last_result_count: Option<usize>,
    pub(crate) last_error_message: Option<String>,
}

/// UI state for VirusTotal manual lookups
#[allow(dead_code)]
#[derive(Clone)]
pub(crate) struct VtUiState {
    pub(crate) querying_vt_pid: Option<u32>,
    pub(crate) querying_vt_sha: Option<String>,
    pub(crate) querying_started_at: Option<std::time::Instant>,
    pub(crate) last_seen_pid: Option<u32>,
    pub(crate) current_process_sha: Option<String>,
    pub(crate) current_process_sha_pending: Arc<Mutex<Option<String>>>,
    pub(crate) last_query_meta: Option<pmonnt_core::vt::VtQueryMeta>,
}

/// UI state for ThreatFox manual lookups
#[derive(Clone, Default)]
pub(crate) struct TfUiState {
    pub(crate) last_query_state: Option<TfQueryState>,
    pub(crate) querying_tf_pid: Option<u32>,
    pub(crate) querying_tf_sha: Option<String>,
    pub(crate) current_process_sha: Option<String>,
    pub(crate) last_seen_pid: Option<u32>,
}

#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct TfQueryState {
    pub(crate) last_query: Option<String>,
    pub(crate) last_http_status: Option<u16>,
    pub(crate) last_query_status: Option<String>,
    pub(crate) last_result_count: Option<usize>,
    pub(crate) last_error_message: Option<String>,
}

/// UI state for YARA scanning
pub(crate) struct YaraScanState {
    pub(crate) scanning: bool,
    pub(crate) last_result: Option<pmonnt_core::yara::scanner::ScanResult>,
    pub(crate) current_progress: Option<pmonnt_core::yara::scanner::ScanProgress>,
    pub(crate) error: Option<String>,
    pub(crate) scan_mode: pmonnt_core::yara::scanner::ScanMode,
    pub(crate) min_severity: pmonnt_core::yara::rules::Severity,
    pub(crate) rt_handle: tokio::runtime::Handle,
    pub(crate) rule_manager: Arc<std::sync::Mutex<pmonnt_core::yara::rules::RuleManager>>,
    pub(crate) yara_engine: Option<Arc<pmonnt_core::yara::engine::YaraEngine>>,
    pub(crate) progress_rx:
        Option<std::sync::mpsc::Receiver<pmonnt_core::yara::scanner::ScanProgress>>,
    pub(crate) needs_engine_rebuild: Arc<AtomicBool>,
}

impl YaraScanState {
    pub(crate) fn rule_count(&self) -> usize {
        let rm = self.rule_manager.lock().unwrap_or_else(|e| e.into_inner());
        rm.rules().len()
    }

    pub(crate) fn start_scan(
        &mut self,
        pid: u32,
        engine: Arc<pmonnt_core::yara::engine::YaraEngine>,
    ) {
        if self.scanning {
            return;
        }
        self.scanning = true;
        self.error = None;
        self.current_progress = None;
        self.last_result = None;

        let (progress_tx, progress_rx) = std::sync::mpsc::channel();
        self.progress_rx = Some(progress_rx);

        let scanner = pmonnt_core::yara::scanner::ProcessScanner::new(Arc::clone(&engine));
        let scan_mode = self.scan_mode;

        std::thread::spawn(move || {
            let options = match scan_mode {
                pmonnt_core::yara::scanner::ScanMode::Quick => {
                    pmonnt_core::yara::scanner::ScanOptions::quick()
                }
                pmonnt_core::yara::scanner::ScanMode::Deep => {
                    pmonnt_core::yara::scanner::ScanOptions::deep()
                }
            };

            let result = scanner.scan_process_sync_with_options(pid, options, progress_tx);
            match result {
                Ok(res) => {
                    log::info!(
                        "YARA scan completed: {} bytes, {} matches",
                        res.bytes_scanned,
                        res.matches.len()
                    );
                }
                Err(e) => {
                    log::error!("YARA scan failed: {}", e);
                }
            }
        });
    }

    #[allow(dead_code)]
    pub(crate) fn refresh_rules(&mut self) {
        self.refresh_yaraify_rules();
    }

    pub(crate) fn load_local_file(&mut self, path: std::path::PathBuf) {
        let mut rm = self.rule_manager.lock().unwrap_or_else(|e| e.into_inner());
        match rm.load_local_file(path.clone()) {
            Ok(count) => {
                log::info!("Loaded {} rule(s) from {:?}", count, path);
                self.needs_engine_rebuild.store(true, Ordering::Release);
                self.error = None;
            }
            Err(e) => {
                log::error!("Failed to load rule file: {}", e);
                self.error = Some(format!("Failed to load: {}", e));
            }
        }
    }

    pub(crate) fn refresh_yaraify_rules(&mut self) {
        let rule_manager = Arc::clone(&self.rule_manager);
        let rt_handle = self.rt_handle.clone();
        let needs_engine_rebuild = Arc::clone(&self.needs_engine_rebuild);
        log::info!("Starting YARAify rules download...");

        rt_handle.spawn(async move {
            let ctx = {
                let rm = rule_manager.lock().unwrap_or_else(|e| e.into_inner());
                rm.yaraify_refresh_context()
            };

            match pmonnt_core::yara::rules::RuleManager::fetch_yaraify(ctx).await {
                Ok(result) => {
                    let mut rm = rule_manager.lock().unwrap_or_else(|e| e.into_inner());
                    let count = rm.apply_yaraify_refresh(result);
                    log::info!("YARAify: loaded {} rules", count);
                    needs_engine_rebuild.store(true, Ordering::Release);
                }
                Err(e) => log::error!("YARAify failed: {}", e),
            }
        });
    }

    pub(crate) fn refresh_threatfox_rules(&mut self, api_key: Option<String>) {
        let rule_manager = Arc::clone(&self.rule_manager);
        let rt_handle = self.rt_handle.clone();
        let needs_engine_rebuild = Arc::clone(&self.needs_engine_rebuild);
        log::info!("Generating YARA rules from ThreatFox IOCs...");

        rt_handle.spawn(async move {
            let cache_dir = {
                let rm = rule_manager.lock().unwrap_or_else(|e| e.into_inner());
                rm.cache_dir.clone()
            };

            match pmonnt_core::yara::rules::RuleManager::fetch_threatfox_rules(
                cache_dir,
                api_key.as_deref(),
            )
            .await
            {
                Ok(rules) => {
                    let mut rm = rule_manager.lock().unwrap_or_else(|e| e.into_inner());
                    let count = rm.apply_threatfox_rules(rules);
                    log::info!("ThreatFox: generated {} rules", count);
                    needs_engine_rebuild.store(true, Ordering::Release);
                }
                Err(e) => log::error!("ThreatFox failed: {}", e),
            }
        });
    }

    pub(crate) fn rule_source_counts(&self) -> (usize, usize, usize) {
        let rm = self.rule_manager.lock().unwrap_or_else(|e| e.into_inner());
        let mut yaraify = 0;
        let mut threatfox = 0;
        let mut local = 0;

        for rule in rm.rules() {
            match &rule.source {
                pmonnt_core::yara::RuleSource::YARAify { .. } => yaraify += 1,
                pmonnt_core::yara::RuleSource::ThreatFoxGenerated => threatfox += 1,
                pmonnt_core::yara::RuleSource::LocalFile { .. } => local += 1,
            }
        }

        (yaraify, threatfox, local)
    }
}
