use super::*;
use std::collections::{HashMap, HashSet};
use std::path::Path;

fn drain_signature_results(
    signature_result_rx: &crossbeam_channel::Receiver<(String, pmonnt_core::SignatureInfo)>,
    signature_in_flight: &mut HashSet<String>,
    signature_cache_by_path: &mut HashMap<String, pmonnt_core::SignatureInfo>,
) {
    while let Ok((path, info)) = signature_result_rx.try_recv() {
        signature_in_flight.remove(&path);
        signature_cache_by_path.insert(path, info);
    }
}

fn drain_security_results(
    security_result_rx: &crossbeam_channel::Receiver<crate::app::SecurityJobResult>,
    security_in_flight: &mut HashSet<u32>,
    security_cache_by_pid: &mut HashMap<u32, crate::app::CachedSecurityInfo>,
) {
    while let Ok(job) = security_result_rx.try_recv() {
        security_in_flight.remove(&job.pid);

        match &job.result {
            Ok(info) => {
                log::info!(
                    "Received security info for PID {}: {} groups, {} privileges",
                    job.pid,
                    info.groups.len(),
                    info.privileges.len()
                );
            }
            Err(e) => {
                log::warn!("Security info failed for PID {}: {}", job.pid, e);
            }
        }

        security_cache_by_pid.insert(
            job.pid,
            crate::app::CachedSecurityInfo {
                fetched_at: Instant::now(),
                result: job.result,
            },
        );
    }
}

fn drain_thread_fetch_results(
    thread_fetch_rx: &crossbeam_channel::Receiver<(
        u32,
        Result<Vec<pmonnt_core::thread::ThreadInfo>, String>,
    )>,
    thread_fetch_in_flight: &mut HashSet<u32>,
    thread_fetch_started: &mut HashMap<u32, Instant>,
    thread_cache: &mut pmonnt_core::thread::ThreadCache,
    thread_prev: &mut HashMap<u32, Vec<pmonnt_core::thread::ThreadInfo>>,
) {
    while let Ok((pid, result)) = thread_fetch_rx.try_recv() {
        thread_fetch_in_flight.remove(&pid);
        thread_fetch_started.remove(&pid);

        match result {
            Ok(threads) => {
                if let Some(old) = thread_cache.peek(pid).cloned() {
                    thread_prev.insert(pid, old);
                }
                thread_cache.insert(pid, threads);
            }
            Err(_) => {}
        }
    }
}

impl PMonNTApp {
    pub(super) fn service_background_work(&mut self) {
        // Promote any completed SHA-256 computations (selection-driven) into UI state.
        // This keeps SHA available even if the reputation panels are not currently rendered.
        if let Ok(mut guard) = self.mb_ui_state.current_process_sha_pending.lock() {
            if let Some(sha) = guard.take() {
                self.mb_ui_state.current_process_sha = Some(sha);
            }
        }
        if let Ok(mut guard) = self.vt_ui_state.current_process_sha_pending.lock() {
            if let Some(sha) = guard.take() {
                self.vt_ui_state.current_process_sha = Some(sha);
            }
        }

        drain_signature_results(
            &self.signature_result_rx,
            &mut self.signature_in_flight,
            &mut self.signature_cache_by_path,
        );

        // Drain service action results (non-blocking)
        while let Ok((pid, service_name, action, result)) = self.service_action_result_rx.try_recv()
        {
            let key = format!("{pid}:{service_name}:{action}");
            self.service_action_in_flight.remove(&key);

            self.last_service_action_message = Some(match result {
                Ok(()) => format!("{action} succeeded: {service_name}"),
                Err(e) => format!("{action} failed: {service_name} ({e})"),
            });

            // If the modal is open for this PID, show result + refresh its list.
            if let Some(dialog) = self.service_dialog.as_mut() {
                if dialog.pid == pid {
                    dialog.last_result =
                        Some(self.last_service_action_message.clone().unwrap_or_default());
                    dialog.last_result_time = Some(Instant::now());
                    if let Ok(mut services) = pmonnt_core::services::get_services_for_process(pid) {
                        services.sort_by(|a, b| a.name.cmp(&b.name));
                        dialog.services = services;
                    }
                }
            }

            // Force refresh for this PID next time the Services tab is opened.
            self.services_cache_by_pid.remove(&pid);
            self.services_error_by_pid.remove(&pid);
        }

        // Drain kill action results (non-blocking)
        while let Ok((pid, kill_tree, is_group, result)) = self.kill_action_result_rx.try_recv() {
            self.on_kill_action_result(pid, kill_tree, is_group, result);
        }

        // Drain dump action results (non-blocking)
        while let Ok(job) = self.dump_action_result_rx.try_recv() {
            self.dump_action_in_flight = None;

            match job.result {
                Ok(path) => {
                    self.last_dump_path = Some(path.clone());
                    self.set_status_line(format!("Dump saved: {}", path.display()));
                }
                Err(e) => {
                    self.last_dump_path = None;
                    self.set_status_line(format!("Dump failed: {e}"));
                }
            }
        }

        drain_security_results(
            &self.security_result_rx,
            &mut self.security_in_flight,
            &mut self.security_cache_by_pid,
        );

        drain_thread_fetch_results(
            &self.thread_fetch_rx,
            &mut self.thread_fetch_in_flight,
            &mut self.thread_fetch_started,
            &mut self.thread_cache,
            &mut self.thread_prev,
        );

        // Drain thread action results (non-blocking)
        while let Ok(job) = self.thread_action_result_rx.try_recv() {
            use crate::app::ThreadActionKind;

            let action_label = match job.action {
                ThreadActionKind::Stack => "Stack",
                ThreadActionKind::Suspend => "Suspend",
                ThreadActionKind::Resume => "Resume",
                ThreadActionKind::Kill => "Kill",
                ThreadActionKind::Permissions => "Permissions",
            };

            let in_flight_key = format!("{}:{}:{}", job.pid, job.tid, action_label);
            self.thread_action_in_flight.remove(&in_flight_key);

            if job.action != ThreadActionKind::Stack {
                let msg = match &job.result {
                    Ok(()) => format!("{action_label} succeeded (TID {})", job.tid),
                    Err(e) => format!("{action_label} failed (TID {}): {e}", job.tid),
                };
                self.thread_action_message_by_key
                    .insert((job.pid, job.tid), (msg, Instant::now()));
            }

            let entry: Result<String, String> = match &job.result {
                Ok(()) => Ok(job.payload.clone().unwrap_or_default()),
                Err(e) => Err(e.clone()),
            };

            if job.action == ThreadActionKind::Permissions {
                self.thread_permissions_cache
                    .insert((job.pid, job.tid), (Instant::now(), entry.clone()));
            }

            if job.action == ThreadActionKind::Stack {
                self.thread_stack_cache
                    .insert((job.pid, job.tid), (Instant::now(), entry));
            }
        }

        // Drain YARA progress updates
        if let Some(ref mut rx) = self.yara_state.progress_rx {
            while let Ok(progress) = rx.try_recv() {
                self.yara_state.current_progress = Some(progress.clone());
                match progress {
                    pmonnt_core::yara::scanner::ScanProgress::Completed { result } => {
                        self.yara_state.last_result = Some(result);
                        self.yara_state.scanning = false;
                    }
                    pmonnt_core::yara::scanner::ScanProgress::Cancelled => {
                        self.yara_state.scanning = false;
                    }
                    pmonnt_core::yara::scanner::ScanProgress::Error { error } => {
                        self.yara_state.error = Some(error);
                        self.yara_state.scanning = false;
                    }
                    _ => {}
                }
            }
        }

        // Rebuild YARA engine if needed after rule refresh
        if self
            .yara_state
            .needs_engine_rebuild
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            let rm = self
                .yara_state
                .rule_manager
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            log::info!("Rebuilding YARA engine with {} rules", rm.rules().len());
            match pmonnt_core::yara::engine::YaraEngine::from_rule_manager(&rm) {
                Ok(engine) => {
                    log::info!("YARA engine rebuilt successfully");
                    self.yara_state.yara_engine = Some(std::sync::Arc::new(engine));
                    self.yara_state.error = None;
                }
                Err(e) => {
                    log::error!("YARA engine rebuild failed: {}", e);
                    self.yara_state.yara_engine = None;
                    self.yara_state.error = Some(format!("Engine compile failed: {}", e));
                }
            }
        }
    }

    pub(crate) fn request_signature_check_for_path(&mut self, path: &str) {
        let key = path.to_string();
        if self.signature_cache_by_path.contains_key(&key) {
            return;
        }
        if self.signature_in_flight.contains(&key) {
            return;
        }

        self.signature_in_flight.insert(key.clone());
        let tx = self.signature_result_tx.clone();

        self.bg_worker.spawn(move || {
            let info = match pmonnt_core::verify_signature(Path::new(&key)) {
                Ok(info) => info,
                Err(e) => pmonnt_core::SignatureInfo {
                    is_signed: true,
                    is_valid: false,
                    error: Some(format!("Error: {e}")),
                    ..Default::default()
                },
            };
            let _ = tx.send((key, info));
        });
    }

    pub(super) fn tick_housekeeping(&mut self, ctx: &egui::Context) {
        // Update tick counter every second
        if self.last_update.elapsed().as_secs() >= 1 {
            self.tick += 1;
            self.last_update = Instant::now();
            // Periodically clean up caches
            self.token_cache.cleanup();
            self.thread_cache.cleanup();
            self.module_cache.cleanup();
            ctx.request_repaint();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pmonnt_core::win::token_info::{IntegrityLevel, SecurityInfo, TokenSummary};

    #[test]
    fn background_drain_clears_in_flight_and_updates_caches() {
        // Signature
        let (sig_tx, sig_rx) =
            crossbeam_channel::unbounded::<(String, pmonnt_core::SignatureInfo)>();
        let mut signature_in_flight: HashSet<String> = HashSet::new();
        let mut signature_cache_by_path: HashMap<String, pmonnt_core::SignatureInfo> =
            HashMap::new();

        let path = r"C:\Windows\System32\notepad.exe".to_string();
        signature_in_flight.insert(path.clone());
        let sig = pmonnt_core::SignatureInfo {
            is_signed: true,
            is_valid: false,
            error: Some("unit test".to_string()),
            ..Default::default()
        };
        sig_tx.send((path.clone(), sig.clone())).unwrap();
        drain_signature_results(
            &sig_rx,
            &mut signature_in_flight,
            &mut signature_cache_by_path,
        );
        assert!(!signature_in_flight.contains(&path));
        assert_eq!(signature_cache_by_path.get(&path), Some(&sig));

        // Security
        let (sec_tx, sec_rx) = crossbeam_channel::unbounded::<crate::app::SecurityJobResult>();
        let mut security_in_flight: HashSet<u32> = HashSet::new();
        let mut security_cache_by_pid: HashMap<u32, crate::app::CachedSecurityInfo> =
            HashMap::new();

        let pid = 4242u32;
        security_in_flight.insert(pid);
        sec_tx
            .send(crate::app::SecurityJobResult {
                pid,
                result: Err("unit test".to_string()),
            })
            .unwrap();
        drain_security_results(&sec_rx, &mut security_in_flight, &mut security_cache_by_pid);
        assert!(!security_in_flight.contains(&pid));
        assert!(security_cache_by_pid.get(&pid).unwrap().result.is_err());

        // Thread fetch
        let (thr_tx, thr_rx) = crossbeam_channel::unbounded::<(
            u32,
            Result<Vec<pmonnt_core::thread::ThreadInfo>, String>,
        )>();
        let mut thread_fetch_in_flight: HashSet<u32> = HashSet::new();
        let mut thread_fetch_started: HashMap<u32, Instant> = HashMap::new();
        let mut thread_cache = pmonnt_core::thread::ThreadCache::new(4);
        let mut thread_prev: HashMap<u32, Vec<pmonnt_core::thread::ThreadInfo>> = HashMap::new();

        let tpid = 31337u32;
        thread_fetch_in_flight.insert(tpid);
        thread_fetch_started.insert(tpid, Instant::now());
        thr_tx.send((tpid, Err("unit test".to_string()))).unwrap();
        drain_thread_fetch_results(
            &thr_rx,
            &mut thread_fetch_in_flight,
            &mut thread_fetch_started,
            &mut thread_cache,
            &mut thread_prev,
        );
        assert!(!thread_fetch_in_flight.contains(&tpid));
        assert!(!thread_fetch_started.contains_key(&tpid));
    }

    fn test_security_info() -> SecurityInfo {
        SecurityInfo {
            summary: TokenSummary {
                user: "unit-test".to_string(),
                user_sid: "S-1-5-21-0".to_string(),
                session_id: 0,
                logon_luid: None,
                integrity: IntegrityLevel::Medium,
                elevation: None,
                virtualization_enabled: None,
                is_app_container: None,
                is_protected_process: None,
                is_ppl: None,
            },
            groups: Vec::new(),
            groups_error: None,
            privileges: Vec::new(),
            privileges_error: None,
        }
    }

    #[test]
    fn service_background_work_error_then_success_updates_caches() {
        let mut app = crate::app::PMonNTApp::try_new().expect("test app init");

        // Signature: error then success should overwrite cache and clear in-flight.
        let path = r"C:\unit-test\fake.exe".to_string();
        app.signature_in_flight.insert(path.clone());
        let sig_err = pmonnt_core::SignatureInfo {
            is_signed: true,
            is_valid: false,
            error: Some("unit test error".to_string()),
            ..Default::default()
        };
        app.signature_result_tx
            .send((path.clone(), sig_err))
            .unwrap();
        app.service_background_work();
        assert!(!app.signature_in_flight.contains(&path));
        assert!(app
            .signature_cache_by_path
            .get(&path)
            .and_then(|s| s.error.clone())
            .unwrap_or_default()
            .contains("unit test error"));

        app.signature_in_flight.insert(path.clone());
        let sig_ok = pmonnt_core::SignatureInfo {
            is_signed: true,
            is_valid: true,
            error: None,
            ..Default::default()
        };
        app.signature_result_tx
            .send((path.clone(), sig_ok))
            .unwrap();
        app.service_background_work();
        assert!(!app.signature_in_flight.contains(&path));
        let cached_sig = app.signature_cache_by_path.get(&path).unwrap();
        assert!(cached_sig.is_valid);
        assert!(cached_sig.error.is_none());

        // Security: error then success should overwrite cache and clear in-flight.
        let pid = 424242u32;
        app.security_in_flight.insert(pid);
        app.security_result_tx
            .send(crate::app::SecurityJobResult {
                pid,
                result: Err("unit test error".to_string()),
            })
            .unwrap();
        app.service_background_work();
        assert!(!app.security_in_flight.contains(&pid));
        assert!(app.security_cache_by_pid.get(&pid).unwrap().result.is_err());

        app.security_in_flight.insert(pid);
        app.security_result_tx
            .send(crate::app::SecurityJobResult {
                pid,
                result: Ok(test_security_info()),
            })
            .unwrap();
        app.service_background_work();
        assert!(!app.security_in_flight.contains(&pid));
        let cached = app.security_cache_by_pid.get(&pid).unwrap();
        assert!(cached.result.is_ok());
        assert_eq!(
            cached.result.as_ref().unwrap().summary.user.as_str(),
            "unit-test"
        );
    }
}
