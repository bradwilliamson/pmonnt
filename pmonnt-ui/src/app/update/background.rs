use super::*;
use crate::app::ReplyIdentity;
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
    is_current: impl Fn(u32, ReplyIdentity) -> bool,
) {
    while let Ok(job) = security_result_rx.try_recv() {
        security_in_flight.remove(&job.pid);
        if !is_current(job.pid, job.identity) {
            log::debug!(
                "Dropping security info for a previous process with PID {}",
                job.pid
            );
            continue;
        }

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

type ThreadFetchReply = (
    u32,
    ReplyIdentity,
    Result<Vec<pmonnt_core::thread::ThreadInfo>, String>,
);

fn drain_thread_fetch_results(
    thread_fetch_rx: &crossbeam_channel::Receiver<ThreadFetchReply>,
    thread_fetch_in_flight: &mut HashSet<u32>,
    thread_fetch_started: &mut HashMap<u32, Instant>,
    thread_cache: &mut pmonnt_core::thread::ThreadCache,
    thread_prev: &mut HashMap<u32, Vec<pmonnt_core::thread::ThreadInfo>>,
    is_current: impl Fn(u32, ReplyIdentity) -> bool,
) {
    while let Ok((pid, identity, result)) = thread_fetch_rx.try_recv() {
        // The in-flight marker is cleared even for a stale reply: at worst the current
        // process is fetched twice, while a kept marker could block its fetch for good.
        thread_fetch_in_flight.remove(&pid);
        thread_fetch_started.remove(&pid);
        if !is_current(pid, identity) {
            log::debug!("Dropping threads of a previous process with PID {pid}");
            continue;
        }

        if let Ok(threads) = result {
            if let Some(old) = thread_cache.peek(pid).cloned() {
                thread_prev.insert(pid, old);
            }
            thread_cache.insert(pid, threads);
        }
    }
}

impl PMonNTApp {
    pub(super) fn service_background_work(&mut self) {
        // Selection-driven SHA-256 (used by "Copy SHA-256"), if it still matches the selection.
        self.accept_selection_sha();

        // Explicit reputation Check/Refresh requests whose hash is ready.
        crate::ui_renderer::dispatch_pending_lookups(
            &self.reputation_service,
            &self.pid_to_image_path,
            self.online_lookups_enabled,
            (
                &mut self.vt_ui_state,
                &mut self.mb_ui_state,
                &mut self.tf_ui_state,
            ),
        );

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
            if let Some(dialog) = self.service_dialog.as_mut()
                && dialog.pid == pid
            {
                dialog.last_result =
                    Some(self.last_service_action_message.clone().unwrap_or_default());
                dialog.last_result_time = Some(Instant::now());
                if let Ok(mut services) = pmonnt_core::services::get_services_for_process(pid) {
                    services.sort_by(|a, b| a.name.cmp(&b.name));
                    dialog.services = services;
                }
            }

            // Force refresh for this PID next time the Services tab is opened.
            self.services_cache_by_pid.remove(&pid);
            self.services_error_by_pid.remove(&pid);
        }

        // Drain kill action results (non-blocking)
        while let Ok((pid, kill_tree, result)) = self.kill_action_result_rx.try_recv() {
            self.on_kill_action_result(pid, kill_tree, result);
        }

        // Drain dump action results (non-blocking)
        while let Ok(job) = self.dump_action_result_rx.try_recv() {
            self.dump_action_in_flight = None;

            match job.result {
                Ok(path) => {
                    self.set_status_line(format!(
                        "{:?} dump of {} ({}) saved: {}",
                        job.kind,
                        job.process_name,
                        job.pid,
                        path.display()
                    ));
                    self.last_dump_path = Some(path);
                }
                Err(e) => {
                    self.last_dump_path = None;
                    self.set_status_line(format!(
                        "{:?} dump of {} ({}) failed: {e}",
                        job.kind, job.process_name, job.pid
                    ));
                }
            }
        }

        // Replies are requested by PID; drop those that describe a process which has since
        // given its PID to another (the refresh already cleared that PID's caches).
        let snapshot = &self.current_snapshot;
        let is_current = |pid: u32, identity: ReplyIdentity| {
            identity.matches(snapshot.get_process(pid).and_then(|p| p.create_time))
        };
        drain_security_results(
            &self.security_result_rx,
            &mut self.security_in_flight,
            &mut self.security_cache_by_pid,
            is_current,
        );

        drain_thread_fetch_results(
            &self.thread_fetch_rx,
            &mut self.thread_fetch_in_flight,
            &mut self.thread_fetch_started,
            &mut self.thread_cache,
            &mut self.thread_prev,
            is_current,
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

        // Recompile the YARA engine off the UI thread after the rules changed.
        if self
            .yara_state
            .needs_engine_rebuild
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            self.yara_state.start_engine_build();
        }
        self.yara_state.poll_engine_build();
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
                identity: ReplyIdentity::Unknown,
                result: Err("unit test".to_string()),
            })
            .unwrap();
        drain_security_results(
            &sec_rx,
            &mut security_in_flight,
            &mut security_cache_by_pid,
            |_, _| true,
        );
        assert!(!security_in_flight.contains(&pid));
        assert!(security_cache_by_pid.get(&pid).unwrap().result.is_err());

        // A reply for a previous owner of the PID is dropped.
        security_cache_by_pid.clear();
        sec_tx
            .send(crate::app::SecurityJobResult {
                pid,
                identity: ReplyIdentity::Known(1),
                result: Err("stale".to_string()),
            })
            .unwrap();
        drain_security_results(
            &sec_rx,
            &mut security_in_flight,
            &mut security_cache_by_pid,
            |_, identity| identity.matches(Some(2)),
        );
        assert!(security_cache_by_pid.is_empty());

        // Thread fetch
        let (thr_tx, thr_rx) = crossbeam_channel::unbounded::<ThreadFetchReply>();
        let mut thread_fetch_in_flight: HashSet<u32> = HashSet::new();
        let mut thread_fetch_started: HashMap<u32, Instant> = HashMap::new();
        let mut thread_cache = pmonnt_core::thread::ThreadCache::new(4);
        let mut thread_prev: HashMap<u32, Vec<pmonnt_core::thread::ThreadInfo>> = HashMap::new();

        let tpid = 31337u32;
        thread_fetch_in_flight.insert(tpid);
        thread_fetch_started.insert(tpid, Instant::now());
        thr_tx
            .send((tpid, ReplyIdentity::Unknown, Err("unit test".to_string())))
            .unwrap();
        drain_thread_fetch_results(
            &thr_rx,
            &mut thread_fetch_in_flight,
            &mut thread_fetch_started,
            &mut thread_cache,
            &mut thread_prev,
            |_, _| true,
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
    fn explicit_lookups_progress_off_screen_and_respect_online_toggle() {
        let mut app = crate::app::PMonNTApp::for_tests();
        // A real file so the re-hash succeeds; two fake PIDs that use it.
        let file = std::env::temp_dir().join(format!("pmonnt_dispatch_{}", std::process::id()));
        std::fs::write(&file, b"dispatch test image").unwrap();
        let path = file.to_string_lossy().to_string();
        let (checked, shown) = (900_001u32, 900_002u32);
        app.pid_to_image_path.insert(checked, path.clone());
        app.pid_to_image_path.insert(shown, path.clone());

        // Check was clicked for `checked`, then the section moved on to `shown`.
        app.reputation_service.rehash_image(&path);
        app.vt_ui_state.pending_checks.insert(checked, false);
        app.vt_ui_state.last_seen_pid = Some(shown);
        for _ in 0..200 {
            app.service_background_work();
            if app.vt_ui_state.pending_checks.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            app.vt_ui_state.pending_checks.is_empty(),
            "lookup started without its section being rendered"
        );
        // The other process's display state was left alone.
        assert_eq!(app.vt_ui_state.current_process_sha, None);
        assert_eq!(app.vt_ui_state.querying_vt_pid, None);

        // With online lookups off, a pending request is dropped rather than sent later.
        app.online_lookups_enabled = false;
        app.mb_ui_state.pending_checks.insert(checked, true);
        app.service_background_work();
        assert!(app.mb_ui_state.pending_checks.is_empty());
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn service_background_work_error_then_success_updates_caches() {
        let mut app = crate::app::PMonNTApp::for_tests();

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
        assert!(
            app.signature_cache_by_path
                .get(&path)
                .and_then(|s| s.error.clone())
                .unwrap_or_default()
                .contains("unit test error")
        );

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
                identity: ReplyIdentity::Unknown,
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
                identity: ReplyIdentity::Unknown,
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
