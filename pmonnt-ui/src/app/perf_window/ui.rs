use std::time::Instant;

use pmonnt_core::module::fetch_modules;

use crate::view::RightTab;

use super::super::PMonNTApp;
use super::ProcessPerfWindow;

impl PMonNTApp {
    pub(crate) fn open_perf_window(&mut self, pid: u32) {
        self.perf_windows
            .entry(pid)
            .or_insert_with(|| ProcessPerfWindow {
                history: Default::default(),
                last_io: None,
                last_cpu_times: None,
                tab: RightTab::Summary,
                selected_tid: None,
                last_stats: None,
                current_stats: None,
                last_sample: None,
                peak_handles: None,
                security_filter: String::new(),
                net_churn_monitor: None,
                include_child_pids: false,
            });

        // Best-effort prefetch so the popout can render Threads quickly.
        if self.thread_cache.get(pid).is_none() && !self.thread_fetch_in_flight.contains(&pid) {
            self.thread_fetch_in_flight.insert(pid);
            self.thread_fetch_started.insert(pid, Instant::now());
            let _ = self.thread_fetch_tx.send(pid);
        }
    }

    pub(crate) fn process_name_for_pid(&self, pid: u32) -> String {
        self.current_snapshot
            .processes
            .iter()
            .find(|p| p.pid == pid)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "<unknown>".to_string())
    }

    pub(crate) fn show_perf_windows(&mut self, ctx: &egui::Context) {
        if self.perf_windows.is_empty() {
            return;
        }

        let main_inner = ctx.input(|i| {
            i.viewport()
                .inner_rect
                .map(|r| r.size())
                .unwrap_or(egui::Vec2::ZERO)
        });

        let pids: Vec<u32> = self.perf_windows.keys().copied().collect();
        let mut to_close: Vec<u32> = Vec::new();
        let mut paths_to_check: Vec<String> = Vec::new();

        for pid in pids {
            let process_name = self.process_name_for_pid(pid);
            let image_path = self.pid_to_image_path.get(&pid).cloned();
            let command_line = self.pid_to_command_line.get(&pid).cloned();
            let company_name = self.pid_to_company_name.get(&pid).cloned();
            let file_description = self.pid_to_file_description.get(&pid).cloned();
            let integrity_level = self.pid_to_integrity_level.get(&pid).cloned();
            let user = self.pid_to_user.get(&pid).cloned();
            let session_id = self.pid_to_session_id.get(&pid).copied();
            let gpu_opt = self.gpu_data.get(&pid).copied();

            let Some(w) = self.perf_windows.get_mut(&pid) else {
                continue;
            };

            // Sample detailed stats if needed
            let now = Instant::now();
            let should_sample = w
                .last_sample
                .map_or(true, |last| now.duration_since(last).as_secs_f64() >= 1.0);
            if should_sample {
                let elapsed = w
                    .last_sample
                    .map_or(1.0, |last| now.duration_since(last).as_secs_f64());
                if let Some(new_stats) =
                    PMonNTApp::sample_perf_stats(pid, w.last_stats.as_ref(), elapsed)
                {
                    w.last_stats = w.current_stats.clone();
                    w.current_stats = Some(new_stats);
                    w.last_sample = Some(now);

                    // Update peak handles
                    if let Some(current) = w.current_stats.as_ref().and_then(|s| s.handles) {
                        if let Some(peak) = w.peak_handles {
                            w.peak_handles = Some(peak.max(current));
                        } else {
                            w.peak_handles = Some(current);
                        }
                        if let Some(stats) = w.current_stats.as_mut() {
                            stats.peak_handles = w.peak_handles;
                        }
                    }
                }
            }

            // Best-effort prefetch (only for open windows).
            if self.thread_cache.get(pid).is_none() && !self.thread_fetch_in_flight.contains(&pid) {
                self.thread_fetch_in_flight.insert(pid);
                self.thread_fetch_started.insert(pid, Instant::now());
                let _ = self.thread_fetch_tx.send(pid);
            }

            let module_result = if let Some(result) = self.module_cache.get(pid) {
                result.clone()
            } else {
                let result = fetch_modules(pid, false);
                self.module_cache.insert(pid, result.clone());
                result
            };

            let title = format!("{} (PID {})", process_name, pid);

            let reputation_service = self.reputation_service.clone();

            // Capture settings/current key strings by value for use in read-only panels.
            // The interactive Settings tab will edit the live values on `self`.
            let tf_api_key_for_scan = self.tf_api_key.clone();

            // Snapshot the per-window tab selection.
            let current_tab = w.tab;
            let current_security_filter = w.security_filter.clone();

            let cpu_values: Vec<f32> = w.history.cpu_percent.iter().copied().collect();
            let mem_values: Vec<u64> = w.history.memory_bytes.iter().copied().collect();
            let priv_values: Vec<u64> = w.history.private_bytes.iter().copied().collect();
            let gpu_values: Vec<f32> = w.history.gpu_percent.iter().copied().collect();
            let io_read_values: Vec<f32> = w.history.io_read_bps.iter().copied().collect();
            let io_write_values: Vec<f32> = w.history.io_write_bps.iter().copied().collect();

            // Snapshot data needed for right-pane parity tabs.
            let stats_opt = w.current_stats.as_ref();

            if let Some(ref path) = image_path {
                paths_to_check.push(path.clone());
            }
            let signature_info = image_path
                .as_ref()
                .and_then(|p| self.signature_cache_by_path.get(p).cloned());
            let signature_in_flight = image_path
                .as_ref()
                .is_some_and(|p| self.signature_in_flight.contains(p));

            let viewport_id = egui::ViewportId::from_hash_of(("process_perf", pid));

            // Choose a sensible initial size for the perf popout.
            // - If we have a remembered size, reuse it.
            // - Otherwise compute from the main window size (Process Explorer-like).
            let min_collapse = egui::vec2(700.0, 500.0);
            let initial_size = if self.perf_window_width >= min_collapse.x
                && self.perf_window_height >= min_collapse.y
                && self.perf_window_width.is_finite()
                && self.perf_window_height.is_finite()
            {
                egui::vec2(self.perf_window_width, self.perf_window_height)
            } else {
                let scale = 0.65;
                let desired = if main_inner.x > 0.0 && main_inner.y > 0.0 {
                    main_inner * scale
                } else {
                    egui::vec2(1000.0, 720.0)
                };

                let min = egui::vec2(900.0, 650.0);
                let max = if main_inner.x > 0.0 && main_inner.y > 0.0 {
                    main_inner * 0.90
                } else {
                    egui::vec2(1600.0, 1200.0)
                };

                // If the main window is small, allow the clamp min to fall back to max.
                let min_x = min.x.min(max.x);
                let min_y = min.y.min(max.y);
                egui::vec2(desired.x.clamp(min_x, max.x), desired.y.clamp(min_y, max.y))
            };

            let builder = egui::ViewportBuilder::default()
                .with_title(title.clone())
                .with_inner_size([initial_size.x, initial_size.y])
                .with_min_inner_size([min_collapse.x, min_collapse.y]);

            #[derive(Clone)]
            struct ViewportStateResult {
                close: bool,
                tab: RightTab,
                security_filter: String,
                inner_size: egui::Vec2,
                net_churn_monitor: Option<crate::app::perf_window::history::NetChurnMonitor>,
                include_child_pids: bool,
                selected_tid: Option<u32>,
            }

            let result = {
                // Borrow the required app state for interactive panels.
                let current_snapshot = &self.current_snapshot;
                let pid_to_image_path_mut = &mut self.pid_to_image_path;
                let token_cache = &mut self.token_cache;
                let thread_cache = &mut self.thread_cache;
                let thread_prev = &self.thread_prev;
                let thread_fetch_in_flight = &mut self.thread_fetch_in_flight;
                let thread_fetch_started = &mut self.thread_fetch_started;
                let thread_fetch_tx = &self.thread_fetch_tx;
                let module_cache = &mut self.module_cache;
                let handle_cache = &mut self.handle_cache;
                let yara_state = &mut self.yara_state;
                let mb_state = &mut self.mb_ui_state;
                let vt_state = &mut self.vt_ui_state;
                let tf_state = &mut self.tf_ui_state;

                let online_lookups_enabled = &mut self.online_lookups_enabled;
                let prev_online_lookups_enabled = &mut self.prev_online_lookups_enabled;
                let vt_api_key = &mut self.vt_api_key;
                let mb_api_key = &mut self.mb_api_key;
                let tf_api_key = &mut self.tf_api_key;
                let vt_enabled = &mut self.vt_enabled;
                let mb_enabled = &mut self.mb_enabled;
                let tf_enabled = &mut self.tf_enabled;
                let vt_provider = &self.vt_provider;

                let bg_worker = &self.bg_worker;

                let security_cache_by_pid = &mut self.security_cache_by_pid;
                let security_in_flight = &mut self.security_in_flight;
                let security_result_tx = &self.security_result_tx;

                let owner_hwnd = self.main_hwnd;
                let process_permissions_hint_by_pid = &mut self.process_permissions_hint_by_pid;

                let last_handle_scan_duration_ms = self.last_handle_scan_duration_ms;
                let handle_scan_interval_secs = self.handle_scan_interval_secs;

                // Extract network churn state from w before moving into closure
                let current_net_churn_monitor = w.net_churn_monitor.clone();
                let current_include_child_pids = w.include_child_pids;
                let current_selected_tid = w.selected_tid;

                ctx.show_viewport_immediate(viewport_id, builder, move |ctx, class| {
                    let mut should_close = ctx.input(|i| i.viewport().close_requested());
                    let mut tab = current_tab;
                    let mut security_filter = current_security_filter.clone();

                    // Create temporary ProcessPerfWindow with network churn state
                    let mut temp_perf_window =
                        crate::app::perf_window::history::ProcessPerfWindow {
                            tab,
                            selected_tid: current_selected_tid,
                            security_filter: security_filter.clone(),
                            history: Default::default(),
                            last_sample: None,
                            current_stats: None,
                            last_stats: None,
                            peak_handles: None,
                            last_io: None,
                            last_cpu_times: None,
                            net_churn_monitor: current_net_churn_monitor.clone(),
                            include_child_pids: current_include_child_pids,
                        };

                    let inner_size = ctx.input(|i| {
                        i.viewport()
                            .inner_rect
                            .map(|r| r.size())
                            .unwrap_or(egui::Vec2::ZERO)
                    });

                    let mut render_tab_content = |ui: &mut egui::Ui, current_tab: RightTab| {
                        crate::app::perf_window::tabs::render_tab(
                            ui,
                            pid,
                            current_tab,
                            &mut temp_perf_window,
                            &mut security_filter,
                            &cpu_values,
                            &mem_values,
                            &priv_values,
                            &gpu_values,
                            &io_read_values,
                            &io_write_values,
                            stats_opt,
                            &module_result,
                            gpu_opt,
                            &image_path,
                            &signature_info,
                            signature_in_flight,
                            &command_line,
                            &company_name,
                            &file_description,
                            &integrity_level,
                            &user,
                            session_id,
                            current_snapshot,
                            pid_to_image_path_mut,
                            token_cache,
                            thread_cache,
                            thread_prev,
                            thread_fetch_in_flight,
                            thread_fetch_started,
                            thread_fetch_tx,
                            module_cache,
                            handle_cache,
                            &reputation_service,
                            bg_worker,
                            yara_state,
                            mb_state,
                            vt_state,
                            tf_state,
                            tf_api_key_for_scan.as_str(),
                            online_lookups_enabled,
                            prev_online_lookups_enabled,
                            vt_api_key,
                            mb_api_key,
                            tf_api_key,
                            vt_enabled,
                            mb_enabled,
                            tf_enabled,
                            vt_provider,
                            last_handle_scan_duration_ms,
                            handle_scan_interval_secs,
                            security_cache_by_pid,
                            security_in_flight,
                            security_result_tx,
                            owner_hwnd,
                            process_permissions_hint_by_pid,
                        );
                    };

                    match class {
                        egui::ViewportClass::Embedded => {
                            let mut open = true;
                            egui::Window::new(title.clone())
                                .open(&mut open)
                                .show(ctx, |ui| {
                                    crate::app::perf_window::tabs::render_window_header(
                                        ui, pid, &title, &mut tab,
                                    );

                                    egui::ScrollArea::vertical()
                                        .id_source(("perf_window_details_scroll", pid))
                                        .show(ui, |ui| {
                                            render_tab_content(ui, tab);
                                        });

                                    crate::app::perf_window::tabs::render_optional_gpu_footer(
                                        ui,
                                        &gpu_values,
                                    );
                                });
                            if !open {
                                should_close = true;
                            }
                        }
                        _ => {
                            egui::CentralPanel::default().show(ctx, |ui| {
                                crate::app::perf_window::tabs::render_window_header(
                                    ui, pid, &title, &mut tab,
                                );

                                egui::ScrollArea::vertical()
                                    .id_source(("perf_window_details_scroll", pid))
                                    .auto_shrink([false; 2])
                                    .show(ui, |ui| {
                                        render_tab_content(ui, tab);
                                    });

                                crate::app::perf_window::tabs::render_optional_gpu_footer(
                                    ui,
                                    &gpu_values,
                                );
                            });
                        }
                    }

                    ViewportStateResult {
                        close: should_close,
                        tab,
                        security_filter,
                        inner_size,
                        net_churn_monitor: temp_perf_window.net_churn_monitor,
                        include_child_pids: temp_perf_window.include_child_pids,
                        selected_tid: temp_perf_window.selected_tid,
                    }
                })
            };

            // Update remembered perf window size in-memory (persisted on shutdown).
            // Avoid churn: only record sane sizes and only if changed by > ~2 points.
            let sz = result.inner_size;
            if sz.x.is_finite()
                && sz.y.is_finite()
                && sz.x >= min_collapse.x
                && sz.y >= min_collapse.y
                && ((sz.x - self.perf_window_width).abs() > 2.0
                    || (sz.y - self.perf_window_height).abs() > 2.0)
            {
                self.perf_window_width = sz.x;
                self.perf_window_height = sz.y;
            }

            if result.close {
                to_close.push(pid);
            } else if let Some(w) = self.perf_windows.get_mut(&pid) {
                w.tab = result.tab;
                w.security_filter = result.security_filter;
                w.net_churn_monitor = result.net_churn_monitor;
                w.include_child_pids = result.include_child_pids;
                w.selected_tid = result.selected_tid;
            }
        }

        for pid in to_close {
            self.perf_windows.remove(&pid);
        }

        for path in paths_to_check {
            self.request_signature_check_for_path(&path);
        }
    }

    /// Collect all descendant PIDs for a root PID (recursive tree traversal)
    #[cfg(feature = "dev-tools")]
    #[allow(dead_code)]
    pub(super) fn collect_descendants(&self, root_pid: u32) -> Vec<u32> {
        use std::collections::{HashMap, HashSet};

        // Build parent -> children map
        let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
        for proc in &self.current_snapshot.processes {
            if let Some(ppid) = proc.ppid {
                if ppid != 0 {
                    children_map.entry(ppid).or_default().push(proc.pid);
                }
            }
        }

        let mut result = Vec::new();
        let mut visited = HashSet::new();
        let mut stack = vec![root_pid];

        while let Some(pid) = stack.pop() {
            if !visited.insert(pid) {
                continue; // Already visited (cycle detection)
            }
            result.push(pid);

            if let Some(children) = children_map.get(&pid) {
                for &child in children {
                    stack.push(child);
                }
            }
        }

        result
    }
}
