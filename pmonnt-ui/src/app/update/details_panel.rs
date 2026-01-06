use std::time::{Duration, Instant};

use eframe::egui;
use egui_extras::{Column, TableBuilder};
use pmonnt_core::module::fetch_modules;
use pmonnt_core::services::{ServiceStartType, ServiceStatus};

use crate::app::network_sort::{sort_connections, NetworkSortKey, NetworkSortState};
use crate::app::{Density, PMonNTApp, RightTab};
use crate::process_table::ProcessColumnId;
use crate::ui_renderer;
use crate::util::format_memory_bytes;

impl PMonNTApp {
    fn render_settings_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("UI Settings");
        ui.separator();

        ui.collapsing("Process Table Columns", |ui| {
            ui.horizontal(|ui| {
                if ui.button("Reset to defaults").clicked() {
                    self.reset_process_columns_to_default();
                }

                ui.label(
                    egui::RichText::new("Some columns may be force-hidden on narrow layouts.")
                        .color(ui.visuals().weak_text_color()),
                );
            });

            egui::Grid::new("process_columns_grid")
                .num_columns(4)
                .spacing([10.0, 4.0])
                .show(ui, |ui| {
                    let cols: Vec<ProcessColumnId> = self.process_columns_order().to_vec();
                    for col in cols {
                        let is_name = col == ProcessColumnId::Name;
                        let mut visible = is_name || !self.process_column_is_hidden(col);

                        let enabled = !is_name;
                        ui.add_enabled_ui(enabled, |ui| {
                            ui.checkbox(&mut visible, "");
                        });

                        ui.label(col.label());

                        let up = ui.add_enabled(enabled, egui::Button::new("↑")).clicked();
                        let down = ui.add_enabled(enabled, egui::Button::new("↓")).clicked();

                        if enabled {
                            // Apply visibility changes.
                            let now_hidden = !visible;
                            self.set_process_column_hidden(col, now_hidden);

                            // Apply ordering changes.
                            if up {
                                self.move_process_column_up(col);
                            }
                            if down {
                                self.move_process_column_down(col);
                            }
                        }

                        ui.end_row();
                    }
                });
        });

        ui.add_space(10.0);
        ui.separator();

        let mut ctx = ui_renderer::ReputationSettingsContext {
            ui,
            reputation_service: &self.reputation_service,
            mb_state: &mut self.mb_ui_state,
            bg_worker: &self.bg_worker,
            pid_to_image_path: &self.pid_to_image_path,
            online_lookups_enabled: &mut self.online_lookups_enabled,
            prev_online_lookups_enabled: &mut self.prev_online_lookups_enabled,
            vt_api_key: &mut self.vt_api_key,
            mb_api_key: &mut self.mb_api_key,
            tf_api_key: &mut self.tf_api_key,
            vt_enabled: &mut self.vt_enabled,
            mb_enabled: &mut self.mb_enabled,
            tf_enabled: &mut self.tf_enabled,
            vt_provider: &self.vt_provider,
        };
        ui_renderer::render_reputation_settings_panel_ctx(&mut ctx);
    }

    pub(super) fn show_details_panel(&mut self, ctx: &egui::Context, selected_pid: Option<u32>) {
        egui::SidePanel::right("details_panel")
            .resizable(true)
            .default_width(self.right_panel_width)
            .width_range(200.0..=1200.0)
            .show(ctx, |ui| {
                // Persist width
                self.right_panel_width = ui.available_width();

                let has_pid = selected_pid.is_some();

                egui::TopBottomPanel::top("thread_tabs").show_inside(ui, |ui| {
                    ui.horizontal(|ui| {
                        // Close button - flat to align with tabs
                        if ui
                            .add(egui::Button::new("X").frame(false))
                            .on_hover_text("Close Details Panel")
                            .clicked()
                        {
                            self.details_panel_visible = false;
                        }
                        ui.separator();

                        ui.add_enabled_ui(has_pid, |ui| {
                            ui.selectable_value(&mut self.right_tab, RightTab::Summary, "Summary");
                            ui.selectable_value(&mut self.right_tab, RightTab::PerformanceGraph, "Performance Graph");
                            ui.selectable_value(&mut self.right_tab, RightTab::Details, "Details");
                            ui.selectable_value(&mut self.right_tab, RightTab::Services, "Services");
                            ui.selectable_value(&mut self.right_tab, RightTab::Threads, "Threads");
                            ui.selectable_value(&mut self.right_tab, RightTab::Handles, "Handles");
                            ui.selectable_value(&mut self.right_tab, RightTab::Network, "Network");
                            ui.selectable_value(&mut self.right_tab, RightTab::GPU, "GPU");
                            ui.selectable_value(&mut self.right_tab, RightTab::Version, "Version");
                            ui.selectable_value(&mut self.right_tab, RightTab::Reputation, "Reputation");
                            ui.selectable_value(&mut self.right_tab, RightTab::Scan, "Scan");
                        });
                        ui.selectable_value(&mut self.right_tab, RightTab::Settings, "Settings");
                    });
                });

                egui::ScrollArea::vertical()
                    .id_source("central_panel_scroll")
                    .show(ui, |ui| {
                        if self.right_tab == RightTab::Settings {
                            self.render_settings_tab(ui);
                            return;
                        }

                        let Some(pid) = selected_pid else {
                            ui.vertical_centered(|ui| {
                                ui.add_space(100.0);
                                ui.heading("Select a process to view details");
                                ui.add_space(20.0);
                                ui.label(
                                    egui::RichText::new(
                                        "Choose a process from the left panel to enable the tabs above.",
                                    )
                                    .color(ui.visuals().weak_text_color()),
                                );
                            });
                            return;
                        };

                        match self.right_tab {
                            RightTab::Summary => self.render_summary_tab(ui, pid),
                            RightTab::PerformanceGraph => {
                                ui.heading("Performance Graph");
                                ui.separator();
                                ui.label(
                                    egui::RichText::new(
                                        "The Performance Graph view is available in the process popout/properties window.",
                                    )
                                    .color(ui.visuals().weak_text_color()),
                                );
                            }
                            RightTab::Details => self.render_details_tab(ui, pid),
                            RightTab::Security => {
                                ui.heading("Security");
                                ui.separator();
                                ui.label(
                                    egui::RichText::new(
                                        "The Security view is available in the process popout/properties window.",
                                    )
                                    .color(ui.visuals().weak_text_color()),
                                );
                            }
                            RightTab::Services => self.render_services_tab(ui, pid),
                            RightTab::Threads => self.render_threads_tab(ui, pid),
                            RightTab::Handles => self.render_handles_tab(ui, pid),
                            RightTab::Network => self.render_network_tab(ui, pid),
                            RightTab::GPU => self.render_gpu_tab(ui, pid),
                            RightTab::Version => self.render_version_tab(ui, pid),
                            RightTab::Reputation => self.render_reputation_tab(ui, pid),
                            RightTab::Scan => self.render_scan_tab(ui, pid),
                            RightTab::Settings => {} // Handled above
                        }
                    });
            });
    }

    fn render_summary_tab(&mut self, ui: &mut egui::Ui, pid: u32) {
        // SUMMARY PANEL - Process overview with grouped sections
        ui.heading("Process Summary");
        ui.separator();

        if let Some(proc) = self
            .current_snapshot
            .processes
            .iter()
            .find(|p| p.pid == pid)
        {
            // === IDENTITY SECTION ===
            ui.group(|ui| {
                ui.label(egui::RichText::new("Identity").strong());

                ui.horizontal(|ui| {
                    ui.label("Name:");
                    ui.label(egui::RichText::new(&proc.name).strong());
                });

                ui.horizontal(|ui| {
                    ui.label("PID:");
                    ui.monospace(format!("{}", pid));
                    if ui.button("📋").on_hover_text("Copy PID").clicked() {
                        ui.output_mut(|o| o.copied_text = format!("{}", pid));
                    }
                });

                if let Some(ppid) = proc.ppid {
                    ui.horizontal(|ui| {
                        ui.label("Parent PID:");
                        ui.monospace(format!("{}", ppid));
                    });
                }
            });

            ui.add_space(8.0);

            // === RUNTIME SECTION ===
            if let Some((cpu_pct, mem_bytes)) = self.cpu_memory_data.get(&pid) {
                ui.group(|ui| {
                    ui.label(egui::RichText::new("Runtime").strong());

                    ui.horizontal(|ui| {
                        ui.label("CPU:");
                        ui.monospace(format!("{:.1}%", cpu_pct));
                    });

                    ui.horizontal(|ui| {
                        ui.label("Memory:");
                        match mem_bytes {
                            Some(mem_bytes) => {
                                ui.monospace(format_memory_bytes(*mem_bytes));
                            }
                            None => {
                                ui.label(
                                    egui::RichText::new("- (perm)").color(egui::Color32::GRAY),
                                );
                            }
                        }
                    });

                    // GPU
                    if let Some((gpu_pct, _, _, gpu_total)) = self.gpu_data.get(&pid) {
                        ui.horizontal(|ui| {
                            ui.label("GPU:");
                            ui.monospace(format!("{:.1}%", gpu_pct));
                        });

                        ui.horizontal(|ui| {
                            ui.label("GPU Memory:");
                            ui.monospace(format_memory_bytes(*gpu_total));
                        });
                    }

                    // Handles and Threads
                    if let Some(thread_count) = self.global_thread_counts.get(&pid) {
                        ui.horizontal(|ui| {
                            ui.label("Threads:");
                            ui.monospace(format!("{}", thread_count));
                        });
                    }

                    if let Some(handle_summary) = self.handle_cache.get(pid) {
                        ui.horizontal(|ui| {
                            ui.label("Handles:");
                            ui.monospace(format!("{}", handle_summary.total));
                        });
                    }
                });

                ui.add_space(8.0);
            }

            // === PATHS SECTION ===
            if self.pid_to_image_path.contains_key(&pid)
                || self.pid_to_command_line.contains_key(&pid)
            {
                ui.group(|ui| {
                    ui.label(egui::RichText::new("Paths").strong());

                    if let Some(path) = self.pid_to_image_path.get(&pid) {
                        ui.horizontal(|ui| {
                            ui.label("Image:");
                            // Truncate path with middle-ellipsis for display
                            let truncated = crate::util::truncate_path_middle(path, 40);
                            ui.label(&truncated);
                            if truncated != *path {
                                ui.label("") // Add hover space
                                    .on_hover_text(path); // Show full path on hover
                            }
                            if ui.button("📋").on_hover_text("Copy Full Path").clicked() {
                                ui.output_mut(|o| o.copied_text = path.clone());
                            }
                        });
                    }

                    if let Some(cmd) = self.pid_to_command_line.get(&pid) {
                        ui.horizontal(|ui| {
                            ui.label("Command:");
                            let truncated = crate::util::truncate_path_middle(cmd, 40);
                            ui.label(&truncated);
                            if truncated != *cmd {
                                ui.label("").on_hover_text(cmd);
                            }
                            if ui.button("📋").on_hover_text("Copy Command Line").clicked() {
                                ui.output_mut(|o| o.copied_text = cmd.clone());
                            }
                        });
                    }
                });

                ui.add_space(8.0);
            }

            // === SECURITY SECTION ===
            let has_security_info = proc.signature.is_some()
                || self
                    .pid_to_image_path
                    .get(&pid)
                    .map(|p| !p.is_empty())
                    .unwrap_or(false);

            if has_security_info {
                ui.group(|ui| {
                    ui.label(egui::RichText::new("Security").strong());

                    if let Some(path) = self.pid_to_image_path.get(&pid) {
                        if !path.is_empty() {
                            let path_cloned = path.clone();
                            // Request signature check
                            self.request_signature_check_for_path(&path_cloned);

                            if let Some(info) = self.signature_cache_by_path.get(&path_cloned) {
                                let (label, color) = match info.status() {
                                    pmonnt_core::SignatureStatus::Valid => (
                                        info.signer_name
                                            .clone()
                                            .unwrap_or_else(|| "Verified".to_string()),
                                        egui::Color32::GREEN,
                                    ),
                                    pmonnt_core::SignatureStatus::CatalogSigned => (
                                        info.signer_name
                                            .clone()
                                            .unwrap_or_else(|| "Verified (Catalog)".to_string()),
                                        egui::Color32::GREEN,
                                    ),
                                    pmonnt_core::SignatureStatus::NotSigned => {
                                        ("Not Signed".to_string(), egui::Color32::GRAY)
                                    }
                                    pmonnt_core::SignatureStatus::Untrusted => (
                                        "Untrusted".to_string(),
                                        egui::Color32::from_rgb(255, 100, 0),
                                    ),
                                    pmonnt_core::SignatureStatus::Invalid => {
                                        ("Invalid".to_string(), egui::Color32::RED)
                                    }
                                    pmonnt_core::SignatureStatus::Expired => (
                                        "Expired".to_string(),
                                        egui::Color32::from_rgb(255, 150, 0),
                                    ),
                                };

                                ui.horizontal(|ui| {
                                    ui.label("Signature:");
                                    ui.colored_label(color, label);
                                });
                            }
                        }
                    }
                });
            }
        }
    }

    fn render_details_tab(&mut self, ui: &mut egui::Ui, pid: u32) {
        // DETAILS PANEL - Process Explorer style details
        ui.heading("Process Details");
        ui.separator();

        let image_path = self.pid_to_image_path.get(&pid).cloned();

        egui::Grid::new("details_grid")
            .num_columns(2)
            .spacing([10.0, 4.0])
            .show(ui, |ui| {
                // Image Path
                ui.label("Image Path:");
                if let Some(path) = image_path.as_deref() {
                    ui.label(path);
                } else {
                    ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                }
                ui.end_row();

                // Signature (Verified Signer style)
                ui.label("Signature:");
                if let Some(ref path) = image_path {
                    self.request_signature_check_for_path(path);
                    if let Some(info) = self.signature_cache_by_path.get(path) {
                        let (label, color) = match info.status() {
                            pmonnt_core::SignatureStatus::Valid => {
                                ("Verified".to_string(), egui::Color32::LIGHT_GREEN)
                            }
                            pmonnt_core::SignatureStatus::CatalogSigned => {
                                ("Verified (Catalog)".to_string(), egui::Color32::LIGHT_GREEN)
                            }
                            pmonnt_core::SignatureStatus::NotSigned => {
                                ("Not signed".to_string(), egui::Color32::GRAY)
                            }
                            pmonnt_core::SignatureStatus::Untrusted => {
                                ("Untrusted".to_string(), egui::Color32::YELLOW)
                            }
                            pmonnt_core::SignatureStatus::Expired => {
                                ("Expired".to_string(), egui::Color32::YELLOW)
                            }
                            pmonnt_core::SignatureStatus::Invalid => {
                                ("Invalid".to_string(), egui::Color32::LIGHT_RED)
                            }
                        };
                        ui.label(egui::RichText::new(label).color(color));
                    } else {
                        ui.label(egui::RichText::new("Checking...").color(egui::Color32::GRAY));
                    }
                } else {
                    ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                }
                ui.end_row();

                // Signer
                ui.label("Signer:");
                if let Some(ref path) = image_path {
                    if let Some(info) = self.signature_cache_by_path.get(path) {
                        if let Some(ref signer) = info.signer_name {
                            ui.label(signer);
                        } else {
                            ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                        }
                    } else {
                        ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                    }
                } else {
                    ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                }
                ui.end_row();

                // Issuer
                ui.label("Issuer:");
                if let Some(ref path) = image_path {
                    if let Some(info) = self.signature_cache_by_path.get(path) {
                        if let Some(ref issuer) = info.issuer_name {
                            ui.label(issuer);
                        } else {
                            ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                        }
                    } else {
                        ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                    }
                } else {
                    ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                }
                ui.end_row();

                // Signature Error
                ui.label("Sig Error:");
                if let Some(ref path) = image_path {
                    if let Some(info) = self.signature_cache_by_path.get(path) {
                        if let Some(ref err) = info.error {
                            ui.label(egui::RichText::new(err).color(egui::Color32::GRAY));
                        } else {
                            ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                        }
                    } else {
                        ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                    }
                } else {
                    ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                }
                ui.end_row();

                // Command Line
                ui.label("Command Line:");
                if let Some(cmd) = self.pid_to_command_line.get(&pid) {
                    ui.label(cmd);
                } else {
                    ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                }
                ui.end_row();

                // Current Directory
                ui.label("Current Directory:");
                if let Some(cwd) = self.pid_to_current_directory.get(&pid) {
                    ui.label(cwd);
                } else {
                    ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                }
                ui.end_row();

                // Company
                ui.label("Company:");
                if let Some(company) = self.pid_to_company_name.get(&pid) {
                    ui.label(company);
                } else {
                    ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                }
                ui.end_row();

                // File Description
                ui.label("Description:");
                if let Some(desc) = self.pid_to_file_description.get(&pid) {
                    ui.label(desc);
                } else {
                    ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                }
                ui.end_row();

                // Integrity Level
                ui.label("Integrity Level:");
                if let Some(integrity) = self.pid_to_integrity_level.get(&pid) {
                    ui.label(integrity);
                } else {
                    ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                }
                ui.end_row();

                // User
                ui.label("User:");
                if let Some(user) = self.pid_to_user.get(&pid) {
                    ui.label(user);
                } else {
                    ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                }
                ui.end_row();

                // Session ID
                ui.label("Session ID:");
                if let Some(session) = self.pid_to_session_id.get(&pid) {
                    ui.label(format!("{}", session));
                } else {
                    ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                }
                ui.end_row();
            });

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(8.0);

        ui.collapsing("Environment (sanitized)", |ui| {
            ui.label(
                egui::RichText::new(
                    "Optional: may contain sensitive values. Common secret-like keys are redacted.",
                )
                .color(ui.visuals().weak_text_color()),
            );

            if let Some(env_rows) = self.pid_to_environment.get(&pid) {
                egui::ScrollArea::vertical()
                    .max_height(260.0)
                    .id_source(("env_scroll", pid))
                    .show(ui, |ui| {
                        egui::Grid::new(("env_grid", pid))
                            .num_columns(2)
                            .spacing([10.0, 2.0])
                            .show(ui, |ui| {
                                for (k, v) in env_rows {
                                    ui.monospace(k);

                                    let display = if v.len() > 200 {
                                        format!("{}…", &v[..200])
                                    } else {
                                        v.clone()
                                    };
                                    let resp = ui.monospace(&display);
                                    if display.len() != v.len() {
                                        resp.on_hover_text(v);
                                    }
                                    ui.end_row();
                                }
                            });
                    });
            } else if self.pid_env_attempted.contains(&pid) {
                ui.label(
                    egui::RichText::new(
                        "Environment unavailable (access denied / protected / exited).",
                    )
                    .color(egui::Color32::GRAY),
                );
            } else if ui.button("Load environment").clicked() {
                self.pid_env_attempted.insert(pid);

                match pmonnt_core::win::process_details::get_process_details(pid, true) {
                    Ok(details) => {
                        if let Some(env) = details.environment {
                            let mut rows: Vec<(String, String)> = env.into_iter().collect();
                            rows.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));
                            self.pid_to_environment.insert(pid, rows);
                        }
                    }
                    Err(_) => {
                        // Best-effort only.
                    }
                }
            }
        });
    }

    fn render_services_tab(&mut self, ui: &mut egui::Ui, pid: u32) {
        ui.heading("Services");
        ui.separator();

        if let Some(msg) = self.last_service_action_message.as_deref() {
            ui.label(egui::RichText::new(msg).color(ui.visuals().weak_text_color()));
            ui.add_space(6.0);
        }

        // Refresh on demand with a short per-PID TTL.
        let refresh_due = self
            .services_cache_by_pid
            .get(&pid)
            .map(|(t, _)| t.elapsed().as_secs() >= 2)
            .unwrap_or(true);

        if refresh_due {
            match pmonnt_core::services::get_services_for_process(pid) {
                Ok(mut svcs) => {
                    svcs.sort_by(|a, b| a.name.cmp(&b.name));
                    self.services_cache_by_pid
                        .insert(pid, (Instant::now(), svcs));
                    self.services_error_by_pid.remove(&pid);
                }
                Err(e) => {
                    self.services_error_by_pid.insert(pid, format!("{e}"));
                }
            }
        }

        if let Some(err) = self.services_error_by_pid.get(&pid) {
            ui.colored_label(egui::Color32::LIGHT_RED, err);
            return;
        }

        let Some((_, services)) = self.services_cache_by_pid.get(&pid) else {
            ui.label(
                egui::RichText::new("No service data yet").color(ui.visuals().weak_text_color()),
            );
            return;
        };

        if services.is_empty() {
            ui.label(
                egui::RichText::new(
                    "No hosted services for this process (common for non-svchost processes).",
                )
                .color(ui.visuals().weak_text_color()),
            );
            return;
        }

        let row_h = ui.spacing().interact_size.y;
        let table = egui_extras::TableBuilder::new(ui)
            .striped(true)
            .column(egui_extras::Column::auto()) // Name
            .column(egui_extras::Column::remainder()) // Display
            .column(egui_extras::Column::auto()) // Status
            .column(egui_extras::Column::auto()) // Start type
            .column(egui_extras::Column::auto()); // Actions

        table
            .header(20.0, |mut header| {
                header.col(|ui| {
                    ui.label("Name");
                });
                header.col(|ui| {
                    ui.label("Display Name");
                });
                header.col(|ui| {
                    ui.label("Status");
                });
                header.col(|ui| {
                    ui.label("Start");
                });
                header.col(|ui| {
                    ui.label("Actions");
                });
            })
            .body(|mut body| {
                for svc in services {
                    body.row(row_h, |mut row| {
                        row.col(|ui| {
                            let name_resp = ui.label(egui::RichText::new(&svc.name).monospace());

                            // Right-click context menu for service control actions.
                            // This is especially useful in the main (Grouped) view.
                            name_resp.context_menu(|ui| {
                                let can_control = self.is_elevated;
                                let restart_key = format!("{pid}:{}:Restart", svc.name);
                                let pause_key = format!("{pid}:{}:Pause", svc.name);
                                let resume_key = format!("{pid}:{}:Resume", svc.name);

                                let restart_enabled = can_control
                                    && svc.status == ServiceStatus::Running
                                    && !self.service_action_in_flight.contains(&restart_key);
                                let pause_enabled = can_control
                                    && svc.status == ServiceStatus::Running
                                    && !self.service_action_in_flight.contains(&pause_key);
                                let resume_enabled = can_control
                                    && svc.status == ServiceStatus::Paused
                                    && !self.service_action_in_flight.contains(&resume_key);

                                let restart_clicked = ui
                                    .add_enabled(restart_enabled, egui::Button::new("Restart"))
                                    .on_disabled_hover_text(
                                        "Requires elevation (and service must be Running)",
                                    )
                                    .clicked();

                                let pause_clicked = ui
                                    .add_enabled(pause_enabled, egui::Button::new("Pause"))
                                    .on_disabled_hover_text(
                                        "Requires elevation (and service must be Running)",
                                    )
                                    .clicked();

                                let resume_clicked = ui
                                    .add_enabled(resume_enabled, egui::Button::new("Resume"))
                                    .on_disabled_hover_text(
                                        "Requires elevation (and service must be Paused)",
                                    )
                                    .clicked();

                                if restart_clicked {
                                    self.service_action_in_flight.insert(restart_key.clone());
                                    let tx = self.service_action_result_tx.clone();
                                    let name = svc.name.clone();
                                    self.bg_worker.spawn(move || {
                                        let r = pmonnt_core::services::restart_service(
                                            &name,
                                            Duration::from_secs(15),
                                        )
                                        .map_err(|e| format!("{e}"));
                                        let _ = tx.send((pid, name, "Restart".to_string(), r));
                                    });
                                    ui.close_menu();
                                }

                                if pause_clicked {
                                    self.service_action_in_flight.insert(pause_key.clone());
                                    let tx = self.service_action_result_tx.clone();
                                    let name = svc.name.clone();
                                    self.bg_worker.spawn(move || {
                                        let r = pmonnt_core::services::pause_service(
                                            &name,
                                            Duration::from_secs(10),
                                        )
                                        .map_err(|e| format!("{e}"));
                                        let _ = tx.send((pid, name, "Pause".to_string(), r));
                                    });
                                    ui.close_menu();
                                }

                                if resume_clicked {
                                    self.service_action_in_flight.insert(resume_key.clone());
                                    let tx = self.service_action_result_tx.clone();
                                    let name = svc.name.clone();
                                    self.bg_worker.spawn(move || {
                                        let r = pmonnt_core::services::resume_service(
                                            &name,
                                            Duration::from_secs(10),
                                        )
                                        .map_err(|e| format!("{e}"));
                                        let _ = tx.send((pid, name, "Resume".to_string(), r));
                                    });
                                    ui.close_menu();
                                }
                            });
                        });
                        row.col(|ui| {
                            ui.label(&svc.display_name);
                            if let Some(desc) = svc.description.as_deref() {
                                ui.label(
                                    egui::RichText::new(desc)
                                        .color(ui.visuals().weak_text_color())
                                        .small(),
                                );
                            }
                        });
                        row.col(|ui| {
                            let (text, color) = match svc.status {
                                ServiceStatus::Running => ("Running", egui::Color32::LIGHT_GREEN),
                                ServiceStatus::Stopped => ("Stopped", egui::Color32::LIGHT_RED),
                                ServiceStatus::StartPending => {
                                    ("Start pending", egui::Color32::YELLOW)
                                }
                                ServiceStatus::StopPending => {
                                    ("Stop pending", egui::Color32::YELLOW)
                                }
                                ServiceStatus::ContinuePending => {
                                    ("Continue pending", egui::Color32::YELLOW)
                                }
                                ServiceStatus::PausePending => {
                                    ("Pause pending", egui::Color32::YELLOW)
                                }
                                ServiceStatus::Paused => ("Paused", egui::Color32::YELLOW),
                            };
                            ui.colored_label(color, text);
                        });
                        row.col(|ui| {
                            let label = match svc.start_type {
                                ServiceStartType::Automatic => "Automatic",
                                ServiceStartType::AutomaticDelayed => "Automatic (Delayed)",
                                ServiceStartType::Manual => "Manual",
                                ServiceStartType::Disabled => "Disabled",
                                ServiceStartType::Boot => "Boot",
                                ServiceStartType::System => "System",
                            };
                            ui.label(label);
                        });
                        row.col(|ui| {
                            let can_control = self.is_elevated;
                            let stop_key = format!("{pid}:{}:Stop", svc.name);
                            let restart_key = format!("{pid}:{}:Restart", svc.name);

                            let stop_enabled =
                                can_control && !self.service_action_in_flight.contains(&stop_key);
                            let restart_enabled = can_control
                                && !self.service_action_in_flight.contains(&restart_key);

                            let stop_clicked = ui
                                .add_enabled(stop_enabled, egui::Button::new("Stop"))
                                .on_disabled_hover_text("Requires elevation")
                                .clicked();
                            let restart_clicked = ui
                                .add_enabled(restart_enabled, egui::Button::new("Restart"))
                                .on_disabled_hover_text("Requires elevation")
                                .clicked();

                            if stop_clicked {
                                self.service_action_in_flight.insert(stop_key.clone());
                                let tx = self.service_action_result_tx.clone();
                                let name = svc.name.clone();
                                self.bg_worker.spawn(move || {
                                    let r = pmonnt_core::services::stop_service(
                                        &name,
                                        Duration::from_secs(10),
                                    )
                                    .map_err(|e| format!("{e}"));
                                    let _ = tx.send((pid, name, "Stop".to_string(), r));
                                });
                            }

                            if restart_clicked {
                                self.service_action_in_flight.insert(restart_key.clone());
                                let tx = self.service_action_result_tx.clone();
                                let name = svc.name.clone();
                                self.bg_worker.spawn(move || {
                                    let r = pmonnt_core::services::restart_service(
                                        &name,
                                        Duration::from_secs(15),
                                    )
                                    .map_err(|e| format!("{e}"));
                                    let _ = tx.send((pid, name, "Restart".to_string(), r));
                                });
                            }
                        });
                    });
                }
            });
    }
    fn render_threads_tab(&mut self, ui: &mut egui::Ui, pid: u32) {
        // THREADS PANEL - async fetch pattern
        let threads_timer = Instant::now();

        if let Some(threads) = self.thread_cache.get(pid) {
            // Cache hit - render threads
            let module_result = if let Some(result) = self.module_cache.get(pid) {
                result.clone()
            } else {
                let result = fetch_modules(pid, false);
                self.module_cache.insert(pid, result.clone());
                result
            };

            // Show module enumeration status for debugging
            ui.horizontal(|ui| {
                ui.label(format!("Modules found: {}", module_result.modules.len()));
                if let Some(err) = &module_result.error {
                    ui.colored_label(egui::Color32::YELLOW, format!("({})", err));
                }
            });

            // Debug: Show first thread's address and first few module ranges
            if let Some(first_thread) = threads.first() {
                if let Some(addr) = first_thread.start_address {
                    ui.horizontal(|ui| {
                        ui.label(format!("First thread addr: 0x{:x}", addr));
                    });
                }
            }

            // Show first 3 modules with their ranges
            ui.collapsing("Module ranges (first 5)", |ui| {
                for (i, m) in module_result.modules.iter().take(5).enumerate() {
                    let end = m.base_address.saturating_add(m.size as u64);
                    ui.label(format!(
                        "{}: {} @ 0x{:x} - 0x{:x} (size: 0x{:x})",
                        i, m.name, m.base_address, end, m.size
                    ));
                }
            });

            let mut sel = self.selected_tid_by_pid.get(&pid).copied();
            let mut actions: Vec<crate::ui_renderer::ThreadActionRequest> = Vec::new();

            let detail_ui = sel.map(|tid| crate::ui_renderer::ThreadDetailUi {
                actions_enabled: true,
                in_flight: &self.thread_action_in_flight,
                message: self.thread_action_message_by_key.get(&(pid, tid)),
                permissions: self.thread_permissions_cache.get(&(pid, tid)),
                stack: self.thread_stack_cache.get(&(pid, tid)),
            });

            crate::ui_renderer::render_threads_panel(
                ui,
                pid,
                threads,
                &self.thread_prev,
                &module_result.modules,
                &mut sel,
                detail_ui,
                |req| actions.push(req),
            );

            match sel {
                Some(tid) => {
                    self.selected_tid_by_pid.insert(pid, tid);
                }
                None => {
                    self.selected_tid_by_pid.remove(&pid);
                }
            }

            for action in actions {
                use crate::app::ThreadActionKind;
                use crate::ui_renderer::ThreadActionRequest;
                use pmonnt_core::module::map_address_to_module;

                let now = Instant::now();
                match action {
                    ThreadActionRequest::Stack { pid, tid } => {
                        let key = format!("{pid}:{tid}:Stack");
                        if self.thread_action_in_flight.contains(&key) {
                            continue;
                        }
                        self.thread_action_in_flight.insert(key);
                        let tx = self.thread_action_result_tx.clone();
                        self.bg_worker.spawn(move || {
                            let r =
                                pmonnt_core::win::thread_stack::thread_stack_trace(pid, tid, 64)
                                    .map_err(|e| e.to_string());
                            let (payload, result) = match r {
                                Ok(text) => (Some(text), Ok(())),
                                Err(e) => (None, Err(e)),
                            };
                            let _ = tx.send(crate::app::ThreadActionJobResult {
                                pid,
                                tid,
                                action: ThreadActionKind::Stack,
                                payload,
                                result,
                            });
                        });
                    }
                    ThreadActionRequest::Module { pid, tid } => {
                        let start_addr = threads
                            .iter()
                            .find(|t| t.tid == tid)
                            .and_then(|t| t.start_address);
                        let msg = match map_address_to_module(start_addr, &module_result.modules) {
                            Some((name, off)) => format!(
                                "Module: {} + 0x{off:x} (start=0x{:x})",
                                name,
                                start_addr.unwrap_or(0)
                            ),
                            None => format!(
                                "Module: <unknown> (start={})",
                                start_addr
                                    .map(|a| format!("0x{a:x}"))
                                    .unwrap_or_else(|| "<unknown>".to_string())
                            ),
                        };
                        self.thread_action_message_by_key
                            .insert((pid, tid), (msg, now));
                    }
                    ThreadActionRequest::Permissions { pid, tid } => {
                        let key = format!("{pid}:{tid}:Permissions");
                        if self.thread_action_in_flight.contains(&key) {
                            continue;
                        }
                        self.thread_action_in_flight.insert(key);
                        let tx = self.thread_action_result_tx.clone();
                        self.bg_worker.spawn(move || {
                            let r = pmonnt_core::win::thread_permissions::thread_security_sddl(tid)
                                .map_err(|e| e.to_string());
                            let (payload, result) = match r {
                                Ok(sddl) => (Some(sddl), Ok(())),
                                Err(e) => (None, Err(e)),
                            };
                            let _ = tx.send(crate::app::ThreadActionJobResult {
                                pid,
                                tid,
                                action: ThreadActionKind::Permissions,
                                payload,
                                result,
                            });
                        });
                    }
                    ThreadActionRequest::Suspend { pid, tid } => {
                        let key = format!("{pid}:{tid}:Suspend");
                        if self.thread_action_in_flight.contains(&key) {
                            continue;
                        }
                        self.thread_action_in_flight.insert(key);
                        let tx = self.thread_action_result_tx.clone();
                        self.bg_worker.spawn(move || {
                            let r = pmonnt_core::win::thread_control::suspend_thread(tid)
                                .map_err(|e| e.to_string());
                            let _ = tx.send(crate::app::ThreadActionJobResult {
                                pid,
                                tid,
                                action: ThreadActionKind::Suspend,
                                payload: None,
                                result: r.map(|_| ()),
                            });
                        });
                    }
                    ThreadActionRequest::Resume { pid, tid } => {
                        let key = format!("{pid}:{tid}:Resume");
                        if self.thread_action_in_flight.contains(&key) {
                            continue;
                        }
                        self.thread_action_in_flight.insert(key);
                        let tx = self.thread_action_result_tx.clone();
                        self.bg_worker.spawn(move || {
                            let r = pmonnt_core::win::thread_control::resume_thread(tid)
                                .map_err(|e| e.to_string());
                            let _ = tx.send(crate::app::ThreadActionJobResult {
                                pid,
                                tid,
                                action: ThreadActionKind::Resume,
                                payload: None,
                                result: r.map(|_| ()),
                            });
                        });
                    }
                    ThreadActionRequest::Kill {
                        pid,
                        tid,
                        exit_code,
                    } => {
                        let key = format!("{pid}:{tid}:Kill");
                        if self.thread_action_in_flight.contains(&key) {
                            continue;
                        }
                        self.thread_action_in_flight.insert(key);
                        let tx = self.thread_action_result_tx.clone();
                        self.bg_worker.spawn(move || {
                            let r = pmonnt_core::win::thread_control::kill_thread(tid, exit_code)
                                .map_err(|e| e.to_string());
                            let _ = tx.send(crate::app::ThreadActionJobResult {
                                pid,
                                tid,
                                action: ThreadActionKind::Kill,
                                payload: None,
                                result: r.map(|_| ()),
                            });
                        });
                    }
                }
            }
            let threads_elapsed = threads_timer.elapsed().as_millis() as u64;
            if threads_elapsed > 10 {
                log::warn!("slow section threads panel: {}ms", threads_elapsed);
            }
        } else {
            // Cache miss - enqueue fetch and show loading
            if !self.thread_fetch_in_flight.contains(&pid) {
                self.thread_fetch_in_flight.insert(pid);
                self.thread_fetch_started.insert(pid, Instant::now());
                let _ = self.thread_fetch_tx.send(pid);
            }

            // Show loading with elapsed time if taking long
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.spinner();

                let elapsed = self
                    .thread_fetch_started
                    .get(&pid)
                    .map(|start| start.elapsed())
                    .unwrap_or_default();

                if elapsed.as_millis() > 800 {
                    ui.label(format!(
                        "Querying threads... ({:.1}s)",
                        elapsed.as_secs_f32()
                    ));
                } else {
                    ui.label("Querying threads...");
                }
            });
        }
    }
    fn render_gpu_tab(&mut self, ui: &mut egui::Ui, pid: u32) {
        // GPU PANEL - GPU-specific details
        ui.heading("GPU Details");
        ui.separator();

        if let Some((gpu_pct, dedicated, shared, total)) = self.gpu_data.get(&pid) {
            ui.horizontal(|ui| {
                ui.label("GPU Usage:");
                ui.label(format!("{:.1}%", gpu_pct));
            });

            ui.horizontal(|ui| {
                ui.label("Dedicated Memory:");
                ui.label(format_memory_bytes(*dedicated));
            });

            ui.horizontal(|ui| {
                ui.label("Shared Memory:");
                ui.label(format_memory_bytes(*shared));
            });

            ui.horizontal(|ui| {
                ui.label("Total Memory:");
                ui.label(format_memory_bytes(*total));
            });
        } else {
            ui.label("No GPU data available for this process");
        }
    }
    fn render_handles_tab(&mut self, ui: &mut egui::Ui, pid: u32) {
        // HANDLES PANEL - with timing
        let handles_timer = Instant::now();
        let mut ctx = ui_renderer::HandlesPanelContext {
            ui,
            pid,
            handle_cache: &mut self.handle_cache,
            pid_to_image_path: &self.pid_to_image_path,
            current_snapshot: &self.current_snapshot,
            token_cache: &mut self.token_cache,
            thread_cache: &mut self.thread_cache,
            thread_prev: &self.thread_prev,
            module_cache: &mut self.module_cache,
            reputation_service: &self.reputation_service,
            scan_duration_ms: self.last_handle_scan_duration_ms,
            scan_interval_secs: self.handle_scan_interval_secs,
        };
        ui_renderer::render_handles_panel_ctx(&mut ctx);
        let handles_elapsed = handles_timer.elapsed().as_millis() as u64;
        if handles_elapsed > 10 {
            log::warn!("slow section handles panel: {}ms", handles_elapsed);
        }
    }
    fn render_network_tab(&mut self, ui: &mut egui::Ui, pid: u32) {
        ui.heading("Network Connections");
        ui.separator();
        ui.label(
            egui::RichText::new(
                "Note: this view shows TCP/UDP sockets only (ICMP like ping.exe will not appear).",
            )
            .color(ui.visuals().weak_text_color()),
        );

        match pmonnt_core::network::get_connections_for_process(pid) {
            Ok(mut conns) => {
                if conns.is_empty() {
                    ui.label(egui::RichText::new("No connections").color(egui::Color32::GRAY));
                } else {
                    fn sort_header_button(
                        ui: &mut egui::Ui,
                        label: &str,
                        key: NetworkSortKey,
                        sort: &mut NetworkSortState,
                    ) {
                        let mut text = label.to_string();
                        if sort.key == key {
                            text.push(' ');
                            text.push_str(if sort.ascending { "▲" } else { "▼" });
                        }

                        let resp = ui.add(
                            egui::Button::new(egui::RichText::new(text).strong()).frame(false),
                        );
                        if resp.clicked() {
                            sort.toggle_or_set(key);
                        }
                        resp.on_hover_text("Click to sort; click again to toggle direction");
                    }

                    let sort_state = self.network_sort;
                    sort_connections(&mut conns, sort_state);

                    let row_h = match self.density {
                        Density::Comfortable => 18.0,
                        Density::Compact => 16.0,
                    };

                    TableBuilder::new(ui)
                        .striped(true)
                        .resizable(true)
                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                        .column(Column::auto()) // Proto
                        .column(Column::remainder().at_least(160.0)) // Local
                        .column(Column::remainder().at_least(160.0)) // Remote
                        .column(Column::auto()) // State
                        .column(Column::auto()) // PID
                        .header(row_h, |mut header| {
                            header.col(|ui| {
                                sort_header_button(
                                    ui,
                                    "Proto",
                                    NetworkSortKey::Protocol,
                                    &mut self.network_sort,
                                );
                            });
                            header.col(|ui| {
                                sort_header_button(
                                    ui,
                                    "Local",
                                    NetworkSortKey::Local,
                                    &mut self.network_sort,
                                );
                            });
                            header.col(|ui| {
                                sort_header_button(
                                    ui,
                                    "Remote",
                                    NetworkSortKey::Remote,
                                    &mut self.network_sort,
                                );
                            });
                            header.col(|ui| {
                                sort_header_button(
                                    ui,
                                    "State",
                                    NetworkSortKey::State,
                                    &mut self.network_sort,
                                );
                            });
                            header.col(|ui| {
                                sort_header_button(
                                    ui,
                                    "PID",
                                    NetworkSortKey::Pid,
                                    &mut self.network_sort,
                                );
                            });
                        })
                        .body(|mut body| {
                            for c in conns {
                                body.row(row_h, |mut row| {
                                    row.col(|ui| {
                                        ui.label(match c.protocol {
                                            pmonnt_core::network::Protocol::Tcp => "TCP",
                                            pmonnt_core::network::Protocol::Udp => "UDP",
                                        });
                                    });

                                    row.col(|ui| {
                                        ui.label(format!("{}:{}", c.local_address, c.local_port));
                                    });

                                    row.col(|ui| {
                                        if let (Some(ip), Some(port)) =
                                            (c.remote_address, c.remote_port)
                                        {
                                            ui.label(format!("{}:{}", ip, port));
                                        } else {
                                            ui.label(
                                                egui::RichText::new("—").color(egui::Color32::GRAY),
                                            );
                                        }
                                    });

                                    row.col(|ui| {
                                        if let Some(state) = c.state {
                                            ui.label(format!("{:?}", state));
                                        } else {
                                            ui.label(
                                                egui::RichText::new("—").color(egui::Color32::GRAY),
                                            );
                                        }
                                    });

                                    row.col(|ui| {
                                        ui.label(
                                            egui::RichText::new(format!("{}", c.pid)).monospace(),
                                        );
                                    });
                                });
                            }
                        });
                }
            }
            Err(e) => {
                ui.colored_label(
                    egui::Color32::LIGHT_RED,
                    format!("Failed to enumerate connections: {}", e),
                );
            }
        }
    }
    fn render_version_tab(&mut self, ui: &mut egui::Ui, pid: u32) {
        // VERSION PANEL - File version information
        ui.heading("Version Information");
        ui.separator();

        if let Some(path) = self.pid_to_image_path.get(&pid) {
            ui.horizontal(|ui| {
                ui.label("File Path:");
                ui.label(path);
            });

            ui.separator();

            let (company, description) = crate::process_info::get_file_version_info(path);

            ui.horizontal(|ui| {
                ui.label("Company Name:");
                if let Some(company) = company {
                    ui.label(&company);
                } else {
                    ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                }
            });

            ui.horizontal(|ui| {
                ui.label("File Description:");
                if let Some(description) = description {
                    ui.label(&description);
                } else {
                    ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                }
            });
        } else {
            ui.label("No image path available");
        }
    }
    fn render_reputation_tab(&mut self, ui: &mut egui::Ui, pid: u32) {
        // REPUTATION PANEL - Hash and VirusTotal information
        let mut ctx = ui_renderer::ReputationPanelContext {
            ui,
            pid,
            reputation_service: &self.reputation_service,
            pid_to_image_path: &mut self.pid_to_image_path,
            online_lookups_enabled: self.online_lookups_enabled,
            vt_enabled: self.vt_enabled,
            mb_enabled: self.mb_enabled,
            tf_enabled: self.tf_enabled,
            mb_state: &mut self.mb_ui_state,
            vt_state: &mut self.vt_ui_state,
            tf_state: &mut self.tf_ui_state,
        };
        ui_renderer::render_reputation_panel_ctx(&mut ctx);
    }
    fn render_scan_tab(&mut self, ui: &mut egui::Ui, pid: u32) {
        ui_renderer::render_scan_panel(ui, pid, &mut self.yara_state, self.tf_api_key.as_str());
    }
}
