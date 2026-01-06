use eframe::egui;
use pmonnt_core::module::map_address_to_module;
use pmonnt_core::thread::ThreadInfo;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

#[derive(Debug, Clone)]
pub enum ThreadActionRequest {
    Stack { pid: u32, tid: u32 },
    Module { pid: u32, tid: u32 },
    Permissions { pid: u32, tid: u32 },
    Kill { pid: u32, tid: u32, exit_code: u32 },
    Suspend { pid: u32, tid: u32 },
    Resume { pid: u32, tid: u32 },
}

pub struct ThreadDetailUi<'a> {
    pub actions_enabled: bool,
    pub in_flight: &'a HashSet<String>,
    pub message: Option<&'a (String, Instant)>,
    pub permissions: Option<&'a (Instant, Result<String, String>)>,
    pub stack: Option<&'a (Instant, Result<String, String>)>,
}

pub fn render_threads_panel<F: FnMut(ThreadActionRequest)>(
    ui: &mut egui::Ui,
    pid: u32,
    threads: &Vec<ThreadInfo>,
    thread_prev: &HashMap<u32, Vec<ThreadInfo>>,
    modules: &[pmonnt_core::module::ModuleInfo],
    selected_tid: &mut Option<u32>,
    detail_ui: Option<ThreadDetailUi<'_>>,
    mut on_action: F,
) {
    // Drop selection if the selected thread no longer exists.
    if let Some(tid) = *selected_tid {
        if !threads.iter().any(|t| t.tid == tid) {
            *selected_tid = None;
        }
    }

    ui.heading("Threads");
    ui.add_space(4.0);

    let prev_tids: std::collections::HashSet<u32> = thread_prev
        .get(&pid)
        .map(|prev| prev.iter().map(|t| t.tid).collect())
        .unwrap_or_default();

    // Build previous cycle times map for delta calculation
    let prev_cycles: HashMap<u32, u64> = thread_prev
        .get(&pid)
        .map(|prev| {
            prev.iter()
                .filter_map(|t| t.cycle_time.map(|c| (t.tid, c)))
                .collect()
        })
        .unwrap_or_default();

    ui.horizontal(|ui| {
        ui.label(format!("Threads: {}", threads.len()));
        if !prev_tids.is_empty() {
            let new_count = threads
                .iter()
                .filter(|t| !prev_tids.contains(&t.tid))
                .count();
            if new_count > 0 {
                ui.colored_label(egui::Color32::LIGHT_GREEN, format!("+{} new", new_count));
            }
        }
    });
    ui.separator();

    let row_height = 18.0;
    let text_style = egui::TextStyle::Body;
    let font_id = ui
        .style()
        .text_styles
        .get(&text_style)
        .cloned()
        .unwrap_or_default();
    let available_width = ui.available_width();

    let mut next_selected_tid = *selected_tid;

    egui::ScrollArea::vertical().show(ui, |ui| {
        egui_extras::TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(egui_extras::Column::exact(60.0)) // TID
            .column(egui_extras::Column::exact(70.0)) // CPU %
            .column(egui_extras::Column::exact(90.0)) // Cycles Delta
            .column(egui_extras::Column::exact(60.0)) // Suspend
            .column(egui_extras::Column::remainder().at_least(200.0)) // Start Address / Module
            .min_scrolled_height(0.0)
            .max_scroll_height(available_width.max(1.0) * 4.0)
            .header(row_height, |mut header| {
                header.col(|ui| {
                    ui.label(egui::RichText::new("TID").font(font_id.clone()).strong());
                });
                header.col(|ui| {
                    ui.label(egui::RichText::new("CPU %").font(font_id.clone()).strong());
                });
                header.col(|ui| {
                    ui.label(
                        egui::RichText::new("Cycles Δ")
                            .font(font_id.clone())
                            .strong(),
                    );
                });
                header.col(|ui| {
                    ui.label(
                        egui::RichText::new("Suspend")
                            .font(font_id.clone())
                            .strong(),
                    );
                });
                header.col(|ui| {
                    ui.label(
                        egui::RichText::new("Start Address")
                            .font(font_id.clone())
                            .strong(),
                    );
                });
            })
            .body(|mut body| {
                for t in threads {
                    let is_new = !prev_tids.is_empty() && !prev_tids.contains(&t.tid);
                    let start_addr = t.start_address;
                    let module_map = map_address_to_module(start_addr, modules);
                    let is_selected_row = next_selected_tid == Some(t.tid);

                    // Calculate CPU time as percentage-ish display (total ms)
                    let cpu_ms = (t.kernel_time_100ns + t.user_time_100ns) / 10_000;

                    // Calculate cycles delta
                    let cycles_delta = t.cycle_time.and_then(|current| {
                        prev_cycles
                            .get(&t.tid)
                            .map(|&prev| current.saturating_sub(prev))
                    });

                    body.row(row_height, |mut row| {
                        row.set_selected(is_selected_row);

                        // TID column
                        row.col(|ui| {
                            let text = if is_new {
                                egui::RichText::new(format!("{}", t.tid))
                                    .color(egui::Color32::LIGHT_GREEN)
                            } else {
                                egui::RichText::new(format!("{}", t.tid))
                            };
                            ui.label(text);
                        });

                        // CPU % column (showing total CPU time in ms for now)
                        row.col(|ui| {
                            // Show "<0.01" for very small values, otherwise show ms
                            if cpu_ms == 0 {
                                ui.label(egui::RichText::new("< 0.01").color(egui::Color32::GRAY));
                            } else {
                                ui.label(format!("{}", cpu_ms));
                            }
                        });

                        // Cycles Delta column
                        row.col(|ui| {
                            if let Some(delta) = cycles_delta {
                                if delta == 0 {
                                    ui.label(egui::RichText::new("0").color(egui::Color32::GRAY));
                                } else {
                                    // Format large numbers with commas
                                    ui.label(format_cycles(delta));
                                }
                            } else if t.cycle_time.is_some() {
                                // First sample - show total cycles
                                if let Some(total) = t.cycle_time {
                                    ui.label(format_cycles(total));
                                } else {
                                    ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                                }
                            } else {
                                ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                            }
                        });

                        // Suspend Count column
                        row.col(|ui| {
                            if let Some(suspend) = t.suspend_count {
                                if suspend > 0 {
                                    ui.label(
                                        egui::RichText::new(format!("{}", suspend))
                                            .color(egui::Color32::YELLOW),
                                    );
                                } else {
                                    ui.label("0");
                                }
                            } else {
                                ui.label(egui::RichText::new("—").color(egui::Color32::GRAY));
                            }
                        });

                        // Start Address / Module column
                        row.col(|ui| {
                            if let Some(err) = &t.error {
                                ui.colored_label(egui::Color32::RED, err);
                                return;
                            }

                            ui.horizontal(|ui| {
                                if let Some((name, offset)) = &module_map {
                                    ui.label(name);
                                    ui.label(
                                        egui::RichText::new(format!("+0x{offset:x}"))
                                            .small()
                                            .color(ui.visuals().weak_text_color()),
                                    );
                                } else if let Some(addr) = start_addr {
                                    // No module found - show raw address
                                    ui.label(
                                        egui::RichText::new(format!("0x{addr:x}"))
                                            .color(egui::Color32::GRAY),
                                    );
                                } else {
                                    ui.label(
                                        egui::RichText::new("<unknown>").color(egui::Color32::GRAY),
                                    );
                                }

                                // Show thread name if available
                                if let Some(thread_name) = &t.name {
                                    if !thread_name.is_empty() {
                                        ui.label(
                                            egui::RichText::new(thread_name)
                                                .small()
                                                .italics()
                                                .color(ui.visuals().weak_text_color()),
                                        );
                                    }
                                }
                            });
                        });

                        // Row click selects.
                        let row_resp = row.response().interact(egui::Sense::click());
                        if row_resp.clicked() {
                            next_selected_tid = Some(t.tid);
                        }
                    });
                }
            });
    });

    *selected_tid = next_selected_tid;

    // Bottom detail panel
    if let Some(tid) = *selected_tid {
        if let Some(t) = threads.iter().find(|t| t.tid == tid) {
            ui.add_space(6.0);
            ui.separator();

            egui::Frame::group(ui.style())
                .inner_margin(egui::Margin::same(8.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading(format!("Thread {tid}"));
                        ui.add_space(8.0);
                        if let Some(name) = t.name.as_deref().filter(|s| !s.is_empty()) {
                            ui.label(
                                egui::RichText::new(name)
                                    .italics()
                                    .color(ui.visuals().weak_text_color()),
                            );
                        }
                    });

                    let module_map = map_address_to_module(t.start_address, modules);

                    egui::Grid::new(("thread_detail_grid", pid, tid))
                        .num_columns(2)
                        .spacing([10.0, 4.0])
                        .show(ui, |ui| {
                            ui.label("Start address:");
                            match (t.start_address, module_map.as_ref()) {
                                (_, Some((name, off))) => {
                                    ui.label(format!("{} + 0x{off:x}", name));
                                }
                                (Some(addr), None) => {
                                    ui.label(format!("0x{addr:x}"));
                                }
                                (None, None) => {
                                    ui.label(
                                        egui::RichText::new("<unknown>").color(egui::Color32::GRAY),
                                    );
                                }
                            }
                            ui.end_row();

                            ui.label("Priority:");
                            ui.label(
                                t.priority
                                    .map(|p| p.to_string())
                                    .unwrap_or_else(|| "-".to_string()),
                            );
                            ui.end_row();

                            ui.label("Base priority:");
                            ui.label(format!("{}", t.base_priority));
                            ui.end_row();

                            ui.label("Suspend count:");
                            ui.label(
                                t.suspend_count
                                    .map(|v| v.to_string())
                                    .unwrap_or_else(|| "-".to_string()),
                            );
                            ui.end_row();

                            ui.label("Context switches:");
                            ui.label(
                                t.context_switches
                                    .map(|v| v.to_string())
                                    .unwrap_or_else(|| "-".to_string()),
                            );
                            ui.end_row();

                            ui.label("Cycle time:");
                            ui.label(
                                t.cycle_time
                                    .map(format_cycles)
                                    .unwrap_or_else(|| "-".to_string()),
                            );
                            ui.end_row();

                            ui.label("State / wait reason:");
                            let state = t
                                .state
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "-".to_string());
                            let wait = t
                                .wait_reason
                                .map(|v| v.to_string())
                                .unwrap_or_else(|| "-".to_string());
                            ui.label(format!("{} / {}", state, wait));
                            ui.end_row();

                            ui.label("Ideal processor:");
                            ui.label(
                                t.ideal_processor
                                    .map(|v| v.to_string())
                                    .unwrap_or_else(|| "-".to_string()),
                            );
                            ui.end_row();
                        });

                    if let Some(detail) = &detail_ui {
                        if let Some((msg, at)) = detail.message {
                            if at.elapsed().as_secs() <= 10 {
                                ui.add_space(6.0);
                                ui.label(
                                    egui::RichText::new(msg).color(ui.visuals().weak_text_color()),
                                );
                            }
                        }

                        if let Some((_, perms)) = detail.permissions {
                            ui.add_space(6.0);
                            ui.label(egui::RichText::new("Permissions (SDDL):").strong());
                            match perms {
                                Ok(sddl) => {
                                    let mut sddl_show = sddl.clone();
                                    ui.add_enabled(
                                        false,
                                        egui::TextEdit::multiline(&mut sddl_show)
                                            .desired_rows(3)
                                            .font(egui::TextStyle::Monospace),
                                    );
                                }
                                Err(e) => {
                                    ui.colored_label(egui::Color32::LIGHT_RED, e);
                                }
                            }
                        }

                        if let Some((_, stack)) = detail.stack {
                            ui.add_space(6.0);
                            ui.label(egui::RichText::new("Stack:").strong());
                            match stack {
                                Ok(text) => {
                                    let mut show = text.clone();
                                    ui.add_enabled(
                                        false,
                                        egui::TextEdit::multiline(&mut show)
                                            .desired_rows(8)
                                            .font(egui::TextStyle::Monospace),
                                    );
                                }
                                Err(e) => {
                                    ui.colored_label(egui::Color32::LIGHT_RED, e);
                                }
                            }
                        }

                        if detail.actions_enabled {
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                let key = |label: &str| format!("{pid}:{tid}:{label}");

                                let stack_key = key("Stack");
                                let stack_busy = detail.in_flight.contains(&stack_key);
                                if ui
                                    .add_enabled(!stack_busy, egui::Button::new("Stack"))
                                    .clicked()
                                {
                                    on_action(ThreadActionRequest::Stack { pid, tid });
                                }

                                if ui.button("Module").clicked() {
                                    on_action(ThreadActionRequest::Module { pid, tid });
                                }

                                let perms_key = key("Permissions");
                                let perms_busy = detail.in_flight.contains(&perms_key);
                                if ui
                                    .add_enabled(!perms_busy, egui::Button::new("Permissions"))
                                    .clicked()
                                {
                                    on_action(ThreadActionRequest::Permissions { pid, tid });
                                }

                                let suspended = t.suspend_count.unwrap_or(0) > 0;
                                let sr_label = if suspended { "Resume" } else { "Suspend" };
                                let sr_key = key(sr_label);
                                let sr_busy = detail.in_flight.contains(&sr_key);
                                if ui
                                    .add_enabled(!sr_busy, egui::Button::new(sr_label))
                                    .clicked()
                                {
                                    if suspended {
                                        on_action(ThreadActionRequest::Resume { pid, tid });
                                    } else {
                                        on_action(ThreadActionRequest::Suspend { pid, tid });
                                    }
                                }

                                let kill_key = key("Kill");
                                let kill_busy = detail.in_flight.contains(&kill_key);
                                if ui
                                    .add_enabled(!kill_busy, egui::Button::new("Kill"))
                                    .clicked()
                                {
                                    on_action(ThreadActionRequest::Kill {
                                        pid,
                                        tid,
                                        exit_code: 1,
                                    });
                                }
                            });
                        }
                    }
                });
        }
    }
}

/// Format large cycle counts with commas for readability
fn format_cycles(cycles: u64) -> String {
    if cycles < 1000 {
        return cycles.to_string();
    }

    let s = cycles.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    let chars: Vec<char> = s.chars().collect();

    for (i, c) in chars.iter().enumerate() {
        if i > 0 && (chars.len() - i).is_multiple_of(3) {
            result.push(',');
        }
        result.push(*c);
    }

    result
}
