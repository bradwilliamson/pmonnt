use eframe::egui;

use crate::app::PMonNTApp;
use crate::process_table::{ProcessColumnId, ProcessColumns, ProcessTablePolicy};
use crate::util::percent_used;
use crate::view::GroupSort;

fn header_cell_button(
    app: &mut PMonNTApp,
    ui: &mut egui::Ui,
    col: ProcessColumnId,
    text: impl Into<egui::WidgetText>,
    released_any: &std::cell::Cell<bool>,
) -> egui::Response {
    let response = ui.add(egui::Button::new(text).sense(egui::Sense::click_and_drag()));

    // Right-click context menu: Task-Manager-style column chooser.
    response.context_menu(|ui| {
        ui.label(
            egui::RichText::new("Columns")
                .strong()
                .color(ui.visuals().text_color()),
        );
        ui.add_space(4.0);

        for c in ProcessColumnId::default_order() {
            let mut visible = c == ProcessColumnId::Name || !app.process_column_is_hidden(c);
            let enabled = c != ProcessColumnId::Name;

            let clicked = ui
                .add_enabled(enabled, egui::Checkbox::new(&mut visible, c.label()))
                .clicked();
            if clicked && enabled {
                app.set_process_column_hidden(c, !visible);
            }
        }

        ui.separator();
        if ui.button("Reset columns").clicked() {
            app.reset_process_columns_to_default();
            ui.close_menu();
        }
    });

    // Drag-to-reorder.
    if response.drag_started() {
        app.process_columns_drag = Some(col);
    }
    if response.dragged() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::Grabbing);
    }

    let released = ui.input(|i| i.pointer.any_released());
    if released {
        released_any.set(true);
    }
    if released {
        if let Some(drag_col) = app.process_columns_drag {
            if response.hovered() {
                app.move_process_column_before(drag_col, col);
            }
        }
    }

    response
}

pub(super) fn render_header(
    app: &mut PMonNTApp,
    mut header: egui_extras::TableRow<'_, '_>,
    policy: ProcessTablePolicy,
    columns: &[ProcessColumnId],
) {
    let show_totals_in_headers = matches!(
        policy.columns,
        ProcessColumns::Wide | ProcessColumns::Medium
    );
    let ram_pct = if app.ram_total_bytes > 0 {
        Some(percent_used(app.ram_used_bytes, app.ram_total_bytes))
    } else {
        None
    };

    let released_any = std::cell::Cell::new(false);

    for &col in columns {
        match col {
            ProcessColumnId::Name => {
                header.col(|ui| {
                    let name_label = if app.group_sort == GroupSort::Name {
                        if app.sort_desc {
                            "Name v"
                        } else {
                            "Name ^"
                        }
                    } else {
                        "Name"
                    };
                    let r = header_cell_button(app, ui, col, name_label, &released_any);
                    if r.clicked() {
                        app.group_sort_by_leader = false;
                        if app.group_sort == GroupSort::Name {
                            app.sort_desc = !app.sort_desc;
                        } else {
                            app.group_sort = GroupSort::Name;
                            app.sort_desc = false;
                        }
                    }
                });
            }
            ProcessColumnId::Leader => {
                header.col(|ui| {
                    let metric = match app.group_sort {
                        GroupSort::CPU => Some("CPU"),
                        GroupSort::Memory => Some("Mem"),
                        GroupSort::Disk => Some("Disk"),
                        GroupSort::GPU => Some("GPU"),
                        GroupSort::GPUMemory => Some("GPU Mem"),
                        GroupSort::Handles => Some("Handles"),
                        GroupSort::Threads => Some("Threads"),
                        GroupSort::PID => Some("PID"),
                        GroupSort::Name | GroupSort::VerifiedSigner => None,
                    };

                    let label = {
                        let base = match metric {
                            Some(m) => format!("Leader ({m})"),
                            None => "Leader".to_string(),
                        };
                        if app.group_sort_by_leader {
                            if app.sort_desc {
                                format!("{base} v")
                            } else {
                                format!("{base} ^")
                            }
                        } else {
                            base
                        }
                    };

                    let r = header_cell_button(app, ui, col, label, &released_any).on_hover_text(
                        "Leader shows the top process inside each group for the current sort metric (CPU/Memory/Disk/GPU/etc). If Sort is Name/Signer, Leader uses CPU as fallback.",
                    );

                    if r.clicked() {
                        if matches!(app.group_sort, GroupSort::Name | GroupSort::VerifiedSigner) {
                            app.group_sort = GroupSort::CPU;
                        }

                        if app.group_sort_by_leader {
                            app.sort_desc = !app.sort_desc;
                        } else {
                            app.group_sort_by_leader = true;
                            // Default sort direction matches other numeric columns.
                            app.sort_desc = true;
                        }
                    }
                });
            }
            ProcessColumnId::VerifiedSigner => {
                header.col(|ui| {
                    let label = if app.group_sort == GroupSort::VerifiedSigner {
                        if app.sort_desc {
                            "Verified Signer v"
                        } else {
                            "Verified Signer ^"
                        }
                    } else {
                        "Verified Signer"
                    };
                    let r = header_cell_button(app, ui, col, label, &released_any);
                    if r.clicked() {
                        app.group_sort_by_leader = false;
                        if app.group_sort == GroupSort::VerifiedSigner {
                            app.sort_desc = !app.sort_desc;
                        } else {
                            app.group_sort = GroupSort::VerifiedSigner;
                            app.sort_desc = false;
                        }
                    }
                });
            }
            ProcessColumnId::CPU => {
                header.col(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let cpu_label = {
                            let prefix = if app.group_sort == GroupSort::CPU {
                                if app.sort_desc {
                                    "v "
                                } else {
                                    "^ "
                                }
                            } else {
                                ""
                            };
                            if show_totals_in_headers {
                                format!("{prefix}CPU {:.0}%", app.total_cpu_percent)
                            } else {
                                format!("{prefix}CPU")
                            }
                        };
                        let r = header_cell_button(app, ui, col, cpu_label, &released_any);
                        if r.clicked() {
                            app.group_sort_by_leader = false;
                            if app.group_sort == GroupSort::CPU {
                                app.sort_desc = !app.sort_desc;
                            } else {
                                app.group_sort = GroupSort::CPU;
                                app.sort_desc = true;
                            }
                        }
                    });
                });
            }
            ProcessColumnId::Memory => {
                header.col(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let mem_label = {
                            let prefix = if app.group_sort == GroupSort::Memory {
                                if app.sort_desc {
                                    "v "
                                } else {
                                    "^ "
                                }
                            } else {
                                ""
                            };
                            if show_totals_in_headers {
                                if let Some(pct) = ram_pct {
                                    format!("{prefix}Memory {:.0}%", pct)
                                } else {
                                    format!("{prefix}Memory")
                                }
                            } else {
                                format!("{prefix}Memory")
                            }
                        };
                        let r = header_cell_button(app, ui, col, mem_label, &released_any);
                        if r.clicked() {
                            app.group_sort_by_leader = false;
                            if app.group_sort == GroupSort::Memory {
                                app.sort_desc = !app.sort_desc;
                            } else {
                                app.group_sort = GroupSort::Memory;
                                app.sort_desc = true;
                            }
                        }
                    });
                });
            }
            ProcessColumnId::Disk => {
                header.col(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let disk_label = if app.group_sort == GroupSort::Disk {
                            if app.sort_desc {
                                "v Disk"
                            } else {
                                "^ Disk"
                            }
                        } else {
                            "Disk"
                        };
                        let r = header_cell_button(app, ui, col, disk_label, &released_any);
                        if r.clicked() {
                            app.group_sort_by_leader = false;
                            if app.group_sort == GroupSort::Disk {
                                app.sort_desc = !app.sort_desc;
                            } else {
                                app.group_sort = GroupSort::Disk;
                                app.sort_desc = true;
                            }
                        }
                    });
                });
            }
            ProcessColumnId::GPU => {
                header.col(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let gpu_label = {
                            let prefix = if app.group_sort == GroupSort::GPU {
                                if app.sort_desc {
                                    "v "
                                } else {
                                    "^ "
                                }
                            } else {
                                ""
                            };
                            if show_totals_in_headers {
                                format!("{prefix}GPU {:.0}%", app.total_gpu_percent)
                            } else {
                                format!("{prefix}GPU")
                            }
                        };
                        let r = header_cell_button(app, ui, col, gpu_label, &released_any);
                        if r.clicked() {
                            app.group_sort_by_leader = false;
                            if app.group_sort == GroupSort::GPU {
                                app.sort_desc = !app.sort_desc;
                            } else {
                                app.group_sort = GroupSort::GPU;
                                app.sort_desc = true;
                            }
                        }
                    });
                });
            }
            ProcessColumnId::GpuDedicated => {
                header.col(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        header_cell_button(app, ui, col, "GPU Dedicated", &released_any);
                    });
                });
            }
            ProcessColumnId::GpuShared => {
                header.col(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        header_cell_button(app, ui, col, "GPU Shared", &released_any);
                    });
                });
            }
            ProcessColumnId::GpuTotal => {
                header.col(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let gpu_total_label = if app.group_sort == GroupSort::GPUMemory {
                            if app.sort_desc {
                                "v GPU Total"
                            } else {
                                "^ GPU Total"
                            }
                        } else {
                            "GPU Total"
                        };
                        let r = header_cell_button(app, ui, col, gpu_total_label, &released_any);
                        if r.clicked() {
                            app.group_sort_by_leader = false;
                            if app.group_sort == GroupSort::GPUMemory {
                                app.sort_desc = !app.sort_desc;
                            } else {
                                app.group_sort = GroupSort::GPUMemory;
                                app.sort_desc = true;
                            }
                        }
                    });
                });
            }
            ProcessColumnId::Handles => {
                header.col(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let handles_label = if app.group_sort == GroupSort::Handles {
                            if app.sort_desc {
                                "v Handles"
                            } else {
                                "^ Handles"
                            }
                        } else {
                            "Handles"
                        };
                        let r = header_cell_button(app, ui, col, handles_label, &released_any);
                        if r.clicked() {
                            app.group_sort_by_leader = false;
                            if app.group_sort == GroupSort::Handles {
                                app.sort_desc = !app.sort_desc;
                            } else {
                                app.group_sort = GroupSort::Handles;
                                app.sort_desc = true;
                            }
                        }
                    });
                });
            }
            ProcessColumnId::Threads => {
                header.col(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let threads_label = if app.group_sort == GroupSort::Threads {
                            if app.sort_desc {
                                "v Threads"
                            } else {
                                "^ Threads"
                            }
                        } else {
                            "Threads"
                        };
                        let r = header_cell_button(app, ui, col, threads_label, &released_any);
                        if r.clicked() {
                            app.group_sort_by_leader = false;
                            if app.group_sort == GroupSort::Threads {
                                app.sort_desc = !app.sort_desc;
                            } else {
                                app.group_sort = GroupSort::Threads;
                                app.sort_desc = true;
                            }
                        }
                    });
                });
            }
            ProcessColumnId::PID => {
                header.col(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let pid_label = if app.group_sort == GroupSort::PID {
                            if app.sort_desc {
                                "v PID"
                            } else {
                                "^ PID"
                            }
                        } else {
                            "PID"
                        };
                        let r = header_cell_button(app, ui, col, pid_label, &released_any);
                        if r.clicked() {
                            app.group_sort_by_leader = false;
                            if app.group_sort == GroupSort::PID {
                                app.sort_desc = !app.sort_desc;
                            } else {
                                app.group_sort = GroupSort::PID;
                                app.sort_desc = false;
                            }
                        }
                    });
                });
            }
        }
    }

    if released_any.get() {
        app.process_columns_drag = None;
    }
}
