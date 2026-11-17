use std::sync::Arc;
use std::time::Instant;

use eframe::egui;
use pmonnt_core::diff::ProcessDiff;

use crate::app::{CompactView, Density, PMonNTApp};
use crate::process_table::{ProcessColumnId, process_table_policy};
use crate::view::{GroupSort, ViewMode};

mod grouped;
mod tree;

impl PMonNTApp {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn show_list_panel(
        &mut self,
        ui: &mut egui::Ui,
        is_compact: bool,
        _available_width: f32,
        _left_min_width: f32,
        _left_max_width: f32,
        tick: u64,
        process_count: usize,
        last_diff: &Option<ProcessDiff>,
        selected_pid_before_panels: Option<u32>,
        input: &egui::InputState,
        selection_changed: &mut bool,
    ) {
        // List Panel is now the CentralPanel, taking up remaining space
        let ctx = &ui.ctx().clone();
        egui::CentralPanel::default().show(ui, |ui| {
            // Text in the process list is not selectable: a selectable label takes the click,
            // so clicking a process's name (or any text cell) did not select its row. The
            // details panels keep selectable text for copying.
            ui.style_mut().interaction.selectable_labels = false;

            // (details tabs, scroll areas) keep their existing feel.
            match self.density {
                Density::Comfortable => {
                    // Keep defaults.
                }
                Density::Compact => {
                    let spacing = &mut ui.style_mut().spacing;
                    spacing.item_spacing.y = spacing.item_spacing.y.min(4.0);
                    spacing.button_padding.y = spacing.button_padding.y.min(2.0);
                }
            }

            ui.heading("PMonNT");
            ui.separator();

            ui.label(format!("Tick: {tick}"));
            ui.label(format!("Process count: {process_count}"));

            if let Some(diff) = last_diff.as_ref()
                && diff.has_changes()
            {
                ui.separator();
                ui.label(format!(
                    "Changes: +{} new, -{} exited, ~{} changed",
                    diff.new_pids.len(),
                    diff.exited_pids.len(),
                    diff.changed_pids.len()
                ));
            }

            ui.separator();

            // View mode toggle
            ui.horizontal(|ui| {
                ui.label("View:");
                if ui
                    .selectable_label(self.view_mode == ViewMode::Grouped, "Grouped")
                    .clicked()
                {
                    self.view_mode = ViewMode::Grouped;
                }
                if ui
                    .selectable_label(self.view_mode == ViewMode::Tree, "Tree (PPID)")
                    .clicked()
                {
                    self.view_mode = ViewMode::Tree;
                }

                ui.separator();

                // Columns button
                ui.menu_button("Columns...", |ui| {
                    ui.label(
                        egui::RichText::new("Select Columns")
                            .strong()
                            .color(ui.visuals().text_color()),
                    );
                    ui.add_space(4.0);

                    for c in ProcessColumnId::default_order() {
                        if self.view_mode != ViewMode::Grouped && c == ProcessColumnId::Leader {
                            continue;
                        }
                        let mut visible =
                            c == ProcessColumnId::Name || !self.process_column_is_hidden(c);
                        let enabled = c != ProcessColumnId::Name;

                        let clicked = ui
                            .add_enabled(enabled, egui::Checkbox::new(&mut visible, c.label()))
                            .clicked();
                        if clicked && enabled {
                            self.set_process_column_hidden(c, !visible);
                        }
                    }

                    ui.separator();
                    if ui.button("Reset columns").clicked() {
                        self.reset_process_columns_to_default();
                        ui.close();
                    }
                });

                // Show Details Panel button if hidden
                if !self.details_panel_visible {
                    ui.separator();
                    if ui.button("Show Details Panel").clicked() {
                        self.details_panel_visible = true;
                    }
                }
            });

            // View mode hint
            ui.label(
                egui::RichText::new(if self.view_mode == ViewMode::Grouped {
                    "Grouped shows apps like Task Manager. Tree shows parent/child (PPID)."
                } else {
                    "Tree shows true process parent-child relationships."
                })
                .small()
                .color(ui.visuals().weak_text_color()),
            );

            if self.view_mode == ViewMode::Grouped {
                ui.label(
                    egui::RichText::new("Grouped (by name) • sorting groups by aggregate")
                        .small()
                        .color(ui.visuals().weak_text_color()),
                );
            }

            ui.separator();
            ui.label("Processes:");

            // Sort controls for grouped view
            if self.view_mode == ViewMode::Grouped {
                ui.horizontal(|ui| {
                    ui.label("Sort by:");
                    if ui
                        .selectable_label(self.group_sort == GroupSort::Name, "Name")
                        .clicked()
                    {
                        self.group_sort_by_leader = false;
                        if self.group_sort == GroupSort::Name {
                            self.sort_desc = !self.sort_desc;
                        } else {
                            self.group_sort = GroupSort::Name;
                            self.sort_desc = false;
                        }
                    }
                    if ui
                        .selectable_label(
                            self.group_sort == GroupSort::VerifiedSigner,
                            "Verified Signer",
                        )
                        .clicked()
                    {
                        self.group_sort_by_leader = false;
                        if self.group_sort == GroupSort::VerifiedSigner {
                            self.sort_desc = !self.sort_desc;
                        } else {
                            self.group_sort = GroupSort::VerifiedSigner;
                            self.sort_desc = false;
                        }
                    }
                    if ui
                        .selectable_label(self.group_sort == GroupSort::CPU, "CPU")
                        .clicked()
                    {
                        self.group_sort_by_leader = false;
                        if self.group_sort == GroupSort::CPU {
                            self.sort_desc = !self.sort_desc;
                        } else {
                            self.group_sort = GroupSort::CPU;
                            self.sort_desc = true;
                        }
                    }
                    if ui
                        .selectable_label(self.group_sort == GroupSort::Memory, "Memory")
                        .clicked()
                    {
                        self.group_sort_by_leader = false;
                        if self.group_sort == GroupSort::Memory {
                            self.sort_desc = !self.sort_desc;
                        } else {
                            self.group_sort = GroupSort::Memory;
                            self.sort_desc = true;
                        }
                    }
                    if ui
                        .selectable_label(self.group_sort == GroupSort::Disk, "Disk")
                        .clicked()
                    {
                        self.group_sort_by_leader = false;
                        if self.group_sort == GroupSort::Disk {
                            self.sort_desc = !self.sort_desc;
                        } else {
                            self.group_sort = GroupSort::Disk;
                            self.sort_desc = true;
                        }
                    }
                    if ui
                        .selectable_label(self.group_sort == GroupSort::GPU, "GPU")
                        .clicked()
                    {
                        self.group_sort_by_leader = false;
                        if self.group_sort == GroupSort::GPU {
                            self.sort_desc = !self.sort_desc;
                        } else {
                            self.group_sort = GroupSort::GPU;
                            self.sort_desc = true;
                        }
                    }
                    if ui
                        .selectable_label(self.group_sort == GroupSort::GPUMemory, "GPU Mem")
                        .clicked()
                    {
                        self.group_sort_by_leader = false;
                        if self.group_sort == GroupSort::GPUMemory {
                            self.sort_desc = !self.sort_desc;
                        } else {
                            self.group_sort = GroupSort::GPUMemory;
                            self.sort_desc = true;
                        }
                    }
                    if ui
                        .selectable_label(self.group_sort == GroupSort::Handles, "Handles")
                        .clicked()
                    {
                        self.group_sort_by_leader = false;
                        if self.group_sort == GroupSort::Handles {
                            self.sort_desc = !self.sort_desc;
                        } else {
                            self.group_sort = GroupSort::Handles;
                            self.sort_desc = true;
                        }
                    }
                    if ui
                        .selectable_label(self.group_sort == GroupSort::PID, "PID")
                        .clicked()
                    {
                        self.group_sort_by_leader = false;
                        if self.group_sort == GroupSort::PID {
                            self.sort_desc = !self.sort_desc;
                        } else {
                            self.group_sort = GroupSort::PID;
                            self.sort_desc = false;
                        }
                    }
                    if ui
                        .selectable_label(self.group_sort == GroupSort::Threads, "Threads")
                        .clicked()
                    {
                        self.group_sort_by_leader = false;
                        if self.group_sort == GroupSort::Threads {
                            self.sort_desc = !self.sort_desc;
                        } else {
                            self.group_sort = GroupSort::Threads;
                            self.sort_desc = true;
                        }
                    }
                });
            }

            // Search/filter input with keyboard shortcut hints
            ui.horizontal(|ui| {
                let filter_label = ui.label("Filter:");
                // Named after its label for screen readers (and UI tests).
                ui.add(
                    egui::TextEdit::singleline(&mut self.filter_text)
                        .id(egui::Id::unique("process_filter_input"))
                        .hint_text("/ or Ctrl+F to focus, Esc to clear"),
                )
                .labelled_by(filter_label.id);

                if ui.button("X").clicked() {
                    self.filter_text.clear();
                }

                // Bulletproof slash consumption: always consume if pending, handle both cases
                if self.slash_focus_pending {
                    if self.filter_text == "/" {
                        self.filter_text.clear();
                    } else if let Some(rest) = self.filter_text.strip_prefix('/') {
                        self.filter_text = rest.to_string();
                    }
                    self.slash_focus_pending = false;
                    ui.ctx().request_repaint(); // One extra repaint to show cleared text
                }
            });

            // Process relationships (children, roots, groups) come from the snapshot's view
            // index, built once per snapshot rather than every frame. Holding the Arc lets us
            // borrow it across the `&mut self` calls below without copying the process list.
            let snapshot = Arc::clone(&self.current_snapshot);

            let filter_timer = Instant::now();
            let filter_lower = self.filter_text.to_lowercase();

            // Grouped view UX: while filter is active, groups auto-expand (temporary).
            // Restore expansion state when filter clears.
            if self.view_mode == ViewMode::Grouped {
                let filter_active = !filter_lower.is_empty();
                if filter_active && !self.grouped_filter_was_active {
                    self.expanded_groups_before_filter = Some(self.expanded_groups.clone());
                }
                if !filter_active
                    && self.grouped_filter_was_active
                    && let Some(prev) = self.expanded_groups_before_filter.take()
                {
                    self.expanded_groups = prev;
                }
                self.grouped_filter_was_active = filter_active;
            }
            // Recompute the filtered PID set only when the filter text or the snapshot changes
            // (new processes must show up while a filter is active).
            if filter_lower != self.last_filter_text_lower
                || self.cached_visible_pids_snapshot != Some(snapshot.taken_at)
            {
                self.last_filter_text_lower.clone_from(&filter_lower);
                self.cached_visible_pids_snapshot = Some(snapshot.taken_at);
                self.cached_visible_pids =
                    pmonnt_core::view::filter_visible_pids(&snapshot, &filter_lower).map(Arc::new);
            }
            let visible_pids = self.cached_visible_pids.clone();

            let filter_elapsed = filter_timer.elapsed().as_millis() as u64;
            if filter_elapsed > 10 {
                log::warn!("slow section filter computation: {filter_elapsed}ms");
            }

            // TableBuilder manages its own layout; no explicit height needed.
            // Density impacts row height (Compact is better for narrow windows).
            let row_height = match self.density {
                Density::Compact => 16.0,
                Density::Comfortable => 18.0,
            };

            // Column policy: keep it simple and width-based.
            let policy = process_table_policy(ui.available_width());

            match self.view_mode {
                ViewMode::Grouped => {
                    self.show_grouped_list_panel(
                        ctx,
                        ui,
                        input,
                        row_height,
                        policy,
                        &snapshot,
                        selection_changed,
                    );
                }
                ViewMode::Tree => {
                    self.show_tree_list_panel(
                        ctx,
                        ui,
                        input,
                        row_height,
                        &snapshot,
                        visible_pids.as_deref(),
                        selection_changed,
                    );
                }
            }

            // Show exited processes
            let now = Instant::now();
            let recent_exited = self.exited_buffer.recent_exited(now);
            if !recent_exited.is_empty() {
                ui.separator();
                ui.label("Exited (last 30s):");

                egui::ScrollArea::vertical()
                    .id_salt("exited_scroll")
                    .max_height(150.0)
                    .show(ui, |ui| {
                        for exited in recent_exited {
                            let age = now.duration_since(exited.exited_at).as_secs();
                            ui.label(format!(
                                "{} (PID {}) - exited {}s ago",
                                exited.process.name, exited.process.pid, age
                            ));
                        }
                    });
            }
        });

        // Some selection changes happen via mouse clicks inside the list/table.
        // Detect them once here so compact mode can auto-switch to Details.
        if self.selected_pid != selected_pid_before_panels {
            *selection_changed = true;
        }

        // Compact UX: selecting a process in the List should naturally show Details.
        if is_compact && self.compact_view == CompactView::List && *selection_changed {
            self.compact_view = CompactView::Details;
        }
    }
}
