use std::collections::{HashMap, HashSet};
use std::time::Instant;

use eframe::egui;
use pmonnt_core::diff::ProcessDiff;
use pmonnt_core::process;

use crate::app::{CompactView, Density, PMonNTApp};
use crate::process_table::{process_table_policy, ProcessColumnId};
use crate::view::{GroupSort, ViewMode};

mod grouped;
mod tree;

impl PMonNTApp {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn show_list_panel(
        &mut self,
        ctx: &egui::Context,
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
        egui::CentralPanel::default().show(ctx, |ui| {
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

            ui.label(format!("Tick: {}", tick));
            ui.label(format!("Process count: {}", process_count));

            if let Some(diff) = last_diff.as_ref() {
                if diff.has_changes() {
                    ui.separator();
                    ui.label(format!(
                        "Changes: +{} new, -{} exited, ~{} changed",
                        diff.new_pids.len(),
                        diff.exited_pids.len(),
                        diff.changed_pids.len()
                    ));
                }
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
                        ui.close_menu();
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
                ui.label("Filter:");
                egui::TextEdit::singleline(&mut self.filter_text)
                    .id(egui::Id::new("process_filter_input"))
                    .hint_text("/ or Ctrl+F to focus, Esc to clear")
                    .show(ui);

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

            // Build PID-based data structures for clean tree rendering.
            // NOTE: Clone the process list so we can pass references to the tree renderer
            // without holding an immutable borrow of `self` across an `&mut self` call.
            let processes = self.current_snapshot.processes.clone();
            let pid_to_proc: HashMap<u32, &process::Process> =
                processes.iter().map(|p| (p.pid, p)).collect();

            let pid_set: HashSet<u32> = pid_to_proc.keys().copied().collect();

            // Build parent -> children map
            let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
            for proc in &processes {
                // Only add to children map when PPID is present and non-zero; roots are handled separately
                if let Some(parent) = proc.ppid {
                    if parent != 0 {
                        children_map.entry(parent).or_default().push(proc.pid);
                    }
                }
            }

            // DEBOUNCE: Only recompute filter if filter_text changed
            let filter_timer = Instant::now();
            let filter_lower = self.filter_text.to_lowercase();

            // Grouped view UX: while filter is active, groups auto-expand (temporary).
            // Restore expansion state when filter clears.
            if self.view_mode == ViewMode::Grouped {
                let filter_active = !filter_lower.is_empty();
                if filter_active && !self.grouped_filter_was_active {
                    self.expanded_groups_before_filter = Some(self.expanded_groups.clone());
                }
                if !filter_active && self.grouped_filter_was_active {
                    if let Some(prev) = self.expanded_groups_before_filter.take() {
                        self.expanded_groups = prev;
                    }
                }
                self.grouped_filter_was_active = filter_active;
            }
            let visible_pids: Option<HashSet<u32>> = if filter_lower != self.last_filter_text_lower
            {
                // Filter text changed - recompute and cache
                self.last_filter_text_lower = filter_lower.clone();

                let result = if !filter_lower.is_empty() {
                    let mut matching_pids = HashSet::new();

                    // Find all processes that match the filter (name or PID)
                    for proc in &processes {
                        if proc.name.to_lowercase().contains(&filter_lower)
                            || proc.pid.to_string().contains(&filter_lower)
                        {
                            matching_pids.insert(proc.pid);
                        }
                    }

                    // Include all ancestors of matching processes with cycle detection
                    let mut expanded = matching_pids.clone();
                    for &pid in &matching_pids {
                        let mut current = pid;
                        let mut visited = HashSet::new();
                        let mut depth = 0;
                        const MAX_DEPTH: usize = 128;

                        while depth < MAX_DEPTH && !visited.contains(&current) {
                            visited.insert(current);

                            if let Some(proc) = pid_to_proc.get(&current) {
                                if let Some(parent_pid) = proc.ppid {
                                    if parent_pid != 0 && parent_pid != current {
                                        expanded.insert(parent_pid);
                                        current = parent_pid;
                                        depth += 1;
                                        continue;
                                    }
                                }
                            }
                            break;
                        }
                    }

                    // Include direct children of matching processes for context
                    let matching_with_children: Vec<u32> = matching_pids.iter().copied().collect();
                    for &pid in &matching_with_children {
                        if let Some(children) = children_map.get(&pid) {
                            for &child in children {
                                expanded.insert(child);
                            }
                        }
                    }

                    Some(expanded)
                } else {
                    None
                };

                self.cached_visible_pids = result.clone();
                result
            } else {
                // Filter unchanged - reuse cached result
                self.cached_visible_pids.clone()
            };

            let filter_elapsed = filter_timer.elapsed().as_millis() as u64;
            if filter_elapsed > 10 {
                log::warn!("slow section filter computation: {}ms", filter_elapsed);
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
                        selection_changed,
                    );
                }
                ViewMode::Tree => {
                    self.show_tree_list_panel(
                        ctx,
                        ui,
                        input,
                        row_height,
                        &pid_set,
                        &pid_to_proc,
                        &children_map,
                        visible_pids.as_ref(),
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
                    .id_source("exited_scroll")
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
