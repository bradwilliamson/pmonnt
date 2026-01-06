use eframe::egui;

use crate::app::{CompactView, Density, PMonNTApp};
use crate::theme::Theme;
use crate::util::{format_memory_bytes, percent_used};

impl PMonNTApp {
    pub(super) fn show_elevation_warning(&self, ctx: &egui::Context) {
        if !self.is_elevated {
            egui::TopBottomPanel::top("elevation_warning").show(ctx, |ui| {
                ui.colored_label(
                    egui::Color32::RED,
                    "WARNING: RUNNING AS USER - ELEVATE FOR FULL HANDLE DETAILS",
                );
            });
        }
    }

    pub(super) fn show_version_footer(&self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("footer").show(ctx, |ui| {
            ui.columns(2, |cols| {
                cols[0].with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    if let Some(status) = self.current_status_line() {
                        ui.label(status);
                    }
                });

                cols[1].with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(format!("v{}", pmonnt_core::version()));
                });
            });
        });
    }

    pub(super) fn compute_responsive_layout(&mut self, ctx: &egui::Context) -> (f32, bool) {
        // --- Responsive layout ---
        // Breakpoint rationale:
        // - We want to behave like Process Explorer: always show split view, just resize panels.
        // - Only switch to compact mode if extremely narrow (e.g. phone size), effectively disabling it for desktop use.
        const COMPACT_BREAKPOINT_PX: f32 = 0.0;
        let available_width = ctx.available_rect().width();
        let is_compact = available_width < COMPACT_BREAKPOINT_PX;

        // Default compact view on entry: selected process => Details; otherwise List.
        if is_compact && !self.was_compact_layout {
            self.compact_view = if self.selected_pid.is_some() {
                CompactView::Details
            } else {
                CompactView::List
            };
        }

        // Compact default: no selection => List.
        if is_compact && self.selected_pid.is_none() {
            self.compact_view = CompactView::List;
        }

        (available_width, is_compact)
    }

    pub(super) fn render_main_toolbar(&mut self, ctx: &egui::Context, is_compact: bool) {
        egui::TopBottomPanel::top("main_toolbar").show(ctx, |ui| {
            ui.columns(2, |cols| {
                cols[0].with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.add_space(6.0);
                    let cpu_txt = format!("CPU {:>3.0}%", self.total_cpu_percent);
                    let ram_txt = if self.ram_total_bytes > 0 {
                        let pct = percent_used(self.ram_used_bytes, self.ram_total_bytes);
                        format!(
                            "RAM {:>3.0}% ({}/{})",
                            pct,
                            format_memory_bytes(self.ram_used_bytes),
                            format_memory_bytes(self.ram_total_bytes)
                        )
                    } else {
                        "RAM -".to_string()
                    };
                    let gpu_txt = format!("GPU {:>3.0}%", self.total_gpu_percent);
                    ui.label(format!("{}   {}   {}", cpu_txt, ram_txt, gpu_txt));
                });

                cols[1].with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add_space(6.0);

                    ui.menu_button("Theme", |ui| {
                        if ui
                            .selectable_label(self.theme == Theme::Dark, "Dark")
                            .clicked()
                        {
                            self.theme = Theme::Dark;
                            ui.close_menu();
                        }
                        if ui
                            .selectable_label(self.theme == Theme::Light, "Light")
                            .clicked()
                        {
                            self.theme = Theme::Light;
                            ui.close_menu();
                        }
                        if ui
                            .selectable_label(self.theme == Theme::GreenScreen, "3270")
                            .clicked()
                        {
                            self.theme = Theme::GreenScreen;
                            ui.close_menu();
                        }
                        if ui
                            .selectable_label(self.theme == Theme::HighContrast, "High Contrast")
                            .clicked()
                        {
                            self.theme = Theme::HighContrast;
                            ui.close_menu();
                        }
                    });

                    ui.separator();
                    ui.label("Density:");
                    ui.selectable_value(&mut self.density, Density::Comfortable, "Comfortable");
                    ui.selectable_value(&mut self.density, Density::Compact, "Compact");

                    if is_compact {
                        ui.separator();
                        ui.add_space(6.0);
                        ui.label("View:");
                        ui.selectable_value(&mut self.compact_view, CompactView::List, "List");
                        ui.selectable_value(
                            &mut self.compact_view,
                            CompactView::Details,
                            "Details",
                        );
                    }
                });
            });
        });
    }
}
