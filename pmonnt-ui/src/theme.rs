use eframe::egui;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Theme {
    #[default]
    Dark,
    Light,
    /// "3270 / Green Screen": near-black background, phosphor-green text, monospace.
    GreenScreen,
    /// High contrast (dark base): larger fonts, thicker strokes, stronger selection.
    HighContrast,
}

impl Theme {
    pub(crate) fn as_key(self) -> &'static str {
        match self {
            Theme::Dark => "dark",
            Theme::Light => "light",
            Theme::GreenScreen => "green_screen",
            Theme::HighContrast => "high_contrast",
        }
    }

    pub(crate) fn from_key(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "dark" => Some(Theme::Dark),
            "light" => Some(Theme::Light),
            "green_screen" | "greenscreen" | "3270" => Some(Theme::GreenScreen),
            "high_contrast" | "highcontrast" => Some(Theme::HighContrast),
            _ => None,
        }
    }
}

pub(crate) fn apply_theme(ctx: &egui::Context, theme: Theme) {
    // Keep this deterministic: rebuild visuals/style/fonts per theme.
    // (No new deps; relies on system fonts when available.)
    let mut visuals = match theme {
        Theme::Light => egui::Visuals::light(),
        _ => egui::Visuals::dark(),
    };

    match theme {
        Theme::Dark | Theme::Light => {
            // Default egui visuals.
        }
        Theme::GreenScreen => {
            let bg = egui::Color32::from_rgb(5, 8, 6);
            let fg = egui::Color32::from_rgb(78, 255, 156);
            let fg_dim = egui::Color32::from_rgb(34, 178, 104);
            let sel_bg = egui::Color32::from_rgb(14, 56, 32);

            visuals.panel_fill = bg;
            visuals.window_fill = bg;
            visuals.faint_bg_color = egui::Color32::from_rgb(10, 16, 12);

            visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, fg);
            visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, fg);
            visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, fg);
            visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, fg);
            visuals.widgets.open.fg_stroke = egui::Stroke::new(1.0, fg);

            visuals.widgets.noninteractive.bg_fill = bg;
            visuals.widgets.inactive.bg_fill = bg;
            visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(9, 20, 13);
            visuals.widgets.active.bg_fill = egui::Color32::from_rgb(10, 26, 16);
            visuals.widgets.open.bg_fill = egui::Color32::from_rgb(10, 26, 16);

            visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(0.5, fg_dim);
            visuals.widgets.inactive.bg_stroke = egui::Stroke::new(0.5, fg_dim);
            visuals.widgets.hovered.bg_stroke = egui::Stroke::new(0.8, fg);
            visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0, fg);
            visuals.widgets.open.bg_stroke = egui::Stroke::new(1.0, fg);

            visuals.selection.bg_fill = sel_bg;
            visuals.selection.stroke = egui::Stroke::new(2.0, fg);
            visuals.hyperlink_color = fg;
            visuals.warn_fg_color = fg;
            visuals.error_fg_color = egui::Color32::from_rgb(255, 120, 120);
            visuals.window_stroke = egui::Stroke::new(0.5, fg_dim);
            visuals.popup_shadow = egui::epaint::Shadow::NONE;
            visuals.window_shadow = egui::epaint::Shadow::NONE;

            // Reduce rounding to keep the terminal vibe.
            visuals.window_rounding = egui::Rounding::same(0.0);
            visuals.widgets.noninteractive.rounding = egui::Rounding::same(0.0);
            visuals.widgets.inactive.rounding = egui::Rounding::same(0.0);
            visuals.widgets.hovered.rounding = egui::Rounding::same(0.0);
            visuals.widgets.active.rounding = egui::Rounding::same(0.0);
            visuals.widgets.open.rounding = egui::Rounding::same(0.0);
        }
        Theme::HighContrast => {
            visuals.panel_fill = egui::Color32::BLACK;
            visuals.window_fill = egui::Color32::BLACK;
            visuals.faint_bg_color = egui::Color32::from_rgb(24, 24, 24);
            visuals.window_stroke = egui::Stroke::new(2.0, egui::Color32::WHITE);

            let fg = egui::Color32::WHITE;
            let stroke = egui::Stroke::new(2.0, fg);
            visuals.widgets.noninteractive.fg_stroke = stroke;
            visuals.widgets.inactive.fg_stroke = stroke;
            visuals.widgets.hovered.fg_stroke = stroke;
            visuals.widgets.active.fg_stroke = egui::Stroke::new(2.5, fg);
            visuals.widgets.open.fg_stroke = stroke;

            visuals.widgets.noninteractive.bg_fill = egui::Color32::BLACK;
            visuals.widgets.inactive.bg_fill = egui::Color32::BLACK;
            visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(36, 36, 36);
            visuals.widgets.active.bg_fill = egui::Color32::from_rgb(56, 56, 56);
            visuals.widgets.open.bg_fill = egui::Color32::from_rgb(56, 56, 56);

            visuals.widgets.noninteractive.bg_stroke = stroke;
            visuals.widgets.inactive.bg_stroke = stroke;
            visuals.widgets.hovered.bg_stroke = egui::Stroke::new(2.5, fg);
            visuals.widgets.active.bg_stroke = egui::Stroke::new(3.0, fg);
            visuals.widgets.open.bg_stroke = egui::Stroke::new(3.0, fg);

            visuals.selection.bg_fill = egui::Color32::from_rgb(0, 92, 255);
            visuals.selection.stroke = egui::Stroke::new(3.0, egui::Color32::WHITE);
            visuals.hyperlink_color = egui::Color32::from_rgb(0, 140, 255);
            visuals.warn_fg_color = egui::Color32::from_rgb(255, 220, 0);
            visuals.error_fg_color = egui::Color32::from_rgb(255, 80, 80);
            visuals.override_text_color = Some(fg);
        }
    }

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    match theme {
        Theme::HighContrast => {
            style.spacing.item_spacing = egui::vec2(10.0, 8.0);
            style.spacing.button_padding = egui::vec2(10.0, 6.0);
            style.spacing.interact_size = egui::vec2(34.0, 26.0);

            use egui::TextStyle;
            style.text_styles.insert(
                TextStyle::Heading,
                egui::FontId::new(22.0, egui::FontFamily::Proportional),
            );
            style.text_styles.insert(
                TextStyle::Body,
                egui::FontId::new(16.0, egui::FontFamily::Proportional),
            );
            style.text_styles.insert(
                TextStyle::Button,
                egui::FontId::new(16.0, egui::FontFamily::Proportional),
            );
            style.text_styles.insert(
                TextStyle::Small,
                egui::FontId::new(14.0, egui::FontFamily::Proportional),
            );
            style.text_styles.insert(
                TextStyle::Monospace,
                egui::FontId::new(16.0, egui::FontFamily::Monospace),
            );

            style.visuals.widgets.noninteractive.fg_stroke.width = style
                .visuals
                .widgets
                .noninteractive
                .fg_stroke
                .width
                .max(2.0);
        }
        Theme::GreenScreen => {
            style.spacing.item_spacing = egui::vec2(8.0, 6.0);
            style.spacing.button_padding = egui::vec2(8.0, 4.0);
            style.spacing.interact_size = egui::vec2(30.0, 22.0);

            // Use monospace text styles without touching font_data.
            // This avoids panics if the OS font names aren't available in egui's font DB.
            use egui::TextStyle;
            let heading_sz = style
                .text_styles
                .get(&TextStyle::Heading)
                .map(|f| f.size)
                .unwrap_or(20.0);
            let body_sz = style
                .text_styles
                .get(&TextStyle::Body)
                .map(|f| f.size)
                .unwrap_or(14.0);
            let button_sz = style
                .text_styles
                .get(&TextStyle::Button)
                .map(|f| f.size)
                .unwrap_or(body_sz);
            let small_sz = style
                .text_styles
                .get(&TextStyle::Small)
                .map(|f| f.size)
                .unwrap_or((body_sz - 1.0).max(10.0));

            style.text_styles.insert(
                TextStyle::Heading,
                egui::FontId::new(heading_sz, egui::FontFamily::Monospace),
            );
            style.text_styles.insert(
                TextStyle::Body,
                egui::FontId::new(body_sz, egui::FontFamily::Monospace),
            );
            style.text_styles.insert(
                TextStyle::Button,
                egui::FontId::new(button_sz, egui::FontFamily::Monospace),
            );
            style.text_styles.insert(
                TextStyle::Small,
                egui::FontId::new(small_sz, egui::FontFamily::Monospace),
            );
        }
        Theme::Dark | Theme::Light => {
            // Keep existing style.
        }
    }
    ctx.set_style(style);
}
