use super::history::PerfStats;
use super::tabs::render_performance_tab;
use egui::{CentralPanel, Context, Pos2, RawInput, Rect, Vec2};

fn render_perf_tab(size: Vec2, stats: &PerfStats) {
    let ctx = Context::default();
    let input = RawInput {
        screen_rect: Some(Rect::from_min_size(Pos2::ZERO, size)),
        ..Default::default()
    };
    let _ = crate::util::run_headless(&ctx, input, |root_ui| {
        CentralPanel::default().show(root_ui, |ui| {
            render_performance_tab(ui, stats, 1234);
        });
    });
}

#[test]
fn performance_tab_renders_without_data_at_any_width() {
    // A freshly opened window has no samples yet; every metric shows as unavailable.
    for size in [
        Vec2::new(1400.0, 900.0),
        Vec2::new(600.0, 700.0),
        Vec2::new(240.0, 300.0),
    ] {
        render_perf_tab(size, &PerfStats::default());
    }
}
