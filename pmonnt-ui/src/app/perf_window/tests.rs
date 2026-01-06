use super::history::fake_perf_stats;
use super::tabs::{clear_card_rects, render_performance_tab, take_card_rect};
use egui::{CentralPanel, Context, Pos2, RawInput, Rect, Vec2};

fn render_perf_tab(size: Vec2) {
    clear_card_rects();

    let ctx = Context::default();
    let input = RawInput {
        screen_rect: Some(Rect::from_min_size(Pos2::ZERO, size)),
        ..Default::default()
    };

    let _ = ctx.run(input, |ctx| {
        CentralPanel::default().show(ctx, |ui| {
            render_performance_tab(ui, &fake_perf_stats(), 1234);
        });
    });
}

#[test]
#[ignore = "Old card-based layout tests - new layout doesn't use cards"]
fn performance_tab_fills_width_large() {
    render_perf_tab(Vec2::new(1400.0, 900.0));

    let cpu = take_card_rect("perf_card_cpu").expect("CPU card not logged");
    let io = take_card_rect("perf_card_io").expect("I/O card not logged");
    let handles = take_card_rect("perf_card_handles").expect("Handles card not logged");

    assert!(
        io.min.x > cpu.min.x + 100.0,
        "I/O card should be placed in the second column on wide layouts",
    );
    assert!(
        (io.min.y - cpu.min.y).abs() < 8.0,
        "Top-row cards should align horizontally on wide layouts",
    );
    assert!(
        handles.min.y > io.max.y,
        "Handles should appear below I/O in the right column",
    );
}

#[test]
#[ignore = "Old card-based layout tests - new layout doesn't use cards"]
fn performance_tab_responsive_small() {
    render_perf_tab(Vec2::new(700.0, 900.0));

    let cpu = take_card_rect("perf_card_cpu").expect("CPU card not logged");
    let io = take_card_rect("perf_card_io").expect("I/O card not logged");
    let handles = take_card_rect("perf_card_handles").expect("Handles card not logged");

    assert!(
        io.min.y > cpu.max.y + 20.0,
        "Narrow layouts should stack I/O below CPU",
    );
    assert!(
        handles.min.y > io.max.y + 5.0,
        "Handles should follow beneath I/O in single-column layout",
    );
}
