fn draw_sparkline_f32(ui: &mut egui::Ui, values: &[f32], y_min: f32, y_max: f32, height: f32) {
    let width = ui.available_width().max(120.0);
    let (rect, _resp) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
    let painter = ui.painter_at(rect);

    // Frame
    painter.rect_stroke(
        rect,
        0.0,
        egui::Stroke::new(1.0, ui.visuals().widgets.inactive.bg_stroke.color),
        egui::StrokeKind::Inside,
    );

    if values.len() < 2 {
        return;
    }

    let n = values.len() as f32;
    let x_step = rect.width() / (n - 1.0);
    let y_span = (y_max - y_min).max(1e-6);

    let mut points: Vec<egui::Pos2> = Vec::with_capacity(values.len());
    for (i, v) in values.iter().copied().enumerate() {
        let t = (v.clamp(y_min, y_max) - y_min) / y_span;
        let x = rect.left() + x_step * (i as f32);
        let y = rect.bottom() - t * rect.height();
        points.push(egui::pos2(x, y));
    }

    painter.add(egui::Shape::line(
        points,
        egui::Stroke::new(1.5, ui.visuals().widgets.active.fg_stroke.color),
    ));
}

pub(super) fn draw_gpu_sparkline(ui: &mut egui::Ui, gpu_values: &[f32]) {
    ui.label(egui::RichText::new("GPU %").strong());
    draw_sparkline_f32(ui, gpu_values, 0.0, 100.0, 64.0);
    if let Some(last) = gpu_values.last().copied() {
        ui.label(egui::RichText::new(format!("Current: {last:.1}%")).monospace());
    }
}

/// Draw sparkline with current value label
pub(super) fn draw_sparkline_f32_with_label(
    ui: &mut egui::Ui,
    values: &[f32],
    y_min: f32,
    y_max: f32,
    height: f32,
) {
    draw_sparkline_f32(ui, values, y_min, y_max, height);
    if let Some(last) = values.last().copied() {
        ui.label(
            egui::RichText::new(format!("Current: {last:.0}"))
                .monospace()
                .small(),
        );
    }
}
