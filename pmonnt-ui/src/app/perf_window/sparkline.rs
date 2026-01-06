#[allow(dead_code)]
fn draw_sparkline_f32_auto(ui: &mut egui::Ui, values: &[f32], height: f32) {
    let max_v = values
        .iter()
        .copied()
        .fold(0.0f32, |a, b| a.max(b))
        .max(1.0);
    draw_sparkline_f32(ui, values, 0.0, max_v, height);
}

#[allow(dead_code)]
fn format_bytes_per_sec(bytes_per_sec: f32) -> String {
    let mut v = bytes_per_sec.max(0.0) as f64;
    let units = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"];
    let mut u = 0usize;
    while v >= 1024.0 && u + 1 < units.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{:.0} {}", v, units[u])
    } else {
        format!("{:.1} {}", v, units[u])
    }
}

fn draw_sparkline_f32(ui: &mut egui::Ui, values: &[f32], y_min: f32, y_max: f32, height: f32) {
    let width = ui.available_width().max(120.0);
    let (rect, _resp) = ui.allocate_exact_size(egui::vec2(width, height), egui::Sense::hover());
    let painter = ui.painter_at(rect);

    // Frame
    painter.rect_stroke(
        rect,
        0.0,
        egui::Stroke::new(1.0, ui.visuals().widgets.inactive.bg_stroke.color),
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

#[allow(dead_code)]
fn draw_sparkline_u64(ui: &mut egui::Ui, values: &[u64], height: f32) {
    let max_v = values.iter().copied().max().unwrap_or(0).max(1);
    let values_f: Vec<f32> = values
        .iter()
        .map(|v| (*v as f64 / max_v as f64 * 100.0) as f32)
        .collect();
    draw_sparkline_f32(ui, &values_f, 0.0, 100.0, height);
}

#[allow(dead_code)]
pub(super) fn draw_cpu_sparkline(ui: &mut egui::Ui, cpu_values: &[f32]) {
    ui.label(egui::RichText::new("CPU %").strong());
    draw_sparkline_f32(ui, cpu_values, 0.0, 100.0, 64.0);
    if let Some(last) = cpu_values.last() {
        ui.label(egui::RichText::new(format!("Current: {last:.1}%")).monospace());
    }
}

#[allow(dead_code)]
pub(super) fn draw_memory_sparkline(ui: &mut egui::Ui, label: &str, values: &[u64]) {
    ui.label(egui::RichText::new(label).strong());
    draw_sparkline_u64(ui, values, 64.0);
    if let Some(last) = values.last().copied() {
        ui.label(
            egui::RichText::new(format!(
                "Current: {}",
                crate::util::format_memory_bytes(last)
            ))
            .monospace(),
        );
    }
}

pub(super) fn draw_gpu_sparkline(ui: &mut egui::Ui, gpu_values: &[f32]) {
    ui.label(egui::RichText::new("GPU %").strong());
    draw_sparkline_f32(ui, gpu_values, 0.0, 100.0, 64.0);
    if let Some(last) = gpu_values.last().copied() {
        ui.label(egui::RichText::new(format!("Current: {last:.1}%")).monospace());
    }
}

#[allow(dead_code)]
pub(super) fn draw_io_sparkline(ui: &mut egui::Ui, label: &str, values: &[f32]) {
    ui.label(egui::RichText::new(label).strong());
    draw_sparkline_f32_auto(ui, values, 64.0);
    if let Some(last) = values.last().copied() {
        ui.label(
            egui::RichText::new(format!("Current: {}", format_bytes_per_sec(last))).monospace(),
        );
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
            egui::RichText::new(format!("Current: {:.0}", last))
                .monospace()
                .small(),
        );
    }
}
