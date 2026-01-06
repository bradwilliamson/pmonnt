use eframe::egui;
use std::collections::HashMap;

pub(super) fn get_or_query_image_path(
    ui: &mut egui::Ui,
    pid: u32,
    pid_to_image_path: &mut HashMap<u32, String>,
) -> Option<String> {
    if let Some(cached_path) = pid_to_image_path.get(&pid) {
        return Some(cached_path.clone());
    }

    match pmonnt_core::win::process_path::get_process_image_path(pid) {
        Ok(path) => {
            pid_to_image_path.insert(pid, path.clone());
            Some(path)
        }
        Err(e) => {
            ui.colored_label(egui::Color32::RED, format!("Cannot access process: {}", e));
            None
        }
    }
}

pub(super) fn render_image_path_row(ui: &mut egui::Ui, image_path: &str) {
    ui.horizontal(|ui| {
        ui.label("Path:");
        ui.label(image_path);
    });
}
