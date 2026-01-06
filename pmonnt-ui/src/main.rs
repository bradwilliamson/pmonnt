use anyhow::Result;
use eframe::egui;
use pmonnt_core::win;

mod app;
mod background_worker;
mod credentials;
mod gpu;
mod gpu_pdh;
mod process_info;
mod process_rows;
mod process_table;
mod theme;
mod ui_renderer;
mod ui_state;
mod util;
mod view;

use crate::app::PMonNTApp;

struct StartupErrorApp {
    message: String,
}

impl eframe::App for StartupErrorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("PMonNT failed to start");
            ui.add_space(8.0);
            ui.label("Initialization failed due to a runtime/environment issue.");
            ui.add_space(8.0);
            ui.label(&self.message);
        });
    }
}

fn main() -> Result<(), eframe::Error> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    // Try to enable SeDebugPrivilege for better access to system processes
    let is_elevated = match win::enable_debug_privilege() {
        Ok(_) => {
            log::info!("SeDebugPrivilege enabled successfully");
            true
        }
        Err(e) => {
            log::warn!("Failed to enable SeDebugPrivilege: {}", e);
            false
        }
    };

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([960.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "PMonNT",
        options,
        Box::new(move |_cc| match PMonNTApp::try_new() {
            Ok(mut app) => {
                app.set_is_elevated(is_elevated);
                Ok(Box::new(app))
            }
            Err(e) => {
                log::error!("Failed to initialize app: {:#}", e);
                Ok(Box::new(StartupErrorApp {
                    message: format!("{e:#}"),
                }))
            }
        }),
    )
}
