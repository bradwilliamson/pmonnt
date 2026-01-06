use crate::ui_state::{MbUiState, TfUiState, VtUiState};
use eframe::egui;
use pmonnt_core::reputation_service::ReputationService;
use std::collections::HashMap;
use std::sync::Arc;

use super::super::context::ReputationPanelContext;

mod image_path;
mod providers;
mod status;

pub fn render_reputation_panel_ctx(ctx: &mut ReputationPanelContext<'_>) {
    super::render_reputation_panel(
        ctx.ui,
        ctx.pid,
        ctx.reputation_service,
        ctx.pid_to_image_path,
        ctx.online_lookups_enabled,
        ctx.vt_enabled,
        ctx.mb_enabled,
        ctx.tf_enabled,
        ctx.mb_state,
        ctx.vt_state,
        ctx.tf_state,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn render_reputation_panel(
    ui: &mut egui::Ui,
    pid: u32,
    reputation_service: &Arc<ReputationService>,
    pid_to_image_path: &mut HashMap<u32, String>,
    online_lookups_enabled: bool,
    vt_enabled: bool,
    mb_enabled: bool,
    tf_enabled: bool,
    mb_state: &mut MbUiState,
    vt_state: &mut VtUiState,
    tf_state: &mut TfUiState,
) {
    ui.heading("Reputation");
    ui.separator();

    if pid == 0 {
        ui.add_space(6.0);
        ui.colored_label(
            egui::Color32::GRAY,
            "Select a process on the left to view reputation.",
        );
        return;
    }

    let Some(image_path) = image_path::get_or_query_image_path(ui, pid, pid_to_image_path) else {
        return;
    };

    image_path::render_image_path_row(ui, &image_path);

    // Check if we have a result, or if job is in-flight
    let result = reputation_service.get_result(&image_path);
    let in_flight = reputation_service.is_in_flight(&image_path);

    // If no result and not in-flight, request lookup
    if result.is_none() && !in_flight {
        reputation_service.request_lookup(image_path.clone(), online_lookups_enabled);
    }

    // Show status based on result/in-flight state
    if let Some(result) = result {
        status::render_sha256_row(ui, &result.sha256);
        status::render_lookup_status_row(
            ui,
            &result.state,
            status::LookupStatusRowParams {
                online_lookups_enabled,
                sha256: &result.sha256,
                in_flight,
                image_path: &image_path,
                reputation_service,
                vt_enabled,
                mb_enabled,
                tf_enabled,
            },
        );

        providers::render_providers_section(
            ui,
            pid,
            reputation_service,
            pid_to_image_path,
            online_lookups_enabled,
            vt_enabled,
            mb_enabled,
            tf_enabled,
            mb_state,
            vt_state,
            tf_state,
            &result.state,
            result.sha256.as_deref(),
            in_flight,
        );
    } else if in_flight {
        // Show hashing spinner
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label("Processing...");
        });
    } else {
        ui.label("Requesting reputation data...");
    }
}
