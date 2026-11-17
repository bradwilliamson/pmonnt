mod feeds;
mod mb;
mod panel;
mod settings;
mod sha;
mod tf;
mod vt;

pub use feeds::render_threat_intel_feeds;
pub use mb::render_malwarebazaar_section;
pub use panel::{render_reputation_panel, render_reputation_panel_ctx};
pub use settings::{render_reputation_settings_panel, render_reputation_settings_panel_ctx};
pub use tf::render_threatfox_section;
pub use vt::render_virustotal_section;

/// Start explicit provider lookups whose image hash has been re-validated (see
/// `sha::dispatch_pending`). Called every frame, independent of what is rendered.
pub fn dispatch_pending_lookups(
    service: &pmonnt_core::reputation_service::ReputationService,
    pid_to_image_path: &std::collections::HashMap<u32, String>,
    online_lookups_enabled: bool,
    states: (
        &mut crate::ui_state::VtUiState,
        &mut crate::ui_state::MbUiState,
        &mut crate::ui_state::TfUiState,
    ),
) {
    let (vt, mb, tf) = states;
    sha::dispatch_pending(service, pid_to_image_path, online_lookups_enabled, vt);
    sha::dispatch_pending(service, pid_to_image_path, online_lookups_enabled, mb);
    sha::dispatch_pending(service, pid_to_image_path, online_lookups_enabled, tf);
}
