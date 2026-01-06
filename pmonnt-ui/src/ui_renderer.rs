pub mod context;

mod affinity_dialog;
mod dump_dialog;
mod handles;
mod kill_dialog;
mod priority_dialog;
mod reputation;
mod scan;
mod service_dialog;
mod threads;

#[allow(unused_imports)]
pub use handles::{render_handles_panel, render_handles_panel_ctx};
#[allow(unused_imports)]
pub use reputation::{
    render_malwarebazaar_section, render_reputation_panel, render_reputation_panel_ctx,
    render_reputation_settings_panel, render_reputation_settings_panel_ctx,
    render_threat_intel_feeds, render_threatfox_section, render_virustotal_section,
};
pub use scan::render_scan_panel;
pub use threads::{render_threads_panel, ThreadActionRequest, ThreadDetailUi};

pub(crate) use kill_dialog::render_kill_dialog;

pub(crate) use affinity_dialog::{render_affinity_dialog, AffinityDialogState};
pub(crate) use dump_dialog::{render_dump_confirm_dialog, DumpConfirmDialogState};
pub(crate) use priority_dialog::{render_priority_dialog, PriorityDialogState};
pub(crate) use service_dialog::{render_service_dialog, ServiceDialogState};

pub use context::{HandlesPanelContext, ReputationPanelContext, ReputationSettingsContext};
