use crate::ui_state::{MbUiState, TfUiState, VtUiState};
use eframe::egui;
use pmonnt_core::handles::HandleCache;
use pmonnt_core::reputation_service::ReputationService;
use pmonnt_core::snapshot::ProcessSnapshot;
use pmonnt_core::thread::ThreadInfo;
use pmonnt_core::vt::VirusTotalProvider;
use pmonnt_core::{module::ModuleCache, thread::ThreadCache, token::TokenCache};
use std::collections::HashMap;
use std::sync::Arc;

pub struct ReputationPanelContext<'a> {
    pub ui: &'a mut egui::Ui,
    pub pid: u32,
    pub reputation_service: &'a Arc<ReputationService>,
    pub pid_to_image_path: &'a mut HashMap<u32, String>,
    pub online_lookups_enabled: bool,
    pub vt_enabled: bool,
    pub mb_enabled: bool,
    pub tf_enabled: bool,
    pub mb_state: &'a mut MbUiState,
    pub vt_state: &'a mut VtUiState,
    pub tf_state: &'a mut TfUiState,
}

pub struct ReputationSettingsContext<'a> {
    pub ui: &'a mut egui::Ui,
    pub reputation_service: &'a Arc<ReputationService>,
    pub mb_state: &'a mut MbUiState,
    pub bg_worker: &'a crate::background_worker::BackgroundWorker,
    pub pid_to_image_path: &'a HashMap<u32, String>,
    pub online_lookups_enabled: &'a mut bool,
    pub prev_online_lookups_enabled: &'a mut bool,
    pub vt_api_key: &'a mut String,
    pub mb_api_key: &'a mut String,
    pub tf_api_key: &'a mut String,
    pub vt_enabled: &'a mut bool,
    pub mb_enabled: &'a mut bool,
    pub tf_enabled: &'a mut bool,
    pub vt_provider: &'a Arc<VirusTotalProvider>,
}

pub struct HandlesPanelContext<'a> {
    pub ui: &'a mut egui::Ui,
    pub pid: u32,
    pub handle_cache: &'a mut HandleCache,
    pub pid_to_image_path: &'a HashMap<u32, String>,
    pub current_snapshot: &'a ProcessSnapshot,
    pub token_cache: &'a mut TokenCache,
    pub thread_cache: &'a mut ThreadCache,
    pub thread_prev: &'a HashMap<u32, Vec<ThreadInfo>>,
    pub module_cache: &'a mut ModuleCache,
    pub reputation_service: &'a Arc<ReputationService>,
    pub scan_duration_ms: u64,
    pub scan_interval_secs: u64,
}
