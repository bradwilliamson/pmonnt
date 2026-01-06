use crate::reputation::LookupState;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Job types for the reputation service
#[derive(Debug, Clone)]
pub(super) enum Job {
    /// Hash a file and optionally lookup reputation
    HashAndLookup {
        image_path: String,
        lookup_enabled: bool,
    },

    /// Perform an on-demand MalwareBazaar lookup for an already-computed SHA-256
    MbLookupHash { sha256: String },

    /// Perform an on-demand ThreatFox lookup for an already-computed SHA-256
    TfLookupHash { sha256: String },

    /// Perform an on-demand VirusTotal lookup for an already-computed SHA-256
    VtLookupHash { sha256: String },
}

/// Command types for runtime configuration updates
#[derive(Debug, Clone)]
pub enum ReputationCommand {
    /// Update API keys and provider enable flags
    UpdateConfig {
        vt_api_key: Option<String>,
        mb_api_key: Option<String>,
        tf_api_key: Option<String>,
        vt_enabled: bool,
        mb_enabled: bool,
        tf_enabled: bool,
    },
}

/// Result from a reputation job
#[derive(Debug, Clone)]
pub struct ReputationResult {
    pub image_path: String,
    pub sha256: Option<String>,
    pub state: LookupState,
}

// Type aliases for complex cache types
pub(super) type MbCacheType = Arc<
    RwLock<
        HashMap<
            String,
            (
                Option<crate::providers::MbSampleInfo>,
                crate::providers::MbQueryMeta,
            ),
        >,
    >,
>;

pub(super) type VtCacheType =
    Arc<RwLock<HashMap<String, (Option<crate::reputation::VtStats>, crate::vt::VtQueryMeta)>>>;
