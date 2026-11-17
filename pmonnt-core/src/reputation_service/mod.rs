//! Reputation service with background worker thread (no tokio)

mod mb;
mod service;
mod sync;
mod tf;
mod types;
mod vt;
mod worker;

pub use service::ReputationService;
pub use types::{ReputationCommand, ReputationResult};
