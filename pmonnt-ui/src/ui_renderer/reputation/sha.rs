//! Image hashes for the provider sections, read from the reputation worker.

use pmonnt_core::reputation::LookupState;
use pmonnt_core::reputation_service::ReputationService;
use std::collections::HashMap;

/// Where the SHA-256 of a process image stands.
///
/// The provider sections never hash on the UI thread: the reputation panel queues the image
/// with the reputation worker before they render, and they read the worker's result here.
pub(super) enum ImageSha {
    Known(String),
    Pending,
    Failed(String),
}

pub(super) fn image_sha(
    service: &ReputationService,
    pid_to_image_path: &HashMap<u32, String>,
    pid: u32,
) -> ImageSha {
    let Some(path) = pid_to_image_path.get(&pid) else {
        return ImageSha::Failed("image path unknown".to_string());
    };
    match service.get_result(path) {
        Some(result) => match (result.sha256, result.state) {
            (Some(sha), _) => ImageSha::Known(sha),
            (None, LookupState::Error(e)) => ImageSha::Failed(e),
            (None, _) => ImageSha::Pending,
        },
        None => ImageSha::Pending,
    }
}
