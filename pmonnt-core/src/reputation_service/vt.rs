use super::service::ReputationService;
use super::types::Job;

impl ReputationService {
    /// Request a VirusTotal lookup for an already-computed SHA-256 on the background worker.
    ///
    /// Without `force`, a definitive cached answer (found / not found) is reused, while an
    /// earlier error, offline or "not configured" result is retried. With `force`, the
    /// lookup also bypasses the provider's local cache, so "Refresh" really asks VirusTotal.
    /// Returns whether a job was queued.
    pub fn request_vt_lookup_for_hash(&self, sha: &str, force: bool) -> bool {
        if !force {
            let cache = self
                .vt_cache
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if cache
                .get(sha)
                .is_some_and(|(_, meta)| vt_result_is_definitive(meta))
            {
                return false;
            }
        }

        // Prevent duplicate in-flight VT queries for same sha
        {
            let mut in_f = self
                .vt_in_flight
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !in_f.insert(sha.to_string()) {
                return false;
            }
        }

        if self
            .job_tx
            .send(Job::VtLookupHash {
                sha256: sha.to_string(),
                bypass_cache: force,
            })
            .is_err()
        {
            let mut in_f = self
                .vt_in_flight
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            in_f.remove(sha);
            return false;
        }

        true
    }

    pub fn get_vt_sample_for_hash(
        &self,
        sha: &str,
    ) -> Option<(Option<crate::reputation::VtStats>, crate::vt::VtQueryMeta)> {
        let guard = self
            .vt_cache
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.get(sha).cloned()
    }
}

/// Whether a cached VirusTotal answer can be reused instead of asking again.
fn vt_result_is_definitive(meta: &crate::vt::VtQueryMeta) -> bool {
    matches!(meta.last_query_status.as_deref(), Some("ok" | "not_found"))
}
