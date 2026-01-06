use super::service::ReputationService;
use super::types::Job;
use super::ReputationRequestError;

impl ReputationService {
    /// Request an on-demand VirusTotal lookup for a process id.
    /// Computes SHA-256 synchronously and enqueues a background job to call VT.
    pub fn request_vt_lookup_for_process_typed(
        &self,
        pid: u32,
    ) -> Result<String, ReputationRequestError> {
        let image_path = crate::win::process_path::get_process_image_path(pid)
            .map_err(|e| ReputationRequestError::ProcessAccess { pid, source: e })?;

        let sha = self
            .hash_computer
            .compute_sha256(&image_path)
            .map_err(|e| ReputationRequestError::Hash { source: e })?;

        // If cached, return sha
        {
            let cache = self.vt_cache.read().unwrap_or_else(|p| p.into_inner());
            if cache.contains_key(&sha) {
                return Ok(sha);
            }
        }

        // Prevent duplicate in-flight VT queries for same sha
        {
            let mut in_f = self.vt_in_flight.lock().unwrap_or_else(|p| p.into_inner());
            if in_f.contains(&sha) {
                return Ok(sha);
            }
            in_f.insert(sha.clone());
        }

        if self
            .job_tx
            .send(Job::VtLookupHash {
                sha256: sha.clone(),
            })
            .is_err()
        {
            let mut in_f = self.vt_in_flight.lock().unwrap_or_else(|p| p.into_inner());
            in_f.remove(&sha);
            return Err(ReputationRequestError::WorkerUnavailable);
        }

        Ok(sha)
    }

    pub fn request_vt_lookup_for_process(&self, pid: u32) -> Result<String, String> {
        self.request_vt_lookup_for_process_typed(pid)
            .map_err(|e| e.to_string())
    }

    pub fn get_vt_sample_for_hash(
        &self,
        sha: &str,
    ) -> Option<(Option<crate::reputation::VtStats>, crate::vt::VtQueryMeta)> {
        let guard = self.vt_cache.read().unwrap_or_else(|p| p.into_inner());
        guard.get(sha).cloned()
    }
}
