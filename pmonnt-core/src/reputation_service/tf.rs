use super::service::ReputationService;
use super::types::Job;
use super::ReputationRequestError;

impl ReputationService {
    /// Request an on-demand ThreatFox lookup for a process id.
    pub fn request_tf_lookup_for_process_typed(
        &self,
        pid: u32,
    ) -> Result<String, ReputationRequestError> {
        let image_path = crate::win::process_path::get_process_image_path(pid)
            .map_err(|e| ReputationRequestError::ProcessAccess { pid, source: e })?;

        let sha = self
            .hash_computer
            .compute_sha256(&image_path)
            .map_err(|e| ReputationRequestError::Hash { source: e })?;

        {
            let cache = self.tf_cache.read().unwrap_or_else(|p| p.into_inner());
            if cache.contains_key(&sha) {
                return Ok(sha);
            }
        }

        {
            let mut in_f = self.tf_in_flight.lock().unwrap_or_else(|p| p.into_inner());
            if in_f.contains(&sha) {
                return Ok(sha);
            }
            in_f.insert(sha.clone());
        }

        log::info!("Requesting ThreatFox lookup for pid {} sha {}", pid, sha);

        if self
            .job_tx
            .send(Job::TfLookupHash {
                sha256: sha.clone(),
            })
            .is_err()
        {
            let mut in_f = self.tf_in_flight.lock().unwrap_or_else(|p| p.into_inner());
            in_f.remove(&sha);
            return Err(ReputationRequestError::WorkerUnavailable);
        }

        Ok(sha)
    }

    pub fn request_tf_lookup_for_process(&self, pid: u32) -> Result<String, String> {
        self.request_tf_lookup_for_process_typed(pid)
            .map_err(|e| e.to_string())
    }

    pub fn request_tf_lookup_for_hash(&self, sha: &str, force: bool) -> bool {
        let sha = sha.to_string();

        if !force {
            let cache = self.tf_cache.read().unwrap_or_else(|p| p.into_inner());
            if cache.contains_key(&sha) {
                return false;
            }
        }

        {
            let mut in_f = self.tf_in_flight.lock().unwrap_or_else(|p| p.into_inner());
            if in_f.contains(&sha) {
                return false;
            }
            in_f.insert(sha.clone());
        }

        log::info!(
            "Requesting ThreatFox lookup for hash {} (force={})",
            sha,
            force
        );

        if self
            .job_tx
            .send(Job::TfLookupHash {
                sha256: sha.clone(),
            })
            .is_err()
        {
            let mut in_f = self.tf_in_flight.lock().unwrap_or_else(|p| p.into_inner());
            in_f.remove(&sha);
            return false;
        }

        true
    }

    pub fn get_tf_iocs_for_hash(
        &self,
        sha: &str,
    ) -> Option<(Vec<crate::providers::TfIoc>, crate::providers::TfQueryMeta)> {
        let guard = self.tf_cache.read().unwrap_or_else(|p| p.into_inner());
        guard
            .get(sha)
            .and_then(|(opt, meta)| opt.clone().map(|iocs| (iocs, meta.clone())))
    }

    pub fn get_tf_result_for_hash(
        &self,
        sha: &str,
    ) -> Option<(
        Option<crate::providers::TfResult>,
        crate::providers::TfQueryMeta,
    )> {
        let guard = self.tf_cache.read().unwrap_or_else(|p| p.into_inner());
        guard.get(sha).cloned()
    }
}
