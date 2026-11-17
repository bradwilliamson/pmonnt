use super::service::ReputationService;
use super::types::Job;

impl ReputationService {
    /// Request a ThreatFox lookup for an already-computed SHA-256 on the background worker.
    /// Without `force`, a cached answer is reused unless that attempt failed.
    /// Returns whether a job was queued.
    pub fn request_tf_lookup_for_hash(&self, sha: &str, force: bool) -> bool {
        let sha = sha.to_string();

        if !force {
            let cache = self
                .tf_cache
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if cache
                .get(&sha)
                .is_some_and(|(_, meta)| meta.last_error_message.is_none())
            {
                return false;
            }
        }

        {
            let mut in_f = self
                .tf_in_flight
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if in_f.contains(&sha) {
                return false;
            }
            in_f.insert(sha.clone());
        }

        log::info!("Requesting ThreatFox lookup for hash {sha} (force={force})");

        if self
            .job_tx
            .send(Job::TfLookupHash {
                sha256: sha.clone(),
            })
            .is_err()
        {
            let mut in_f = self
                .tf_in_flight
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            in_f.remove(&sha);
            return false;
        }

        true
    }

    pub fn get_tf_iocs_for_hash(
        &self,
        sha: &str,
    ) -> Option<(Vec<crate::providers::TfIoc>, crate::providers::TfQueryMeta)> {
        let guard = self
            .tf_cache
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        let guard = self
            .tf_cache
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.get(sha).cloned()
    }
}
