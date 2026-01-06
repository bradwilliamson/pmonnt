use super::service::ReputationService;
use super::types::Job;
use super::ReputationRequestError;

impl ReputationService {
    /// Request an on-demand MalwareBazaar lookup for a process id.
    /// This computes the image path and SHA-256 (using the service's HashComputer),
    /// then enqueues a job onto the service's background worker to call the MB provider.
    /// Returns the computed SHA-256 on success (lookup started or cached), or Err on failure.
    pub fn request_mb_lookup_for_process_typed(
        &self,
        pid: u32,
    ) -> Result<String, ReputationRequestError> {
        // Resolve image path
        let image_path = crate::win::process_path::get_process_image_path(pid)
            .map_err(|e| ReputationRequestError::ProcessAccess { pid, source: e })?;

        // Compute sha256 synchronously (reuse HashComputer)
        let sha = self
            .hash_computer
            .compute_sha256(&image_path)
            .map_err(|e| ReputationRequestError::Hash { source: e })?;

        // If cached, do nothing
        {
            let cache = self.mb_cache.read().unwrap_or_else(|p| p.into_inner());
            if cache.contains_key(&sha) {
                return Ok(sha);
            }
        }

        // Prevent duplicate in-flight MB queries for same sha
        {
            let mut in_f = self.mb_in_flight.lock().unwrap_or_else(|p| p.into_inner());
            if in_f.contains(&sha) {
                return Ok(sha);
            }
            in_f.insert(sha.clone());
        }

        if self
            .job_tx
            .send(Job::MbLookupHash {
                sha256: sha.clone(),
            })
            .is_err()
        {
            // Worker is gone; ensure we don't leave this sha stuck as in-flight.
            let mut in_f = self.mb_in_flight.lock().unwrap_or_else(|p| p.into_inner());
            in_f.remove(&sha);
            return Err(ReputationRequestError::WorkerUnavailable);
        }

        Ok(sha)
    }

    pub fn request_mb_lookup_for_process(&self, pid: u32) -> Result<String, String> {
        self.request_mb_lookup_for_process_typed(pid)
            .map_err(|e| e.to_string())
    }

    /// Force-refresh MB lookup for a given SHA-256 (spawn background job)
    pub fn request_mb_lookup_for_hash(&self, sha: &str, force: bool) -> bool {
        let sha = sha.to_string();
        if !force {
            let cache = self.mb_cache.read().unwrap_or_else(|p| p.into_inner());
            if cache.contains_key(&sha) {
                return false;
            }
        }
        {
            let mut in_f = self.mb_in_flight.lock().unwrap_or_else(|p| p.into_inner());
            if in_f.contains(&sha) {
                return false;
            }
            in_f.insert(sha.clone());
        }

        if self
            .job_tx
            .send(Job::MbLookupHash {
                sha256: sha.clone(),
            })
            .is_err()
        {
            let mut in_f = self.mb_in_flight.lock().unwrap_or_else(|p| p.into_inner());
            in_f.remove(&sha);
            return false;
        }

        true
    }

    /// Get cached MB sample/meta for a SHA-256 if present
    pub fn get_mb_sample_for_hash(
        &self,
        sha: &str,
    ) -> Option<(
        Option<crate::providers::MbSampleInfo>,
        crate::providers::MbQueryMeta,
    )> {
        let guard = self.mb_cache.read().unwrap_or_else(|p| p.into_inner());
        guard.get(sha).cloned()
    }

    /// Get last MalwareBazaar query metadata
    pub fn mb_get_last_query_meta(&self) -> Option<crate::providers::MbQueryMeta> {
        self.mb_provider.get_last_query_meta()
    }

    /// Get last MalwareBazaar sample (cached from most recent get_info)
    pub fn mb_get_last_sample(&self) -> Option<crate::providers::MbSampleInfo> {
        self.mb_provider.get_last_sample()
    }

    /// Get recent detections from MalwareBazaar
    pub fn mb_recent_detections(
        &self,
        hours: Option<u32>,
    ) -> Result<Vec<crate::providers::MbRecentDetection>, crate::providers::MbApiError> {
        self.mb_provider.recent_detections(hours)
    }

    /// Get recent additions (get_recent) from MalwareBazaar
    pub fn mb_get_recent(
        &self,
        selector: &str,
    ) -> Result<Vec<crate::providers::MbRecentSample>, crate::providers::MbApiError> {
        self.mb_provider.get_recent(selector)
    }

    /// Get Code Signing Certificate Blocklist entries
    pub fn mb_get_cscb(
        &self,
    ) -> Result<Vec<crate::providers::MbCscbEntry>, crate::providers::MbApiError> {
        self.mb_provider.get_cscb()
    }

    /// Search for samples by tag in MalwareBazaar
    pub fn mb_tag_search(
        &self,
        tag: &str,
        limit: Option<u32>,
    ) -> Result<Vec<crate::providers::MbTagInfoSample>, crate::providers::MbApiError> {
        self.mb_provider.get_taginfo(tag, limit)
    }

    /// Download sample from MalwareBazaar
    pub fn mb_download_sample(
        &self,
        sha256: &str,
        dest_dir: &std::path::Path,
    ) -> Result<crate::providers::MbDownloadResult, crate::providers::MbApiError> {
        self.mb_provider.download_sample(sha256, dest_dir)
    }
}
