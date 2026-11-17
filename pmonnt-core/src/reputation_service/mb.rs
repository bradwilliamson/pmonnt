use super::service::ReputationService;
use super::types::Job;

impl ReputationService {
    /// Request a MalwareBazaar lookup for an already-computed SHA-256 on the background
    /// worker. Without `force`, a cached answer is reused unless that attempt failed.
    /// Returns whether a job was queued.
    pub fn request_mb_lookup_for_hash(&self, sha: &str, force: bool) -> bool {
        let sha = sha.to_string();
        if !force {
            let cache = self
                .mb_cache
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
                .mb_in_flight
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let mut in_f = self
                .mb_in_flight
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        let guard = self
            .mb_cache
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
