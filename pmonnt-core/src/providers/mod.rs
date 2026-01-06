//! Additional reputation providers (MalwareBazaar, ThreatFox)

pub mod aggregator;
mod malwarebazaar;
mod threatfox;

pub use aggregator::AggregatorProvider;

pub use malwarebazaar::{
    MalwareBazaarProvider, MbApiError, MbComment, MbCscbEntry, MbDownloadResult, MbQueryMeta,
    MbRecentDetection, MbRecentSample, MbSampleInfo, MbTagInfoSample,
};

pub use threatfox::{
    parse_threatfox_search_hash_response_json, TfIoc, TfMalwareSample, TfQueryMeta, TfResult,
    ThreatFoxProvider,
};
