use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReputationRequestError {
    #[error("cannot access process {pid}: {source}")]
    ProcessAccess {
        pid: u32,
        #[source]
        source: anyhow::Error,
    },

    #[error("hash error: {source}")]
    Hash {
        #[source]
        source: anyhow::Error,
    },

    #[error("reputation worker not available")]
    WorkerUnavailable,
}
