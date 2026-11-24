mod admission;
mod buffer;
mod decode;
mod input;
mod observe;
pub mod parser;
mod reception;
pub mod service;
pub mod transport;
mod zstd;
use crate::engine::IngestError;
pub use admission::{Admission, BudgetConfig, ByteLease, IngestBudget, RequestLease};
pub use buffer::{DecodeBuffers, EntryRanges, PutChunk};
use connectrpc::ConnectError;
pub use decode::{DecodeOutput, DecodeState};
pub use input::{
    box_body, BlockingDecodeExecutor, DecodeExecutor, DrainOutcome, PutBody, PutEncoding, PutInput,
    PutLimits, PutMetadata,
};
pub use observe::{IngestEvent, IngestObserver};
pub use reception::maximum_reception_bytes;
pub use service::{PutConfig, PutMiddleware, PutService};

#[derive(Clone, Debug, thiserror::Error)]
pub enum PutError {
    #[error("{0}")]
    Connect(#[from] ConnectError),
    #[error("{0}")]
    Backend(#[from] IngestError),
}

impl PutError {
    pub fn into_connect(self) -> ConnectError {
        match self {
            Self::Connect(error) => error,
            Self::Backend(error) => crate::connect::ingest_error_to_connect(error),
        }
    }
}

#[cfg(test)]
mod contract_tests;
