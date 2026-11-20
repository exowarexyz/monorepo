use commonware_storage::{merkle, qmdb};
use exoware_sdk::{ClientError, ConnectError};

// Native Merkle errors cannot carry RPC codes. Reserve this tag to preserve Store retryability.
const STORE_READ_ABORTED: &str = "exoware-qmdb Store read aborted";

pub(crate) fn store_read_error<F: merkle::Family>(
    error: ClientError,
    message: &'static str,
) -> merkle::Error<F> {
    if error.rpc_code() == Some(connectrpc::ErrorCode::Aborted) {
        merkle::Error::DataCorrupted(STORE_READ_ABORTED)
    } else {
        merkle::Error::DataCorrupted(message)
    }
}

pub(crate) fn merkle_error<F: merkle::Family>(error: merkle::Error<F>) -> QmdbError {
    match error {
        merkle::Error::DataCorrupted(STORE_READ_ABORTED) => {
            ClientError::Rpc(Box::new(ConnectError::aborted(STORE_READ_ABORTED))).into()
        }
        error => QmdbError::CommonwareMerkle(error.to_string()),
    }
}

pub(crate) fn current_proof_error<F: merkle::Family>(error: qmdb::Error<F>) -> QmdbError {
    match error {
        qmdb::Error::Merkle(merkle::Error::DataCorrupted(STORE_READ_ABORTED)) => {
            ClientError::Rpc(Box::new(ConnectError::aborted(STORE_READ_ABORTED))).into()
        }
        error => QmdbError::CommonwareMerkle(error.to_string()),
    }
}

pub(crate) fn error_key<K: AsRef<[u8]> + ?Sized>(key: &K) -> Vec<u8> {
    key.as_ref().to_vec()
}

/// Which proof shape failed verification. Carried on
/// [`QmdbError::ProofVerification`] so callers and tests can discriminate
/// without string matching on the error message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofKind {
    /// [`KeyValueProof`](crate::proof::KeyValueProof): a key's current value.
    KeyValue,
    /// [`KeyExclusionProof`](crate::proof::KeyExclusionProof): an ordered key
    /// is inactive.
    KeyExclusion,
    /// [`OperationMultiProof`](crate::proof::OperationMultiProof): operations at
    /// selected locations.
    OperationMulti,
    /// [`OperationRangeProof`](crate::proof::OperationRangeProof): a contiguous
    /// operation range.
    OperationRange,
    /// [`CurrentOperationRangeProof`](crate::proof::CurrentOperationRangeProof):
    /// a contiguous operation range with its activity bitmap.
    CurrentOperationRange,
    /// [`Publication`](crate::adapter::upload::Publication): a current batch
    /// whose root and operation-log witness bind to the expected root.
    Publication,
}

impl std::fmt::Display for ProofKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::KeyValue => "key-value",
            Self::KeyExclusion => "key-exclusion",
            Self::OperationMulti => "operation multi",
            Self::OperationRange => "operation range",
            Self::CurrentOperationRange => "current operation range",
            Self::Publication => "publication",
        };
        f.write_str(s)
    }
}

impl From<crate::request::InvalidWindow> for QmdbError {
    fn from(err: crate::request::InvalidWindow) -> Self {
        use crate::request::InvalidWindow;
        match err {
            InvalidWindow::TipOverflow => Self::TipOverflow,
            InvalidWindow::StartOutOfBounds { start, count } => Self::LocationOutOfBounds {
                location: start,
                count,
            },
            InvalidWindow::ZeroMaximum => Self::InvalidRangeLength,
        }
    }
}

impl From<crate::request::InvalidLocations> for QmdbError {
    fn from(err: crate::request::InvalidLocations) -> Self {
        match err {
            crate::request::InvalidLocations::TipOverflow => Self::TipOverflow,
            _ => Self::InvalidRequestedLocations(err.to_string()),
        }
    }
}

/// Errors returned by this crate. A read at a tip that is not published yet fails with
/// [`Self::NoPublishedWatermark`] when no watermark has been published and with
/// [`Self::WatermarkTooLow`] when the tip is above the published watermark.
#[derive(Debug, thiserror::Error)]
pub enum QmdbError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("proof request must not be empty")]
    EmptyProofRequest,
    #[error("range length must be > 0")]
    InvalidRangeLength,
    #[error("range limit {limit} exceeds maximum {max}")]
    RangeLimitTooLarge { limit: u32, max: u32 },
    #[error("invalid key range: start_key {start_key:?} must be less than end_key {end_key:?}")]
    InvalidKeyRange {
        start_key: Vec<u8>,
        end_key: Vec<u8>,
    },
    #[error("duplicate key in proof request: {key:?}")]
    DuplicateRequestedKey { key: Vec<u8> },
    #[error("no watermark has been published; requested tip {tip}")]
    NoPublishedWatermark { tip: u64 },
    #[error("requested tip {tip} is above published watermark {watermark}")]
    WatermarkTooLow { tip: u64, watermark: u64 },
    #[error("requested key not found at tip {tip}: {key:?}")]
    KeyNotFound { tip: u64, key: Vec<u8> },
    #[error("requested key is not active at tip {tip}: {key:?}")]
    KeyNotActive { tip: u64, key: Vec<u8> },
    #[error(
        "current proofs are only available at uploaded batch locations; no batch ends at tip {tip}"
    )]
    CurrentProofRequiresBatchBoundary { tip: u64 },
    #[error("current-state rows have not been uploaded for the batch ending at tip {tip}")]
    CurrentStateMissing { tip: u64 },
    #[error("location {location} is out of bounds for tip with {count} leaves")]
    LocationOutOfBounds { location: u64, count: u64 },
    #[error("invalid requested locations: {0}")]
    InvalidRequestedLocations(String),
    #[error("requested tip exceeds the operation location domain")]
    TipOverflow,
    #[error("encoded value exceeds store value limit ({len} > {max})")]
    EncodedValueTooLarge { len: usize, max: usize },
    #[error(
        "sortable key encoding for raw key length {raw_len} expands to {encoded_len} bytes, exceeding max {max}"
    )]
    SortableKeyTooLarge {
        raw_len: usize,
        encoded_len: usize,
        max: usize,
    },
    #[error("{kind} proof failed verification")]
    ProofVerification { kind: ProofKind },
    #[error("range proof does not satisfy the request: {0}")]
    RangeMismatch(&'static str),
    #[error("corrupt qmdb data: {0}")]
    CorruptData(String),
    #[error("commonware merkle error: {0}")]
    CommonwareMerkle(String),
    #[error("qmdb stream transport error: {0}")]
    Stream(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_storage::merkle::mmr;
    use connectrpc::ErrorCode;

    #[test]
    fn proof_boundaries_preserve_only_structured_store_aborts() {
        for code in [
            ErrorCode::Aborted,
            ErrorCode::Internal,
            ErrorCode::Unavailable,
        ] {
            let failure = || {
                store_read_error::<mmr::Family>(
                    ClientError::Rpc(Box::new(ConnectError::new(code, STORE_READ_ABORTED))),
                    "node fetch failed",
                )
            };
            for error in [
                merkle_error(failure()),
                current_proof_error(qmdb::Error::Merkle(failure())),
            ] {
                if code == ErrorCode::Aborted {
                    assert!(
                        matches!(error, QmdbError::Client(error) if error.rpc_code() == Some(code))
                    );
                } else {
                    assert!(matches!(error, QmdbError::CommonwareMerkle(_)));
                }
            }
        }
        for error in [
            merkle_error(merkle::Error::<mmr::Family>::DataCorrupted("invalid node")),
            current_proof_error(qmdb::Error::Merkle(
                merkle::Error::<mmr::Family>::ElementPruned(merkle::Position::new(0)),
            )),
        ] {
            assert!(matches!(error, QmdbError::CommonwareMerkle(_)));
        }
    }
}
