use commonware_storage::mmr::Location;
use exoware_sdk_rs::ClientError;

#[derive(Debug, thiserror::Error)]
pub enum QmdbError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("uploaded location range [{start_location}, {latest_location}] is invalid for {count} operations")]
    InvalidLocationRange {
        start_location: Location,
        latest_location: Location,
        count: usize,
    },
    #[error("batch must contain at least one operation")]
    EmptyBatch,
    #[error("proof request must contain at least one key")]
    EmptyProofRequest,
    #[error("range proof max_locations must be > 0")]
    InvalidRangeLength,
    #[error("batch with latest location {latest_location} already exists")]
    DuplicateBatchWatermark { latest_location: Location },
    #[error("duplicate key in proof request: {key:?}")]
    DuplicateRequestedKey { key: Vec<u8> },
    #[error("requested location {requested} is above published writer watermark {available}")]
    WatermarkTooLow {
        requested: Location,
        available: Location,
    },
    #[error("proof key not found at watermark {watermark}: {key:?}")]
    ProofKeyNotFound { watermark: Location, key: Vec<u8> },
    #[error("requested key is not active at watermark {watermark}: {key:?}")]
    KeyNotActive { watermark: Location, key: Vec<u8> },
    #[error("current proofs are only available at uploaded batch locations; no batch ends at {location}")]
    CurrentProofRequiresBatchBoundary { location: Location },
    #[error("current boundary state has not been uploaded for batch location {location}")]
    CurrentBoundaryStateMissing { location: Location },
    #[error("range proof start {start} is out of bounds for watermark with {count} leaves")]
    RangeStartOutOfBounds { start: Location, count: Location },
    #[error("encoded value exceeds store value limit ({len} > {max})")]
    EncodedValueTooLarge { len: usize, max: usize },
    #[error("raw key length {len} exceeds supported limit {max}")]
    RawKeyTooLarge { len: usize, max: usize },
    #[error(
        "sortable key encoding for raw key length {raw_len} expands to {encoded_len} bytes, exceeding max {max}"
    )]
    SortableKeyTooLarge {
        raw_len: usize,
        encoded_len: usize,
        max: usize,
    },
    #[error("corrupt qmdb data: {0}")]
    CorruptData(String),
    #[error("commonware MMR error: {0}")]
    CommonwareMmr(String),
    /// A live `stream_batches` transport error. Typically means the subscriber
    /// was dropped by the server (slow consumer) or the connection closed;
    /// callers should resubscribe via `since = last_seq + 1` to replay the gap.
    #[error("qmdb stream transport error: {0}")]
    Stream(String),
}
