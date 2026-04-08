//! Store-backed bridge for Commonware authenticated storage proofs.
//!
//! The crate currently supports multiple Commonware authenticated backends:
//! - ordered QMDB (`qmdb::any` and `qmdb::current::ordered`)
//! - immutable (`qmdb::immutable`)
//! - keyless (`qmdb::keyless`)
//!
//! Writers upload exact Commonware operations into the Exoware store, then publish an
//! externally authoritative watermark once the uploaded prefix is complete.
//!
//! Uploads may still happen concurrently and out of order. Current batch-boundary
//! state may also be uploaded ahead of publication. Only watermark publication is
//! monotonic: publishing watermark `W` means the whole contiguous prefix
//! `[0, W]` is available and may now be trusted by readers.
//!
//! Readers fence historical queries against that low watermark. Historical proofs
//! use the global ops-MMR nodes stored by `Position`.
//!
//! Current ordered proofs use versioned current-state deltas:
//! - bitmap chunk rows
//! - grafted-node rows
//!
//! Those rows are versioned by uploaded batch boundary `Location`, not by the
//! final published watermark. That is what preserves lower-boundary current
//! proofs below a later published low watermark.

pub mod prune;

use commonware_codec::{Codec, Decode, DecodeExt, Encode, RangeCfg};
use commonware_cryptography::{sha256::Digest as QmdbDigest, Hasher as _, Sha256};
use commonware_storage::{
    mmr::{
        self, iterator::PeakIterator, storage::Storage as MmrStorage, verification, Location,
        Position, StandardHasher,
    },
    qmdb::{
        any::ordered::{variable::Operation as QmdbOperation, Update as QmdbUpdate},
        any::unordered::{
            variable::Operation as UnorderedQmdbOperation, Update as UnorderedUpdate,
        },
        current::{
            ordered::db::KeyValueProof as CurrentKeyValueProof,
            proof::{OperationProof as CurrentOperationProof, RangeProof as CurrentRangeProof},
        },
        immutable::Operation as ImmutableOperation,
        keyless::Operation as KeylessOperation,
        verify::{verify_multi_proof, verify_proof},
    },
};
use commonware_utils::{Array, Span};
use exoware_common::keys::{Key, KeyCodec};

/// Maximum encoded operation size for QMDB key and value payloads (u16 length on the wire).
pub const MAX_OPERATION_SIZE: usize = u16::MAX as usize;
use exoware_sdk_rs::{ClientError, RangeMode, SerializableReadSession, StoreClient};
use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    sync::{atomic::AtomicU64, Arc},
    time::Duration,
};

use commonware_storage::mmr::{mem::Mmr, UnmerkleizedBatch};

pub(crate) const RESERVED_BITS: u8 = 4;
pub(crate) const UPDATE_FAMILY: u16 = 0x1;
const PRESENCE_FAMILY: u16 = 0x2;
const WATERMARK_FAMILY: u16 = 0x3;
const OP_FAMILY: u16 = 0x4;
const NODE_FAMILY: u16 = 0x5;
const GRAFTED_NODE_FAMILY: u16 = 0x6;
const CHUNK_FAMILY: u16 = 0x7;
const CURRENT_META_FAMILY: u16 = 0x8;
const AUTH_OP_FAMILY: u16 = 0x9;
const AUTH_NODE_FAMILY: u16 = 0xA;
const AUTH_WATERMARK_FAMILY: u16 = 0xB;
const AUTH_INDEX_FAMILY: u16 = 0xC;
const AUTH_IMMUTABLE_UPDATE_FAMILY: u16 = 0xD;
const DIGEST_LEN: usize = 32;
const UPDATE_VERSION_LEN: usize = 8;
const AUTH_NAMESPACE_LEN: usize = 1;
const ORDERED_KEY_ESCAPE_BYTE: u8 = 0x00;
const ORDERED_KEY_ZERO_ESCAPE: u8 = 0xFF;
const ORDERED_KEY_TERMINATOR_LEN: usize = 2;
const POST_INGEST_QUERY_RETRY_MAX_ATTEMPTS: usize = 6;
const POST_INGEST_QUERY_RETRY_INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const POST_INGEST_QUERY_RETRY_MAX_BACKOFF: Duration = Duration::from_millis(1_000);
pub const BITMAP_CHUNK_BYTES: usize = 32;
const BITMAP_CHUNK_BITS: u64 = (BITMAP_CHUNK_BYTES as u64) * 8;
const GRAFTING_HEIGHT: u32 = BITMAP_CHUNK_BITS.trailing_zeros();
const NO_PARTIAL_CHUNK: u64 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthenticatedBackendNamespace {
    Immutable = 1,
    Keyless = 2,
}

impl AuthenticatedBackendNamespace {
    const fn tag(self) -> u8 {
        self as u8
    }
}

/// Exact Commonware QMDB operation type used by this crate.
pub type BatchOperation = QmdbOperation<Vec<u8>, Vec<u8>>;

/// Exact Commonware unordered QMDB operation type used by this crate.
pub type UnorderedBatchOperation = UnorderedQmdbOperation<Vec<u8>, Vec<u8>>;

/// Exact Commonware MMR proof type used by this crate.
pub type BatchProof = mmr::Proof<QmdbDigest>;

/// Exact Commonware current-state range proof type used by this crate.
pub type BatchCurrentRangeProof = CurrentRangeProof<QmdbDigest>;

/// Exact Commonware current-state operation proof type used by this crate.
pub type BatchCurrentOperationProof = CurrentOperationProof<QmdbDigest, BITMAP_CHUNK_BYTES>;

/// Exact Commonware current ordered key-value proof type used by this crate.
pub type BatchCurrentKeyValueProof = CurrentKeyValueProof<Vec<u8>, QmdbDigest, BITMAP_CHUNK_BYTES>;

/// QMDB proof/root variant supported by `exoware-qmdb`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QmdbVariant {
    /// Historical `qmdb::any` root / proof over the uploaded ordered operation log.
    Any,
    /// Current-state `qmdb::current::ordered` root / proof at an uploaded batch boundary.
    Current,
}

/// Limits used when decoding QMDB `any::variable` operations from storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmdbConfig {
    pub max_operation_key_len: usize,
    pub max_operation_value_len: usize,
}

impl Default for QmdbConfig {
    fn default() -> Self {
        Self {
            max_operation_key_len: MAX_OPERATION_SIZE,
            max_operation_value_len: MAX_OPERATION_SIZE,
        }
    }
}

async fn wait_until_query_visible_sequence(
    visible_sequence: Option<&Arc<AtomicU64>>,
    token: u64,
) -> Result<(), QmdbError> {
    let Some(seq) = visible_sequence else {
        return Ok(());
    };
    if token == 0 {
        return Ok(());
    }
    use std::sync::atomic::Ordering;
    for _ in 0..10_000 {
        if seq.load(Ordering::Relaxed) >= token {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    Err(QmdbError::CorruptData(
        "timed out waiting for query worker visible_sequence to catch ingest consistency token"
            .to_string(),
    ))
}

fn is_transient_post_ingest_query_error(err: &QmdbError) -> bool {
    match err {
        QmdbError::Client(ClientError::Http(_)) => true,
        QmdbError::Client(err) => err.rpc_code().is_some_and(|code| {
            matches!(
                code,
                connectrpc::ErrorCode::Aborted
                    | connectrpc::ErrorCode::ResourceExhausted
                    | connectrpc::ErrorCode::Unavailable
            )
        }),
        _ => false,
    }
}

fn post_ingest_query_retry_backoff(attempt: usize) -> Duration {
    let exponent = (attempt.saturating_sub(1)).min(20) as u32;
    let factor = 1u128 << exponent;
    let base_ms = POST_INGEST_QUERY_RETRY_INITIAL_BACKOFF.as_millis();
    let capped_ms = base_ms
        .saturating_mul(factor)
        .min(POST_INGEST_QUERY_RETRY_MAX_BACKOFF.as_millis());
    Duration::from_millis(capped_ms.min(u64::MAX as u128) as u64)
}

async fn retry_transient_post_ingest_query<F, Fut, T>(mut op: F) -> Result<T, QmdbError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, QmdbError>>,
{
    let mut attempt = 1usize;
    loop {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err)
                if attempt < POST_INGEST_QUERY_RETRY_MAX_ATTEMPTS
                    && is_transient_post_ingest_query_error(&err) =>
            {
                tokio::time::sleep(post_ingest_query_retry_backoff(attempt)).await;
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

/// Convenience input for `upload_batch`.
#[derive(Clone, Copy, Debug)]
pub struct BatchEntry<'a> {
    pub key: &'a [u8],
    pub value: Option<&'a [u8]>,
}

impl<'a> BatchEntry<'a> {
    pub const fn put(key: &'a [u8], value: &'a [u8]) -> Self {
        Self {
            key,
            value: Some(value),
        }
    }

    pub const fn delete(key: &'a [u8]) -> Self {
        Self { key, value: None }
    }
}

/// Typed convenience input for `upload_typed_batch`.
#[derive(Clone, Copy, Debug)]
pub struct TypedBatchEntry<'a, K, V> {
    pub key: &'a K,
    pub value: Option<&'a V>,
}

impl<'a, K, V> TypedBatchEntry<'a, K, V> {
    pub const fn put(key: &'a K, value: &'a V) -> Self {
        Self {
            key,
            value: Some(value),
        }
    }

    pub const fn delete(key: &'a K) -> Self {
        Self { key, value: None }
    }
}

/// Historical value resolved for one logical key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionedValue {
    pub key: Vec<u8>,
    pub location: Location,
    pub value: Option<Vec<u8>>,
}

/// Historical value resolved and decoded into caller-provided Commonware types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedVersionedValue<K, V> {
    pub key: K,
    pub location: Location,
    pub value: Option<V>,
}

/// Metadata returned after uploading one operation slice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadReceipt {
    pub latest_location: Location,
    pub operation_count: Location,
    pub keyed_operation_count: u32,
    pub writer_location_watermark: Option<Location>,
    pub sequence_number: u64,
}

pub type BatchUploadReceipt = UploadReceipt;

/// Current-state rows for one uploaded batch boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentBoundaryState {
    /// Canonical current::ordered root for this uploaded batch boundary.
    pub root: QmdbDigest,

    /// Sparse chunk delta for this boundary.
    ///
    /// Only chunks that changed relative to the previous uploaded batch
    /// boundary need to be included.
    pub chunks: Vec<(u64, [u8; BITMAP_CHUNK_BYTES])>,

    /// Sparse grafted-node delta for this boundary.
    ///
    /// Only grafted nodes whose digests changed relative to the previous
    /// uploaded batch boundary need to be included.
    pub grafted_nodes: Vec<(Position, QmdbDigest)>,
}

/// Build the [`CurrentBoundaryState`] needed by
/// [`OrderedClient::upload_current_boundary_state`] from the raw operation sequence.
///
/// `previous_operations` is `None` for the first batch; for subsequent batches
/// pass the operations from the prior uploaded batch so the delta is sparse.
pub async fn build_current_boundary_state(
    previous_operations: Option<&[BatchOperation]>,
    operations: &[BatchOperation],
) -> CurrentBoundaryState {
    let state = RebuiltCurrentState::build(operations.to_vec()).expect("rebuild current state");

    let storage = RebuiltCurrentStorage {
        ops_mmr: &state.ops_mmr,
        grafted_mmr: &state.grafted_mmr,
    };
    let grafted_root = compute_storage_root(&storage)
        .await
        .expect("compute rebuilt grafted root");
    let root = combine_current_roots(
        &state.ops_root,
        &grafted_root,
        state
            .partial_chunk_digest
            .as_ref()
            .map(|(next_bit, digest)| (*next_bit, digest)),
    );

    let previous_state = previous_operations.map(|ops| {
        RebuiltCurrentState::build(ops.to_vec()).expect("rebuild previous current state")
    });

    let chunks = state
        .chunks
        .iter()
        .enumerate()
        .filter_map(|(chunk_index, chunk)| {
            let changed = previous_state
                .as_ref()
                .and_then(|previous| previous.chunks.get(chunk_index))
                .is_none_or(|previous| previous != chunk);
            changed.then_some((chunk_index as u64, *chunk))
        })
        .collect::<Vec<_>>();
    let grafted_nodes = (0..*state.grafted_mmr.size())
        .filter_map(|raw_position| {
            let position = Position::new(raw_position);
            let digest = state
                .grafted_mmr
                .get_node(position)
                .expect("rebuilt grafted node exists");
            let changed = previous_state
                .as_ref()
                .and_then(|previous| previous.grafted_mmr.get_node(position))
                .is_none_or(|previous| previous != digest);
            changed.then_some((position, digest))
        })
        .collect::<Vec<_>>();
    CurrentBoundaryState {
        root,
        chunks,
        grafted_nodes,
    }
}

/// Multi-proof over arbitrary keyed operations against one published watermark.
#[derive(Clone, Debug, PartialEq)]
pub struct MultiProofResult {
    pub watermark: Location,
    /// Historical ops-MMR root for this watermark.
    pub root: QmdbDigest,
    pub proof: BatchProof,
    pub operations: Vec<(Location, BatchOperation)>,
}

impl MultiProofResult {
    pub fn verify(&self) -> bool {
        let mut hasher = StandardHasher::<Sha256>::new();
        verify_multi_proof(&mut hasher, &self.proof, &self.operations, &self.root)
    }
}

pub type BatchMultiProofResult = MultiProofResult;

/// Contiguous range proof over global operations against one published watermark.
#[derive(Clone, Debug, PartialEq)]
pub struct OperationRangeProof {
    pub watermark: Location,
    /// Historical ops-MMR root for this watermark.
    pub root: QmdbDigest,
    pub start_location: Location,
    pub proof: BatchProof,
    pub operations: Vec<BatchOperation>,
}

impl OperationRangeProof {
    pub fn verify(&self) -> bool {
        let mut hasher = StandardHasher::<Sha256>::new();
        verify_proof(
            &mut hasher,
            &self.proof,
            self.start_location,
            &self.operations,
            &self.root,
        )
    }
}

pub type BatchOperationRangeProof = OperationRangeProof;

/// Contiguous range proof over unordered operations against one published watermark.
#[derive(Clone, Debug, PartialEq)]
pub struct UnorderedOperationRangeProof {
    pub watermark: Location,
    pub root: QmdbDigest,
    pub start_location: Location,
    pub proof: BatchProof,
    pub operations: Vec<UnorderedBatchOperation>,
}

impl UnorderedOperationRangeProof {
    pub fn verify(&self) -> bool {
        let mut hasher = StandardHasher::<Sha256>::new();
        verify_proof(
            &mut hasher,
            &self.proof,
            self.start_location,
            &self.operations,
            &self.root,
        )
    }
}

/// Contiguous current-state range proof over global operations against one published watermark.
#[derive(Clone, Debug, PartialEq)]
pub struct CurrentOperationRangeProofResult {
    pub watermark: Location,
    pub root: QmdbDigest,
    pub start_location: Location,
    pub proof: BatchCurrentRangeProof,
    pub operations: Vec<BatchOperation>,
    pub chunks: Vec<[u8; BITMAP_CHUNK_BYTES]>,
}

impl CurrentOperationRangeProofResult {
    pub fn verify(&self) -> bool {
        let mut hasher = Sha256::default();
        self.proof.verify(
            &mut hasher,
            self.start_location,
            &self.operations,
            &self.chunks,
            &self.root,
        )
    }
}

/// Variant-selected root returned by `root_for_variant`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariantRoot {
    pub watermark: Location,
    pub variant: QmdbVariant,
    pub root: QmdbDigest,
}

/// Variant-selected contiguous range proof returned by `operation_range_proof_for_variant`.
#[derive(Clone, Debug, PartialEq)]
pub enum VariantOperationRangeProof {
    Any(OperationRangeProof),
    Current(CurrentOperationRangeProofResult),
}

impl VariantOperationRangeProof {
    pub fn verify(&self) -> bool {
        match self {
            Self::Any(proof) => proof.verify(),
            Self::Current(proof) => proof.verify(),
        }
    }

    pub fn watermark(&self) -> Location {
        match self {
            Self::Any(proof) => proof.watermark,
            Self::Current(proof) => proof.watermark,
        }
    }

    pub fn variant(&self) -> QmdbVariant {
        match self {
            Self::Any(_) => QmdbVariant::Any,
            Self::Current(_) => QmdbVariant::Current,
        }
    }
}

/// Proof that a key currently has the uploaded value at one published watermark.
#[derive(Clone, Debug, PartialEq)]
pub struct KeyValueProofResult {
    pub watermark: Location,
    pub root: QmdbDigest,
    pub proof: BatchCurrentKeyValueProof,
    pub operation: BatchOperation,
}

impl KeyValueProofResult {
    pub fn verify(&self) -> bool {
        let BatchOperation::Update(update) = &self.operation else {
            return false;
        };
        let operation = BatchOperation::Update(QmdbUpdate {
            key: update.key.clone(),
            value: update.value.clone(),
            next_key: self.proof.next_key.clone(),
        });
        let mut hasher = Sha256::default();
        self.proof.proof.verify(&mut hasher, operation, &self.root)
    }
}

/// `exoware-qmdb` client errors.
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
    #[error("ordered exoware-qmdb requires exact ordered operations; use upload_operations")]
    ExactOrderedOperationsRequired,
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
}

pub type AuthenticatedStorageError = QmdbError;

#[derive(Clone, Copy, Debug)]
struct HistoricalOpsClientCore<'a> {
    client: &'a StoreClient,
    config: &'a QmdbConfig,
    query_visible_sequence: Option<&'a Arc<AtomicU64>>,
}

impl<'a> HistoricalOpsClientCore<'a> {
    async fn sync_after_ingest(&self) -> Result<(), QmdbError> {
        let token = self.client.sequence_number();
        wait_until_query_visible_sequence(self.query_visible_sequence, token).await
    }

    async fn writer_location_watermark(&self) -> Result<Option<Location>, QmdbError> {
        retry_transient_post_ingest_query(|| {
            let session = self.client.create_session();
            async move { self.read_latest_watermark(&session).await }
        })
        .await
    }

    async fn read_latest_watermark(
        &self,
        session: &SerializableReadSession,
    ) -> Result<Option<Location>, QmdbError> {
        let (start, end) = watermark_codec().family_bounds();
        let rows = session
            .range_with_mode(&start, &end, 1, RangeMode::Reverse)
            .await?;
        match rows.into_iter().next() {
            Some((key, _)) => Ok(Some(decode_watermark_location(&key)?)),
            None => Ok(None),
        }
    }

    async fn require_published_watermark(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
    ) -> Result<(), QmdbError> {
        let available = self
            .read_latest_watermark(session)
            .await?
            .unwrap_or(Location::new(0));
        let watermark_exists = session
            .get(&encode_watermark_key(watermark))
            .await?
            .is_some();
        if available < watermark
            || (!watermark_exists && available == Location::new(0) && watermark == Location::new(0))
        {
            return Err(QmdbError::WatermarkTooLow {
                requested: watermark,
                available,
            });
        }
        Ok(())
    }

    async fn require_batch_boundary(
        &self,
        session: &SerializableReadSession,
        location: Location,
    ) -> Result<(), QmdbError> {
        if session.get(&encode_presence_key(location)).await?.is_some() {
            Ok(())
        } else {
            Err(QmdbError::CurrentProofRequiresBatchBoundary { location })
        }
    }

    async fn load_latest_update_row(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
        key: &[u8],
    ) -> Result<Option<(Key, Vec<u8>)>, QmdbError> {
        let start = encode_update_key(key, Location::new(0))?;
        let end = encode_update_key(key, watermark)?;
        let rows = session
            .range_with_mode(&start, &end, 1, RangeMode::Reverse)
            .await?;
        Ok(rows
            .into_iter()
            .next()
            .map(|(key, value)| (key, value.to_vec())))
    }

    fn operation_codec_cfg(&self) -> ((RangeCfg<usize>, ()), (RangeCfg<usize>, ())) {
        (
            ((0..=self.config.max_operation_key_len).into(), ()),
            ((0..=self.config.max_operation_value_len).into(), ()),
        )
    }

    async fn append_encoded_ops_nodes_incrementally(
        &self,
        session: &SerializableReadSession,
        previous_ops_size: Position,
        encoded_operations: &[Vec<u8>],
        rows: &mut Vec<(Key, Vec<u8>)>,
    ) -> Result<(Position, BTreeMap<Position, QmdbDigest>, QmdbDigest), QmdbError> {
        let mut peaks = Vec::<(Position, u32, QmdbDigest)>::new();
        for (peak_pos, height) in PeakIterator::new(previous_ops_size) {
            let Some(bytes) = session.get(&encode_node_key(peak_pos)).await? else {
                return Err(QmdbError::CorruptData(format!(
                    "missing prior ops peak node at position {peak_pos}"
                )));
            };
            peaks.push((
                peak_pos,
                height,
                decode_digest(bytes.as_ref(), format!("prior ops peak node at {peak_pos}"))?,
            ));
        }

        let mut current_size = previous_ops_size;
        let mut overlay = BTreeMap::<Position, QmdbDigest>::new();
        let mut hasher = StandardHasher::<Sha256>::new();
        for encoded in encoded_operations {
            ensure_encoded_value_size(encoded.len())?;
            let leaf_pos = current_size;
            let leaf_digest = mmr::hasher::Hasher::leaf_digest(&mut hasher, leaf_pos, encoded);
            overlay.insert(leaf_pos, leaf_digest);
            rows.push((encode_node_key(leaf_pos), leaf_digest.as_ref().to_vec()));
            current_size = Position::new(*current_size + 1);

            let mut carry_pos = leaf_pos;
            let mut carry_digest = leaf_digest;
            let mut carry_height = 0u32;
            while peaks
                .last()
                .is_some_and(|(_, height, _)| *height == carry_height)
            {
                let (_, _, left_digest) = peaks.pop().expect("peak exists");
                let parent_pos = current_size;
                let parent_digest = mmr::hasher::Hasher::node_digest(
                    &mut hasher,
                    parent_pos,
                    &left_digest,
                    &carry_digest,
                );
                overlay.insert(parent_pos, parent_digest);
                rows.push((encode_node_key(parent_pos), parent_digest.as_ref().to_vec()));
                current_size = Position::new(*current_size + 1);
                carry_pos = parent_pos;
                carry_digest = parent_digest;
                carry_height += 1;
            }
            peaks.push((carry_pos, carry_height, carry_digest));
        }

        let leaves = Location::try_from(current_size)
            .map_err(|e| QmdbError::CorruptData(format!("invalid incremental ops size: {e}")))?;
        let ops_root = mmr::hasher::Hasher::root(
            &mut hasher,
            leaves,
            peaks.iter().map(|(_, _, digest)| digest),
        );
        Ok((current_size, overlay, ops_root))
    }

    pub(crate) async fn compute_ops_root(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
    ) -> Result<QmdbDigest, QmdbError> {
        let size = mmr_size_for_watermark(watermark)?;
        let leaves = watermark
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        let mut peaks = Vec::new();
        for (peak_pos, _) in PeakIterator::new(size) {
            let Some(bytes) = session.get(&encode_node_key(peak_pos)).await? else {
                return Err(QmdbError::CorruptData(format!(
                    "missing MMR peak node at position {peak_pos}"
                )));
            };
            peaks.push(decode_digest(
                bytes.as_ref(),
                format!("MMR peak node at position {peak_pos}"),
            )?);
        }
        let mut hasher = StandardHasher::<Sha256>::new();
        Ok(mmr::hasher::Hasher::root(&mut hasher, leaves, peaks.iter()))
    }

    async fn load_operation_bytes_at(
        &self,
        session: &SerializableReadSession,
        location: Location,
    ) -> Result<Vec<u8>, QmdbError> {
        let Some(bytes) = session.get(&encode_operation_key(location)).await? else {
            return Err(QmdbError::CorruptData(format!(
                "missing operation row at location {location}"
            )));
        };
        Ok(bytes.to_vec())
    }

    async fn load_operation_bytes_range(
        &self,
        session: &SerializableReadSession,
        start_location: Location,
        end_location_exclusive: Location,
    ) -> Result<Vec<Vec<u8>>, QmdbError> {
        if start_location >= end_location_exclusive {
            return Ok(Vec::new());
        }
        let start = encode_operation_key(start_location);
        // Inclusive store range over operation keys for locations
        // `[start_location, end_location_exclusive)`.
        let end = encode_operation_key(end_location_exclusive - 1);
        let rows = session
            .range(
                &start,
                &end,
                (*end_location_exclusive - *start_location) as usize,
            )
            .await?;
        if rows.len() != (*end_location_exclusive - *start_location) as usize {
            return Err(QmdbError::CorruptData(format!(
                "expected {} operation rows in location range [{start_location}, {end_location_exclusive}), found {}",
                *end_location_exclusive - *start_location,
                rows.len()
            )));
        }
        let mut encoded = Vec::with_capacity(rows.len());
        for (offset, (key, value)) in rows.into_iter().enumerate() {
            let expected_location = start_location + offset as u64;
            let location = decode_operation_location_key(&key)?;
            if location != expected_location {
                return Err(QmdbError::CorruptData(format!(
                    "operation row order mismatch: expected {expected_location}, got {location}"
                )));
            }
            encoded.push(value.to_vec());
        }
        Ok(encoded)
    }

    async fn query_many_at<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        max_location: Location,
    ) -> Result<Vec<Option<VersionedValue>>, QmdbError> {
        let session = self.client.create_session();
        self.require_published_watermark(&session, max_location)
            .await?;

        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            let key_bytes = key.as_ref();
            let Some((row_key, row_value)) = self
                .load_latest_update_row(&session, max_location, key_bytes)
                .await?
            else {
                results.push(None);
                continue;
            };
            let location = decode_update_location(&row_key)?;
            let decoded = decode_update_row(row_value.as_ref())?;
            results.push(Some(VersionedValue {
                key: decoded.key,
                location,
                value: decoded.value,
            }));
        }
        Ok(results)
    }

    async fn publish_writer_location_watermark_with_encoded_ops(
        &self,
        session: &SerializableReadSession,
        latest_watermark: Option<Location>,
        location: Location,
        encoded_delta_ops: &[Vec<u8>],
        kind: &str,
    ) -> Result<Location, QmdbError> {
        let previous_ops_size = match latest_watermark {
            Some(previous) => mmr_size_for_watermark(previous)?,
            None => Position::new(0),
        };
        let mut rows = Vec::<(Key, Vec<u8>)>::new();
        self.append_encoded_ops_nodes_incrementally(
            session,
            previous_ops_size,
            encoded_delta_ops,
            &mut rows,
        )
        .await?;
        rows.push((encode_watermark_key(location), Vec::new()));
        let refs = rows
            .iter()
            .map(|(key, value)| (key, value.as_slice()))
            .collect::<Vec<_>>();
        self.client.put(&refs).await?;
        self.sync_after_ingest().await?;
        let visible = self.writer_location_watermark().await?;
        if visible < Some(location) {
            return Err(QmdbError::CorruptData(format!(
                "{kind} watermark publish did not become query-visible: requested={location}, visible={visible:?}"
            )));
        }
        Ok(location)
    }
}

/// Operation-indexed client backed by the Exoware store and exact Commonware QMDB ops.
#[derive(Clone, Debug)]
pub struct OrderedClient {
    client: StoreClient,
    config: QmdbConfig,
    query_visible_sequence: Option<Arc<AtomicU64>>,
}

/// Backward-compatible alias.
pub type QmdbClient = OrderedClient;

impl OrderedClient {
    fn core(&self) -> HistoricalOpsClientCore<'_> {
        HistoricalOpsClientCore {
            client: &self.client,
            config: &self.config,
            query_visible_sequence: self.query_visible_sequence.as_ref(),
        }
    }

    pub fn new(url: &str) -> Self {
        Self::from_client(StoreClient::new(url))
    }

    pub fn from_client(client: StoreClient) -> Self {
        Self {
            client,
            config: QmdbConfig::default(),
            query_visible_sequence: None,
        }
    }

    /// When set, blocks after each ingest until the query worker advances `visible_sequence`
    /// to at least the client's observed consistency token (test harness synchronization).
    pub fn with_query_visible_sequence(mut self, seq: Arc<AtomicU64>) -> Self {
        self.query_visible_sequence = Some(seq);
        self
    }

    pub fn with_config(mut self, config: QmdbConfig) -> Self {
        self.config = config;
        self
    }

    pub(crate) async fn sync_after_ingest(&self) -> Result<(), QmdbError> {
        self.core().sync_after_ingest().await
    }

    pub fn inner(&self) -> &StoreClient {
        &self.client
    }

    pub fn sequence_number(&self) -> u64 {
        self.client.sequence_number()
    }

    pub async fn writer_location_watermark(&self) -> Result<Option<Location>, QmdbError> {
        self.core().writer_location_watermark().await
    }

    /// Publish the latest externally authoritative writer location watermark to exoware-qmdb.
    ///
    /// Readers on other processes or machines use this stored watermark to fence
    /// `query_many_at(..., X)` calls.
    pub async fn publish_writer_location_watermark(
        &self,
        location: Location,
    ) -> Result<Location, QmdbError> {
        let session = self.client.create_session();
        let latest_watermark = self.core().read_latest_watermark(&session).await?;
        if let Some(watermark) = latest_watermark {
            if watermark >= location {
                return Ok(watermark);
            }
        }
        self.core()
            .require_batch_boundary(&session, location)
            .await?;
        self.require_current_boundary_state(&session, location)
            .await?;
        let previous_watermark = latest_watermark;
        let previous_ops_size = match previous_watermark {
            Some(previous) => mmr_size_for_watermark(previous)?,
            None => Position::new(0),
        };
        let delta_start_location = previous_watermark.map_or(Location::new(0), |w| w + 1);
        let end_location_exclusive = location
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        let delta_operations = self
            .load_operation_range(&session, delta_start_location, end_location_exclusive)
            .await?;
        let mut rows = Vec::<(Key, Vec<u8>)>::new();
        self.append_ops_nodes_incrementally(
            &session,
            previous_ops_size,
            &delta_operations,
            &mut rows,
        )
        .await?;
        rows.push((encode_watermark_key(location), Vec::new()));
        let refs = rows
            .iter()
            .map(|(key, value)| (key, value.as_slice()))
            .collect::<Vec<_>>();
        self.client.put(&refs).await?;
        self.sync_after_ingest().await?;
        let visible = self.writer_location_watermark().await?;
        if visible < Some(location) {
            return Err(QmdbError::CorruptData(format!(
                "ordered watermark publish did not become query-visible: requested={location}, visible={visible:?}"
            )));
        }
        Ok(location)
    }

    /// Ordered exoware-qmdb requires callers to provide exact ordered operations.
    pub async fn upload_batch(
        &self,
        _latest_location: Location,
        entries: &[BatchEntry<'_>],
    ) -> Result<UploadReceipt, QmdbError> {
        if entries.is_empty() {
            return Err(QmdbError::EmptyBatch);
        }
        Err(QmdbError::ExactOrderedOperationsRequired)
    }

    /// Ordered exoware-qmdb requires callers to provide exact ordered operations.
    pub async fn upload_typed_batch<K, V>(
        &self,
        _latest_location: Location,
        entries: &[TypedBatchEntry<'_, K, V>],
    ) -> Result<UploadReceipt, QmdbError>
    where
        K: Span,
        V: Codec<Cfg = ()> + Clone,
    {
        if entries.is_empty() {
            return Err(QmdbError::EmptyBatch);
        }
        Err(QmdbError::ExactOrderedOperationsRequired)
    }

    /// Upload the exact Commonware QMDB operation sequence for one batch whose
    /// final global location is `latest_location`.
    pub async fn upload_operations(
        &self,
        latest_location: Location,
        operations: &[BatchOperation],
    ) -> Result<UploadReceipt, QmdbError> {
        if operations.is_empty() {
            return Err(QmdbError::EmptyBatch);
        }
        if self
            .client
            .get(&encode_presence_key(latest_location))
            .await?
            .is_some()
        {
            return Err(QmdbError::DuplicateBatchWatermark { latest_location });
        }

        let prepared = PreparedUpload::build(latest_location, operations)?;
        let refs = prepared
            .rows
            .iter()
            .map(|(key, value)| (key, value.as_slice()))
            .collect::<Vec<_>>();
        self.client.put(&refs).await?;
        self.sync_after_ingest().await?;

        let writer_location_watermark = self.writer_location_watermark().await?;
        Ok(UploadReceipt {
            latest_location,
            operation_count: Location::from(prepared.operation_count as u64),
            keyed_operation_count: prepared.keyed_operation_count,
            writer_location_watermark,
            sequence_number: self.client.sequence_number(),
        })
    }

    /// Upload exact ordered operations plus the current-state rows for the same
    /// uploaded batch boundary in one ingest.
    pub async fn upload_operations_with_current_boundary(
        &self,
        latest_location: Location,
        operations: &[BatchOperation],
        current_boundary: &CurrentBoundaryState,
    ) -> Result<UploadReceipt, QmdbError> {
        if operations.is_empty() {
            return Err(QmdbError::EmptyBatch);
        }
        if self
            .client
            .get(&encode_presence_key(latest_location))
            .await?
            .is_some()
        {
            return Err(QmdbError::DuplicateBatchWatermark { latest_location });
        }

        let prepared_ops = PreparedUpload::build(latest_location, operations)?;
        let prepared_current =
            PreparedCurrentBoundaryUpload::build(latest_location, current_boundary)?;
        let refs = prepared_ops
            .rows
            .iter()
            .chain(prepared_current.rows.iter())
            .map(|(key, value)| (key, value.as_slice()))
            .collect::<Vec<_>>();
        self.client.put(&refs).await?;
        self.sync_after_ingest().await?;

        let writer_location_watermark = self.writer_location_watermark().await?;
        Ok(UploadReceipt {
            latest_location,
            operation_count: Location::from(prepared_ops.operation_count as u64),
            keyed_operation_count: prepared_ops.keyed_operation_count,
            writer_location_watermark,
            sequence_number: self.client.sequence_number(),
        })
    }

    /// Upload current-state proof rows for one uploaded batch boundary. This may
    /// be called before the low watermark is published.
    pub async fn upload_current_boundary_state(
        &self,
        latest_location: Location,
        current_boundary: &CurrentBoundaryState,
    ) -> Result<(), QmdbError> {
        let prepared = PreparedCurrentBoundaryUpload::build(latest_location, current_boundary)?;
        let refs = prepared
            .rows
            .iter()
            .map(|(key, value)| (key, value.as_slice()))
            .collect::<Vec<_>>();
        self.client.put(&refs).await?;
        self.sync_after_ingest().await?;
        Ok(())
    }

    /// Return the historical ops-MMR root for one published watermark.
    pub async fn root_at(&self, watermark: Location) -> Result<QmdbDigest, QmdbError> {
        Ok(self
            .root_for_variant(watermark, QmdbVariant::Any)
            .await?
            .root)
    }

    pub async fn batch_root(&self, latest_location: Location) -> Result<QmdbDigest, QmdbError> {
        self.root_at(latest_location).await
    }

    /// Return the current-state ordered root for one published watermark.
    ///
    /// Current-state proofs are only available at uploaded batch locations
    /// (the `latest_location` used for an `upload_operations` call).
    pub async fn current_root_at(&self, watermark: Location) -> Result<QmdbDigest, QmdbError> {
        Ok(self
            .root_for_variant(watermark, QmdbVariant::Current)
            .await?
            .root)
    }

    /// Return the root for the selected QMDB variant at one published watermark.
    pub async fn root_for_variant(
        &self,
        watermark: Location,
        variant: QmdbVariant,
    ) -> Result<VariantRoot, QmdbError> {
        let session = self.client.create_session();
        self.core()
            .require_published_watermark(&session, watermark)
            .await?;
        let root = match variant {
            QmdbVariant::Any => self.compute_ops_root(&session, watermark).await?,
            QmdbVariant::Current => {
                self.core()
                    .require_batch_boundary(&session, watermark)
                    .await?;
                self.load_current_boundary_root(&session, watermark).await?
            }
        };
        Ok(VariantRoot {
            watermark,
            variant,
            root,
        })
    }

    /// Resolve each key to the latest update row at `location <= max_location`.
    ///
    /// This only succeeds when the published writer watermark is at least
    /// `max_location`.
    pub async fn query_many_at<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        max_location: Location,
    ) -> Result<Vec<Option<VersionedValue>>, QmdbError> {
        self.core().query_many_at(keys, max_location).await
    }

    /// Typed historical query for Commonware `Span` keys and `Codec` values.
    pub async fn query_many_at_typed<K, V>(
        &self,
        keys: &[K],
        max_location: Location,
    ) -> Result<Vec<Option<TypedVersionedValue<K, V>>>, QmdbError>
    where
        K: Span,
        V: Codec<Cfg = ()> + Clone,
    {
        let encoded_keys = keys
            .iter()
            .map(|key| key.encode().to_vec())
            .collect::<Vec<_>>();
        let raw = self.query_many_at(&encoded_keys, max_location).await?;
        raw.into_iter()
            .map(|item| match item {
                Some(item) => {
                    let key = K::decode(item.key.as_slice()).map_err(|e| {
                        QmdbError::CorruptData(format!("failed to decode typed key: {e}"))
                    })?;
                    let value = item
                        .value
                        .map(|bytes| {
                            V::decode(bytes.as_slice()).map_err(|e| {
                                QmdbError::CorruptData(format!("failed to decode typed value: {e}"))
                            })
                        })
                        .transpose()?;
                    Ok(Some(TypedVersionedValue {
                        key,
                        location: item.location,
                        value,
                    }))
                }
                None => Ok(None),
            })
            .collect()
    }

    /// Generate a QMDB multi-proof for the latest keyed operation for each
    /// requested key at or below one published watermark.
    pub async fn multi_proof_at<K: AsRef<[u8]>>(
        &self,
        watermark: Location,
        keys: &[K],
    ) -> Result<MultiProofResult, QmdbError> {
        if keys.is_empty() {
            return Err(QmdbError::EmptyProofRequest);
        }

        let session = self.client.create_session();
        self.core()
            .require_published_watermark(&session, watermark)
            .await?;
        let storage = KvMmrStorage {
            session: &session,
            mmr_size: mmr_size_for_watermark(watermark)?,
        };
        let root = self.compute_ops_root(&session, watermark).await?;

        let mut seen = BTreeSet::<Vec<u8>>::new();
        let mut locations = Vec::<Location>::with_capacity(keys.len());
        let mut operations = Vec::<(Location, BatchOperation)>::with_capacity(keys.len());
        for key in keys {
            let key_bytes = key.as_ref().to_vec();
            if !seen.insert(key_bytes.clone()) {
                return Err(QmdbError::DuplicateRequestedKey { key: key_bytes });
            }
            let start = encode_update_key(key.as_ref(), Location::new(0))?;
            let end = encode_update_key(key.as_ref(), watermark)?;
            let rows = session
                .range_with_mode(&start, &end, 1, RangeMode::Reverse)
                .await?;
            let Some((row_key, row_value)) = rows.into_iter().next() else {
                return Err(QmdbError::ProofKeyNotFound {
                    watermark,
                    key: key.as_ref().to_vec(),
                });
            };
            let global_loc = decode_update_location(&row_key)?;
            let decoded = decode_update_row(row_value.as_ref())?;
            if decoded.key != key.as_ref() {
                return Err(QmdbError::ProofKeyNotFound {
                    watermark,
                    key: key.as_ref().to_vec(),
                });
            }
            let operation = self.load_operation_at(&session, global_loc).await?;
            locations.push(global_loc);
            operations.push((global_loc, operation));
        }
        operations.sort_by_key(|(loc, _)| *loc);
        locations.sort();

        let proof = verification::multi_proof(&storage, &locations)
            .await
            .map_err(|e| QmdbError::CommonwareMmr(e.to_string()))?;
        Ok(MultiProofResult {
            watermark,
            root,
            proof,
            operations,
        })
    }

    /// Typed convenience wrapper for `multi_proof_at`.
    pub async fn multi_proof_at_typed<K: Span>(
        &self,
        watermark: Location,
        keys: &[K],
    ) -> Result<MultiProofResult, QmdbError> {
        let encoded_keys = keys
            .iter()
            .map(|key| key.encode().to_vec())
            .collect::<Vec<_>>();
        self.multi_proof_at(watermark, &encoded_keys).await
    }

    pub async fn batch_multi_proof<K: AsRef<[u8]>>(
        &self,
        latest_location: Location,
        keys: &[K],
    ) -> Result<BatchMultiProofResult, QmdbError> {
        self.multi_proof_at(latest_location, keys).await
    }

    pub async fn batch_multi_proof_typed<K: Span>(
        &self,
        latest_location: Location,
        keys: &[K],
    ) -> Result<BatchMultiProofResult, QmdbError> {
        self.multi_proof_at_typed(latest_location, keys).await
    }

    /// Generate a contiguous historical ops-MMR proof over global operation
    /// locations against one published watermark.
    pub async fn operation_range_proof(
        &self,
        watermark: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<OperationRangeProof, QmdbError> {
        match self
            .operation_range_proof_for_variant(
                watermark,
                QmdbVariant::Any,
                start_location,
                max_locations,
            )
            .await?
        {
            VariantOperationRangeProof::Any(proof) => Ok(proof),
            VariantOperationRangeProof::Current(_) => Err(QmdbError::CorruptData(
                "unexpected current proof returned for any variant request".to_string(),
            )),
        }
    }

    /// Generate a contiguous range proof for the selected QMDB variant over
    /// global operation locations against one published watermark.
    pub async fn operation_range_proof_for_variant(
        &self,
        watermark: Location,
        variant: QmdbVariant,
        start_location: Location,
        max_locations: u32,
    ) -> Result<VariantOperationRangeProof, QmdbError> {
        if max_locations == 0 {
            return Err(QmdbError::InvalidRangeLength);
        }

        let session = self.client.create_session();
        self.core()
            .require_published_watermark(&session, watermark)
            .await?;
        let count = watermark
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        if start_location >= count {
            return Err(QmdbError::RangeStartOutOfBounds {
                start: start_location,
                count,
            });
        }
        let end = start_location
            .saturating_add(max_locations as u64)
            .min(count);
        match variant {
            QmdbVariant::Any => {
                let storage = KvMmrStorage {
                    session: &session,
                    mmr_size: mmr_size_for_watermark(watermark)?,
                };
                let proof = verification::range_proof(&storage, start_location..end)
                    .await
                    .map_err(|e| QmdbError::CommonwareMmr(e.to_string()))?;
                let root = self.compute_ops_root(&session, watermark).await?;
                let operations = self
                    .load_operation_range(&session, start_location, end)
                    .await?;

                Ok(VariantOperationRangeProof::Any(OperationRangeProof {
                    watermark,
                    root,
                    start_location,
                    proof,
                    operations,
                }))
            }
            QmdbVariant::Current => {
                self.core()
                    .require_batch_boundary(&session, watermark)
                    .await?;
                let proof = self
                    .build_current_range_proof(&session, watermark, start_location, end)
                    .await?;
                let root = self.load_current_boundary_root(&session, watermark).await?;
                let operations = self
                    .load_operation_range(&session, start_location, end)
                    .await?;
                let chunks = self
                    .load_bitmap_chunks(&session, watermark, start_location, end)
                    .await?;

                Ok(VariantOperationRangeProof::Current(
                    CurrentOperationRangeProofResult {
                        watermark,
                        root,
                        start_location,
                        proof,
                        operations,
                        chunks,
                    },
                ))
            }
        }
    }

    pub async fn batch_operation_range_proof(
        &self,
        latest_location: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<BatchOperationRangeProof, QmdbError> {
        self.operation_range_proof(latest_location, start_location, max_locations)
            .await
    }

    /// Generate a contiguous current-state ordered proof over global operation
    /// locations against one published batch location.
    pub async fn current_operation_range_proof(
        &self,
        watermark: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<CurrentOperationRangeProofResult, QmdbError> {
        match self
            .operation_range_proof_for_variant(
                watermark,
                QmdbVariant::Current,
                start_location,
                max_locations,
            )
            .await?
        {
            VariantOperationRangeProof::Current(proof) => Ok(proof),
            VariantOperationRangeProof::Any(_) => Err(QmdbError::CorruptData(
                "unexpected any proof returned for current variant request".to_string(),
            )),
        }
    }

    /// Generate a current-state ordered proof for the latest active value of one
    /// key at one published batch location.
    pub async fn key_value_proof_at<K: AsRef<[u8]>>(
        &self,
        watermark: Location,
        key: K,
    ) -> Result<KeyValueProofResult, QmdbError> {
        let session = self.client.create_session();
        self.core()
            .require_published_watermark(&session, watermark)
            .await?;
        self.core()
            .require_batch_boundary(&session, watermark)
            .await?;

        let key_bytes = key.as_ref().to_vec();
        let Some((row_key, row_value)) = self
            .load_latest_update_row(&session, watermark, key.as_ref())
            .await?
        else {
            return Err(QmdbError::ProofKeyNotFound {
                watermark,
                key: key_bytes,
            });
        };
        let location = decode_update_location(&row_key)?;
        let decoded = decode_update_row(row_value.as_ref())?;
        if decoded.key != key.as_ref() {
            return Err(QmdbError::ProofKeyNotFound {
                watermark,
                key: key.as_ref().to_vec(),
            });
        }
        if decoded.value.is_none() {
            return Err(QmdbError::KeyNotActive {
                watermark,
                key: key.as_ref().to_vec(),
            });
        }

        let operation = self.load_operation_at(&session, location).await?;
        let BatchOperation::Update(update) = &operation else {
            return Err(QmdbError::KeyNotActive {
                watermark,
                key: key.as_ref().to_vec(),
            });
        };
        let range_proof = self
            .build_current_range_proof(&session, watermark, location, location + 1)
            .await?;
        let chunk = self
            .load_bitmap_chunk(&session, watermark, chunk_index_for_location(location))
            .await?;
        let root = self.load_current_boundary_root(&session, watermark).await?;

        Ok(KeyValueProofResult {
            watermark,
            root,
            proof: BatchCurrentKeyValueProof {
                proof: BatchCurrentOperationProof {
                    loc: location,
                    chunk,
                    range_proof,
                },
                next_key: update.next_key.clone(),
            },
            operation,
        })
    }

    async fn require_current_boundary_state(
        &self,
        session: &SerializableReadSession,
        location: Location,
    ) -> Result<(), QmdbError> {
        if session
            .get(&encode_current_meta_key(location))
            .await?
            .is_some()
        {
            Ok(())
        } else {
            Err(QmdbError::CurrentBoundaryStateMissing { location })
        }
    }

    async fn load_current_boundary_root(
        &self,
        session: &SerializableReadSession,
        location: Location,
    ) -> Result<QmdbDigest, QmdbError> {
        self.require_current_boundary_state(session, location)
            .await?;
        let Some(bytes) = session.get(&encode_current_meta_key(location)).await? else {
            return Err(QmdbError::CurrentBoundaryStateMissing { location });
        };
        decode_digest(
            bytes.as_ref(),
            format!("current boundary root at {location}"),
        )
    }

    async fn append_ops_nodes_incrementally<Op: Encode>(
        &self,
        session: &SerializableReadSession,
        previous_ops_size: Position,
        delta_operations: &[Op],
        rows: &mut Vec<(Key, Vec<u8>)>,
    ) -> Result<(Position, BTreeMap<Position, QmdbDigest>, QmdbDigest), QmdbError> {
        let encoded = delta_operations
            .iter()
            .map(|operation| {
                let bytes = operation.encode().to_vec();
                ensure_encoded_value_size(bytes.len())?;
                Ok(bytes)
            })
            .collect::<Result<Vec<_>, QmdbError>>()?;
        self.core()
            .append_encoded_ops_nodes_incrementally(session, previous_ops_size, &encoded, rows)
            .await
    }

    pub(crate) async fn compute_ops_root(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
    ) -> Result<QmdbDigest, QmdbError> {
        self.core().compute_ops_root(session, watermark).await
    }

    async fn build_current_range_proof(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
        start_location: Location,
        end_location_exclusive: Location,
    ) -> Result<BatchCurrentRangeProof, QmdbError> {
        let storage = KvCurrentStorage {
            session,
            watermark,
            mmr_size: mmr_size_for_watermark(watermark)?,
        };
        let proof = verification::range_proof(&storage, start_location..end_location_exclusive)
            .await
            .map_err(|e| QmdbError::CommonwareMmr(e.to_string()))?;
        Ok(BatchCurrentRangeProof {
            proof,
            partial_chunk_digest: self
                .load_partial_chunk_digest(session, watermark)
                .await?
                .map(|(_, digest)| digest),
            ops_root: self.compute_ops_root(session, watermark).await?,
        })
    }

    async fn load_bitmap_chunk(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
        chunk_index: u64,
    ) -> Result<[u8; BITMAP_CHUNK_BYTES], QmdbError> {
        let start = encode_chunk_key(chunk_index, Location::new(0));
        let end = encode_chunk_key(chunk_index, watermark);
        let rows = session
            .range_with_mode(&start, &end, 1, RangeMode::Reverse)
            .await?;
        let Some((_, bytes)) = rows.into_iter().next() else {
            return Err(QmdbError::CorruptData(format!(
                "missing bitmap chunk {chunk_index} at watermark {watermark}"
            )));
        };
        if bytes.len() != BITMAP_CHUNK_BYTES {
            return Err(QmdbError::CorruptData(format!(
                "bitmap chunk {chunk_index} has invalid length {}",
                bytes.len()
            )));
        }
        let mut chunk = [0u8; BITMAP_CHUNK_BYTES];
        chunk.copy_from_slice(bytes.as_ref());
        Ok(chunk)
    }

    async fn load_bitmap_chunks(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
        start_location: Location,
        end_location_exclusive: Location,
    ) -> Result<Vec<[u8; BITMAP_CHUNK_BYTES]>, QmdbError> {
        let start_chunk = chunk_index_for_location(start_location);
        let end_chunk = chunk_index_for_location(end_location_exclusive - 1);
        let mut chunks = Vec::with_capacity((end_chunk - start_chunk + 1) as usize);
        for chunk_index in start_chunk..=end_chunk {
            chunks.push(
                self.load_bitmap_chunk(session, watermark, chunk_index)
                    .await?,
            );
        }
        Ok(chunks)
    }

    async fn load_partial_chunk_digest(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
    ) -> Result<Option<(u64, QmdbDigest)>, QmdbError> {
        let leaves = watermark
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        let next_bit = *leaves % BITMAP_CHUNK_BITS;
        if next_bit == NO_PARTIAL_CHUNK {
            return Ok(None);
        }
        let chunk_index = *leaves / BITMAP_CHUNK_BITS;
        let chunk = self
            .load_bitmap_chunk(session, watermark, chunk_index)
            .await?;
        let mut hasher = Sha256::default();
        hasher.update(&chunk);
        Ok(Some((next_bit, hasher.finalize())))
    }

    async fn load_operation_at(
        &self,
        session: &SerializableReadSession,
        location: Location,
    ) -> Result<BatchOperation, QmdbError> {
        let bytes = self
            .core()
            .load_operation_bytes_at(session, location)
            .await?;
        BatchOperation::decode_cfg(bytes.as_slice(), &self.core().operation_codec_cfg()).map_err(
            |e| {
                QmdbError::CorruptData(format!(
                    "failed to decode qmdb operation at location {location}: {e}"
                ))
            },
        )
    }

    async fn load_operation_range(
        &self,
        session: &SerializableReadSession,
        start_location: Location,
        end_location_exclusive: Location,
    ) -> Result<Vec<BatchOperation>, QmdbError> {
        let rows = self
            .core()
            .load_operation_bytes_range(session, start_location, end_location_exclusive)
            .await?;
        rows.into_iter()
            .enumerate()
            .map(|(offset, bytes)| {
                let location = start_location + offset as u64;
                BatchOperation::decode_cfg(bytes.as_slice(), &self.core().operation_codec_cfg())
                    .map_err(|e| {
                        QmdbError::CorruptData(format!(
                            "failed to decode qmdb operation at location {location}: {e}"
                        ))
                    })
            })
            .collect()
    }

    async fn load_latest_update_row(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
        key: &[u8],
    ) -> Result<Option<(Key, Vec<u8>)>, QmdbError> {
        self.core()
            .load_latest_update_row(session, watermark, key)
            .await
    }
}

#[derive(Clone, Debug)]
struct PreparedUpload {
    operation_count: u32,
    keyed_operation_count: u32,
    rows: Vec<(Key, Vec<u8>)>,
}

impl PreparedUpload {
    fn build(latest_location: Location, operations: &[BatchOperation]) -> Result<Self, QmdbError> {
        Self::build_from_ops(latest_location, operations, |op| match op {
            BatchOperation::Update(QmdbUpdate {
                key,
                value,
                next_key: _,
            }) => Some((key, Some(value))),
            BatchOperation::Delete(key) => Some((key, None)),
            BatchOperation::CommitFloor(_, _) => None,
        })
    }

    fn build_unordered(
        latest_location: Location,
        operations: &[UnorderedBatchOperation],
    ) -> Result<Self, QmdbError> {
        Self::build_from_ops(latest_location, operations, |op| match op {
            UnorderedBatchOperation::Update(UnorderedUpdate(key, value)) => {
                Some((key, Some(value)))
            }
            UnorderedBatchOperation::Delete(key) => Some((key, None)),
            UnorderedBatchOperation::CommitFloor(_, _) => None,
        })
    }

    fn build_from_ops<Op: Encode>(
        latest_location: Location,
        operations: &[Op],
        extract_keyed: impl Fn(&Op) -> Option<(&Vec<u8>, Option<&Vec<u8>>)>,
    ) -> Result<Self, QmdbError> {
        let mut rows = Vec::<(Key, Vec<u8>)>::with_capacity(operations.len() * 2 + 1);
        let mut keyed_operation_count = 0u32;
        let count_u64 = operations.len() as u64;
        let Some(start_location) = latest_location
            .checked_add(1)
            .and_then(|n| n.checked_sub(count_u64))
        else {
            return Err(QmdbError::InvalidLocationRange {
                start_location: Location::new(0),
                latest_location,
                count: operations.len(),
            });
        };

        for (index, op) in operations.iter().enumerate() {
            let location = start_location + index as u64;
            let encoded = op.encode().to_vec();
            ensure_encoded_value_size(encoded.len())?;
            rows.push((encode_operation_key(location), encoded));

            if let Some((key, value)) = extract_keyed(op) {
                keyed_operation_count += 1;
                rows.push((
                    encode_update_key(key, location)?,
                    encode_update_row(key, value.map(|v| v.as_slice()))?,
                ));
            }
        }

        let operation_count = u32::try_from(operations.len()).map_err(|_| {
            QmdbError::CorruptData("operation count does not fit in u32".to_string())
        })?;
        rows.push((encode_presence_key(latest_location), Vec::new()));

        Ok(Self {
            operation_count,
            keyed_operation_count,
            rows,
        })
    }
}

#[derive(Clone, Debug)]
struct PreparedCurrentBoundaryUpload {
    rows: Vec<(Key, Vec<u8>)>,
}

impl PreparedCurrentBoundaryUpload {
    fn build(
        latest_location: Location,
        current_boundary: &CurrentBoundaryState,
    ) -> Result<Self, QmdbError> {
        let mut rows = Vec::with_capacity(
            1 + current_boundary.chunks.len() + current_boundary.grafted_nodes.len(),
        );
        rows.push((
            encode_current_meta_key(latest_location),
            current_boundary.root.as_ref().to_vec(),
        ));
        for &(chunk_index, chunk) in &current_boundary.chunks {
            rows.push((
                encode_chunk_key(chunk_index, latest_location),
                chunk.to_vec(),
            ));
        }
        for &(grafted_position, digest) in &current_boundary.grafted_nodes {
            rows.push((
                encode_grafted_node_key(grafted_position, latest_location),
                digest.as_ref().to_vec(),
            ));
        }
        Ok(Self { rows })
    }
}

struct KvMmrStorage<'a> {
    session: &'a SerializableReadSession,
    mmr_size: Position,
}

impl MmrStorage<QmdbDigest> for KvMmrStorage<'_> {
    async fn size(&self) -> Position {
        self.mmr_size
    }

    async fn get_node(&self, position: Position) -> Result<Option<QmdbDigest>, mmr::Error> {
        let key = encode_node_key(position);
        let bytes = self
            .session
            .get(&key)
            .await
            .map_err(|_| mmr::Error::DataCorrupted("exoware-qmdb node fetch failed"))?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        if bytes.len() != DIGEST_LEN {
            return Err(mmr::Error::DataCorrupted(
                "exoware-qmdb node digest has invalid length",
            ));
        }
        let mut digest = [0u8; DIGEST_LEN];
        digest.copy_from_slice(bytes.as_ref());
        Ok(Some(QmdbDigest::from(digest)))
    }
}

struct KvCurrentStorage<'a> {
    session: &'a SerializableReadSession,
    watermark: Location,
    mmr_size: Position,
}

impl MmrStorage<QmdbDigest> for KvCurrentStorage<'_> {
    async fn size(&self) -> Position {
        self.mmr_size
    }

    async fn get_node(&self, position: Position) -> Result<Option<QmdbDigest>, mmr::Error> {
        if position_height(position) < GRAFTING_HEIGHT {
            let key = encode_node_key(position);
            let bytes = self.session.get(&key).await.map_err(|_| {
                mmr::Error::DataCorrupted("exoware-qmdb current ops node fetch failed")
            })?;
            let Some(bytes) = bytes else {
                return Ok(None);
            };
            if bytes.len() != DIGEST_LEN {
                return Err(mmr::Error::DataCorrupted(
                    "exoware-qmdb current ops node has invalid length",
                ));
            }
            let mut digest = [0u8; DIGEST_LEN];
            digest.copy_from_slice(bytes.as_ref());
            return Ok(Some(QmdbDigest::from(digest)));
        }

        let grafted_position = ops_to_grafted_pos(position, GRAFTING_HEIGHT);
        let start = encode_grafted_node_key(grafted_position, Location::new(0));
        let end = encode_grafted_node_key(grafted_position, self.watermark);
        let rows = self
            .session
            .range_with_mode(&start, &end, 1, RangeMode::Reverse)
            .await
            .map_err(|_| {
                mmr::Error::DataCorrupted("exoware-qmdb current grafted node fetch failed")
            })?;
        let Some((_, bytes)) = rows.into_iter().next() else {
            return Ok(None);
        };
        if bytes.len() != DIGEST_LEN {
            return Err(mmr::Error::DataCorrupted(
                "exoware-qmdb current grafted node has invalid length",
            ));
        }
        let mut digest = [0u8; DIGEST_LEN];
        digest.copy_from_slice(bytes.as_ref());
        Ok(Some(QmdbDigest::from(digest)))
    }
}

struct RebuiltCurrentState {
    ops_mmr: Mmr<QmdbDigest>,
    ops_root: QmdbDigest,
    chunks: Vec<[u8; BITMAP_CHUNK_BYTES]>,
    grafted_mmr: Mmr<QmdbDigest>,
    partial_chunk_digest: Option<(u64, QmdbDigest)>,
}

impl RebuiltCurrentState {
    fn build(operations: Vec<BatchOperation>) -> Result<Self, QmdbError> {
        let encoded_operations = operations
            .iter()
            .map(|operation| {
                let encoded = operation.encode().to_vec();
                ensure_encoded_value_size(encoded.len())?;
                Ok(encoded)
            })
            .collect::<Result<Vec<_>, QmdbError>>()?;
        let ops_mmr = build_operation_mmr(&encoded_operations)?;
        let ops_root = *ops_mmr.root();
        let chunks = build_bitmap_chunks(&operations);
        let complete_chunks = operations.len() / BITMAP_CHUNK_BITS as usize;
        let grafted_mmr = build_grafted_mmr(&ops_mmr, &chunks[..complete_chunks])?;
        let partial_chunk_digest =
            if operations.len().is_multiple_of(BITMAP_CHUNK_BITS as usize) || chunks.is_empty() {
                None
            } else {
                let next_bit = (operations.len() % BITMAP_CHUNK_BITS as usize) as u64;
                let mut hasher = Sha256::default();
                hasher.update(&chunks[chunks.len() - 1]);
                Some((next_bit, hasher.finalize()))
            };
        Ok(Self {
            ops_mmr,
            ops_root,
            chunks,
            grafted_mmr,
            partial_chunk_digest,
        })
    }
}

struct RebuiltCurrentStorage<'a> {
    ops_mmr: &'a Mmr<QmdbDigest>,
    grafted_mmr: &'a Mmr<QmdbDigest>,
}

impl MmrStorage<QmdbDigest> for RebuiltCurrentStorage<'_> {
    async fn size(&self) -> Position {
        self.ops_mmr.size()
    }

    async fn get_node(&self, position: Position) -> Result<Option<QmdbDigest>, mmr::Error> {
        if position_height(position) < GRAFTING_HEIGHT {
            return Ok(self.ops_mmr.get_node(position));
        }
        let grafted_position = ops_to_grafted_pos(position, GRAFTING_HEIGHT);
        Ok(self.grafted_mmr.get_node(grafted_position))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DecodedUpdate {
    key: Vec<u8>,
    value: Option<Vec<u8>>,
}

fn build_operation_mmr(
    encoded_operations: &[Vec<u8>],
) -> Result<mmr::mem::Mmr<QmdbDigest>, QmdbError> {
    let mut hasher = StandardHasher::<Sha256>::new();
    let mut mmr = mmr::mem::Mmr::new(&mut hasher);
    let changeset = {
        let mut batch = UnmerkleizedBatch::new(&mmr);
        for op in encoded_operations {
            batch.add(&mut hasher, op);
        }
        batch.merkleize(&mut hasher).finalize()
    };
    mmr.apply(changeset)
        .map_err(|e| QmdbError::CommonwareMmr(e.to_string()))?;
    Ok(mmr)
}

fn build_bitmap_chunks(operations: &[BatchOperation]) -> Vec<[u8; BITMAP_CHUNK_BYTES]> {
    let mut latest_active = BTreeMap::<Vec<u8>, usize>::new();
    let mut latest_commit = None::<usize>;
    let mut bits = vec![false; operations.len()];

    for (index, operation) in operations.iter().enumerate() {
        match operation {
            BatchOperation::Update(update) => {
                bits[index] = true;
                if let Some(previous) = latest_active.insert(update.key.clone(), index) {
                    bits[previous] = false;
                }
            }
            BatchOperation::Delete(key) => {
                if let Some(previous) = latest_active.remove(key) {
                    bits[previous] = false;
                }
            }
            BatchOperation::CommitFloor(_, _) => {
                bits[index] = true;
                if let Some(previous) = latest_commit.replace(index) {
                    bits[previous] = false;
                }
            }
        }
    }

    let chunk_count = operations.len().div_ceil(BITMAP_CHUNK_BITS as usize);
    let mut chunks = vec![[0u8; BITMAP_CHUNK_BYTES]; chunk_count];
    for (bit_index, is_set) in bits.into_iter().enumerate() {
        if !is_set {
            continue;
        }
        let chunk_index = bit_index / BITMAP_CHUNK_BITS as usize;
        let bit_in_chunk = bit_index % BITMAP_CHUNK_BITS as usize;
        chunks[chunk_index][bit_in_chunk / 8] |= 1 << (bit_in_chunk % 8);
    }
    chunks
}

fn build_grafted_mmr(
    ops_mmr: &Mmr<QmdbDigest>,
    complete_chunks: &[[u8; BITMAP_CHUNK_BYTES]],
) -> Result<Mmr<QmdbDigest>, QmdbError> {
    let mut grafted_hasher = GraftedHasher::new(StandardHasher::<Sha256>::new(), GRAFTING_HEIGHT);
    let mut grafted_mmr = Mmr::new(&mut grafted_hasher);
    if complete_chunks.is_empty() {
        return Ok(grafted_mmr);
    }

    let zero_chunk = [0u8; BITMAP_CHUNK_BYTES];
    let changeset = {
        let mut batch = grafted_mmr.new_batch();
        for (chunk_index, chunk) in complete_chunks.iter().enumerate() {
            let ops_position = chunk_idx_to_ops_pos(chunk_index as u64, GRAFTING_HEIGHT);
            let ops_digest = ops_mmr.get_node(ops_position).ok_or_else(|| {
                QmdbError::CorruptData(format!(
                    "missing ops subtree root at position {ops_position} for chunk {chunk_index}"
                ))
            })?;
            let digest = if *chunk == zero_chunk {
                ops_digest
            } else {
                let mut hasher = Sha256::default();
                hasher.update(chunk);
                hasher.update(&ops_digest);
                hasher.finalize()
            };
            batch.add_leaf_digest(digest);
        }
        batch.merkleize(&mut grafted_hasher).finalize()
    };
    grafted_mmr
        .apply(changeset)
        .map_err(|e| QmdbError::CommonwareMmr(e.to_string()))?;
    Ok(grafted_mmr)
}

async fn compute_storage_root(
    storage: &impl MmrStorage<QmdbDigest>,
) -> Result<QmdbDigest, QmdbError> {
    let size = storage.size().await;
    let leaves = Location::try_from(size)
        .map_err(|e| QmdbError::CorruptData(format!("invalid storage size: {e}")))?;
    let mut peaks = Vec::new();
    for (peak_pos, _) in PeakIterator::new(size) {
        let digest = storage
            .get_node(peak_pos)
            .await
            .map_err(|e| QmdbError::CommonwareMmr(e.to_string()))?
            .ok_or_else(|| {
                QmdbError::CorruptData(format!("missing peak node at position {peak_pos}"))
            })?;
        peaks.push(digest);
    }
    let mut hasher = StandardHasher::<Sha256>::new();
    Ok(mmr::hasher::Hasher::root(&mut hasher, leaves, peaks.iter()))
}

fn combine_current_roots(
    ops_root: &QmdbDigest,
    grafted_root: &QmdbDigest,
    partial_chunk: Option<(u64, &QmdbDigest)>,
) -> QmdbDigest {
    let mut hasher = Sha256::default();
    hasher.update(ops_root);
    hasher.update(grafted_root);
    if let Some((next_bit, digest)) = partial_chunk {
        hasher.update(&next_bit.to_be_bytes());
        hasher.update(digest);
    }
    hasher.finalize()
}

fn decode_digest(bytes: &[u8], label: String) -> Result<QmdbDigest, QmdbError> {
    if bytes.len() != DIGEST_LEN {
        return Err(QmdbError::CorruptData(format!(
            "{label} has invalid length {}",
            bytes.len()
        )));
    }
    let mut digest = [0u8; DIGEST_LEN];
    digest.copy_from_slice(bytes);
    Ok(QmdbDigest::from(digest))
}

fn chunk_index_for_location(location: Location) -> u64 {
    *location / BITMAP_CHUNK_BITS
}

fn chunk_idx_to_ops_pos(chunk_idx: u64, grafting_height: u32) -> Position {
    let first_leaf_loc = Location::new(chunk_idx << grafting_height);
    let first_leaf_pos = Position::try_from(first_leaf_loc).expect("chunk_idx_to_ops_pos overflow");
    Position::new(*first_leaf_pos + (1u64 << (grafting_height + 1)) - 2)
}

fn ops_to_grafted_pos(ops_pos: Position, grafting_height: u32) -> Position {
    let ops_height = position_height(ops_pos);
    assert!(
        ops_height >= grafting_height,
        "position height {ops_height} < grafting height {grafting_height}"
    );
    let grafted_height = ops_height - grafting_height;
    let leftmost_ops_leaf_pos = *ops_pos + 2 - (1u64 << (ops_height + 1));
    let ops_leaf_loc = Location::try_from(Position::new(leftmost_ops_leaf_pos))
        .expect("leftmost ops leaf is not a valid leaf");
    let chunk_idx = *ops_leaf_loc >> grafting_height;
    let grafted_leaf_pos =
        Position::try_from(Location::new(chunk_idx)).expect("chunk index overflow");
    Position::new(*grafted_leaf_pos + (1u64 << (grafted_height + 1)) - 2)
}

fn grafted_to_ops_pos(grafted_pos: Position, grafting_height: u32) -> Position {
    let grafted_height = position_height(grafted_pos);
    let leftmost_grafted_leaf_pos = grafted_pos + 2 - (1u64 << (grafted_height + 1));
    let chunk_idx = *Location::try_from(leftmost_grafted_leaf_pos)
        .expect("leftmost leaf is not a valid grafted leaf");
    let ops_leaf_loc = chunk_idx << grafting_height;
    let ops_leaf_pos =
        Position::try_from(Location::new(ops_leaf_loc)).expect("ops leaf loc overflow");
    let ops_height = grafted_height + grafting_height;
    Position::new(*ops_leaf_pos + (1u64 << (ops_height + 1)) - 2)
}

fn position_height(pos: Position) -> u32 {
    let mut pos = pos.as_u64();
    if pos == 0 {
        return 0;
    }

    let mut size = u64::MAX >> pos.leading_zeros();
    while size != 0 {
        if pos >= size {
            pos -= size;
        }
        size >>= 1;
    }
    pos as u32
}

struct GraftedHasher {
    inner: StandardHasher<Sha256>,
    grafting_height: u32,
}

impl GraftedHasher {
    const fn new(inner: StandardHasher<Sha256>, grafting_height: u32) -> Self {
        Self {
            inner,
            grafting_height,
        }
    }
}

impl mmr::hasher::Hasher for GraftedHasher {
    type Digest = QmdbDigest;
    type Inner = Sha256;

    fn leaf_digest(&mut self, pos: Position, element: &[u8]) -> Self::Digest {
        self.inner.leaf_digest(pos, element)
    }

    fn node_digest(
        &mut self,
        pos: Position,
        left: &Self::Digest,
        right: &Self::Digest,
    ) -> Self::Digest {
        let ops_pos = grafted_to_ops_pos(pos, self.grafting_height);
        self.inner.node_digest(ops_pos, left, right)
    }

    fn root<'a>(
        &mut self,
        leaves: Location,
        peak_digests: impl Iterator<Item = &'a Self::Digest>,
    ) -> Self::Digest {
        self.inner.root(leaves, peak_digests)
    }

    fn digest(&mut self, data: &[u8]) -> Self::Digest {
        self.inner.digest(data)
    }

    fn inner(&mut self) -> &mut Self::Inner {
        self.inner.inner()
    }

    fn fork(&self) -> impl mmr::hasher::Hasher<Digest = Self::Digest> {
        Self {
            inner: StandardHasher::<Sha256>::new(),
            grafting_height: self.grafting_height,
        }
    }
}

fn mmr_size_for_watermark(watermark: Location) -> Result<Position, QmdbError> {
    let leaves = watermark
        .checked_add(1)
        .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
    Position::try_from(leaves)
        .map_err(|e| QmdbError::CorruptData(format!("invalid MMR size for watermark: {e}")))
}

fn ensure_encoded_value_size(len: usize) -> Result<(), QmdbError> {
    if len <= MAX_OPERATION_SIZE {
        Ok(())
    } else {
        Err(QmdbError::EncodedValueTooLarge {
            len,
            max: MAX_OPERATION_SIZE,
        })
    }
}

fn encode_update_row(raw_key: &[u8], value: Option<&[u8]>) -> Result<Vec<u8>, QmdbError> {
    if raw_key.len() > u16::MAX as usize {
        return Err(QmdbError::RawKeyTooLarge {
            len: raw_key.len(),
            max: u16::MAX as usize,
        });
    }
    let value_len = value.map_or(0usize, |value| value.len());
    if value_len > u16::MAX as usize {
        return Err(QmdbError::EncodedValueTooLarge {
            len: value_len,
            max: u16::MAX as usize,
        });
    }

    let mut out = Vec::with_capacity(2 + raw_key.len() + 1 + 2 + value_len);
    out.extend_from_slice(&(raw_key.len() as u16).to_be_bytes());
    out.extend_from_slice(raw_key);
    match value {
        Some(bytes) => {
            out.push(1);
            out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        None => {
            out.push(0);
            out.extend_from_slice(&0u16.to_be_bytes());
        }
    }
    ensure_encoded_value_size(out.len())?;
    Ok(out)
}

fn decode_update_row(bytes: &[u8]) -> Result<DecodedUpdate, QmdbError> {
    if bytes.len() < 5 {
        return Err(QmdbError::CorruptData(
            "update row shorter than minimum header".to_string(),
        ));
    }
    let key_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    let key_end = 2 + key_len;
    if bytes.len() < key_end + 3 {
        return Err(QmdbError::CorruptData(
            "update row truncated while reading key".to_string(),
        ));
    }
    let key = bytes[2..key_end].to_vec();
    let has_value = bytes[key_end];
    let value_len = u16::from_be_bytes([bytes[key_end + 1], bytes[key_end + 2]]) as usize;
    let value_start = key_end + 3;
    if bytes.len() != value_start + value_len {
        return Err(QmdbError::CorruptData(
            "update row length does not match encoded payload".to_string(),
        ));
    }

    let value = match has_value {
        0 => {
            if value_len != 0 {
                return Err(QmdbError::CorruptData(
                    "tombstone row encoded with non-zero value length".to_string(),
                ));
            }
            None
        }
        1 => Some(bytes[value_start..].to_vec()),
        other => {
            return Err(QmdbError::CorruptData(format!(
                "invalid value presence marker {other}"
            )))
        }
    };
    Ok(DecodedUpdate { key, value })
}

fn ordered_key_encoded_len(raw_key: &[u8]) -> usize {
    raw_key.len()
        + raw_key
            .iter()
            .filter(|&&byte| byte == ORDERED_KEY_ESCAPE_BYTE)
            .count()
        + ORDERED_KEY_TERMINATOR_LEN
}

fn encode_ordered_key_bytes(raw_key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ordered_key_encoded_len(raw_key));
    for &byte in raw_key {
        if byte == ORDERED_KEY_ESCAPE_BYTE {
            out.push(ORDERED_KEY_ESCAPE_BYTE);
            out.push(ORDERED_KEY_ZERO_ESCAPE);
        } else {
            out.push(byte);
        }
    }
    out.push(ORDERED_KEY_ESCAPE_BYTE);
    out.push(ORDERED_KEY_ESCAPE_BYTE);
    out
}

fn validate_ordered_key_bytes(bytes: &[u8], label: &str) -> Result<(), QmdbError> {
    if bytes.len() < ORDERED_KEY_TERMINATOR_LEN {
        return Err(QmdbError::CorruptData(format!(
            "{label} shorter than ordered-key terminator"
        )));
    }
    let mut idx = 0usize;
    let end = bytes.len() - ORDERED_KEY_TERMINATOR_LEN;
    while idx < end {
        if bytes[idx] == ORDERED_KEY_ESCAPE_BYTE {
            match bytes.get(idx + 1) {
                Some(&ORDERED_KEY_ZERO_ESCAPE) => idx += 2,
                Some(_) => {
                    return Err(QmdbError::CorruptData(format!(
                        "{label} contains invalid ordered-key escape"
                    )))
                }
                None => {
                    return Err(QmdbError::CorruptData(format!(
                        "{label} truncated in ordered-key escape"
                    )))
                }
            }
        } else {
            idx += 1;
        }
    }
    if bytes[end] != ORDERED_KEY_ESCAPE_BYTE || bytes[end + 1] != ORDERED_KEY_ESCAPE_BYTE {
        return Err(QmdbError::CorruptData(format!(
            "{label} missing ordered-key terminator"
        )));
    }
    Ok(())
}

fn encode_ordered_update_payload(
    codec: KeyCodec,
    raw_key: &[u8],
    fixed_suffix_len: usize,
) -> Result<Vec<u8>, QmdbError> {
    let encoded = encode_ordered_key_bytes(raw_key);
    let payload_len = encoded.len() + fixed_suffix_len;
    let max = codec.max_payload_capacity_bytes();
    if payload_len > max {
        return Err(QmdbError::SortableKeyTooLarge {
            raw_len: raw_key.len(),
            encoded_len: payload_len,
            max,
        });
    }
    Ok(encoded)
}

fn encode_update_key(raw_key: &[u8], location: Location) -> Result<Key, QmdbError> {
    let codec = update_codec();
    let ordered_key = encode_ordered_update_payload(codec, raw_key, UPDATE_VERSION_LEN)?;
    let total_len = codec.min_key_len_for_payload(ordered_key.len() + UPDATE_VERSION_LEN);
    let mut key = codec
        .new_key_with_len(total_len)
        .expect("update key length should fit");
    codec
        .write_payload(&mut key, 0, &ordered_key)
        .expect("update key bytes fit");
    codec
        .write_payload(
            &mut key,
            ordered_key.len(),
            &location.as_u64().to_be_bytes(),
        )
        .expect("update location fits");
    Ok(key.freeze())
}

fn decode_update_location(key: &Key) -> Result<Location, QmdbError> {
    let codec = update_codec();
    if !codec.matches(key) {
        return Err(QmdbError::CorruptData(
            "update key prefix mismatch".to_string(),
        ));
    }
    let payload_capacity = codec.payload_capacity_bytes_for_key_len(key.len());
    if payload_capacity < ORDERED_KEY_TERMINATOR_LEN + UPDATE_VERSION_LEN {
        return Err(QmdbError::CorruptData(
            "update key payload shorter than minimum layout".to_string(),
        ));
    }
    let ordered_len = payload_capacity - UPDATE_VERSION_LEN;
    let ordered_key = codec
        .read_payload(key, 0, ordered_len)
        .map_err(|e| QmdbError::CorruptData(format!("cannot decode update key bytes: {e}")))?;
    validate_ordered_key_bytes(&ordered_key, "update key")?;
    let bytes = codec
        .read_payload_exact::<8>(key, ordered_len)
        .map_err(|e| QmdbError::CorruptData(format!("cannot decode update location: {e}")))?;
    Ok(Location::new(u64::from_be_bytes(bytes)))
}

fn encode_presence_key(latest_location: Location) -> Key {
    let codec = presence_codec();
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(8))
        .expect("presence key length should fit");
    codec
        .write_payload(&mut key, 0, &latest_location.as_u64().to_be_bytes())
        .expect("presence latest location fits");
    key.freeze()
}

fn encode_watermark_key(location: Location) -> Key {
    let codec = watermark_codec();
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(8))
        .expect("watermark key length should fit");
    codec
        .write_payload(&mut key, 0, &location.as_u64().to_be_bytes())
        .expect("watermark location fits");
    key.freeze()
}

fn decode_watermark_location(key: &Key) -> Result<Location, QmdbError> {
    let codec = watermark_codec();
    if !codec.matches(key) {
        return Err(QmdbError::CorruptData(
            "watermark key prefix mismatch".to_string(),
        ));
    }
    let bytes = codec
        .read_payload_exact::<8>(key, 0)
        .map_err(|e| QmdbError::CorruptData(format!("cannot decode watermark location: {e}")))?;
    Ok(Location::new(u64::from_be_bytes(bytes)))
}

fn encode_operation_key(location: Location) -> Key {
    let codec = operation_codec();
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(8))
        .expect("operation key length should fit");
    codec
        .write_payload(&mut key, 0, &location.as_u64().to_be_bytes())
        .expect("operation location fits");
    key.freeze()
}

fn encode_node_key(position: Position) -> Key {
    let codec = node_codec();
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(8))
        .expect("node key length should fit");
    codec
        .write_payload(&mut key, 0, &position.as_u64().to_be_bytes())
        .expect("node position fits");
    key.freeze()
}

fn encode_current_meta_key(location: Location) -> Key {
    let codec = current_meta_codec();
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(8))
        .expect("current meta key length should fit");
    codec
        .write_payload(&mut key, 0, &location.as_u64().to_be_bytes())
        .expect("current meta location fits");
    key.freeze()
}

fn encode_grafted_node_key(position: Position, watermark: Location) -> Key {
    let codec = grafted_node_codec();
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(16))
        .expect("grafted node key length should fit");
    codec
        .write_payload(&mut key, 0, &position.as_u64().to_be_bytes())
        .expect("grafted node position fits");
    codec
        .write_payload(&mut key, 8, &watermark.as_u64().to_be_bytes())
        .expect("grafted node watermark fits");
    key.freeze()
}

fn encode_chunk_key(chunk_index: u64, watermark: Location) -> Key {
    let codec = chunk_codec();
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(16))
        .expect("chunk key length should fit");
    codec
        .write_payload(&mut key, 0, &chunk_index.to_be_bytes())
        .expect("chunk index fits");
    codec
        .write_payload(&mut key, 8, &watermark.as_u64().to_be_bytes())
        .expect("chunk watermark fits");
    key.freeze()
}

fn decode_operation_location_key(key: &Key) -> Result<Location, QmdbError> {
    let codec = operation_codec();
    if !codec.matches(key) {
        return Err(QmdbError::CorruptData(
            "operation key prefix mismatch".to_string(),
        ));
    }
    let bytes = codec
        .read_payload_exact::<8>(key, 0)
        .map_err(|e| QmdbError::CorruptData(format!("cannot decode operation location: {e}")))?;
    Ok(Location::new(u64::from_be_bytes(bytes)))
}

fn update_codec() -> KeyCodec {
    KeyCodec::new(RESERVED_BITS, UPDATE_FAMILY).expect("static update codec")
}

fn presence_codec() -> KeyCodec {
    KeyCodec::new(RESERVED_BITS, PRESENCE_FAMILY).expect("static presence codec")
}

fn watermark_codec() -> KeyCodec {
    KeyCodec::new(RESERVED_BITS, WATERMARK_FAMILY).expect("static watermark codec")
}

fn operation_codec() -> KeyCodec {
    KeyCodec::new(RESERVED_BITS, OP_FAMILY).expect("static operation codec")
}

fn node_codec() -> KeyCodec {
    KeyCodec::new(RESERVED_BITS, NODE_FAMILY).expect("static node codec")
}

fn current_meta_codec() -> KeyCodec {
    KeyCodec::new(RESERVED_BITS, CURRENT_META_FAMILY).expect("static current meta codec")
}

fn grafted_node_codec() -> KeyCodec {
    KeyCodec::new(RESERVED_BITS, GRAFTED_NODE_FAMILY).expect("static grafted node codec")
}

fn chunk_codec() -> KeyCodec {
    KeyCodec::new(RESERVED_BITS, CHUNK_FAMILY).expect("static chunk codec")
}

/// Common alias for the crate's public error surface.
pub type AuthenticatedError = QmdbError;

/// Generic contiguous historical proof for one authenticated backend.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticatedOperationRangeProof<Op> {
    pub watermark: Location,
    pub root: QmdbDigest,
    pub start_location: Location,
    pub proof: BatchProof,
    pub operations: Vec<Op>,
}

impl<Op: Encode> AuthenticatedOperationRangeProof<Op> {
    pub fn verify(&self) -> bool {
        let mut hasher = StandardHasher::<Sha256>::new();
        verify_proof(
            &mut hasher,
            &self.proof,
            self.start_location,
            &self.operations,
            &self.root,
        )
    }
}

/// Unordered QMDB client backed by the Exoware store.
///
/// Wraps [`OrderedClient`] for watermark/query/node logic but uses
/// [`UnorderedBatchOperation`] for uploads and proof decoding.
/// Does not support exclusion proofs or current-state boundary uploads.
#[derive(Clone, Debug)]
pub struct UnorderedClient {
    client: StoreClient,
    config: QmdbConfig,
    query_visible_sequence: Option<Arc<AtomicU64>>,
}

impl UnorderedClient {
    fn core(&self) -> HistoricalOpsClientCore<'_> {
        HistoricalOpsClientCore {
            client: &self.client,
            config: &self.config,
            query_visible_sequence: self.query_visible_sequence.as_ref(),
        }
    }

    pub fn new(url: &str) -> Self {
        Self::from_client(StoreClient::new(url))
    }

    pub fn from_client(client: StoreClient) -> Self {
        Self {
            client,
            config: QmdbConfig::default(),
            query_visible_sequence: None,
        }
    }

    pub fn with_query_visible_sequence(mut self, seq: Arc<AtomicU64>) -> Self {
        self.query_visible_sequence = Some(seq);
        self
    }

    pub fn with_config(mut self, config: QmdbConfig) -> Self {
        self.config = config;
        self
    }

    pub fn inner(&self) -> &StoreClient {
        &self.client
    }

    pub async fn writer_location_watermark(&self) -> Result<Option<Location>, QmdbError> {
        self.core().writer_location_watermark().await
    }

    pub async fn publish_writer_location_watermark(
        &self,
        location: Location,
    ) -> Result<Location, QmdbError> {
        let session = self.client.create_session();
        let latest_watermark = self.core().read_latest_watermark(&session).await?;
        if let Some(watermark) = latest_watermark {
            if watermark >= location {
                return Ok(watermark);
            }
        }
        self.core()
            .require_batch_boundary(&session, location)
            .await?;
        let delta_start_location = latest_watermark.map_or(Location::new(0), |w| w + 1);
        let end_location_exclusive = location
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        let op_rows = self
            .core()
            .load_operation_bytes_range(&session, delta_start_location, end_location_exclusive)
            .await?;
        let cfg = (
            ((0..=self.config.max_operation_key_len).into(), ()),
            ((0..=self.config.max_operation_value_len).into(), ()),
        );
        for (offset, bytes) in op_rows.iter().enumerate() {
            let op_location = delta_start_location + offset as u64;
            let _ = UnorderedBatchOperation::decode_cfg(bytes.as_slice(), &cfg).map_err(|e| {
                QmdbError::CorruptData(format!(
                    "failed to decode unordered operation at location {op_location}: {e}"
                ))
            })?;
        }
        self.core()
            .publish_writer_location_watermark_with_encoded_ops(
                &session,
                latest_watermark,
                location,
                &op_rows,
                "unordered",
            )
            .await
    }

    pub async fn upload_operations(
        &self,
        latest_location: Location,
        operations: &[UnorderedBatchOperation],
    ) -> Result<UploadReceipt, QmdbError> {
        if operations.is_empty() {
            return Err(QmdbError::EmptyBatch);
        }
        if self
            .client
            .get(&encode_presence_key(latest_location))
            .await?
            .is_some()
        {
            return Err(QmdbError::DuplicateBatchWatermark { latest_location });
        }

        let prepared = PreparedUpload::build_unordered(latest_location, operations)?;
        let refs = prepared
            .rows
            .iter()
            .map(|(key, value)| (key, value.as_slice()))
            .collect::<Vec<_>>();
        self.client.put(&refs).await?;
        self.core().sync_after_ingest().await?;

        let writer_location_watermark = self.writer_location_watermark().await?;
        Ok(UploadReceipt {
            latest_location,
            operation_count: Location::from(prepared.operation_count as u64),
            keyed_operation_count: prepared.keyed_operation_count,
            writer_location_watermark,
            sequence_number: self.client.sequence_number(),
        })
    }

    pub async fn query_many_at<K: AsRef<[u8]>>(
        &self,
        keys: &[K],
        watermark: Location,
    ) -> Result<Vec<Option<VersionedValue>>, QmdbError> {
        self.core().query_many_at(keys, watermark).await
    }

    pub async fn root_at(&self, watermark: Location) -> Result<QmdbDigest, QmdbError> {
        let session = self.client.create_session();
        self.core()
            .require_published_watermark(&session, watermark)
            .await?;
        self.core().compute_ops_root(&session, watermark).await
    }

    pub async fn operation_range_proof(
        &self,
        watermark: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<UnorderedOperationRangeProof, QmdbError> {
        if max_locations == 0 {
            return Err(QmdbError::InvalidRangeLength);
        }
        let session = self.client.create_session();
        self.core()
            .require_published_watermark(&session, watermark)
            .await?;
        let count = watermark
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        if start_location >= count {
            return Err(QmdbError::RangeStartOutOfBounds {
                start: start_location,
                count,
            });
        }
        let end = start_location
            .saturating_add(max_locations as u64)
            .min(count);
        let storage = KvMmrStorage {
            session: &session,
            mmr_size: mmr_size_for_watermark(watermark)?,
        };
        let proof = verification::range_proof(&storage, start_location..end)
            .await
            .map_err(|e| QmdbError::CommonwareMmr(e.to_string()))?;
        let root = self.core().compute_ops_root(&session, watermark).await?;
        let rows = self
            .core()
            .load_operation_bytes_range(&session, start_location, end)
            .await?;
        let cfg = (
            ((0..=MAX_OPERATION_SIZE).into(), ()),
            ((0..=MAX_OPERATION_SIZE).into(), ()),
        );
        let mut operations = Vec::with_capacity(rows.len());
        for (offset, value) in rows.iter().enumerate() {
            let location = start_location + offset as u64;
            let op = UnorderedBatchOperation::decode_cfg(value.as_slice(), &cfg).map_err(|e| {
                QmdbError::CorruptData(format!(
                    "failed to decode unordered operation at location {location}: {e}"
                ))
            })?;
            operations.push(op);
        }

        Ok(UnorderedOperationRangeProof {
            watermark,
            root,
            start_location,
            proof,
            operations,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ImmutableClient<K, V: Codec + Send + Sync> {
    client: StoreClient,
    value_cfg: V::Cfg,
    query_visible_sequence: Option<Arc<AtomicU64>>,
    _marker: PhantomData<K>,
}

impl<K, V> ImmutableClient<K, V>
where
    K: Array + Clone + AsRef<[u8]>,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    ImmutableOperation<K, V>: Encode + Decode<Cfg = V::Cfg> + Clone,
{
    pub fn new(url: &str, value_cfg: V::Cfg) -> Self {
        Self::from_client(StoreClient::new(url), value_cfg)
    }

    pub fn from_client(client: StoreClient, value_cfg: V::Cfg) -> Self {
        Self {
            client,
            value_cfg,
            query_visible_sequence: None,
            _marker: PhantomData,
        }
    }

    pub fn with_query_visible_sequence(mut self, seq: Arc<AtomicU64>) -> Self {
        self.query_visible_sequence = Some(seq);
        self
    }

    pub fn inner(&self) -> &StoreClient {
        &self.client
    }

    pub fn sequence_number(&self) -> u64 {
        self.client.sequence_number()
    }

    async fn sync_after_ingest(&self) -> Result<(), QmdbError> {
        let token = self.client.sequence_number();
        wait_until_query_visible_sequence(self.query_visible_sequence.as_ref(), token).await
    }

    pub async fn writer_location_watermark(&self) -> Result<Option<Location>, QmdbError> {
        retry_transient_post_ingest_query(|| {
            let session = self.client.create_session();
            async move {
                read_latest_auth_watermark(&session, AuthenticatedBackendNamespace::Immutable).await
            }
        })
        .await
    }

    pub async fn upload_operations(
        &self,
        latest_location: Location,
        operations: &[ImmutableOperation<K, V>],
    ) -> Result<UploadReceipt, QmdbError> {
        if operations.is_empty() {
            return Err(QmdbError::EmptyBatch);
        }
        let namespace = AuthenticatedBackendNamespace::Immutable;
        if self
            .client
            .get(&encode_auth_presence_key(namespace, latest_location))
            .await?
            .is_some()
        {
            return Err(QmdbError::DuplicateBatchWatermark { latest_location });
        }
        let (keyed_operation_count, rows) =
            build_auth_immutable_upload_rows(latest_location, operations)?;
        let refs = rows
            .iter()
            .map(|(key, value)| (key, value.as_slice()))
            .collect::<Vec<_>>();
        self.client.put(&refs).await?;
        self.sync_after_ingest().await?;
        Ok(UploadReceipt {
            latest_location,
            operation_count: Location::new(operations.len() as u64),
            keyed_operation_count,
            writer_location_watermark: self.writer_location_watermark().await?,
            sequence_number: self.client.sequence_number(),
        })
    }

    pub async fn publish_writer_location_watermark(
        &self,
        location: Location,
    ) -> Result<Location, QmdbError> {
        let namespace = AuthenticatedBackendNamespace::Immutable;
        let session = self.client.create_session();
        let latest = read_latest_auth_watermark(&session, namespace).await?;
        if let Some(watermark) = latest {
            if watermark >= location {
                return Ok(watermark);
            }
        }
        require_auth_uploaded_boundary(&session, namespace, location).await?;
        let previous_ops_size = match latest {
            Some(previous) => mmr_size_for_watermark(previous)?,
            None => Position::new(0),
        };
        let delta_start = latest.map_or(Location::new(0), |watermark| watermark + 1);
        let end_exclusive = location
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        let encoded =
            load_auth_operation_bytes_range(&session, namespace, delta_start, end_exclusive)
                .await?;
        let mut rows = Vec::new();
        append_auth_nodes_incrementally(
            &session,
            namespace,
            previous_ops_size,
            &encoded,
            &mut rows,
        )
        .await?;
        rows.push((encode_auth_watermark_key(namespace, location), Vec::new()));
        let refs = rows
            .iter()
            .map(|(key, value)| (key, value.as_slice()))
            .collect::<Vec<_>>();
        self.client.put(&refs).await?;
        self.sync_after_ingest().await?;
        let visible = self.writer_location_watermark().await?;
        if visible < Some(location) {
            return Err(QmdbError::CorruptData(format!(
                "immutable watermark publish did not become query-visible: requested={location}, visible={visible:?}"
            )));
        }
        Ok(location)
    }

    pub async fn root_at(&self, watermark: Location) -> Result<QmdbDigest, QmdbError> {
        let namespace = AuthenticatedBackendNamespace::Immutable;
        let session = self.client.create_session();
        require_published_auth_watermark(&session, namespace, watermark).await?;
        compute_auth_root(&session, namespace, watermark).await
    }

    pub async fn get_at(
        &self,
        key: &K,
        watermark: Location,
    ) -> Result<Option<TypedVersionedValue<K, V>>, QmdbError> {
        let namespace = AuthenticatedBackendNamespace::Immutable;
        let session = self.client.create_session();
        require_published_auth_watermark(&session, namespace, watermark).await?;
        let Some((row_key, row_value)) =
            load_latest_auth_immutable_update_row(&session, watermark, key.as_ref()).await?
        else {
            return Ok(None);
        };
        let location = decode_auth_immutable_update_location(&row_key)?;
        let decoded = decode_update_row(row_value.as_ref())?;
        if decoded.key != key.as_ref() {
            return Err(QmdbError::CorruptData(format!(
                "authenticated immutable update row key mismatch at location {location}"
            )));
        }
        let operation = load_auth_operation_at::<ImmutableOperation<K, V>>(
            &session,
            namespace,
            location,
            &self.value_cfg,
        )
        .await?;
        match operation {
            ImmutableOperation::Set(operation_key, value) if operation_key == *key => {
                Ok(Some(TypedVersionedValue {
                    key: operation_key,
                    location,
                    value: Some(value),
                }))
            }
            ImmutableOperation::Set(_, _) => Err(QmdbError::CorruptData(format!(
                "authenticated immutable update row does not match operation key at location {location}"
            ))),
            ImmutableOperation::Commit(_) => Err(QmdbError::CorruptData(format!(
                "authenticated immutable update row points at commit location {location}"
            ))),
        }
    }

    pub async fn operation_range_proof(
        &self,
        watermark: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<AuthenticatedOperationRangeProof<ImmutableOperation<K, V>>, QmdbError> {
        if max_locations == 0 {
            return Err(QmdbError::InvalidRangeLength);
        }
        let namespace = AuthenticatedBackendNamespace::Immutable;
        let session = self.client.create_session();
        require_published_auth_watermark(&session, namespace, watermark).await?;
        let count = watermark
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        if start_location >= count {
            return Err(QmdbError::RangeStartOutOfBounds {
                start: start_location,
                count,
            });
        }
        let end = start_location
            .saturating_add(max_locations as u64)
            .min(count);
        let storage = AuthKvMmrStorage {
            session: &session,
            namespace,
            mmr_size: mmr_size_for_watermark(watermark)?,
        };
        let proof = verification::range_proof(&storage, start_location..end)
            .await
            .map_err(|e| QmdbError::CommonwareMmr(e.to_string()))?;
        Ok(AuthenticatedOperationRangeProof {
            watermark,
            root: compute_auth_root(&session, namespace, watermark).await?,
            start_location,
            proof,
            operations: load_auth_operation_range::<ImmutableOperation<K, V>>(
                &session,
                namespace,
                start_location,
                end,
                &self.value_cfg,
            )
            .await?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct KeylessClient<V: Codec + Send + Sync> {
    client: StoreClient,
    value_cfg: V::Cfg,
    query_visible_sequence: Option<Arc<AtomicU64>>,
}

impl<V> KeylessClient<V>
where
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    KeylessOperation<V>: Encode + Decode<Cfg = V::Cfg> + Clone,
{
    pub fn new(url: &str, value_cfg: V::Cfg) -> Self {
        Self::from_client(StoreClient::new(url), value_cfg)
    }

    pub fn from_client(client: StoreClient, value_cfg: V::Cfg) -> Self {
        Self {
            client,
            value_cfg,
            query_visible_sequence: None,
        }
    }

    /// When set, blocks after each ingest until the query worker advances `visible_sequence`
    /// to at least the client's observed consistency token (test harness synchronization).
    pub fn with_query_visible_sequence(mut self, seq: Arc<AtomicU64>) -> Self {
        self.query_visible_sequence = Some(seq);
        self
    }

    pub fn inner(&self) -> &StoreClient {
        &self.client
    }

    pub fn sequence_number(&self) -> u64 {
        self.client.sequence_number()
    }

    async fn sync_after_ingest(&self) -> Result<(), QmdbError> {
        let token = self.client.sequence_number();
        wait_until_query_visible_sequence(self.query_visible_sequence.as_ref(), token).await
    }

    pub async fn writer_location_watermark(&self) -> Result<Option<Location>, QmdbError> {
        retry_transient_post_ingest_query(|| {
            let session = self.client.create_session();
            async move {
                read_latest_auth_watermark(&session, AuthenticatedBackendNamespace::Keyless).await
            }
        })
        .await
    }

    pub async fn upload_operations(
        &self,
        latest_location: Location,
        operations: &[KeylessOperation<V>],
    ) -> Result<UploadReceipt, QmdbError> {
        if operations.is_empty() {
            return Err(QmdbError::EmptyBatch);
        }
        let namespace = AuthenticatedBackendNamespace::Keyless;
        if self
            .client
            .get(&encode_auth_presence_key(namespace, latest_location))
            .await?
            .is_some()
        {
            return Err(QmdbError::DuplicateBatchWatermark { latest_location });
        }
        let encoded = operations
            .iter()
            .map(|operation| {
                let bytes = operation.encode().to_vec();
                ensure_encoded_value_size(bytes.len())?;
                Ok(bytes)
            })
            .collect::<Result<Vec<_>, QmdbError>>()?;
        let (_, rows) = build_auth_upload_rows(namespace, latest_location, &encoded)?;
        let refs = rows
            .iter()
            .map(|(key, value)| (key, value.as_slice()))
            .collect::<Vec<_>>();
        self.client.put(&refs).await?;
        self.sync_after_ingest().await?;

        Ok(UploadReceipt {
            latest_location,
            operation_count: Location::new(operations.len() as u64),
            keyed_operation_count: 0,
            writer_location_watermark: self.writer_location_watermark().await?,
            sequence_number: self.client.sequence_number(),
        })
    }

    pub async fn publish_writer_location_watermark(
        &self,
        location: Location,
    ) -> Result<Location, QmdbError> {
        let namespace = AuthenticatedBackendNamespace::Keyless;
        let session = self.client.create_session();
        let latest = read_latest_auth_watermark(&session, namespace).await?;
        if let Some(watermark) = latest {
            if watermark >= location {
                return Ok(watermark);
            }
        }
        require_auth_uploaded_boundary(&session, namespace, location).await?;
        let previous_ops_size = match latest {
            Some(previous) => mmr_size_for_watermark(previous)?,
            None => Position::new(0),
        };
        let delta_start = latest.map_or(Location::new(0), |watermark| watermark + 1);
        let end_exclusive = location
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        let encoded =
            load_auth_operation_bytes_range(&session, namespace, delta_start, end_exclusive)
                .await?;
        let mut rows = Vec::new();
        append_auth_nodes_incrementally(
            &session,
            namespace,
            previous_ops_size,
            &encoded,
            &mut rows,
        )
        .await?;
        rows.push((encode_auth_watermark_key(namespace, location), Vec::new()));
        let refs = rows
            .iter()
            .map(|(key, value)| (key, value.as_slice()))
            .collect::<Vec<_>>();
        self.client.put(&refs).await?;
        self.sync_after_ingest().await?;
        let visible = self.writer_location_watermark().await?;
        if visible < Some(location) {
            return Err(QmdbError::CorruptData(format!(
                "keyless watermark publish did not become query-visible: requested={location}, visible={visible:?}"
            )));
        }
        Ok(location)
    }

    pub async fn root_at(&self, watermark: Location) -> Result<QmdbDigest, QmdbError> {
        let namespace = AuthenticatedBackendNamespace::Keyless;
        let session = self.client.create_session();
        require_published_auth_watermark(&session, namespace, watermark).await?;
        compute_auth_root(&session, namespace, watermark).await
    }

    pub async fn get_at(
        &self,
        location: Location,
        watermark: Location,
    ) -> Result<Option<V>, QmdbError> {
        let namespace = AuthenticatedBackendNamespace::Keyless;
        let session = self.client.create_session();
        require_published_auth_watermark(&session, namespace, watermark).await?;
        let count = watermark
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        if location >= count {
            return Err(QmdbError::RangeStartOutOfBounds {
                start: location,
                count,
            });
        }
        let operation = load_auth_operation_at::<KeylessOperation<V>>(
            &session,
            namespace,
            location,
            &self.value_cfg,
        )
        .await?;
        Ok(operation.into_value())
    }

    pub async fn operation_range_proof(
        &self,
        watermark: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<AuthenticatedOperationRangeProof<KeylessOperation<V>>, QmdbError> {
        if max_locations == 0 {
            return Err(QmdbError::InvalidRangeLength);
        }
        let namespace = AuthenticatedBackendNamespace::Keyless;
        let session = self.client.create_session();
        require_published_auth_watermark(&session, namespace, watermark).await?;
        let count = watermark
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        if start_location >= count {
            return Err(QmdbError::RangeStartOutOfBounds {
                start: start_location,
                count,
            });
        }
        let end = start_location
            .saturating_add(max_locations as u64)
            .min(count);
        let storage = AuthKvMmrStorage {
            session: &session,
            namespace,
            mmr_size: mmr_size_for_watermark(watermark)?,
        };
        let proof = verification::range_proof(&storage, start_location..end)
            .await
            .map_err(|e| QmdbError::CommonwareMmr(e.to_string()))?;
        Ok(AuthenticatedOperationRangeProof {
            watermark,
            root: compute_auth_root(&session, namespace, watermark).await?,
            start_location,
            proof,
            operations: load_auth_operation_range::<KeylessOperation<V>>(
                &session,
                namespace,
                start_location,
                end,
                &self.value_cfg,
            )
            .await?,
        })
    }
}

struct AuthKvMmrStorage<'a> {
    session: &'a SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
    mmr_size: Position,
}

impl MmrStorage<QmdbDigest> for AuthKvMmrStorage<'_> {
    async fn size(&self) -> Position {
        self.mmr_size
    }

    async fn get_node(&self, position: Position) -> Result<Option<QmdbDigest>, mmr::Error> {
        let key = encode_auth_node_key(self.namespace, position);
        let bytes = self
            .session
            .get(&key)
            .await
            .map_err(|_| mmr::Error::DataCorrupted("exoware-qmdb node fetch failed"))?;
        let Some(bytes) = bytes else {
            return Ok(None);
        };
        if bytes.len() != DIGEST_LEN {
            return Err(mmr::Error::DataCorrupted(
                "exoware-qmdb node digest has invalid length",
            ));
        }
        let mut digest = [0u8; DIGEST_LEN];
        digest.copy_from_slice(bytes.as_ref());
        Ok(Some(QmdbDigest::from(digest)))
    }
}

async fn read_latest_auth_watermark(
    session: &SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
) -> Result<Option<Location>, QmdbError> {
    let (start, end) = auth_namespace_bounds(auth_watermark_codec(), namespace);
    let rows = session
        .range_with_mode(&start, &end, 1, RangeMode::Reverse)
        .await?;
    match rows.into_iter().next() {
        Some((key, _)) => Ok(Some(decode_auth_watermark_location(namespace, &key)?)),
        None => Ok(None),
    }
}

async fn require_published_auth_watermark(
    session: &SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
    watermark: Location,
) -> Result<(), QmdbError> {
    let available = read_latest_auth_watermark(session, namespace)
        .await?
        .unwrap_or(Location::new(0));
    let watermark_exists = session
        .get(&encode_auth_watermark_key(namespace, watermark))
        .await?
        .is_some();
    if available < watermark
        || (!watermark_exists && available == Location::new(0) && watermark == Location::new(0))
    {
        return Err(QmdbError::WatermarkTooLow {
            requested: watermark,
            available,
        });
    }
    Ok(())
}

async fn require_auth_uploaded_boundary(
    session: &SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
    location: Location,
) -> Result<(), QmdbError> {
    if session
        .get(&encode_auth_presence_key(namespace, location))
        .await?
        .is_some()
    {
        Ok(())
    } else {
        Err(QmdbError::CorruptData(format!(
            "authenticated backend upload boundary missing at {location}"
        )))
    }
}

fn build_auth_upload_rows(
    namespace: AuthenticatedBackendNamespace,
    latest_location: Location,
    encoded_operations: &[Vec<u8>],
) -> Result<(u32, AuthRows), QmdbError> {
    let mut rows = Vec::<(Key, Vec<u8>)>::with_capacity(encoded_operations.len() + 1);
    let count_u64 = encoded_operations.len() as u64;
    let Some(start_location) = latest_location
        .checked_add(1)
        .and_then(|next| next.checked_sub(count_u64))
    else {
        return Err(QmdbError::InvalidLocationRange {
            start_location: Location::new(0),
            latest_location,
            count: encoded_operations.len(),
        });
    };
    for (index, encoded) in encoded_operations.iter().enumerate() {
        ensure_encoded_value_size(encoded.len())?;
        rows.push((
            encode_auth_operation_key(namespace, start_location + index as u64),
            encoded.clone(),
        ));
    }
    rows.push((
        encode_auth_presence_key(namespace, latest_location),
        Vec::new(),
    ));
    let operation_count = u32::try_from(encoded_operations.len()).map_err(|_| {
        QmdbError::CorruptData("authenticated operation count overflow".to_string())
    })?;
    Ok((operation_count, rows))
}

type AuthRows = Vec<(Key, Vec<u8>)>;

async fn append_auth_nodes_incrementally(
    session: &SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
    previous_ops_size: Position,
    delta_operations: &[Vec<u8>],
    rows: &mut Vec<(Key, Vec<u8>)>,
) -> Result<(Position, QmdbDigest), QmdbError> {
    let mut peaks = Vec::<(Position, u32, QmdbDigest)>::new();
    for (peak_pos, height) in PeakIterator::new(previous_ops_size) {
        let Some(bytes) = session
            .get(&encode_auth_node_key(namespace, peak_pos))
            .await?
        else {
            return Err(QmdbError::CorruptData(format!(
                "missing authenticated peak node at position {peak_pos}"
            )));
        };
        peaks.push((
            peak_pos,
            height,
            decode_digest(
                bytes.as_ref(),
                format!("authenticated peak node at position {peak_pos}"),
            )?,
        ));
    }

    let mut current_size = previous_ops_size;
    let mut hasher = StandardHasher::<Sha256>::new();
    for encoded in delta_operations {
        let leaf_pos = current_size;
        let leaf_digest = mmr::hasher::Hasher::leaf_digest(&mut hasher, leaf_pos, encoded);
        rows.push((
            encode_auth_node_key(namespace, leaf_pos),
            leaf_digest.as_ref().to_vec(),
        ));
        current_size = Position::new(*current_size + 1);

        let mut carry_pos = leaf_pos;
        let mut carry_digest = leaf_digest;
        let mut carry_height = 0u32;
        while peaks
            .last()
            .is_some_and(|(_, height, _)| *height == carry_height)
        {
            let (_, _, left_digest) = peaks.pop().expect("peak exists");
            let parent_pos = current_size;
            let parent_digest = mmr::hasher::Hasher::node_digest(
                &mut hasher,
                parent_pos,
                &left_digest,
                &carry_digest,
            );
            rows.push((
                encode_auth_node_key(namespace, parent_pos),
                parent_digest.as_ref().to_vec(),
            ));
            current_size = Position::new(*current_size + 1);
            carry_pos = parent_pos;
            carry_digest = parent_digest;
            carry_height += 1;
        }
        peaks.push((carry_pos, carry_height, carry_digest));
    }

    let leaves = Location::try_from(current_size)
        .map_err(|e| QmdbError::CorruptData(format!("invalid authenticated ops size: {e}")))?;
    let root = mmr::hasher::Hasher::root(
        &mut hasher,
        leaves,
        peaks.iter().map(|(_, _, digest)| digest),
    );
    Ok((current_size, root))
}

async fn compute_auth_root(
    session: &SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
    watermark: Location,
) -> Result<QmdbDigest, QmdbError> {
    let size = mmr_size_for_watermark(watermark)?;
    let leaves = watermark
        .checked_add(1)
        .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
    let mut peaks = Vec::new();
    for (peak_pos, _) in PeakIterator::new(size) {
        let Some(bytes) = session
            .get(&encode_auth_node_key(namespace, peak_pos))
            .await?
        else {
            return Err(QmdbError::CorruptData(format!(
                "missing authenticated MMR peak node at position {peak_pos}"
            )));
        };
        peaks.push(decode_digest(
            bytes.as_ref(),
            format!("authenticated peak node at position {peak_pos}"),
        )?);
    }
    let mut hasher = StandardHasher::<Sha256>::new();
    Ok(mmr::hasher::Hasher::root(&mut hasher, leaves, peaks.iter()))
}

async fn load_auth_operation_at<Op>(
    session: &SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
    location: Location,
    cfg: &Op::Cfg,
) -> Result<Op, QmdbError>
where
    Op: Decode,
{
    let Some(bytes) = session
        .get(&encode_auth_operation_key(namespace, location))
        .await?
    else {
        return Err(QmdbError::CorruptData(format!(
            "missing authenticated operation row at location {location}"
        )));
    };
    Op::decode_cfg(bytes.as_ref(), cfg).map_err(|e| {
        QmdbError::CorruptData(format!(
            "failed to decode authenticated operation at location {location}: {e}"
        ))
    })
}

async fn load_auth_operation_bytes_range(
    session: &SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
    start_location: Location,
    end_location_exclusive: Location,
) -> Result<Vec<Vec<u8>>, QmdbError> {
    if start_location >= end_location_exclusive {
        return Ok(Vec::new());
    }
    let start = encode_auth_operation_key(namespace, start_location);
    let end = encode_auth_operation_key(namespace, end_location_exclusive - 1);
    let rows = session
        .range(
            &start,
            &end,
            (*end_location_exclusive - *start_location) as usize,
        )
        .await?;
    if rows.len() != (*end_location_exclusive - *start_location) as usize {
        return Err(QmdbError::CorruptData(format!(
            "expected {} authenticated operation rows in range [{start_location}, {end_location_exclusive}), found {}",
            *end_location_exclusive - *start_location,
            rows.len()
        )));
    }
    let mut operations = Vec::with_capacity(rows.len());
    for (offset, (key, value)) in rows.into_iter().enumerate() {
        let expected_location = start_location + offset as u64;
        let location = decode_auth_operation_location(namespace, &key)?;
        if location != expected_location {
            return Err(QmdbError::CorruptData(format!(
                "authenticated operation row order mismatch: expected {expected_location}, got {location}"
            )));
        }
        operations.push(value.to_vec());
    }
    Ok(operations)
}

async fn load_auth_operation_range<Op>(
    session: &SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
    start_location: Location,
    end_location_exclusive: Location,
    cfg: &Op::Cfg,
) -> Result<Vec<Op>, QmdbError>
where
    Op: Decode,
{
    load_auth_operation_bytes_range(session, namespace, start_location, end_location_exclusive)
        .await?
        .into_iter()
        .enumerate()
        .map(|(offset, bytes)| {
            let location = start_location + offset as u64;
            Op::decode_cfg(bytes.as_slice(), cfg).map_err(|e| {
                QmdbError::CorruptData(format!(
                    "failed to decode authenticated operation at location {location}: {e}"
                ))
            })
        })
        .collect()
}

fn auth_operation_codec() -> KeyCodec {
    KeyCodec::new(RESERVED_BITS, AUTH_OP_FAMILY).expect("static authenticated op codec")
}

fn auth_node_codec() -> KeyCodec {
    KeyCodec::new(RESERVED_BITS, AUTH_NODE_FAMILY).expect("static authenticated node codec")
}

fn auth_watermark_codec() -> KeyCodec {
    KeyCodec::new(RESERVED_BITS, AUTH_WATERMARK_FAMILY)
        .expect("static authenticated watermark codec")
}

fn auth_presence_codec() -> KeyCodec {
    KeyCodec::new(RESERVED_BITS, AUTH_INDEX_FAMILY).expect("static authenticated presence codec")
}

fn auth_immutable_update_codec() -> KeyCodec {
    KeyCodec::new(RESERVED_BITS, AUTH_IMMUTABLE_UPDATE_FAMILY)
        .expect("static authenticated immutable update codec")
}

fn auth_namespace_bounds(codec: KeyCodec, namespace: AuthenticatedBackendNamespace) -> (Key, Key) {
    let tail_len = 8usize;
    let total_len = codec.min_key_len_for_payload(AUTH_NAMESPACE_LEN + tail_len);
    let mut start = codec
        .new_key_with_len(total_len)
        .expect("authenticated namespace start key length should fit");
    let mut end = codec
        .new_key_with_len(total_len)
        .expect("authenticated namespace end key length should fit");
    codec
        .write_payload(&mut start, 0, &[namespace.tag()])
        .expect("authenticated namespace tag fits");
    codec
        .write_payload(&mut end, 0, &[namespace.tag()])
        .expect("authenticated namespace tag fits");
    codec
        .fill_payload(&mut start, AUTH_NAMESPACE_LEN, tail_len, 0)
        .expect("authenticated start tail fits");
    codec
        .fill_payload(&mut end, AUTH_NAMESPACE_LEN, tail_len, 0xFF)
        .expect("authenticated end tail fits");
    (start.freeze(), end.freeze())
}

fn ensure_auth_namespace(
    codec: KeyCodec,
    namespace: AuthenticatedBackendNamespace,
    key: &Key,
    label: &str,
) -> Result<(), QmdbError> {
    if !codec.matches(key) {
        return Err(QmdbError::CorruptData(format!(
            "{label} key prefix mismatch"
        )));
    }
    let actual = codec
        .read_payload_exact::<1>(key, 0)
        .map_err(|e| QmdbError::CorruptData(format!("cannot decode {label} namespace: {e}")))?[0];
    if actual != namespace.tag() {
        return Err(QmdbError::CorruptData(format!(
            "{label} namespace mismatch: expected {}, got {actual}",
            namespace.tag()
        )));
    }
    Ok(())
}

fn encode_auth_operation_key(namespace: AuthenticatedBackendNamespace, location: Location) -> Key {
    let codec = auth_operation_codec();
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(AUTH_NAMESPACE_LEN + 8))
        .expect("authenticated operation key length should fit");
    codec
        .write_payload(&mut key, 0, &[namespace.tag()])
        .expect("authenticated operation namespace fits");
    codec
        .write_payload(
            &mut key,
            AUTH_NAMESPACE_LEN,
            &location.as_u64().to_be_bytes(),
        )
        .expect("authenticated operation location fits");
    key.freeze()
}

fn encode_auth_node_key(namespace: AuthenticatedBackendNamespace, position: Position) -> Key {
    let codec = auth_node_codec();
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(AUTH_NAMESPACE_LEN + 8))
        .expect("authenticated node key length should fit");
    codec
        .write_payload(&mut key, 0, &[namespace.tag()])
        .expect("authenticated node namespace fits");
    codec
        .write_payload(
            &mut key,
            AUTH_NAMESPACE_LEN,
            &position.as_u64().to_be_bytes(),
        )
        .expect("authenticated node position fits");
    key.freeze()
}

fn encode_auth_watermark_key(namespace: AuthenticatedBackendNamespace, location: Location) -> Key {
    let codec = auth_watermark_codec();
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(AUTH_NAMESPACE_LEN + 8))
        .expect("authenticated watermark key length should fit");
    codec
        .write_payload(&mut key, 0, &[namespace.tag()])
        .expect("authenticated watermark namespace fits");
    codec
        .write_payload(
            &mut key,
            AUTH_NAMESPACE_LEN,
            &location.as_u64().to_be_bytes(),
        )
        .expect("authenticated watermark fits");
    key.freeze()
}

fn encode_auth_presence_key(namespace: AuthenticatedBackendNamespace, location: Location) -> Key {
    let codec = auth_presence_codec();
    let mut key = codec
        .new_key_with_len(codec.min_key_len_for_payload(AUTH_NAMESPACE_LEN + 8))
        .expect("authenticated presence key length should fit");
    codec
        .write_payload(&mut key, 0, &[namespace.tag()])
        .expect("authenticated presence namespace fits");
    codec
        .write_payload(
            &mut key,
            AUTH_NAMESPACE_LEN,
            &location.as_u64().to_be_bytes(),
        )
        .expect("authenticated presence location fits");
    key.freeze()
}

fn encode_auth_immutable_update_key(raw_key: &[u8], location: Location) -> Result<Key, QmdbError> {
    let codec = auth_immutable_update_codec();
    let ordered_key = encode_ordered_update_payload(codec, raw_key, UPDATE_VERSION_LEN)?;
    let total_len = codec.min_key_len_for_payload(ordered_key.len() + UPDATE_VERSION_LEN);
    let mut key = codec
        .new_key_with_len(total_len)
        .expect("authenticated immutable update key length should fit");
    codec
        .write_payload(&mut key, 0, &ordered_key)
        .expect("authenticated immutable update key bytes fit");
    codec
        .write_payload(
            &mut key,
            ordered_key.len(),
            &location.as_u64().to_be_bytes(),
        )
        .expect("authenticated immutable update location fits");
    Ok(key.freeze())
}

fn decode_auth_immutable_update_location(key: &Key) -> Result<Location, QmdbError> {
    let codec = auth_immutable_update_codec();
    if !codec.matches(key) {
        return Err(QmdbError::CorruptData(
            "authenticated immutable update key prefix mismatch".to_string(),
        ));
    }
    let payload_capacity = codec.payload_capacity_bytes_for_key_len(key.len());
    if payload_capacity < ORDERED_KEY_TERMINATOR_LEN + UPDATE_VERSION_LEN {
        return Err(QmdbError::CorruptData(
            "authenticated immutable update payload shorter than minimum layout".to_string(),
        ));
    }
    let ordered_len = payload_capacity - UPDATE_VERSION_LEN;
    let ordered_key = codec.read_payload(key, 0, ordered_len).map_err(|e| {
        QmdbError::CorruptData(format!(
            "cannot decode authenticated immutable update key bytes: {e}"
        ))
    })?;
    validate_ordered_key_bytes(&ordered_key, "authenticated immutable update key")?;
    let bytes = codec
        .read_payload_exact::<8>(key, ordered_len)
        .map_err(|e| {
            QmdbError::CorruptData(format!(
                "cannot decode authenticated immutable update location: {e}"
            ))
        })?;
    Ok(Location::new(u64::from_be_bytes(bytes)))
}

async fn load_latest_auth_immutable_update_row(
    session: &SerializableReadSession,
    watermark: Location,
    key: &[u8],
) -> Result<Option<(Key, Vec<u8>)>, QmdbError> {
    let start = encode_auth_immutable_update_key(key, Location::new(0))?;
    let end = encode_auth_immutable_update_key(key, watermark)?;
    let rows = session
        .range_with_mode(&start, &end, 1, RangeMode::Reverse)
        .await?;
    Ok(rows
        .into_iter()
        .next()
        .map(|(key, value)| (key, value.to_vec())))
}

fn build_auth_immutable_upload_rows<K, V>(
    latest_location: Location,
    operations: &[ImmutableOperation<K, V>],
) -> Result<(u32, AuthRows), QmdbError>
where
    K: Array + AsRef<[u8]>,
    V: Codec + Clone + Send + Sync,
{
    let count_u64 = operations.len() as u64;
    let Some(start_location) = latest_location
        .checked_add(1)
        .and_then(|next| next.checked_sub(count_u64))
    else {
        return Err(QmdbError::InvalidLocationRange {
            start_location: Location::new(0),
            latest_location,
            count: operations.len(),
        });
    };
    let mut rows = Vec::<(Key, Vec<u8>)>::with_capacity(operations.len() * 2 + 1);
    let mut keyed_operation_count = 0u32;
    for (index, operation) in operations.iter().enumerate() {
        let location = start_location + index as u64;
        let encoded = operation.encode().to_vec();
        ensure_encoded_value_size(encoded.len())?;
        rows.push((
            encode_auth_operation_key(AuthenticatedBackendNamespace::Immutable, location),
            encoded,
        ));
        if let ImmutableOperation::Set(key, value) = operation {
            keyed_operation_count += 1;
            rows.push((
                encode_auth_immutable_update_key(key.as_ref(), location)?,
                encode_update_row(key.as_ref(), Some(value.encode().as_ref()))?,
            ));
        }
    }
    rows.push((
        encode_auth_presence_key(AuthenticatedBackendNamespace::Immutable, latest_location),
        Vec::new(),
    ));
    Ok((keyed_operation_count, rows))
}

fn decode_auth_operation_location(
    namespace: AuthenticatedBackendNamespace,
    key: &Key,
) -> Result<Location, QmdbError> {
    let codec = auth_operation_codec();
    ensure_auth_namespace(codec, namespace, key, "authenticated operation")?;
    let bytes = codec
        .read_payload_exact::<8>(key, AUTH_NAMESPACE_LEN)
        .map_err(|e| {
            QmdbError::CorruptData(format!(
                "cannot decode authenticated operation location: {e}"
            ))
        })?;
    Ok(Location::new(u64::from_be_bytes(bytes)))
}

fn decode_auth_watermark_location(
    namespace: AuthenticatedBackendNamespace,
    key: &Key,
) -> Result<Location, QmdbError> {
    let codec = auth_watermark_codec();
    ensure_auth_namespace(codec, namespace, key, "authenticated watermark")?;
    let bytes = codec
        .read_payload_exact::<8>(key, AUTH_NAMESPACE_LEN)
        .map_err(|e| {
            QmdbError::CorruptData(format!(
                "cannot decode authenticated watermark location: {e}"
            ))
        })?;
    Ok(Location::new(u64::from_be_bytes(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, tokio as cw_tokio, Metrics as _, Runner as _,
    };
    use commonware_storage::{
        mmr::hasher::Hasher as _,
        qmdb::{
            current::{ordered::variable::Db as LocalQmdbDb, VariableConfig},
            immutable::{Config as ImmutableConfig, Immutable as LocalImmutableDb},
            keyless::{Config as KeylessConfig, Keyless as LocalKeylessDb},
            operation::Operation as _,
            store::LogStore as _,
        },
        translator::TwoCap,
    };
    use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
    use rand::rngs::StdRng;
    use rand::{seq::SliceRandom, Rng, SeedableRng};
    use std::collections::{BTreeMap, BTreeSet};
    use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
    use std::sync::{atomic::AtomicU64, Arc};

    type LocalVariableQmdb =
        LocalQmdbDb<cw_tokio::Context, Vec<u8>, Vec<u8>, Sha256, TwoCap, BITMAP_CHUNK_BYTES>;
    type LocalImmutable =
        LocalImmutableDb<deterministic::Context, FixedBytes<32>, Vec<u8>, Sha256, TwoCap>;
    type LocalKeyless = LocalKeylessDb<deterministic::Context, Vec<u8>, Sha256>;

    struct TestStoreBridgeServers {
        ingest_url: String,
        query_url: String,
        visible_sequence: Arc<AtomicU64>,
    }

    impl TestStoreBridgeServers {
        fn client(&self) -> StoreClient {
            StoreClient::with_split_urls(&self.query_url, &self.ingest_url, &self.query_url)
        }

        fn qmdb_client(&self) -> OrderedClient {
            OrderedClient::from_client(self.client())
                .with_query_visible_sequence(self.visible_sequence.clone())
        }

        fn immutable_client(&self) -> ImmutableClient<FixedBytes<32>, Vec<u8>> {
            ImmutableClient::from_client(self.client(), ((0..=10000).into(), ()))
                .with_query_visible_sequence(self.visible_sequence.clone())
        }

        fn keyless_client(&self) -> KeylessClient<Vec<u8>> {
            KeylessClient::from_client(self.client(), ((0..=10000).into(), ()))
                .with_query_visible_sequence(self.visible_sequence.clone())
        }
    }

    async fn spawn_test_server() -> TestStoreBridgeServers {
        spawn_test_server_with_query_tick(Duration::from_millis(1)).await
    }

    async fn spawn_test_server_with_query_tick(_query_tick: Duration) -> TestStoreBridgeServers {
        use axum::{routing::get, Router};
        use exoware_server::{connect_stack, AppState};
        use exoware_simulator::RocksStore;
        use tempfile::tempdir;

        let dir = tempdir().expect("tempdir");
        let visible_for_clients = Arc::new(AtomicU64::new(0));
        let db = RocksStore::open_with_observer(dir.path(), Some(visible_for_clients.clone()))
            .expect("rocksdb");
        let state = AppState::new(Arc::new(db));
        let connect = connect_stack(state);
        let app = Router::new()
            .route("/health", get(|| async { "ok" }))
            .fallback_service(connect);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        for _ in 0..200 {
            if reqwest::get(format!("{url}/health"))
                .await
                .ok()
                .is_some_and(|resp| resp.status().is_success())
            {
                return TestStoreBridgeServers {
                    ingest_url: url.clone(),
                    query_url: url,
                    visible_sequence: visible_for_clients,
                };
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        panic!("test store simulator did not become ready");
    }

    async fn init_local_qmdb(context: cw_tokio::Context, label: &'static str) -> LocalVariableQmdb {
        let cfg = VariableConfig {
            mmr_journal_partition: "mmr-journal".to_string(),
            mmr_items_per_blob: NonZeroU64::new(8).expect("non-zero"),
            mmr_write_buffer: NonZeroUsize::new(1024).expect("non-zero"),
            mmr_metadata_partition: "mmr-metadata".to_string(),
            log_partition: "log".to_string(),
            log_write_buffer: NonZeroUsize::new(1024).expect("non-zero"),
            log_compression: None,
            log_codec_config: (
                ((0..=MAX_OPERATION_SIZE).into(), ()),
                ((0..=MAX_OPERATION_SIZE).into(), ()),
            ),
            log_items_per_blob: NonZeroU64::new(8).expect("non-zero"),
            grafted_mmr_metadata_partition: "grafted-metadata".to_string(),
            translator: TwoCap,
            thread_pool: None,
            page_cache: CacheRef::from_pooler(
                &context,
                NonZeroU16::new(256).expect("non-zero"),
                NonZeroUsize::new(16).expect("non-zero"),
            ),
        };

        LocalVariableQmdb::init(context.with_label(label), cfg)
            .await
            .expect("init local qmdb")
    }

    fn random_test_key(key_id: u32) -> Vec<u8> {
        format!("key-{key_id:06}").into_bytes()
    }

    fn missing_test_key(sample_idx: usize) -> Vec<u8> {
        format!("missing-{sample_idx:06}").into_bytes()
    }

    fn random_test_value(rng: &mut StdRng) -> Vec<u8> {
        let len = rng.gen_range(4..=32);
        (0..len)
            .map(|_| b'a' + rng.gen_range(0..26))
            .collect::<Vec<_>>()
    }

    fn immutable_key(byte: u8) -> FixedBytes<32> {
        FixedBytes::new([byte; 32])
    }

    fn immutable_config(
        context: &deterministic::Context,
        suffix: &str,
    ) -> ImmutableConfig<TwoCap, (RangeCfg<usize>, ())> {
        ImmutableConfig {
            mmr_journal_partition: format!("immutable-mmr-journal-{suffix}"),
            mmr_metadata_partition: format!("immutable-mmr-metadata-{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("immutable-log-{suffix}"),
            log_items_per_section: NZU64!(5),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            log_write_buffer: NZUsize!(1024),
            translator: TwoCap,
            thread_pool: None,
            page_cache: CacheRef::from_pooler(context, NZU16!(77), NZUsize!(9)),
        }
    }

    fn keyless_config(
        context: &deterministic::Context,
        suffix: &str,
    ) -> KeylessConfig<(RangeCfg<usize>, ())> {
        KeylessConfig {
            mmr_journal_partition: format!("keyless-mmr-journal-{suffix}"),
            mmr_metadata_partition: format!("keyless-mmr-metadata-{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("keyless-log-{suffix}"),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: ((0..=10000).into(), ()),
            log_items_per_section: NZU64!(7),
            thread_pool: None,
            page_cache: CacheRef::from_pooler(context, NZU16!(101), NZUsize!(11)),
        }
    }

    #[derive(Clone, Debug)]
    struct LocalImmutableReference {
        latest_location: Location,
        root: QmdbDigest,
        proof: BatchProof,
        operations: Vec<ImmutableOperation<FixedBytes<32>, Vec<u8>>>,
        queried_key: FixedBytes<32>,
        queried_value: Vec<u8>,
    }

    async fn build_local_immutable_reference() -> LocalImmutableReference {
        tokio::task::spawn_blocking(|| {
            deterministic::Runner::default().start(|context| async move {
                let mut db: LocalImmutable = LocalImmutable::init(
                    context.with_label("immutable_db"),
                    immutable_config(&context, "parity"),
                )
                .await
                .expect("init local immutable");

                let key_a = immutable_key(0x11);
                let key_b = immutable_key(0x22);
                let value_a = b"alpha".to_vec();
                let value_b = b"beta".to_vec();

                let finalized = {
                    let mut batch = db.new_batch();
                    batch.set(key_a, value_a);
                    batch.set(key_b.clone(), value_b.clone());
                    batch.merkleize(None::<Vec<u8>>).finalize()
                };
                db.apply_batch(finalized)
                    .await
                    .expect("apply immutable batch1");

                let latest_location = db.bounds().await.end - 1;
                let proof_count = NonZeroU64::new(*latest_location + 1).expect("non-zero");
                let (proof, operations) = db
                    .historical_proof(latest_location + 1, Location::new(0), proof_count)
                    .await
                    .expect("immutable historical proof");
                let root = db.root();
                db.destroy().await.expect("destroy immutable db");

                LocalImmutableReference {
                    latest_location,
                    root,
                    proof,
                    operations,
                    queried_key: key_b,
                    queried_value: value_b,
                }
            })
        })
        .await
        .expect("join local immutable builder")
    }

    #[derive(Clone, Debug)]
    struct LocalKeylessReference {
        latest_location: Location,
        root: QmdbDigest,
        proof: BatchProof,
        operations: Vec<KeylessOperation<Vec<u8>>>,
        queried_location: Location,
        queried_value: Vec<u8>,
    }

    async fn build_local_keyless_reference() -> LocalKeylessReference {
        tokio::task::spawn_blocking(|| {
            deterministic::Runner::default().start(|context| async move {
                let mut db: LocalKeyless = LocalKeyless::init(
                    context.with_label("keyless_db"),
                    keyless_config(&context, "parity"),
                )
                .await
                .expect("init local keyless");

                let first = b"first".to_vec();
                let second = b"second".to_vec();
                let finalized = {
                    let mut batch = db.new_batch();
                    batch.append(first.clone());
                    batch.append(second);
                    batch.merkleize(None::<Vec<u8>>).finalize()
                };
                db.apply_batch(finalized)
                    .await
                    .expect("apply keyless batch");

                let latest_location = db.bounds().await.end - 1;
                let proof_count = NonZeroU64::new(*latest_location + 1).expect("non-zero");
                let (proof, operations) = db
                    .historical_proof(latest_location + 1, Location::new(0), proof_count)
                    .await
                    .expect("keyless historical proof");
                let root = db.root();
                db.destroy().await.expect("destroy keyless db");

                LocalKeylessReference {
                    latest_location,
                    root,
                    proof,
                    operations,
                    queried_location: Location::new(1),
                    queried_value: first,
                }
            })
        })
        .await
        .expect("join local keyless builder")
    }

    #[derive(Clone, Debug)]
    struct OperationSnapshot {
        latest_locations: BTreeMap<Vec<u8>, Location>,
        values: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    }

    fn summarize_operations(operations: &[BatchOperation]) -> OperationSnapshot {
        let mut latest_locations = BTreeMap::new();
        let mut values = BTreeMap::new();
        for (index, operation) in operations.iter().enumerate() {
            let location = Location::new(index as u64);
            match operation {
                BatchOperation::Update(update) => {
                    latest_locations.insert(update.key.clone(), location);
                    values.insert(update.key.clone(), Some(update.value.clone()));
                }
                BatchOperation::Delete(key) => {
                    latest_locations.insert(key.clone(), location);
                    values.insert(key.clone(), None);
                }
                BatchOperation::CommitFloor(_, _) => {}
            }
        }
        OperationSnapshot {
            latest_locations,
            values,
        }
    }

    fn sample_distinct_keys(rng: &mut StdRng, keys: &[Vec<u8>], max_count: usize) -> Vec<Vec<u8>> {
        let mut sampled = keys.to_vec();
        sampled.shuffle(rng);
        let count = sampled.len().min(max_count);
        if count == 0 {
            return Vec::new();
        }
        sampled.truncate(rng.gen_range(1..=count));
        sampled
    }

    #[derive(Clone, Debug)]
    struct LocalKeyProofReference {
        proof: BatchCurrentKeyValueProof,
        operation: BatchOperation,
    }

    #[derive(Clone, Debug)]
    struct RandomLocalQmdbScenario {
        latest_location: Location,
        operations: Vec<BatchOperation>,
        batch_boundaries: Vec<Location>,
        all_keys: Vec<Vec<u8>>,
    }

    struct LocalQmdbReference {
        latest_location: Location,
        operations: Vec<BatchOperation>,
        historical_range_proof: BatchProof,
        ops_root: QmdbDigest,
        current_range_proof: BatchCurrentRangeProof,
        current_chunks: Vec<[u8; BITMAP_CHUNK_BYTES]>,
        current_root: QmdbDigest,
        multi_proof: BatchProof,
        multi_operations: Vec<(Location, BatchOperation)>,
        key_proofs: BTreeMap<Vec<u8>, LocalKeyProofReference>,
        values: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    }

    #[derive(Clone, Debug)]
    struct LocalBoundaryReference {
        ops_root: QmdbDigest,
        historical_range_proof: BatchProof,
        historical_range_operations: Vec<BatchOperation>,
        current_root: QmdbDigest,
        current_range_proof: BatchCurrentRangeProof,
        current_range_operations: Vec<BatchOperation>,
        current_chunks: Vec<[u8; BITMAP_CHUNK_BYTES]>,
        multi_proof: BatchProof,
        multi_operations: Vec<(Location, BatchOperation)>,
        key_proofs: BTreeMap<Vec<u8>, LocalKeyProofReference>,
    }

    #[derive(Clone, Debug)]
    struct RandomUploadWindow {
        latest_location: Location,
        operations: Vec<BatchOperation>,
        current_boundary: CurrentBoundaryState,
    }

    #[derive(Clone, Debug)]
    struct BoundaryCheckPlan {
        boundary: Location,
        range_start: Location,
        range_len: NonZeroU64,
        multi_keys: Vec<Vec<u8>>,
        key_proof_keys: Vec<Vec<u8>>,
    }

    #[derive(Clone, Debug)]
    struct BoundaryCheckCase {
        plan: BoundaryCheckPlan,
        query_keys: Vec<Vec<u8>>,
    }

    async fn build_local_qmdb_reference() -> LocalQmdbReference {
        tokio::task::spawn_blocking(|| {
            cw_tokio::Runner::default().start(|context| async move {
                let mut db = init_local_qmdb(context, "qmdb").await;

                let finalized = {
                    let mut batch = db.new_batch();
                    batch.write(b"alpha".to_vec(), Some(b"one".to_vec()));
                    batch.write(b"beta".to_vec(), Some(b"two".to_vec()));
                    batch
                        .merkleize(None::<Vec<u8>>)
                        .await
                        .expect("merkleize batch1")
                };
                db.apply_batch(finalized.finalize())
                    .await
                    .expect("apply batch1");

                let finalized = {
                    let mut batch = db.new_batch();
                    batch.write(b"alpha".to_vec(), Some(b"three".to_vec()));
                    batch.write(b"gamma".to_vec(), Some(b"four".to_vec()));
                    batch
                        .merkleize(None::<Vec<u8>>)
                        .await
                        .expect("merkleize batch2")
                };
                db.apply_batch(finalized.finalize())
                    .await
                    .expect("apply batch2");

                let finalized = {
                    let mut batch = db.new_batch();
                    batch.write(b"beta".to_vec(), None);
                    batch
                        .merkleize(None::<Vec<u8>>)
                        .await
                        .expect("merkleize batch3")
                };
                db.apply_batch(finalized.finalize())
                    .await
                    .expect("apply batch3");

                let latest_location = db.bounds().await.end - 1;
                let historical_size = latest_location + 1;
                let op_count = NonZeroU64::new(*historical_size).expect("non-zero");
                let (historical_range_proof, operations): (BatchProof, Vec<BatchOperation>) = db
                    .ops_historical_proof(historical_size, Location::new(0), op_count)
                    .await
                    .expect("extract historical range");
                let encoded_operations = operations
                    .iter()
                    .map(|op| op.encode().to_vec())
                    .collect::<Vec<_>>();
                let ops_mmr =
                    build_operation_mmr(&encoded_operations).expect("build local batch mmr");
                let ops_root = *ops_mmr.root();
                let mut range_hasher = StandardHasher::<Sha256>::new();
                let (current_range_proof, current_operations, current_chunks) = db
                    .range_proof(range_hasher.inner(), Location::new(0), op_count)
                    .await
                    .expect("current range proof");
                assert_eq!(current_operations, operations);

                let historical_range_proof_expected = ops_mmr
                    .range_proof(Location::new(0)..Location::new(operations.len() as u64))
                    .expect("local historical range proof");
                assert_eq!(historical_range_proof_expected, historical_range_proof);

                let mut key_locations = BTreeMap::<Vec<u8>, Location>::new();
                for (index, op) in operations.iter().enumerate() {
                    if let Some(key) = op.key() {
                        key_locations.insert(key.to_vec(), Location::new(index as u64));
                    }
                }
                let mut target_locations = vec![
                    key_locations[b"alpha".as_slice()],
                    key_locations[b"gamma".as_slice()],
                ];
                target_locations.sort();
                let multi_proof = verification::multi_proof(&ops_mmr, &target_locations)
                    .await
                    .expect("local multi proof");
                let multi_operations = target_locations
                    .into_iter()
                    .map(|loc| {
                        let idx = *loc as usize;
                        (loc, operations[idx].clone())
                    })
                    .collect::<Vec<_>>();

                let mut key_proofs = BTreeMap::new();
                let mut key_hasher = StandardHasher::<Sha256>::new();
                let alpha_proof = db
                    .key_value_proof(key_hasher.inner(), b"alpha".to_vec())
                    .await
                    .expect("alpha proof");
                key_proofs.insert(
                    b"alpha".to_vec(),
                    LocalKeyProofReference {
                        proof: alpha_proof,
                        operation: operations[*key_locations[b"alpha".as_slice()] as usize].clone(),
                    },
                );
                let gamma_proof = db
                    .key_value_proof(key_hasher.inner(), b"gamma".to_vec())
                    .await
                    .expect("gamma proof");
                key_proofs.insert(
                    b"gamma".to_vec(),
                    LocalKeyProofReference {
                        proof: gamma_proof,
                        operation: operations[*key_locations[b"gamma".as_slice()] as usize].clone(),
                    },
                );

                let mut values = BTreeMap::new();
                values.insert(
                    b"alpha".to_vec(),
                    db.get(&b"alpha".to_vec()).await.expect("alpha get"),
                );
                values.insert(
                    b"beta".to_vec(),
                    db.get(&b"beta".to_vec()).await.expect("beta get"),
                );
                values.insert(
                    b"gamma".to_vec(),
                    db.get(&b"gamma".to_vec()).await.expect("gamma get"),
                );
                let current_root = db.root();
                db.sync().await.expect("sync local qmdb");
                db.destroy().await.expect("destroy local qmdb");

                LocalQmdbReference {
                    latest_location,
                    operations,
                    historical_range_proof,
                    ops_root,
                    current_range_proof,
                    current_chunks,
                    current_root,
                    multi_proof,
                    multi_operations,
                    key_proofs,
                    values,
                }
            })
        })
        .await
        .expect("join local qmdb builder")
    }

    async fn build_random_local_qmdb_scenario(seed: u64) -> RandomLocalQmdbScenario {
        tokio::task::spawn_blocking(move || {
            cw_tokio::Runner::default().start(|context| async move {
                const RANDOM_BATCHES: usize = 96;
                const MIN_BATCH_OPS: usize = 8;
                const MAX_BATCH_OPS: usize = 16;

                let mut rng = StdRng::seed_from_u64(seed);
                let mut db = init_local_qmdb(context, "random-qmdb").await;
                let mut active = BTreeMap::<Vec<u8>, Vec<u8>>::new();
                let mut all_keys = Vec::<Vec<u8>>::new();
                let mut batch_boundaries = Vec::with_capacity(RANDOM_BATCHES);
                let mut next_key_id = 0u32;

                for batch_index in 0..RANDOM_BATCHES {
                    let op_count = if batch_index == 0 || rng.gen_bool(0.9) {
                        rng.gen_range(MIN_BATCH_OPS..=MAX_BATCH_OPS)
                    } else {
                        0
                    };
                    let mut batch = db.new_batch();
                    let mut batch_keys = BTreeSet::<Vec<u8>>::new();

                    for _ in 0..op_count {
                        let delete_candidates = active
                            .keys()
                            .filter(|key| !batch_keys.contains(*key))
                            .cloned()
                            .collect::<Vec<_>>();
                        if !delete_candidates.is_empty() && rng.gen_bool(0.25) {
                            let key = delete_candidates[rng.gen_range(0..delete_candidates.len())]
                                .clone();
                            batch.write(key.clone(), None);
                            active.remove(&key);
                            batch_keys.insert(key);
                            continue;
                        }

                        let existing_candidates = all_keys
                            .iter()
                            .filter(|key| !batch_keys.contains(*key))
                            .cloned()
                            .collect::<Vec<_>>();
                        let key = if !existing_candidates.is_empty() && rng.gen_bool(0.6) {
                            existing_candidates[rng.gen_range(0..existing_candidates.len())].clone()
                        } else {
                            let key = random_test_key(next_key_id);
                            next_key_id += 1;
                            all_keys.push(key.clone());
                            key
                        };
                        let value = random_test_value(&mut rng);
                        batch.write(key.clone(), Some(value.clone()));
                        active.insert(key.clone(), value);
                        batch_keys.insert(key);
                    }

                    let finalized = batch
                        .merkleize(None::<Vec<u8>>)
                        .await
                        .expect("merkleize random batch")
                        .finalize();
                    db.apply_batch(finalized).await.expect("apply random batch");
                    batch_boundaries.push(db.bounds().await.end - 1);
                }

                let latest_location = *batch_boundaries.last().expect("batch boundary exists");
                let historical_size = latest_location + 1;
                let op_count = NonZeroU64::new(*historical_size).expect("non-zero");
                let (_, operations): (BatchProof, Vec<BatchOperation>) = db
                    .ops_historical_proof(historical_size, Location::new(0), op_count)
                    .await
                    .expect("extract random historical range");
                assert_eq!(operations.len(), *historical_size as usize);
                db.sync().await.expect("sync local qmdb");
                db.destroy().await.expect("destroy local qmdb");

                RandomLocalQmdbScenario {
                    latest_location,
                    operations,
                    batch_boundaries,
                    all_keys,
                }
            })
        })
        .await
        .expect("join random local qmdb builder")
    }

    async fn build_random_local_boundary_references(
        seed: u64,
        plans: &[BoundaryCheckPlan],
    ) -> Vec<LocalBoundaryReference> {
        let plans = plans.to_vec();
        tokio::task::spawn_blocking(move || {
            cw_tokio::Runner::default().start(|context| async move {
                const RANDOM_BATCHES: usize = 96;
                const MIN_BATCH_OPS: usize = 8;
                const MAX_BATCH_OPS: usize = 16;

                let plan_count = plans.len();
                let mut pending_plans =
                    BTreeMap::<Location, Vec<(usize, BoundaryCheckPlan)>>::new();
                for (index, plan) in plans.into_iter().enumerate() {
                    pending_plans
                        .entry(plan.boundary)
                        .or_default()
                        .push((index, plan));
                }
                let mut references = vec![None; plan_count];
                let mut rng = StdRng::seed_from_u64(seed);
                let mut db = init_local_qmdb(context, "reference-qmdb").await;
                let mut active = BTreeMap::<Vec<u8>, Vec<u8>>::new();
                let mut all_keys = Vec::<Vec<u8>>::new();
                let mut next_key_id = 0u32;

                for batch_index in 0..RANDOM_BATCHES {
                    let op_count = if batch_index == 0 || rng.gen_bool(0.9) {
                        rng.gen_range(MIN_BATCH_OPS..=MAX_BATCH_OPS)
                    } else {
                        0
                    };
                    let mut batch = db.new_batch();
                    let mut batch_keys = BTreeSet::<Vec<u8>>::new();

                    for _ in 0..op_count {
                        let delete_candidates = active
                            .keys()
                            .filter(|key| !batch_keys.contains(*key))
                            .cloned()
                            .collect::<Vec<_>>();
                        if !delete_candidates.is_empty() && rng.gen_bool(0.25) {
                            let key = delete_candidates[rng.gen_range(0..delete_candidates.len())]
                                .clone();
                            batch.write(key.clone(), None);
                            active.remove(&key);
                            batch_keys.insert(key);
                            continue;
                        }

                        let existing_candidates = all_keys
                            .iter()
                            .filter(|key| !batch_keys.contains(*key))
                            .cloned()
                            .collect::<Vec<_>>();
                        let key = if !existing_candidates.is_empty() && rng.gen_bool(0.6) {
                            existing_candidates[rng.gen_range(0..existing_candidates.len())].clone()
                        } else {
                            let key = random_test_key(next_key_id);
                            next_key_id += 1;
                            all_keys.push(key.clone());
                            key
                        };
                        let value = random_test_value(&mut rng);
                        batch.write(key.clone(), Some(value.clone()));
                        active.insert(key.clone(), value);
                        batch_keys.insert(key);
                    }

                    let finalized = batch
                        .merkleize(None::<Vec<u8>>)
                        .await
                        .expect("merkleize reference batch")
                        .finalize();
                    db.apply_batch(finalized)
                        .await
                        .expect("apply reference batch");
                    let boundary = db.bounds().await.end - 1;

                    let Some(boundary_plans) = pending_plans.remove(&boundary) else {
                        continue;
                    };

                    let historical_size = boundary + 1;
                    let full_count = NonZeroU64::new(*historical_size).expect("non-zero");
                    let (_, operations): (BatchProof, Vec<BatchOperation>) = db
                        .ops_historical_proof(historical_size, Location::new(0), full_count)
                        .await
                        .expect("extract reference historical range");
                    let snapshot = summarize_operations(&operations);
                    let encoded_operations = operations
                        .iter()
                        .map(|operation| operation.encode().to_vec())
                        .collect::<Vec<_>>();
                    let ops_mmr =
                        build_operation_mmr(&encoded_operations).expect("build local ops mmr");
                    let ops_root = *ops_mmr.root();
                    let current_root = db.root();

                    for (index, plan) in boundary_plans {
                        let (historical_range_proof, historical_range_operations): (
                            BatchProof,
                            Vec<BatchOperation>,
                        ) = db
                            .ops_historical_proof(historical_size, plan.range_start, plan.range_len)
                            .await
                            .expect("extract historical range");
                        let mut range_hasher = StandardHasher::<Sha256>::new();
                        let (current_range_proof, current_range_operations, current_chunks) = db
                            .range_proof(range_hasher.inner(), plan.range_start, plan.range_len)
                            .await
                            .expect("current range proof");

                        let mut target_locations = plan
                            .multi_keys
                            .iter()
                            .map(|key| snapshot.latest_locations[key])
                            .collect::<Vec<_>>();
                        target_locations.sort();
                        let multi_proof = verification::multi_proof(&ops_mmr, &target_locations)
                            .await
                            .expect("local multi proof");
                        let multi_operations = target_locations
                            .into_iter()
                            .map(|location| {
                                let operation_index = *location as usize;
                                (location, operations[operation_index].clone())
                            })
                            .collect::<Vec<_>>();

                        let mut key_proofs = BTreeMap::new();
                        let mut key_hasher = StandardHasher::<Sha256>::new();
                        for key in &plan.key_proof_keys {
                            let proof = db
                                .key_value_proof(key_hasher.inner(), key.clone())
                                .await
                                .expect("key value proof");
                            key_proofs.insert(
                                key.clone(),
                                LocalKeyProofReference {
                                    proof,
                                    operation: operations[*snapshot.latest_locations[key] as usize]
                                        .clone(),
                                },
                            );
                        }

                        references[index] = Some(LocalBoundaryReference {
                            ops_root,
                            historical_range_proof,
                            historical_range_operations,
                            current_root,
                            current_range_proof,
                            current_range_operations,
                            current_chunks,
                            multi_proof,
                            multi_operations,
                            key_proofs,
                        });
                    }
                }

                assert!(
                    pending_plans.is_empty(),
                    "all boundary plans should be satisfied"
                );
                db.sync().await.expect("sync local qmdb");
                db.destroy().await.expect("destroy local qmdb");
                references
                    .into_iter()
                    .map(|reference| reference.expect("reference exists"))
                    .collect::<Vec<_>>()
            })
        })
        .await
        .expect("join local boundary reference builder")
    }

    async fn rebuilt_current_root(operations: &[BatchOperation]) -> QmdbDigest {
        let state = RebuiltCurrentState::build(operations.to_vec()).expect("rebuild current state");
        let storage = RebuiltCurrentStorage {
            ops_mmr: &state.ops_mmr,
            grafted_mmr: &state.grafted_mmr,
        };
        let grafted_root = compute_storage_root(&storage)
            .await
            .expect("compute rebuilt grafted root");
        combine_current_roots(
            &state.ops_root,
            &grafted_root,
            state
                .partial_chunk_digest
                .as_ref()
                .map(|(next_bit, digest)| (*next_bit, digest)),
        )
    }

    async fn current_boundary_state_from_operations(
        previous_operations: Option<&[BatchOperation]>,
        operations: &[BatchOperation],
    ) -> CurrentBoundaryState {
        crate::build_current_boundary_state(previous_operations, operations).await
    }

    #[tokio::test]
    async fn local_immutable_reference_matches_authenticated_queries_and_proofs() {
        let servers = spawn_test_server().await;
        let client = servers.immutable_client();
        let reference = build_local_immutable_reference().await;

        client
            .upload_operations(reference.latest_location, &reference.operations)
            .await
            .expect("upload immutable ops");
        client
            .publish_writer_location_watermark(reference.latest_location)
            .await
            .expect("publish immutable watermark");

        assert_eq!(
            client
                .root_at(reference.latest_location)
                .await
                .expect("immutable root"),
            reference.root
        );
        let queried = client
            .get_at(&reference.queried_key, reference.latest_location)
            .await
            .expect("immutable get")
            .expect("immutable value present");
        assert_eq!(queried.key, reference.queried_key);
        assert_eq!(queried.value, Some(reference.queried_value));

        let remote = client
            .operation_range_proof(
                reference.latest_location,
                Location::new(0),
                reference.operations.len() as u32,
            )
            .await
            .expect("immutable remote proof");
        assert_eq!(remote.root, reference.root);
        assert_eq!(remote.proof, reference.proof);
        assert_eq!(remote.operations, reference.operations);
        assert!(remote.verify());
    }

    #[tokio::test]
    async fn local_keyless_reference_matches_authenticated_queries_and_proofs() {
        let servers = spawn_test_server().await;
        let client = servers.keyless_client();
        let reference = build_local_keyless_reference().await;

        client
            .upload_operations(reference.latest_location, &reference.operations)
            .await
            .expect("upload keyless ops");
        client
            .publish_writer_location_watermark(reference.latest_location)
            .await
            .expect("publish keyless watermark");

        assert_eq!(
            client
                .root_at(reference.latest_location)
                .await
                .expect("keyless root"),
            reference.root
        );
        assert_eq!(
            client
                .get_at(reference.queried_location, reference.latest_location)
                .await
                .expect("keyless get"),
            Some(reference.queried_value)
        );

        let remote = client
            .operation_range_proof(
                reference.latest_location,
                Location::new(0),
                reference.operations.len() as u32,
            )
            .await
            .expect("keyless remote proof");
        assert_eq!(remote.root, reference.root);
        assert_eq!(remote.proof, reference.proof);
        assert_eq!(remote.operations, reference.operations);
        assert!(remote.verify());
    }

    #[tokio::test]
    async fn local_keyless_reference_matches_with_fresh_clients_per_step() {
        let servers = spawn_test_server_with_query_tick(Duration::from_millis(100)).await;
        let reference = build_local_keyless_reference().await;

        KeylessClient::<Vec<u8>>::from_client(servers.client(), ((0..=10000).into(), ()))
            .upload_operations(reference.latest_location, &reference.operations)
            .await
            .expect("upload keyless ops");
        KeylessClient::<Vec<u8>>::from_client(servers.client(), ((0..=10000).into(), ()))
            .publish_writer_location_watermark(reference.latest_location)
            .await
            .expect("publish keyless watermark");

        assert_eq!(
            KeylessClient::<Vec<u8>>::from_client(servers.client(), ((0..=10000).into(), ()))
                .root_at(reference.latest_location)
                .await
                .expect("keyless root"),
            reference.root
        );
        assert_eq!(
            KeylessClient::<Vec<u8>>::from_client(servers.client(), ((0..=10000).into(), ()))
                .get_at(reference.queried_location, reference.latest_location)
                .await
                .expect("keyless get"),
            Some(reference.queried_value.clone())
        );

        let remote =
            KeylessClient::<Vec<u8>>::from_client(servers.client(), ((0..=10000).into(), ()))
                .operation_range_proof(
                    reference.latest_location,
                    Location::new(0),
                    reference.operations.len() as u32,
                )
                .await
                .expect("keyless remote proof");
        assert_eq!(remote.root, reference.root);
        assert_eq!(remote.proof, reference.proof);
        assert_eq!(remote.operations, reference.operations);
        assert!(remote.verify());
    }

    #[tokio::test]
    async fn ordered_upload_receipt_retries_until_slow_query_tick_catches_up() {
        let servers = spawn_test_server_with_query_tick(Duration::from_millis(500)).await;
        let client = OrderedClient::from_client(servers.client());
        let reference = build_local_qmdb_reference().await;

        let receipt = client
            .upload_operations(reference.latest_location, &reference.operations)
            .await
            .expect("upload ordered ops with slow query tick");

        assert_eq!(receipt.latest_location, reference.latest_location);
        assert_eq!(receipt.writer_location_watermark, None);
        assert!(receipt.sequence_number > 0);
    }

    #[tokio::test]
    async fn unordered_publish_does_not_require_current_boundary_state() {
        let servers = spawn_test_server().await;
        let latest_location = Location::new(1);
        let operations = vec![
            UnorderedBatchOperation::Update(UnorderedUpdate(b"alpha".to_vec(), b"one".to_vec())),
            UnorderedBatchOperation::Update(UnorderedUpdate(b"beta".to_vec(), b"two".to_vec())),
        ];

        UnorderedClient::from_client(servers.client())
            .upload_operations(latest_location, &operations)
            .await
            .expect("upload unordered ops");
        UnorderedClient::from_client(servers.client())
            .publish_writer_location_watermark(latest_location)
            .await
            .expect("publish unordered watermark");

        let watermark = UnorderedClient::from_client(servers.client())
            .writer_location_watermark()
            .await
            .expect("unordered watermark");
        assert_eq!(watermark, Some(latest_location));

        let queried = UnorderedClient::from_client(servers.client())
            .query_many_at(&[b"alpha".as_slice(), b"beta".as_slice()], latest_location)
            .await
            .expect("unordered query_many_at");
        assert_eq!(
            queried[0].as_ref().and_then(|value| value.value.clone()),
            Some(b"one".to_vec())
        );
        assert_eq!(
            queried[1].as_ref().and_then(|value| value.value.clone()),
            Some(b"two".to_vec())
        );
    }

    #[tokio::test]
    async fn immutable_upload_receipt_retries_until_slow_query_tick_catches_up() {
        let servers = spawn_test_server_with_query_tick(Duration::from_millis(500)).await;
        let client = ImmutableClient::from_client(servers.client(), ((0..=10000).into(), ()));
        let reference = build_local_immutable_reference().await;

        let receipt = client
            .upload_operations(reference.latest_location, &reference.operations)
            .await
            .expect("upload immutable ops with slow query tick");

        assert_eq!(receipt.latest_location, reference.latest_location);
        assert_eq!(receipt.writer_location_watermark, None);
        assert!(receipt.sequence_number > 0);
    }

    #[tokio::test]
    async fn keyless_upload_receipt_retries_until_slow_query_tick_catches_up() {
        let servers = spawn_test_server_with_query_tick(Duration::from_millis(500)).await;
        let client = KeylessClient::from_client(servers.client(), ((0..=10000).into(), ()));
        let reference = build_local_keyless_reference().await;

        let receipt = client
            .upload_operations(reference.latest_location, &reference.operations)
            .await
            .expect("upload keyless ops with slow query tick");

        assert_eq!(receipt.latest_location, reference.latest_location);
        assert_eq!(receipt.writer_location_watermark, None);
        assert!(receipt.sequence_number > 0);
    }

    #[tokio::test]
    async fn immutable_get_at_uses_indexed_latest_set_at_or_below_watermark() {
        let servers = spawn_test_server().await;
        let client = servers.immutable_client();
        let key_a = immutable_key(0x33);
        let key_b = immutable_key(0x44);
        let value_a = b"alpha".to_vec();
        let value_b = b"bravo".to_vec();
        let metadata = b"commit".to_vec();
        let operations = vec![
            ImmutableOperation::Set(key_a, value_a.clone()),
            ImmutableOperation::Set(key_b.clone(), value_b.clone()),
            ImmutableOperation::Commit(Some(metadata)),
        ];
        let latest_location = Location::new(2);

        client
            .upload_operations(latest_location, &operations)
            .await
            .expect("upload immutable ops");
        client
            .publish_writer_location_watermark(latest_location)
            .await
            .expect("publish immutable watermark");

        let queried = client
            .get_at(&key_b, latest_location)
            .await
            .expect("indexed immutable get")
            .expect("indexed immutable value present");
        assert_eq!(queried.key, key_b);
        assert_eq!(queried.location, Location::new(1));
        assert_eq!(queried.value, Some(value_b));

        assert_eq!(
            client
                .get_at(&immutable_key(0x55), latest_location)
                .await
                .expect("missing immutable get"),
            None
        );
        assert_eq!(
            client
                .get_at(&immutable_key(0x66), Location::new(0))
                .await
                .expect("lower watermark immutable get"),
            None
        );
        let first = client
            .get_at(
                &operations[0].key().expect("set key").clone(),
                Location::new(0),
            )
            .await
            .expect("first immutable get")
            .expect("first immutable value present");
        assert_eq!(first.location, Location::new(0));
        assert_eq!(first.value, Some(value_a));
    }

    #[tokio::test]
    async fn authenticated_clients_reject_unpublished_watermarks() {
        let servers = spawn_test_server().await;
        let immutable = servers.immutable_client();
        let keyless = servers.keyless_client();
        let immutable_reference = build_local_immutable_reference().await;
        let keyless_reference = build_local_keyless_reference().await;

        immutable
            .upload_operations(
                immutable_reference.latest_location,
                &immutable_reference.operations,
            )
            .await
            .expect("upload immutable ops");
        keyless
            .upload_operations(
                keyless_reference.latest_location,
                &keyless_reference.operations,
            )
            .await
            .expect("upload keyless ops");

        assert!(matches!(
            immutable.root_at(immutable_reference.latest_location).await,
            Err(QmdbError::WatermarkTooLow { .. })
        ));
        assert!(matches!(
            immutable
                .get_at(
                    &immutable_reference.queried_key,
                    immutable_reference.latest_location,
                )
                .await,
            Err(QmdbError::WatermarkTooLow { .. })
        ));
        assert!(matches!(
            immutable
                .operation_range_proof(immutable_reference.latest_location, Location::new(0), 1,)
                .await,
            Err(QmdbError::WatermarkTooLow { .. })
        ));
        assert!(matches!(
            keyless.root_at(keyless_reference.latest_location).await,
            Err(QmdbError::WatermarkTooLow { .. })
        ));
        assert!(matches!(
            keyless
                .get_at(
                    keyless_reference.queried_location,
                    keyless_reference.latest_location,
                )
                .await,
            Err(QmdbError::WatermarkTooLow { .. })
        ));
        assert!(matches!(
            keyless
                .operation_range_proof(keyless_reference.latest_location, Location::new(0), 1)
                .await,
            Err(QmdbError::WatermarkTooLow { .. })
        ));
    }

    #[tokio::test]
    async fn authenticated_range_proofs_validate_partial_and_error_cases() {
        let servers = spawn_test_server().await;
        let immutable = servers.immutable_client();
        let keyless = servers.keyless_client();
        let immutable_reference = build_local_immutable_reference().await;
        let keyless_reference = build_local_keyless_reference().await;

        immutable
            .upload_operations(
                immutable_reference.latest_location,
                &immutable_reference.operations,
            )
            .await
            .expect("upload immutable ops");
        immutable
            .publish_writer_location_watermark(immutable_reference.latest_location)
            .await
            .expect("publish immutable watermark");
        keyless
            .upload_operations(
                keyless_reference.latest_location,
                &keyless_reference.operations,
            )
            .await
            .expect("upload keyless ops");
        keyless
            .publish_writer_location_watermark(keyless_reference.latest_location)
            .await
            .expect("publish keyless watermark");

        let immutable_partial = immutable
            .operation_range_proof(immutable_reference.latest_location, Location::new(1), 1)
            .await
            .expect("immutable partial proof");
        assert_eq!(immutable_partial.start_location, Location::new(1));
        assert_eq!(
            immutable_partial.operations,
            immutable_reference.operations[1..2].to_vec()
        );
        assert!(immutable_partial.verify());

        let keyless_partial = keyless
            .operation_range_proof(keyless_reference.latest_location, Location::new(1), 1)
            .await
            .expect("keyless partial proof");
        assert_eq!(keyless_partial.start_location, Location::new(1));
        assert_eq!(
            keyless_partial.operations,
            keyless_reference.operations[1..2].to_vec()
        );
        assert!(keyless_partial.verify());

        assert!(matches!(
            immutable
                .operation_range_proof(immutable_reference.latest_location, Location::new(0), 0)
                .await,
            Err(QmdbError::InvalidRangeLength)
        ));
        assert!(matches!(
            keyless
                .operation_range_proof(keyless_reference.latest_location, Location::new(0), 0)
                .await,
            Err(QmdbError::InvalidRangeLength)
        ));
        assert!(matches!(
            immutable
                .operation_range_proof(
                    immutable_reference.latest_location,
                    immutable_reference.latest_location + 1,
                    1,
                )
                .await,
            Err(QmdbError::RangeStartOutOfBounds { .. })
        ));
        assert!(matches!(
            keyless
                .operation_range_proof(
                    keyless_reference.latest_location,
                    keyless_reference.latest_location + 1,
                    1,
                )
                .await,
            Err(QmdbError::RangeStartOutOfBounds { .. })
        ));
    }

    #[tokio::test]
    async fn watermark_getters_distinguish_unpublished_from_published_zero() {
        let servers = spawn_test_server().await;

        let ordered = servers.qmdb_client();
        assert_eq!(
            ordered
                .writer_location_watermark()
                .await
                .expect("read empty ordered watermark"),
            None
        );
        let ordered_ops = vec![BatchOperation::Update(QmdbUpdate {
            key: b"alpha".to_vec(),
            value: b"one".to_vec(),
            next_key: Vec::new(),
        })];
        let ordered_current = current_boundary_state_from_operations(None, &ordered_ops).await;
        let ordered_receipt = ordered
            .upload_operations(Location::new(0), &ordered_ops)
            .await
            .expect("upload ordered ops");
        assert_eq!(ordered_receipt.writer_location_watermark, None);
        ordered
            .upload_current_boundary_state(Location::new(0), &ordered_current)
            .await
            .expect("upload ordered current boundary");
        ordered
            .publish_writer_location_watermark(Location::new(0))
            .await
            .expect("publish ordered watermark zero");
        assert_eq!(
            ordered
                .writer_location_watermark()
                .await
                .expect("read published ordered watermark"),
            Some(Location::new(0))
        );

        let immutable = servers.immutable_client();
        assert_eq!(
            immutable
                .writer_location_watermark()
                .await
                .expect("read empty immutable watermark"),
            None
        );
        let immutable_ops = vec![ImmutableOperation::Set(
            immutable_key(0x77),
            b"immutable".to_vec(),
        )];
        let immutable_receipt = immutable
            .upload_operations(Location::new(0), &immutable_ops)
            .await
            .expect("upload immutable ops");
        assert_eq!(immutable_receipt.writer_location_watermark, None);
        immutable
            .publish_writer_location_watermark(Location::new(0))
            .await
            .expect("publish immutable watermark zero");
        assert_eq!(
            immutable
                .writer_location_watermark()
                .await
                .expect("read published immutable watermark"),
            Some(Location::new(0))
        );

        let keyless = servers.keyless_client();
        assert_eq!(
            keyless
                .writer_location_watermark()
                .await
                .expect("read empty keyless watermark"),
            None
        );
        let keyless_ops = vec![KeylessOperation::Append(b"keyless".to_vec())];
        let keyless_receipt = keyless
            .upload_operations(Location::new(0), &keyless_ops)
            .await
            .expect("upload keyless ops");
        assert_eq!(keyless_receipt.writer_location_watermark, None);
        keyless
            .publish_writer_location_watermark(Location::new(0))
            .await
            .expect("publish keyless watermark zero");
        assert_eq!(
            keyless
                .writer_location_watermark()
                .await
                .expect("read published keyless watermark"),
            Some(Location::new(0))
        );
    }

    #[test]
    fn update_row_round_trip() {
        let encoded = encode_update_row(b"alpha", Some(b"bravo")).expect("encode");
        let decoded = decode_update_row(&encoded).expect("decode");
        assert_eq!(decoded.key, b"alpha");
        assert_eq!(decoded.value.as_deref(), Some(b"bravo".as_slice()));
    }

    #[test]
    fn update_key_keeps_prefix_related_raw_keys_in_logical_order() {
        let key_a0 = encode_update_key(b"a", Location::new(0)).expect("encode key a0");
        let key_a1 = encode_update_key(b"a", Location::new(1)).expect("encode key a1");
        let key_a_nul = encode_update_key(b"a\0", Location::new(0)).expect("encode key a nul");
        let mut ordered = vec![key_a_nul.clone(), key_a1.clone(), key_a0.clone()];
        ordered.sort();
        assert_eq!(
            ordered,
            vec![key_a0.clone(), key_a1.clone(), key_a_nul.clone()]
        );
        assert_eq!(
            decode_update_location(&key_a0).expect("decode location"),
            Location::new(0)
        );
        assert_eq!(
            decode_update_location(&key_a1).expect("decode location"),
            Location::new(1)
        );
        assert_eq!(
            decode_update_location(&key_a_nul).expect("decode location"),
            Location::new(0)
        );
    }

    #[test]
    fn auth_immutable_update_key_keeps_prefix_related_raw_keys_in_logical_order() {
        let key_a0 =
            encode_auth_immutable_update_key(b"a", Location::new(0)).expect("encode key a0");
        let key_a1 =
            encode_auth_immutable_update_key(b"a", Location::new(1)).expect("encode key a1");
        let key_a_nul =
            encode_auth_immutable_update_key(b"a\0", Location::new(0)).expect("encode key a nul");
        let mut ordered = vec![key_a_nul.clone(), key_a1.clone(), key_a0.clone()];
        ordered.sort();
        assert_eq!(
            ordered,
            vec![key_a0.clone(), key_a1.clone(), key_a_nul.clone()]
        );
        assert_eq!(
            decode_auth_immutable_update_location(&key_a0).expect("decode location"),
            Location::new(0)
        );
        assert_eq!(
            decode_auth_immutable_update_location(&key_a1).expect("decode location"),
            Location::new(1)
        );
        assert_eq!(
            decode_auth_immutable_update_location(&key_a_nul).expect("decode location"),
            Location::new(0)
        );
    }

    #[tokio::test]
    async fn upload_batch_requires_exact_ordered_operations() {
        let servers = spawn_test_server().await;
        let client = servers.qmdb_client();
        let err = client
            .upload_batch(Location::new(1), &[BatchEntry::put(b"dup", b"v1")])
            .await
            .expect_err("ordered convenience upload should fail");
        assert!(matches!(err, QmdbError::ExactOrderedOperationsRequired));

        let typed = [TypedBatchEntry::put(&7u64, &11u32)];
        let err = client
            .upload_typed_batch(Location::new(1), &typed)
            .await
            .expect_err("typed ordered convenience upload should fail");
        assert!(matches!(err, QmdbError::ExactOrderedOperationsRequired));
    }

    #[tokio::test]
    async fn local_current_ordered_reference_matches_qmdb_queries_and_proofs() {
        let reference = build_local_qmdb_reference().await;
        let servers = spawn_test_server().await;
        let client = servers.qmdb_client();
        let current_boundary =
            current_boundary_state_from_operations(None, &reference.operations).await;

        client
            .upload_operations(reference.latest_location, &reference.operations)
            .await
            .expect("upload local qmdb ops");
        client
            .upload_current_boundary_state(reference.latest_location, &current_boundary)
            .await
            .expect("upload current boundary");
        client
            .publish_writer_location_watermark(reference.latest_location)
            .await
            .expect("publish watermark");

        let queried = client
            .query_many_at(
                &[b"alpha".as_slice(), b"beta".as_slice(), b"gamma".as_slice()],
                reference.latest_location,
            )
            .await
            .expect("query many");
        assert_eq!(
            queried[0].as_ref().and_then(|value| value.value.clone()),
            reference.values.get(b"alpha".as_slice()).cloned().flatten()
        );
        assert_eq!(
            queried[1].as_ref().and_then(|value| value.value.clone()),
            reference.values.get(b"beta".as_slice()).cloned().flatten()
        );
        assert_eq!(
            queried[2].as_ref().and_then(|value| value.value.clone()),
            reference.values.get(b"gamma".as_slice()).cloned().flatten()
        );

        let historical_range = client
            .operation_range_proof(
                reference.latest_location,
                Location::new(0),
                reference.operations.len() as u32,
            )
            .await
            .expect("historical range proof");
        assert_eq!(historical_range.root, reference.ops_root);
        assert_eq!(historical_range.proof, reference.historical_range_proof);
        assert_eq!(historical_range.operations, reference.operations);
        assert!(historical_range.verify());

        let remote_multi = client
            .multi_proof_at(
                reference.latest_location,
                &[b"alpha".as_slice(), b"gamma".as_slice()],
            )
            .await
            .expect("remote multi proof");
        assert_eq!(remote_multi.root, reference.ops_root);
        assert_eq!(remote_multi.proof, reference.multi_proof);
        assert_eq!(remote_multi.operations, reference.multi_operations);
        assert!(remote_multi.verify());

        assert_eq!(
            client
                .current_root_at(reference.latest_location)
                .await
                .expect("current root"),
            reference.current_root
        );

        let current_range = client
            .current_operation_range_proof(
                reference.latest_location,
                Location::new(0),
                reference.operations.len() as u32,
            )
            .await
            .expect("current range proof");
        assert_eq!(current_range.root, reference.current_root);
        assert_eq!(current_range.proof, reference.current_range_proof);
        assert_eq!(current_range.operations, reference.operations);
        assert_eq!(current_range.chunks, reference.current_chunks);
        assert!(current_range.verify());

        for key in [b"alpha".as_slice(), b"gamma".as_slice()] {
            let remote = client
                .key_value_proof_at(reference.latest_location, key)
                .await
                .expect("key value proof");
            let expected = &reference.key_proofs[key];
            assert_eq!(remote.root, reference.current_root);
            assert_eq!(remote.proof, expected.proof);
            assert_eq!(remote.operation, expected.operation);
            assert!(remote.verify());
        }
    }

    #[tokio::test]
    async fn variant_selected_roots_and_range_proofs_match_specific_helpers() {
        let reference = build_local_qmdb_reference().await;
        let servers = spawn_test_server().await;
        let client = servers.qmdb_client();
        let current_boundary =
            current_boundary_state_from_operations(None, &reference.operations).await;

        client
            .upload_operations(reference.latest_location, &reference.operations)
            .await
            .expect("upload local qmdb ops");
        client
            .upload_current_boundary_state(reference.latest_location, &current_boundary)
            .await
            .expect("upload current boundary");
        client
            .publish_writer_location_watermark(reference.latest_location)
            .await
            .expect("publish watermark");

        let any_root = client
            .root_for_variant(reference.latest_location, QmdbVariant::Any)
            .await
            .expect("any root");
        assert_eq!(any_root.variant, QmdbVariant::Any);
        assert_eq!(any_root.root, reference.ops_root);
        assert_eq!(
            any_root.root,
            client
                .root_at(reference.latest_location)
                .await
                .expect("specific any root")
        );

        let current_root = client
            .root_for_variant(reference.latest_location, QmdbVariant::Current)
            .await
            .expect("current root");
        assert_eq!(current_root.variant, QmdbVariant::Current);
        assert_eq!(current_root.root, reference.current_root);
        assert_eq!(
            current_root.root,
            client
                .current_root_at(reference.latest_location)
                .await
                .expect("specific current root")
        );

        let any_range = client
            .operation_range_proof_for_variant(
                reference.latest_location,
                QmdbVariant::Any,
                Location::new(0),
                reference.operations.len() as u32,
            )
            .await
            .expect("any range proof");
        let VariantOperationRangeProof::Any(any_range) = any_range else {
            panic!("expected any proof variant");
        };
        assert_eq!(any_range.root, reference.ops_root);
        assert_eq!(any_range.proof, reference.historical_range_proof);
        assert_eq!(any_range.operations, reference.operations);
        assert_eq!(
            any_range,
            client
                .operation_range_proof(
                    reference.latest_location,
                    Location::new(0),
                    reference.operations.len() as u32,
                )
                .await
                .expect("specific any range proof")
        );
        assert!(any_range.verify());

        let current_range = client
            .operation_range_proof_for_variant(
                reference.latest_location,
                QmdbVariant::Current,
                Location::new(0),
                reference.operations.len() as u32,
            )
            .await
            .expect("current range proof");
        let VariantOperationRangeProof::Current(current_range) = current_range else {
            panic!("expected current proof variant");
        };
        assert_eq!(current_range.root, reference.current_root);
        assert_eq!(current_range.proof, reference.current_range_proof);
        assert_eq!(current_range.operations, reference.operations);
        assert_eq!(current_range.chunks, reference.current_chunks);
        assert_eq!(
            current_range,
            client
                .current_operation_range_proof(
                    reference.latest_location,
                    Location::new(0),
                    reference.operations.len() as u32,
                )
                .await
                .expect("specific current range proof")
        );
        assert!(current_range.verify());
    }

    #[tokio::test]
    async fn any_variant_proofs_work_below_non_boundary_watermark() {
        let reference = build_local_qmdb_reference().await;
        let servers = spawn_test_server().await;
        let client = servers.qmdb_client();
        let current_boundary =
            current_boundary_state_from_operations(None, &reference.operations).await;

        client
            .upload_operations(reference.latest_location, &reference.operations)
            .await
            .expect("upload local qmdb ops");
        client
            .upload_current_boundary_state(reference.latest_location, &current_boundary)
            .await
            .expect("upload current boundary");
        client
            .publish_writer_location_watermark(reference.latest_location)
            .await
            .expect("publish watermark");

        let non_boundary = reference.latest_location - 1;
        let prefix_operations = &reference.operations[..=*non_boundary as usize];
        let encoded_prefix = prefix_operations
            .iter()
            .map(|op| op.encode().to_vec())
            .collect::<Vec<_>>();
        let ops_mmr = build_operation_mmr(&encoded_prefix).expect("build prefix mmr");
        let expected_root = *ops_mmr.root();
        let start = Location::new(1);
        let expected_end = Location::new((prefix_operations.len()).min(4) as u64);
        let expected_proof = ops_mmr
            .range_proof(start..expected_end)
            .expect("prefix range proof");

        let any_root = client
            .root_for_variant(non_boundary, QmdbVariant::Any)
            .await
            .expect("any root below non-boundary watermark");
        assert_eq!(any_root.root, expected_root);

        let any_range = client
            .operation_range_proof_for_variant(non_boundary, QmdbVariant::Any, start, 3)
            .await
            .expect("any range below non-boundary watermark");
        let VariantOperationRangeProof::Any(any_range) = any_range else {
            panic!("expected any proof variant");
        };
        assert_eq!(any_range.root, expected_root);
        assert_eq!(any_range.proof, expected_proof);
        assert_eq!(
            any_range.operations,
            prefix_operations[*start as usize..*expected_end as usize].to_vec()
        );
        assert!(any_range.verify());

        assert!(matches!(
            client
                .root_for_variant(non_boundary, QmdbVariant::Current)
                .await,
            Err(QmdbError::CurrentProofRequiresBatchBoundary { .. })
        ));
        assert!(matches!(
            client
                .operation_range_proof_for_variant(non_boundary, QmdbVariant::Current, start, 1)
                .await,
            Err(QmdbError::CurrentProofRequiresBatchBoundary { .. })
        ));
    }

    #[tokio::test]
    async fn randomized_local_qmdb_reference_matches_qmdb_across_random_windows_and_proofs() {
        const SCENARIO_SEED: u64 = 0x51A9_7C21_D00D_BAAD;
        const SAMPLE_COUNT: usize = 12;

        let scenario = build_random_local_qmdb_scenario(SCENARIO_SEED).await;
        let servers = spawn_test_server().await;
        let client = servers.qmdb_client();
        let mut rng = StdRng::seed_from_u64(SCENARIO_SEED ^ 0xA11C_E5EE_D5EE_D123);
        let mut ordered_windows = Vec::<RandomUploadWindow>::new();
        let mut batch_start = 0usize;
        let mut previous_upload_end = None::<usize>;

        while batch_start < scenario.batch_boundaries.len() {
            let remaining = scenario.batch_boundaries.len() - batch_start;
            let batches_in_window = rng.gen_range(1..=remaining.min(6));
            let end_batch = batch_start + batches_in_window - 1;
            let latest_location = scenario.batch_boundaries[end_batch];
            let start_location = if batch_start == 0 {
                0usize
            } else {
                *scenario.batch_boundaries[batch_start - 1] as usize + 1
            };
            let end_location = *latest_location as usize;
            let prefix = &scenario.operations[..=end_location];
            let current_boundary = current_boundary_state_from_operations(
                previous_upload_end.map(|end| &scenario.operations[..=end]),
                prefix,
            )
            .await;
            ordered_windows.push(RandomUploadWindow {
                latest_location,
                operations: scenario.operations[start_location..=end_location].to_vec(),
                current_boundary,
            });
            previous_upload_end = Some(end_location);
            batch_start = end_batch + 1;
        }

        let mut shuffled_windows = ordered_windows.clone();
        shuffled_windows.shuffle(&mut rng);
        let mut uploads = Vec::with_capacity(shuffled_windows.len());
        for window in shuffled_windows {
            let client = client.clone();
            uploads.push(tokio::spawn(async move {
                client
                    .upload_operations_with_current_boundary(
                        window.latest_location,
                        &window.operations,
                        &window.current_boundary,
                    )
                    .await
            }));
        }
        for upload in uploads {
            upload.await.expect("join upload").expect("upload window");
        }

        client
            .publish_writer_location_watermark(scenario.latest_location)
            .await
            .expect("publish final watermark");

        let uploaded_boundaries = ordered_windows
            .iter()
            .map(|window| window.latest_location)
            .collect::<Vec<_>>();
        let mut cases = Vec::<BoundaryCheckCase>::with_capacity(SAMPLE_COUNT);
        for sample_idx in 0..SAMPLE_COUNT {
            let boundary = *uploaded_boundaries
                .choose(&mut rng)
                .expect("uploaded boundary exists");
            let prefix_end = *boundary as usize;
            let prefix_operations = &scenario.operations[..=prefix_end];
            let snapshot = summarize_operations(prefix_operations);
            let mut known_keys = snapshot
                .latest_locations
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            known_keys.sort();
            let mut active_keys = snapshot
                .values
                .iter()
                .filter_map(|(key, value)| value.as_ref().map(|_| key.clone()))
                .collect::<Vec<_>>();
            active_keys.sort();
            let min_range_start = prefix_end.saturating_sub(63);
            let range_start_index = rng.gen_range(min_range_start..=prefix_end);
            let max_range_len = (prefix_end - range_start_index + 1).min(24);
            let range_len = NonZeroU64::new(rng.gen_range(1..=max_range_len) as u64)
                .expect("non-zero range length");
            let multi_keys = sample_distinct_keys(&mut rng, &known_keys, 6);
            let key_proof_keys = sample_distinct_keys(&mut rng, &active_keys, 4);
            let mut query_keys = sample_distinct_keys(&mut rng, &known_keys, 6);
            query_keys.push(missing_test_key(sample_idx));
            if !scenario.all_keys.is_empty() {
                query_keys
                    .push(scenario.all_keys[rng.gen_range(0..scenario.all_keys.len())].clone());
            }
            cases.push(BoundaryCheckCase {
                plan: BoundaryCheckPlan {
                    boundary,
                    range_start: Location::new(range_start_index as u64),
                    range_len,
                    multi_keys,
                    key_proof_keys,
                },
                query_keys,
            });
        }

        let plans = cases
            .iter()
            .map(|case| case.plan.clone())
            .collect::<Vec<_>>();
        let references = build_random_local_boundary_references(SCENARIO_SEED, &plans).await;

        for (sample_idx, (case, reference)) in cases.iter().zip(references.iter()).enumerate() {
            let boundary = case.plan.boundary;
            let prefix_end = *boundary as usize;
            let prefix_operations = &scenario.operations[..=prefix_end];
            let snapshot = summarize_operations(prefix_operations);

            let query_key_refs = case
                .query_keys
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>();
            let queried = client
                .query_many_at(&query_key_refs, boundary)
                .await
                .expect("query many");
            assert_eq!(queried.len(), case.query_keys.len());
            for (index, key) in case.query_keys.iter().enumerate() {
                let expected = snapshot
                    .latest_locations
                    .get(key)
                    .map(|location| VersionedValue {
                        key: key.clone(),
                        location: *location,
                        value: snapshot.values.get(key).cloned().unwrap_or(None),
                    });
                assert_eq!(
                    queried[index],
                    expected,
                    "query mismatch for sample {sample_idx} key {}",
                    String::from_utf8_lossy(key)
                );
            }

            let historical_range = client
                .operation_range_proof(
                    boundary,
                    case.plan.range_start,
                    case.plan.range_len.get() as u32,
                )
                .await
                .expect("historical range proof");
            assert_eq!(historical_range.root, reference.ops_root);
            assert_eq!(historical_range.proof, reference.historical_range_proof);
            assert_eq!(
                historical_range.operations,
                reference.historical_range_operations
            );
            assert!(historical_range.verify());

            let multi_key_refs = case
                .plan
                .multi_keys
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>();
            let remote_multi = client
                .multi_proof_at(boundary, &multi_key_refs)
                .await
                .expect("remote multi proof");
            assert_eq!(remote_multi.root, reference.ops_root);
            assert_eq!(remote_multi.proof, reference.multi_proof);
            assert_eq!(remote_multi.operations, reference.multi_operations);
            assert!(remote_multi.verify());

            assert_eq!(
                client
                    .current_root_at(boundary)
                    .await
                    .expect("current root"),
                reference.current_root
            );

            let current_range = client
                .current_operation_range_proof(
                    boundary,
                    case.plan.range_start,
                    case.plan.range_len.get() as u32,
                )
                .await
                .expect("current range proof");
            assert_eq!(current_range.root, reference.current_root);
            assert_eq!(current_range.proof, reference.current_range_proof);
            assert_eq!(current_range.operations, reference.current_range_operations);
            assert_eq!(current_range.chunks, reference.current_chunks);
            assert!(current_range.verify());

            for key in &case.plan.key_proof_keys {
                let remote = client
                    .key_value_proof_at(boundary, key.as_slice())
                    .await
                    .expect("key value proof");
                let expected = &reference.key_proofs[key];
                assert_eq!(remote.root, reference.current_root);
                assert_eq!(remote.proof, expected.proof);
                assert_eq!(remote.operation, expected.operation);
                assert!(remote.verify());
            }
        }
    }

    #[tokio::test]
    async fn concurrent_uploads_allow_current_proofs_below_published_low_watermark() {
        let reference = build_local_qmdb_reference().await;
        let servers = spawn_test_server().await;
        let client = servers.qmdb_client();
        let all_operations = reference.operations;
        let split_a = 3usize;
        let split_b = *reference.key_proofs[b"gamma".as_slice()].proof.proof.loc as usize + 1;
        let latest = Location::new(all_operations.len() as u64 - 1);
        let lower_watermark = Location::new(split_b as u64 - 1);
        let boundary_a =
            current_boundary_state_from_operations(None, &all_operations[..split_a]).await;
        let boundary_b = current_boundary_state_from_operations(
            Some(&all_operations[..split_a]),
            &all_operations[..split_b],
        )
        .await;
        let boundary_c = current_boundary_state_from_operations(
            Some(&all_operations[..split_b]),
            &all_operations,
        )
        .await;

        let client_a = client.clone();
        let client_b = client.clone();
        let client_c = client.clone();
        let (upload_c, upload_a, upload_b) = tokio::join!(
            client_c.upload_operations_with_current_boundary(
                latest,
                &all_operations[split_b..],
                &boundary_c
            ),
            client_a.upload_operations_with_current_boundary(
                Location::new(split_a as u64 - 1),
                &all_operations[..split_a],
                &boundary_a
            ),
            client_b.upload_operations_with_current_boundary(
                Location::new(split_b as u64 - 1),
                &all_operations[split_a..split_b],
                &boundary_b
            ),
        );
        upload_c.expect("upload trailing slice");
        upload_a.expect("upload leading slice");
        upload_b.expect("upload middle slice");
        assert!(matches!(
            client
                .query_many_at(&[b"gamma".as_slice()], latest)
                .await
                .expect_err("watermark not yet published"),
            QmdbError::WatermarkTooLow { .. }
        ));
        client
            .publish_writer_location_watermark(latest)
            .await
            .expect("publish watermark");

        let prefix = &all_operations[..=*lower_watermark as usize];
        let expected_root = rebuilt_current_root(prefix).await;
        assert_eq!(
            client
                .current_root_at(lower_watermark)
                .await
                .expect("current root at lower watermark"),
            expected_root
        );

        let range = client
            .current_operation_range_proof(lower_watermark, Location::new(0), 3)
            .await
            .expect("range proof");
        assert_eq!(range.root, expected_root);
        assert!(range.verify());

        let alpha = client
            .key_value_proof_at(lower_watermark, b"alpha".as_slice())
            .await
            .expect("alpha key proof at lower watermark");
        assert_eq!(alpha.root, expected_root);
        assert!(alpha.verify());

        let gamma = client
            .key_value_proof_at(lower_watermark, b"gamma".as_slice())
            .await
            .expect("gamma key proof at lower watermark");
        assert_eq!(gamma.root, expected_root);
        assert!(gamma.verify());

        let historical = client
            .multi_proof_at(lower_watermark, &[b"alpha".as_slice(), b"gamma".as_slice()])
            .await
            .expect("historical proof below low watermark");
        assert!(historical.verify());
    }

    #[tokio::test]
    async fn current_proofs_require_uploaded_batch_boundary() {
        let reference = build_local_qmdb_reference().await;
        let servers = spawn_test_server().await;
        let client = servers.qmdb_client();
        let current_boundary =
            current_boundary_state_from_operations(None, &reference.operations).await;

        client
            .upload_operations(reference.latest_location, &reference.operations)
            .await
            .expect("upload local qmdb ops");
        client
            .upload_current_boundary_state(reference.latest_location, &current_boundary)
            .await
            .expect("upload current boundary");
        client
            .publish_writer_location_watermark(reference.latest_location)
            .await
            .expect("publish watermark");

        let non_boundary = reference.latest_location - 1;
        assert!(matches!(
            client.current_root_at(non_boundary).await,
            Err(QmdbError::CurrentProofRequiresBatchBoundary { .. })
        ));
        assert!(matches!(
            client
                .current_operation_range_proof(non_boundary, Location::new(0), 1)
                .await,
            Err(QmdbError::CurrentProofRequiresBatchBoundary { .. })
        ));
        assert!(matches!(
            client
                .key_value_proof_at(non_boundary, b"alpha".as_slice())
                .await,
            Err(QmdbError::CurrentProofRequiresBatchBoundary { .. })
        ));
    }

    #[tokio::test]
    async fn immutable_watermark_publish_syncs_before_returning() {
        let servers = spawn_test_server().await;
        let client = servers.immutable_client();

        let key_a = immutable_key(0xAA);
        let key_b = immutable_key(0xBB);
        let value_a = b"first".to_vec();
        let value_b = b"second".to_vec();

        let operations_1 = vec![
            ImmutableOperation::Set(key_a.clone(), value_a.clone()),
            ImmutableOperation::Commit(None),
        ];
        let loc_1 = Location::new(1);

        client
            .upload_operations(loc_1, &operations_1)
            .await
            .expect("upload batch 1");
        client
            .publish_writer_location_watermark(loc_1)
            .await
            .expect("publish watermark 1");

        let got = client
            .get_at(&key_a, loc_1)
            .await
            .expect("get key_a after watermark 1")
            .expect("key_a should be present");
        assert_eq!(got.key, key_a);
        assert_eq!(got.value, Some(value_a));

        let operations_2 = vec![
            ImmutableOperation::Set(key_b.clone(), value_b.clone()),
            ImmutableOperation::Commit(None),
        ];
        let loc_2 = Location::new(3);

        client
            .upload_operations(loc_2, &operations_2)
            .await
            .expect("upload batch 2");
        client
            .publish_writer_location_watermark(loc_2)
            .await
            .expect("publish watermark 2");

        let got_b = client
            .get_at(&key_b, loc_2)
            .await
            .expect("get key_b after watermark 2")
            .expect("key_b should be present");
        assert_eq!(got_b.key, key_b);
        assert_eq!(got_b.value, Some(value_b));

        let got_a_again = client
            .get_at(&key_a, loc_2)
            .await
            .expect("get key_a at higher watermark")
            .expect("key_a still present at higher watermark");
        assert_eq!(got_a_again.key, key_a);

        let _root = client
            .root_at(loc_2)
            .await
            .expect("root at final watermark");

        let proof = client
            .operation_range_proof(loc_2, Location::new(0), 4)
            .await
            .expect("full range proof");
        assert!(proof.verify());
    }

    /// `load_operation_bytes_range` uses an inclusive store `end` key at
    /// `encode_operation_key(end_exclusive - 1)`; this must match contiguous windows from
    /// [`OrderedClient::operation_range_proof`].
    #[tokio::test]
    async fn load_operation_bytes_range_matches_proof_windows_and_inclusive_end() {
        let servers = spawn_test_server().await;
        let client = servers.qmdb_client();
        let ops: Vec<BatchOperation> = (0..5)
            .map(|i| {
                BatchOperation::Update(QmdbUpdate {
                    key: format!("k{i}").into_bytes(),
                    value: vec![i as u8],
                    next_key: Vec::new(),
                })
            })
            .collect();
        let boundary = current_boundary_state_from_operations(None, &ops).await;
        let batch_boundary = Location::new(4);
        client
            .upload_operations(batch_boundary, &ops)
            .await
            .expect("upload");
        client
            .upload_current_boundary_state(batch_boundary, &boundary)
            .await
            .expect("boundary upload");
        client
            .publish_writer_location_watermark(batch_boundary)
            .await
            .expect("publish");

        let wm = batch_boundary;
        let store = client.inner();
        let session = store.create_session();
        let decode_cfg = (
            ((0..=MAX_OPERATION_SIZE).into(), ()),
            ((0..=MAX_OPERATION_SIZE).into(), ()),
        );

        let full = harness_load_operation_bytes_range(store, &session, Location::new(0), Location::new(5))
            .await
            .expect("full range");
        assert_eq!(full.len(), 5, "locations [0,5) => five encoded rows");

        let proof_full = client
            .operation_range_proof(wm, Location::new(0), 5)
            .await
            .expect("proof full");
        assert_eq!(proof_full.operations.len(), 5);
        for i in 0..5 {
            let decoded = BatchOperation::decode_cfg(full[i].as_slice(), &decode_cfg).expect("decode");
            assert_eq!(decoded, proof_full.operations[i]);
        }

        let mid = harness_load_operation_bytes_range(store, &session, Location::new(2), Location::new(4))
            .await
            .expect("mid range");
        assert_eq!(mid.len(), 2);
        assert_eq!(mid[0], full[2]);
        assert_eq!(mid[1], full[3]);

        let proof_mid = client
            .operation_range_proof(wm, Location::new(2), 2)
            .await
            .expect("proof mid");
        assert_eq!(proof_mid.operations.as_slice(), &proof_full.operations[2..4]);

        let single = harness_load_operation_bytes_range(store, &session, Location::new(4), Location::new(5))
            .await
            .expect("single");
        assert_eq!(single.len(), 1);
        assert_eq!(single[0], full[4]);

        assert!(
            harness_load_operation_bytes_range(store, &session, Location::new(3), Location::new(3))
                .await
                .expect("empty")
                .is_empty()
        );
    }

    /// Same inclusive-end contract for authenticated operation keys (`load_auth_operation_bytes_range`).
    #[tokio::test]
    async fn load_auth_operation_bytes_range_inclusive_end_aligns_with_slice() {
        let servers = spawn_test_server().await;
        let client = servers.immutable_client();
        let key = immutable_key(0xAB);
        let ops = vec![
            ImmutableOperation::Set(key.clone(), b"v0".to_vec()),
            ImmutableOperation::Set(key.clone(), b"v1".to_vec()),
            ImmutableOperation::Set(key, b"v2".to_vec()),
        ];
        let latest = Location::new(2);
        client
            .upload_operations(latest, &ops)
            .await
            .expect("upload");
        client
            .publish_writer_location_watermark(latest)
            .await
            .expect("publish");

        let store = client.inner();
        let session = store.create_session();
        let ns = AuthenticatedBackendNamespace::Immutable;

        let full = harness_load_auth_operation_bytes_range(&session, ns, Location::new(0), Location::new(3))
            .await
            .expect("full");
        assert_eq!(full.len(), 3);

        let mid = harness_load_auth_operation_bytes_range(&session, ns, Location::new(1), Location::new(3))
            .await
            .expect("mid");
        assert_eq!(mid.len(), 2);
        assert_eq!(mid[0], full[1]);
        assert_eq!(mid[1], full[2]);

        assert!(
            harness_load_auth_operation_bytes_range(&session, ns, Location::new(2), Location::new(2))
                .await
                .expect("empty")
                .is_empty()
        );
    }
}

#[cfg(test)]
async fn harness_load_operation_bytes_range(
    client: &StoreClient,
    session: &SerializableReadSession,
    start: Location,
    end_location_exclusive: Location,
) -> Result<Vec<Vec<u8>>, QmdbError> {
    let core = HistoricalOpsClientCore {
        client,
        config: &QmdbConfig::default(),
        query_visible_sequence: None,
    };
    core.load_operation_bytes_range(session, start, end_location_exclusive)
        .await
}

#[cfg(test)]
async fn harness_load_auth_operation_bytes_range(
    session: &SerializableReadSession,
    namespace: AuthenticatedBackendNamespace,
    start: Location,
    end_location_exclusive: Location,
) -> Result<Vec<Vec<u8>>, QmdbError> {
    load_auth_operation_bytes_range(session, namespace, start, end_location_exclusive).await
}
