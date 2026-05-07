//! Store-backed bridge for Commonware authenticated storage proofs.
//!
//! The crate currently supports multiple Commonware authenticated backends:
//! - ordered QMDB (`qmdb::any` and `qmdb::current::ordered`)
//! - unordered QMDB (`qmdb::any::unordered` and current hit proofs when callers
//!   upload current-boundary rows)
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
//! use the global ops Merkle nodes stored by `Position`.
//!
//! Current QMDB proofs use versioned current-state deltas:
//! - bitmap chunk rows
//! - grafted-node rows
//!
//! Those rows are versioned by uploaded batch boundary `Location`, not by the
//! final published watermark. That is what preserves lower-boundary current
//! proofs below a later published low watermark.

mod auth;
mod boundary;
pub(crate) mod codec;
mod connect;
mod connect_client;
mod core;
pub mod error;
pub mod proof;
pub mod prune;
pub(crate) mod storage;

mod immutable;
mod keyless;
mod ordered;
mod subscription;
mod unordered;
mod writer;

pub use error::{ProofKind, QmdbError};
pub use immutable::ImmutableClient;
pub use keyless::KeylessClient;
pub use ordered::OrderedClient;
pub use proof::{
    CurrentOperationRangeProofResult, OperationRangeCheckpoint, RawKeyValueProof, RawMultiProof,
    VariantRoot, VerifiedCurrentRange, VerifiedKeyLookup, VerifiedKeyRange, VerifiedKeyValue,
    VerifiedMultiOperations, VerifiedOperationRange, VerifiedUnorderedKeyValue,
    VerifiedVariantRange,
};
pub use unordered::UnorderedClient;
pub use writer::{
    build_immutable_upload, build_keyless_upload, build_ordered_upload, build_unordered_upload,
    BuiltImmutableUpload, BuiltKeylessUpload, BuiltOrderedUpload, BuiltUnorderedUpload,
    ImmutableWriter, KeylessWriter, OrderedWriter, PreparedUpload, PreparedWatermark,
    UnorderedWriter,
};

pub use boundary::recover_boundary_state;
pub use connect::{
    immutable_operation_log_connect_stack, keyless_operation_log_connect_stack,
    ordered_connect_stack, unordered_connect_stack, unordered_operation_log_connect_stack,
    OrderedConnect, UnorderedConnect,
};
pub use connect_client::{
    CurrentOperationClient, CurrentOperationRangeProof, OperationLogClient, OperationLogRangeProof,
    OperationLogSubscribeProof, OperationLogSubscription, OrderedConnectClient,
    UnorderedConnectClient,
};

use commonware_codec::Encode;
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::merkle::{self, Family, Location, Position, Proof};
use commonware_storage::qmdb::current::proof::OpsRootWitness;

/// Maximum encoded operation size for QMDB key and value payloads (u16 length on the wire).
pub const MAX_OPERATION_SIZE: usize = u16::MAX as usize;

/// QMDB proof/root variant supported by `exoware-qmdb`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QmdbVariant {
    /// Historical `qmdb::any` root / proof over the uploaded ordered operation log.
    Any,
    /// Current-state `qmdb::current::ordered` root / proof at an uploaded batch boundary.
    Current,
}

/// Historical value resolved for one logical key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionedValue<K, V, F: Family> {
    pub key: K,
    pub location: Location<F>,
    pub value: Option<V>,
}

/// Metadata returned after uploading one batch of QMDB operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UploadReceipt<F: Family> {
    /// Monotonic request id assigned by the writer for this upload.
    pub writer_request_id: u64,
    /// Inclusive maximum Location of ops in this batch.
    pub latest_location: Location<F>,
    /// Store sequence number at which this upload's rows became durable.
    pub store_sequence_number: u64,
    /// The watermark this batch published, if any. `None` when pipelining
    /// deferred the watermark to a later `flush()` or batch.
    pub writer_location_watermark: Option<PublishedCheckpoint<F>>,
}

/// Writer publication point that is known to be durable in Store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublishedCheckpoint<F: Family> {
    /// Inclusive maximum QMDB Location authorized by this checkpoint.
    pub location: Location<F>,
    /// Store sequence number at which the checkpoint became visible.
    pub sequence_number: u64,
}

/// Caller-owned frontier for resuming a single-writer helper without reading
/// the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriterState<D: Digest, F: Family> {
    pub peaks: Vec<(Position<F>, u32, D)>,
    pub ops_size: Position<F>,
    pub next_location: Location<F>,
}

impl<D: Digest, F: Family> WriterState<D, F> {
    pub fn empty() -> Self {
        Self {
            peaks: Vec::new(),
            ops_size: Position::new(0),
            next_location: Location::new(0),
        }
    }

    pub fn latest_committed_location(&self) -> Option<Location<F>> {
        self.next_location.checked_sub(1)
    }

    pub fn from_checkpoint<H: Hasher<Digest = D>>(
        checkpoint: &OperationRangeCheckpoint<D, F>,
    ) -> Result<Self, QmdbError> {
        Ok(Self {
            peaks: checkpoint.reconstruct_peaks::<H>()?,
            ops_size: Position::try_from(checkpoint.proof.leaves).map_err(|e| {
                QmdbError::CorruptData(format!("invalid checkpoint leaf count: {e}"))
            })?,
            next_location: checkpoint
                .watermark
                .checked_add(1)
                .ok_or_else(|| QmdbError::CorruptData("checkpoint watermark overflow".into()))?,
        })
    }

    pub fn from_proof<H, Op>(
        watermark: Location<F>,
        start_location: Location<F>,
        proof: &Proof<F, D>,
        operations: &[Op],
    ) -> Result<Self, QmdbError>
    where
        H: Hasher<Digest = D>,
        Op: Encode,
    {
        let encoded_operations: Vec<Vec<u8>> =
            operations.iter().map(|op| op.encode().to_vec()).collect();
        if start_location != Location::new(0)
            || encoded_operations.len() as u64 != proof.leaves.as_u64()
        {
            return Err(QmdbError::CorruptData(
                "WriterState::from_proof requires a full operation-prefix proof".into(),
            ));
        }
        let ops_size = Position::try_from(proof.leaves)
            .map_err(|e| QmdbError::CorruptData(format!("invalid proof leaf count: {e}")))?;
        let extension = crate::core::extend_merkle_from_peaks::<F, H, _>(
            Vec::new(),
            Position::new(0),
            encoded_operations.iter().map(Vec::as_slice),
        )?;
        if extension.size != ops_size {
            return Err(QmdbError::CorruptData(format!(
                "proof size mismatch: expected {ops_size}, got {}",
                extension.size
            )));
        }
        Ok(Self {
            peaks: extension.peaks,
            ops_size,
            next_location: watermark
                .checked_add(1)
                .ok_or_else(|| QmdbError::CorruptData("proof watermark overflow".into()))?,
        })
    }
}

/// Current-state rows for one uploaded ordered batch boundary.
///
/// Ordered QMDB uploads carry more than the historical op log: each published
/// batch boundary also stores the current-state root plus the subset of bitmap
/// chunks and grafted nodes that changed at that boundary. This struct is
/// that versioned delta payload.
///
/// Callers typically obtain it from [`recover_boundary_state`], using a local
/// Commonware `current::ordered::Db`, and then pass it to
/// [`OrderedWriter::prepare_upload`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentBoundaryState<D: Digest, const N: usize, F: Family> {
    /// Canonical current-state root at this batch boundary.
    pub root: D,
    /// Optional proof that the raw operation-log root is committed by `root`.
    pub ops_root_witness: Option<OpsRootWitness<D>>,
    /// Changed bitmap chunks keyed by chunk index.
    pub chunks: Vec<(u64, [u8; N])>,
    /// Changed grafted digests keyed by ops-space Merkle position.
    pub grafted_nodes: Vec<(merkle::Position<F>, D)>,
}
