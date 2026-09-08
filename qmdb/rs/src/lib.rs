#![allow(clippy::type_complexity)]

//! Store-backed bridge for Commonware authenticated storage proofs.
//!
//! The crate currently supports multiple Commonware authenticated backends:
//! - ordered QMDB (`qmdb::any::ordered` and `qmdb::current::ordered`)
//! - unordered QMDB (`qmdb::any::unordered` and current hit proofs when callers
//!   upload current-boundary rows)
//! - immutable (`qmdb::immutable`)
//! - keyless (`qmdb::keyless`)
//!
//! Callers provide authenticated Commonware operation ranges and stage their Store rows
//! without constructing an uploader or reading remote state. An application-owned durable
//! queue publishes the watermark after the whole contiguous prefix is durable.
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
#[cfg(feature = "test-utils")]
pub use codec::{CHUNK_FAMILY, NODE_FAMILY};
mod connect;
mod connect_client;
mod core;
pub mod error;
pub mod proof;
pub mod proto;
pub mod prune;
mod request;
#[cfg(test)]
mod request_tests;
pub(crate) mod storage;

mod authenticated_range;
mod immutable;
mod keyless;
mod ordered;
mod subscription;
mod unordered;

pub use authenticated_range::{
    prepare_authenticated_range, stage_authenticated_range, stage_watermark,
    AuthenticatedOperationRange, PreparedAuthenticatedRange, UploadOperation,
};
pub use error::{ProofKind, QmdbError};
pub use immutable::ImmutableClient;
pub use keyless::KeylessClient;
pub use ordered::OrderedClient;
pub use proof::{
    CurrentOperationRangeProofResult, OperationRangeCheckpoint, RawKeyValueProof, RawMultiProof,
    VerifiedCurrentRange, VerifiedKeyLookup, VerifiedKeyRange, VerifiedKeyValue,
    VerifiedMultiOperations, VerifiedOperationRange,
};
pub use unordered::UnorderedClient;

pub use boundary::recover_boundary_state;
pub use connect::{
    immutable_operation_log_connect_stack, keyless_operation_log_connect_stack,
    ordered_connect_stack, ordered_operation_log_connect_stack, unordered_connect_stack,
    unordered_operation_log_connect_stack, OrderedConnect, UnorderedConnect,
};
pub use connect_client::{
    CurrentOperationClient, CurrentOperationRangeProof, OperationLogClient, OperationLogRangeProof,
    OperationLogSubscribeProof, OperationLogSubscription, OrderedConnectClient,
    UnorderedConnectClient,
};

use commonware_cryptography::Digest;
use commonware_storage::merkle::{self, Family, Graftable, Location};
use commonware_storage::qmdb::current::proof::OpsRootWitness;

/// Maximum encoded operation size for QMDB key and value payloads (u16 length on the wire).
pub const MAX_OPERATION_SIZE: usize = u16::MAX as usize;

/// Historical value resolved for one logical key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionedValue<K, V, F: Family> {
    pub key: K,
    pub location: Location<F>,
    pub value: Option<V>,
}

/// Current-state rows for one uploaded current batch boundary.
///
/// Current QMDB uploads carry more than the historical op log: each published
/// batch boundary also stores the current-state root, op-root witness, and the
/// subset of bitmap chunks and grafted nodes that changed at that boundary.
/// This struct is that versioned delta payload.
///
/// Callers typically obtain it from [`recover_boundary_state`], using a local
/// Commonware current DB, then attach it with
/// [`PreparedAuthenticatedRange::with_current_boundary`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentBoundaryState<D: Digest, const N: usize, F: Graftable> {
    /// Canonical current-state root at this batch boundary.
    pub root: D,
    /// Number of complete, all-zero chunks discarded from the start of the source bitmap.
    /// Source pruning preserves the root. This count does not delete backend rows.
    pub pruned_chunks: u64,
    /// Proof that the raw operation-log root is committed by `root`.
    pub ops_root_witness: OpsRootWitness<F, D>,
    /// Changed bitmap chunks keyed by chunk index.
    pub chunks: Vec<(u64, [u8; N])>,
    /// Changed grafted digests keyed by ops-space Merkle position.
    pub grafted_nodes: Vec<(merkle::Position<F>, D)>,
}
