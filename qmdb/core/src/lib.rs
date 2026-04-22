//! Shared read-side and proof logic for Exoware QMDB.
//!
//! This crate intentionally excludes transport-specific store clients and
//! write-side helpers so the same logic can back both native Rust and
//! browser/WASM facades.

pub mod boundary;
pub mod codec;
pub mod error;
pub mod proof;
pub mod read_store;
pub mod stream;

pub use boundary::recover_boundary_state;
pub use error::QmdbError;
pub use proof::{
    OperationRangeCheckpoint, RawMmrProof, VariantRoot, VerifiedCurrentRange, VerifiedKeyValue,
    VerifiedMultiOperations, VerifiedOperationRange, VerifiedVariantRange,
};

use commonware_cryptography::Digest;
use commonware_storage::mmr::{Location, Position};

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
pub struct VersionedValue<K, V> {
    pub key: K,
    pub location: Location,
    pub value: Option<V>,
}

/// Current-state rows for one uploaded ordered batch boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentBoundaryState<D: Digest, const N: usize> {
    /// Canonical current-state root at this batch boundary.
    pub root: D,
    /// Changed bitmap chunks keyed by chunk index.
    pub chunks: Vec<(u64, [u8; N])>,
    /// Changed grafted-MMR digests keyed by ops-space MMR position.
    pub grafted_nodes: Vec<(Position, D)>,
}
