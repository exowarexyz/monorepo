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

mod auth;
#[cfg(any(test, feature = "test-utils"))]
mod boundary;
pub(crate) mod codec;
mod core;
pub mod error;
pub mod proof;
pub mod prune;
pub(crate) mod storage;

mod immutable;
mod keyless;
mod ordered;
mod stream;
mod unordered;
mod writer;

pub use error::QmdbError;
pub use immutable::ImmutableClient;
pub use keyless::KeylessClient;
pub use ordered::OrderedClient;
pub use proof::{
    VariantRoot, VerifiedCurrentRange, VerifiedKeyValue, VerifiedMultiOperations,
    VerifiedOperationRange, VerifiedVariantRange,
};
pub use unordered::UnorderedClient;
pub use writer::{
    build_immutable_upload, build_keyless_upload, build_ordered_upload, build_unordered_upload,
    BuiltImmutableUpload, BuiltKeylessUpload, BuiltOrderedUpload, BuiltUnorderedUpload,
    ImmutableWriter, KeylessWriter, OrderedWriter, UnorderedWriter,
};

#[cfg(any(test, feature = "test-utils"))]
pub use boundary::build_current_boundary_state;

use commonware_cryptography::Digest;
use commonware_storage::mmr::Location;

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

/// Metadata returned after uploading one batch of QMDB operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UploadReceipt {
    /// Inclusive maximum Location of ops in this batch.
    pub latest_location: Location,
    /// The watermark this batch published, if any. `None` when pipelining
    /// deferred the watermark to a later `flush()` or batch.
    pub writer_location_watermark: Option<Location>,
}

/// Current-state rows for one uploaded batch boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentBoundaryState<D: Digest, const N: usize> {
    pub root: D,
    pub chunks: Vec<(u64, [u8; N])>,
    pub grafted_nodes: Vec<(commonware_storage::mmr::Position, D)>,
}

// Keep test module inline since it tests the full integrated stack.
