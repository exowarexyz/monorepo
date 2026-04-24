//! Single-writer helpers that push QMDB state into the store without reading
//! the store in the hot loop.
//!
//! Each variant exposes a pure `build_*_upload` function that deterministically
//! turns (MMR peaks, ops) into the full set of store rows, plus a stateful
//! `*Writer` wrapper around [`core::WriterCore`] that starts from caller-supplied
//! frontier state, prepares rows for caller-owned Store write batches, gates
//! in-band watermark emission on pipeline emptiness, and exposes a `flush()` to
//! publish a catch-up watermark after bursts.
//!
//! Multiple `prepare_upload` calls may be issued concurrently against the same
//! writer instance. The writer serializes frontier assignment under its
//! internal mutex, then releases that lock before any network I/O, so
//! independent Store batches can be in flight at the same time while watermark
//! publication still follows the contiguous-committed prefix.
//!
//! Callers own durability. On any PUT error the writer poisons; the caller must
//! construct a fresh writer from a caller-owned committed frontier. Since PUT rows are
//! content-addressed and MMR math is deterministic, retries are idempotent.

mod core;
mod immutable;
mod keyless;
mod ordered;
mod unordered;

pub use immutable::{build_immutable_upload, BuiltImmutableUpload, ImmutableWriter};
pub use keyless::{build_keyless_upload, BuiltKeylessUpload, KeylessWriter};
pub use ordered::{build_ordered_upload, BuiltOrderedUpload, OrderedWriter};
pub use unordered::{build_unordered_upload, BuiltUnorderedUpload, UnorderedWriter};

use commonware_storage::mmr::Location;
use exoware_sdk::{keys::Key, StoreClient, StoreWriteBatch};

use crate::{PublishedCheckpoint, QmdbError, UploadReceipt};

/// A QMDB upload that has reserved writer state and encoded its Store rows,
/// but has not yet been persisted.
///
/// Stage this into a [`StoreWriteBatch`] with the originating writer, commit
/// the batch, then mark the upload persisted with the returned Store sequence.
#[derive(Debug)]
#[must_use]
pub struct PreparedUpload {
    pub(crate) dispatch_id: u64,
    pub(crate) latest_location: Location,
    pub(crate) writer_location_watermark: Option<Location>,
    pub(crate) rows: Vec<(Key, Vec<u8>)>,
}

impl PreparedUpload {
    pub fn request_id(&self) -> u64 {
        self.dispatch_id
    }

    pub fn latest_location(&self) -> Location {
        self.latest_location
    }

    pub fn writer_location_watermark(&self) -> Option<Location> {
        self.writer_location_watermark
    }

    pub fn row_count(&self) -> usize {
        self.rows.len()
    }
}

/// A prepared QMDB watermark row that should be staged into the same Store
/// batch as the uploads it publishes.
#[derive(Debug)]
#[must_use]
pub struct PreparedWatermark {
    pub(crate) location: Location,
    pub(crate) row: (Key, Vec<u8>),
}

impl PreparedWatermark {
    pub fn location(&self) -> Location {
        self.location
    }
}

pub(crate) fn stage_rows(
    client: &StoreClient,
    batch: &mut StoreWriteBatch,
    rows: &[(Key, Vec<u8>)],
) -> Result<(), QmdbError> {
    for (key, value) in rows {
        batch.push(client, key, value)?;
    }
    Ok(())
}

pub(crate) fn stage_watermark(
    client: &StoreClient,
    batch: &mut StoreWriteBatch,
    watermark: &PreparedWatermark,
) -> Result<(), QmdbError> {
    let (key, value) = &watermark.row;
    batch.push(client, key, value)?;
    Ok(())
}

pub(crate) fn upload_receipt(prepared: &PreparedUpload, sequence_number: u64) -> UploadReceipt {
    UploadReceipt {
        writer_request_id: prepared.dispatch_id,
        latest_location: prepared.latest_location,
        store_sequence_number: sequence_number,
        writer_location_watermark: prepared.writer_location_watermark.map(|location| {
            PublishedCheckpoint {
                location,
                sequence_number,
            }
        }),
    }
}
