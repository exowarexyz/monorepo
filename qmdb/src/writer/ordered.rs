//! Single-writer helper for the ordered QMDB variant.
//!
//! In addition to op / presence / update-index / MMR node / watermark rows,
//! ordered batches carry current-state rows (bitmap chunks, grafted-MMR
//! nodes, and the current-state root) keyed by the batch boundary Location.
//! Those are deterministic from the full op history but require running a
//! local commonware `current::ordered::Db` (or the test-only rebuild helper)
//! to compute; the writer takes them as an input rather than trying to
//! compute them internally.
//!
//! Callers typically drive a local commonware QMDB alongside the writer,
//! reading the new current-boundary state from the local Db after each batch
//! and passing it in via [`OrderedWriter::upload_and_publish`].
//!
//! TODO: once upstream commonware exposes the `MerkleizedBatch.bitmap` and
//! `.grafted` fields publicly, wire this module to extract those deltas
//! directly from a local `current::ordered::Db` so callers can mirror
//! without the O(n_total_ops) `build_current_boundary_state` rebuild path.

use std::marker::PhantomData;

use commonware_codec::{Codec, Decode, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::mmr::{Location, Position};
use commonware_storage::qmdb::{
    any::ordered::variable::Operation as QmdbOperation, operation::Key as QmdbKey,
};
use exoware_sdk_rs::keys::Key;
use exoware_sdk_rs::StoreClient;

use crate::codec::{
    decode_watermark_location, encode_node_key, encode_watermark_key, mmr_size_for_watermark,
    WATERMARK_CODEC,
};
use crate::core::{extend_mmr_from_peaks, load_ops_peaks, PreparedCurrentBoundaryUpload, PreparedUpload};
use crate::error::QmdbError;
use crate::writer::core::{Cache, WriterCore};
use crate::{CurrentBoundaryState, UploadReceipt};

#[derive(Clone, Debug)]
pub struct BuiltOrderedUpload<D> {
    pub rows: Vec<(Key, Vec<u8>)>,
    pub new_peaks: Vec<(Position, u32, D)>,
    pub new_ops_size: Position,
    pub new_ops_root: D,
    pub latest_location: Location,
    pub operation_count: u32,
    pub keyed_operation_count: u32,
    pub includes_watermark: bool,
}

/// Build every store row for one ordered batch: op rows, update-index rows,
/// presence row, MMR node rows (derived from the supplied peaks), current-state
/// rows (from the caller-supplied `current_boundary`), and optionally the
/// watermark row. No I/O.
pub fn build_ordered_upload<H, K, V, const N: usize>(
    peaks: Vec<(Position, u32, H::Digest)>,
    prev_ops_size: Position,
    latest_location: Location,
    ops: &[QmdbOperation<K, V>],
    current_boundary: &CurrentBoundaryState<H::Digest, N>,
    watermark_at: Option<Location>,
) -> Result<BuiltOrderedUpload<H::Digest>, QmdbError>
where
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    QmdbOperation<K, V>: Encode,
{
    if ops.is_empty() {
        return Err(QmdbError::EmptyBatch);
    }
    let prepared_ops = PreparedUpload::build(latest_location, ops)?;
    let prepared_current = PreparedCurrentBoundaryUpload::build(latest_location, current_boundary)?;
    let encoded: Vec<Vec<u8>> = ops.iter().map(|op| op.encode().to_vec()).collect();
    let ext = extend_mmr_from_peaks::<H>(peaks, prev_ops_size, &encoded)?;

    let mut rows = prepared_ops.rows;
    rows.extend(prepared_current.rows);
    for (pos, digest) in &ext.new_nodes {
        rows.push((encode_node_key(*pos), digest.as_ref().to_vec()));
    }
    if let Some(loc) = watermark_at {
        rows.push((encode_watermark_key(loc), Vec::new()));
    }

    Ok(BuiltOrderedUpload {
        rows,
        new_peaks: ext.peaks,
        new_ops_size: ext.size,
        new_ops_root: ext.root,
        latest_location,
        operation_count: prepared_ops.operation_count,
        keyed_operation_count: prepared_ops.keyed_operation_count,
        includes_watermark: watermark_at.is_some(),
    })
}

/// Sole-writer ordered QMDB helper. Pipelining, flushing, failure, and
/// sole-writer contract are identical to
/// [`KeylessWriter`](crate::KeylessWriter) — see its docs for details.
/// `upload_and_publish` additionally requires the caller-supplied
/// `CurrentBoundaryState` for the batch.
pub struct OrderedWriter<
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
> {
    client: StoreClient,
    core: WriterCore<H::Digest>,
    _marker: PhantomData<(K, V)>,
}

impl<H, K, V, const N: usize> OrderedWriter<H, K, V, N>
where
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    QmdbOperation<K, V>: Encode + Decode,
{
    /// Construct a writer and bootstrap its in-memory state from the store
    /// in one step.
    pub async fn new(client: StoreClient) -> Result<Self, QmdbError> {
        let writer = Self {
            client,
            core: WriterCore::new(),
            _marker: PhantomData,
        };
        writer.bootstrap().await?;
        Ok(writer)
    }

    /// Re-read the store's latest watermark + peaks into local state.
    /// Call after a poisoned error to reset the writer before resuming.
    pub async fn bootstrap(&self) -> Result<(), QmdbError> {
        let session = self.client.create_session();
        let (start, end) = WATERMARK_CODEC.prefix_bounds();
        let rows = session
            .range_with_mode(&start, &end, 1, exoware_sdk_rs::RangeMode::Reverse)
            .await?;
        let latest = match rows.into_iter().next() {
            Some((key, _)) => Some(decode_watermark_location(&key)?),
            None => None,
        };
        let ops_size = match latest {
            Some(w) => mmr_size_for_watermark(w)?,
            None => Position::new(0),
        };
        let peaks = load_ops_peaks::<H>(&session, ops_size).await?;
        let next_location = latest.map_or(Location::new(0), |w| w + 1);
        self.core
            .install(Cache {
                peaks,
                ops_size,
                next_location,
                latest_published: latest,
                latest_dispatched: latest,
                pending: std::collections::VecDeque::new(),
                latest_contiguous_acked: latest,
            })
            .await;
        Ok(())
    }

    pub async fn latest_published_watermark(&self) -> Option<Location> {
        self.core.latest_published().await
    }

    /// Upload `ops` plus the caller-supplied current boundary state in one
    /// atomic PUT. `current_boundary` must correspond to the state AFTER
    /// applying `ops`.
    pub async fn upload_and_publish(
        &self,
        ops: &[QmdbOperation<K, V>],
        current_boundary: &CurrentBoundaryState<H::Digest, N>,
    ) -> Result<UploadReceipt, QmdbError> {
        let begin = self.core.begin(ops.len() as u64).await?;
        let built = build_ordered_upload::<H, K, V, N>(
            begin.peaks,
            begin.ops_size,
            begin.latest_location,
            ops,
            current_boundary,
            begin.watermark_at,
        )?;
        self.core
            .advance(crate::writer::core::BatchAdvance {
                new_peaks: built.new_peaks,
                new_ops_size: built.new_ops_size,
                latest_location: built.latest_location,
                watermark_at: begin.watermark_at,
                dispatch_id: begin.dispatch_id,
            })
            .await;

        let refs: Vec<(&Key, &[u8])> = built.rows.iter().map(|(k, v)| (k, v.as_slice())).collect();
        match self.client.ingest().put(&refs).await {
            Ok(_) => {
                self.core.ack_success(begin.dispatch_id).await;
                Ok(UploadReceipt {
                    latest_location: built.latest_location,
                    writer_location_watermark: begin.watermark_at,
                })
            }
            Err(err) => {
                let msg = format!(
                    "ordered upload ending at {} failed: {err}",
                    built.latest_location
                );
                self.core.ack_failure(msg).await;
                Err(QmdbError::Client(err))
            }
        }
    }

    pub async fn flush(&self) -> Result<(), QmdbError> {
        self.core.await_drain().await;
        let Some(target) = self.core.pending_watermark().await? else {
            return Ok(());
        };
        let key = encode_watermark_key(target);
        let empty: &[u8] = &[];
        self.client
            .ingest()
            .put(&[(&key, empty)])
            .await
            .map_err(QmdbError::Client)?;
        self.core.mark_watermark_published(target).await;
        Ok(())
    }
}

impl<H, K, V, const N: usize> std::fmt::Debug for OrderedWriter<H, K, V, N>
where
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrderedWriter").finish_non_exhaustive()
    }
}
