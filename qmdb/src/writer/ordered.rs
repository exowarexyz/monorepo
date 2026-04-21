//! Single-writer helper for the ordered QMDB variant.
//!
//! In addition to op / presence / update-index / MMR node / watermark rows,
//! ordered batches carry current-state rows (bitmap chunks, grafted-MMR
//! nodes, and the current-state root) keyed by the batch boundary Location.
//! Those are deterministic from the full op history but require running a
//! local commonware `current::ordered::Db` to compute; the writer takes them
//! as an input rather than trying to compute them internally.
//!
//! Callers typically drive a local commonware QMDB alongside the writer,
//! reading the new current-boundary state from the local Db after each batch
//! and passing it in via [`OrderedWriter::upload_and_publish`].
//!
//! Typical flow:
//!
//! 1. apply one batch to a local `current::ordered::Db`
//! 2. recover the boundary delta with [`crate::recover_boundary_state`]
//! 3. upload the historical ordered ops plus that boundary delta with
//!    [`OrderedWriter::upload_and_publish`]
//!
//! The writer itself does not inspect the local DB; it only consumes the
//! caller-supplied [`crate::CurrentBoundaryState`].
//!
//! Multiple [`OrderedWriter::upload_and_publish`] calls may be in flight on
//! the same writer at once. The writer assigns locations and safe watermark
//! candidates in dispatch order, then allows the PUTs themselves to run
//! concurrently; later ACKs do not publish past an earlier hole.

use std::marker::PhantomData;

use commonware_codec::{Codec, Decode, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::mmr::{Location, Position};
use commonware_storage::qmdb::{
    any::ordered::variable::Operation as QmdbOperation, operation::Key as QmdbKey,
};
use exoware_sdk_rs::keys::Key;
use exoware_sdk_rs::StoreClient;

use crate::codec::{encode_node_key, encode_watermark_key};
use crate::core::{extend_mmr_from_peaks, PreparedCurrentBoundaryUpload, PreparedUpload};
use crate::error::QmdbError;
use crate::writer::core::{Cache, WriterCore};
use crate::{CurrentBoundaryState, UploadReceipt, WriterState};

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
    let ext = extend_mmr_from_peaks::<H, _>(peaks, prev_ops_size, prepared_ops.op_bytes())?;
    let operation_count = prepared_ops.operation_count;
    let keyed_operation_count = prepared_ops.keyed_operation_count;

    let mut rows = prepared_ops.into_all_rows();
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
        operation_count,
        keyed_operation_count,
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
    /// Construct a writer from caller-supplied frontier state. No store I/O.
    pub fn new(client: StoreClient, state: WriterState<H::Digest>) -> Self {
        Self {
            client,
            core: WriterCore::from_cache(Cache::from_writer_state(state)),
            _marker: PhantomData,
        }
    }

    pub fn empty(client: StoreClient) -> Self {
        Self::new(client, WriterState::empty())
    }

    pub async fn latest_published_watermark(&self) -> Option<Location> {
        self.core.latest_published().await
    }

    /// Upload `ops` plus the caller-supplied current boundary state in one
    /// atomic PUT.
    ///
    /// `current_boundary` must correspond to the state after applying `ops`
    /// to the caller's local ordered Commonware DB. In the common case callers
    /// produce it with [`crate::recover_boundary_state`] immediately after the
    /// local `apply_batch`.
    ///
    /// This method is concurrency-safe for a single writer instance: multiple
    /// calls may be awaited simultaneously and the writer will preserve the
    /// correct contiguous watermark semantics internally.
    pub async fn upload_and_publish(
        &self,
        ops: &[QmdbOperation<K, V>],
        current_boundary: &CurrentBoundaryState<H::Digest, N>,
    ) -> Result<UploadReceipt, QmdbError> {
        let prepared = self
            .core
            .prepare(ops.len() as u64, |ctx| {
                let built = build_ordered_upload::<H, K, V, N>(
                    ctx.peaks,
                    ctx.ops_size,
                    ctx.latest_location,
                    ops,
                    current_boundary,
                    ctx.watermark_at,
                )?;
                Ok(crate::writer::core::BuildResult {
                    new_peaks: built.new_peaks,
                    new_ops_size: built.new_ops_size,
                    output: built.rows,
                })
            })
            .await?;

        let refs: Vec<(&Key, &[u8])> = prepared
            .output
            .iter()
            .map(|(k, v)| (k, v.as_slice()))
            .collect();
        match self.client.ingest().put(&refs).await {
            Ok(_) => {
                self.core.ack_success(prepared.dispatch_id).await;
                Ok(UploadReceipt {
                    latest_location: prepared.latest_location,
                    writer_location_watermark: prepared.watermark_at,
                })
            }
            Err(err) => {
                let msg = format!(
                    "ordered upload ending at {} failed: {err}",
                    prepared.latest_location
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
