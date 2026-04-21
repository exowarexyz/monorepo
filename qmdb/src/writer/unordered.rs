//! Single-writer helper for the unordered QMDB variant (uses the
//! unauthenticated key family shared with the ordered variant).

use std::marker::PhantomData;

use commonware_codec::{Codec, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::mmr::{Location, Position};
use commonware_storage::qmdb::{
    any::unordered::variable::Operation as UnorderedQmdbOperation, operation::Key as QmdbKey,
};
use exoware_sdk_rs::keys::Key;
use exoware_sdk_rs::StoreClient;

use crate::codec::{encode_node_key, encode_watermark_key};
use crate::core::{extend_mmr_from_peaks, PreparedUpload};
use crate::error::QmdbError;
use crate::writer::core::{Cache, WriterCore};
use crate::{UploadReceipt, WriterState};

/// Deterministic output of an unordered row-build.
#[derive(Clone, Debug)]
pub struct BuiltUnorderedUpload<D> {
    pub rows: Vec<(Key, Vec<u8>)>,
    pub new_peaks: Vec<(Position, u32, D)>,
    pub new_ops_size: Position,
    pub new_root: D,
    pub latest_location: Location,
    pub operation_count: u32,
    pub keyed_operation_count: u32,
    pub includes_watermark: bool,
}

/// Pure row-build for an unordered batch. Produces op rows, update-index
/// rows for keyed ops, presence row, MMR node rows, and (optionally) the
/// watermark row.
pub fn build_unordered_upload<H, K, V>(
    peaks: Vec<(Position, u32, H::Digest)>,
    prev_ops_size: Position,
    latest_location: Location,
    ops: &[UnorderedQmdbOperation<K, V>],
    watermark_at: Option<Location>,
) -> Result<BuiltUnorderedUpload<H::Digest>, QmdbError>
where
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    UnorderedQmdbOperation<K, V>: Encode,
{
    if ops.is_empty() {
        return Err(QmdbError::EmptyBatch);
    }
    let prepared = PreparedUpload::build_unordered(latest_location, ops)?;
    let ext = extend_mmr_from_peaks::<H, _>(peaks, prev_ops_size, prepared.op_bytes())?;
    let operation_count = prepared.operation_count;
    let keyed_operation_count = prepared.keyed_operation_count;

    let mut rows = prepared.into_all_rows();
    for (pos, digest) in &ext.new_nodes {
        rows.push((encode_node_key(*pos), digest.as_ref().to_vec()));
    }
    if let Some(loc) = watermark_at {
        rows.push((encode_watermark_key(loc), Vec::new()));
    }
    Ok(BuiltUnorderedUpload {
        rows,
        new_peaks: ext.peaks,
        new_ops_size: ext.size,
        new_root: ext.root,
        latest_location,
        operation_count,
        keyed_operation_count,
        includes_watermark: watermark_at.is_some(),
    })
}

/// Sole-writer unordered QMDB helper. Pipelining, flushing, failure, and
/// sole-writer contract are identical to
/// [`KeylessWriter`](crate::KeylessWriter) — see its docs for details.
pub struct UnorderedWriter<H: Hasher, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync> {
    client: StoreClient,
    core: WriterCore<H::Digest>,
    _marker: PhantomData<(K, V)>,
}

impl<H, K, V> UnorderedWriter<H, K, V>
where
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    UnorderedQmdbOperation<K, V>: Encode,
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

    pub async fn upload_and_publish(
        &self,
        ops: &[UnorderedQmdbOperation<K, V>],
    ) -> Result<UploadReceipt, QmdbError> {
        let prepared = self
            .core
            .prepare(ops.len() as u64, |ctx| {
                let built = build_unordered_upload::<H, K, V>(
                    ctx.peaks,
                    ctx.ops_size,
                    ctx.latest_location,
                    ops,
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
                    "unordered upload ending at {} failed: {err}",
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

impl<H, K, V> std::fmt::Debug for UnorderedWriter<H, K, V>
where
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnorderedWriter").finish_non_exhaustive()
    }
}
