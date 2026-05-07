//! Single-writer helper for the unordered QMDB variant (uses the
//! unauthenticated key family shared with the ordered variant).

use std::marker::PhantomData;

use commonware_codec::{Codec, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::mmr::{Location, Position};
use commonware_storage::qmdb::{
    any::unordered::variable::Operation as UnorderedQmdbOperation, operation::Key as QmdbKey,
};
use exoware_sdk::keys::Key;
use exoware_sdk::{
    StoreBatchPublication, StoreBatchUpload, StoreClient, StorePublicationFrontierWriter,
    StoreWriteBatch,
};
use futures::future::BoxFuture;

use crate::codec::{encode_node_key, encode_watermark_key};
use crate::core::{
    extend_mmr_from_peaks, PreparedCurrentBoundaryUpload, PreparedUpload as CorePreparedUpload,
};
use crate::error::QmdbError;
use crate::writer::core::{Cache, WriterCore};
use crate::{CurrentBoundaryState, PublishedCheckpoint, UploadReceipt, WriterState};

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
    ops: &[UnorderedQmdbOperation<commonware_storage::mmr::Family, K, V>],
    watermark_at: Option<Location>,
) -> Result<BuiltUnorderedUpload<H::Digest>, QmdbError>
where
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    UnorderedQmdbOperation<commonware_storage::mmr::Family, K, V>: Encode,
{
    if ops.is_empty() {
        return Err(QmdbError::EmptyBatch);
    }
    let prepared = CorePreparedUpload::build_unordered(latest_location, ops)?;
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

pub fn build_unordered_current_upload<H, K, V, const N: usize>(
    peaks: Vec<(Position, u32, H::Digest)>,
    prev_ops_size: Position,
    latest_location: Location,
    ops: &[UnorderedQmdbOperation<commonware_storage::mmr::Family, K, V>],
    current_boundary: &CurrentBoundaryState<H::Digest, N>,
    watermark_at: Option<Location>,
) -> Result<BuiltUnorderedUpload<H::Digest>, QmdbError>
where
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    UnorderedQmdbOperation<commonware_storage::mmr::Family, K, V>: Encode,
{
    let mut built = build_unordered_upload::<H, K, V>(
        peaks,
        prev_ops_size,
        latest_location,
        ops,
        watermark_at,
    )?;
    let prepared_current = PreparedCurrentBoundaryUpload::build(latest_location, current_boundary)?;
    built.rows.extend(prepared_current.rows);
    Ok(built)
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
    UnorderedQmdbOperation<commonware_storage::mmr::Family, K, V>: Encode,
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

    pub async fn latest_published_checkpoint(&self) -> Option<PublishedCheckpoint> {
        self.core.latest_published_checkpoint().await
    }

    pub async fn prepare_upload(
        &self,
        ops: &[UnorderedQmdbOperation<commonware_storage::mmr::Family, K, V>],
    ) -> Result<super::PreparedUpload, QmdbError> {
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
        Ok(super::PreparedUpload {
            dispatch_id: prepared.dispatch_id,
            latest_location: prepared.latest_location,
            writer_location_watermark: prepared.watermark_at,
            rows: prepared.output,
        })
    }

    pub async fn prepare_current_upload<const N: usize>(
        &self,
        ops: &[UnorderedQmdbOperation<commonware_storage::mmr::Family, K, V>],
        current_boundary: &CurrentBoundaryState<H::Digest, N>,
    ) -> Result<super::PreparedUpload, QmdbError> {
        let prepared = self
            .core
            .prepare(ops.len() as u64, |ctx| {
                let built = build_unordered_current_upload::<H, K, V, N>(
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
        Ok(super::PreparedUpload {
            dispatch_id: prepared.dispatch_id,
            latest_location: prepared.latest_location,
            writer_location_watermark: prepared.watermark_at,
            rows: prepared.output,
        })
    }

    pub fn stage_upload(
        &self,
        prepared: &super::PreparedUpload,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), QmdbError> {
        super::stage_rows(&self.client, batch, &prepared.rows)
    }

    pub async fn mark_upload_persisted(
        &self,
        prepared: super::PreparedUpload,
        sequence_number: u64,
    ) -> UploadReceipt {
        self.core
            .ack_success(prepared.dispatch_id, sequence_number)
            .await;
        super::upload_receipt(&prepared, sequence_number)
    }

    pub async fn mark_upload_failed(&self, prepared: super::PreparedUpload, err: impl ToString) {
        let msg = format!(
            "unordered upload ending at {} failed: {}",
            prepared.latest_location,
            err.to_string()
        );
        self.core.ack_failure(msg).await;
    }

    pub async fn prepare_flush(&self) -> Result<Option<super::PreparedWatermark>, QmdbError> {
        let Some(target) = self.core.pending_watermark().await? else {
            return Ok(None);
        };
        Ok(Some(super::PreparedWatermark {
            location: target,
            row: (encode_watermark_key(target), Vec::new()),
        }))
    }

    pub fn stage_flush(
        &self,
        prepared: &super::PreparedWatermark,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), QmdbError> {
        super::stage_watermark(&self.client, batch, prepared)
    }

    pub async fn mark_flush_persisted(
        &self,
        prepared: super::PreparedWatermark,
        sequence_number: u64,
    ) -> PublishedCheckpoint {
        self.core
            .mark_watermark_published(prepared.location, sequence_number)
            .await;
        PublishedCheckpoint {
            location: prepared.location,
            sequence_number,
        }
    }

    pub async fn flush_with_receipt(&self) -> Result<Option<PublishedCheckpoint>, QmdbError> {
        self.core.await_drain().await;
        let Some(prepared) = self.prepare_flush().await? else {
            return Ok(None);
        };
        Ok(Some(self.commit_publication(&self.client, prepared).await?))
    }

    pub async fn flush(&self) -> Result<(), QmdbError> {
        self.flush_with_receipt().await.map(|_| ())
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

impl<H, K, V> StoreBatchUpload for UnorderedWriter<H, K, V>
where
    H: Hasher + Sync,
    K: QmdbKey + Codec + Sync,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    UnorderedQmdbOperation<commonware_storage::mmr::Family, K, V>: Encode,
{
    type Prepared = super::PreparedUpload;
    type Receipt = UploadReceipt;
    type Error = QmdbError;

    fn stage_upload(
        &self,
        prepared: &Self::Prepared,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), Self::Error> {
        UnorderedWriter::stage_upload(self, prepared, batch)
    }

    fn commit_error(&self, error: exoware_sdk::ClientError) -> Self::Error {
        QmdbError::Client(error)
    }

    fn mark_upload_persisted<'a>(
        &'a self,
        prepared: Self::Prepared,
        sequence_number: u64,
    ) -> BoxFuture<'a, Self::Receipt>
    where
        Self: Sync + 'a,
        Self::Prepared: 'a,
    {
        Box::pin(async move {
            UnorderedWriter::mark_upload_persisted(self, prepared, sequence_number).await
        })
    }

    fn mark_upload_failed<'a>(
        &'a self,
        prepared: Self::Prepared,
        error: String,
    ) -> BoxFuture<'a, ()>
    where
        Self: Sync + 'a,
        Self::Prepared: 'a,
    {
        Box::pin(async move {
            UnorderedWriter::mark_upload_failed(self, prepared, error).await;
        })
    }
}

impl<H, K, V> StoreBatchPublication for UnorderedWriter<H, K, V>
where
    H: Hasher + Sync,
    K: QmdbKey + Codec + Sync,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    UnorderedQmdbOperation<commonware_storage::mmr::Family, K, V>: Encode,
{
    type PreparedPublication = super::PreparedWatermark;
    type PublicationReceipt = PublishedCheckpoint;
    type Error = QmdbError;

    fn stage_publication(
        &self,
        prepared: &Self::PreparedPublication,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), Self::Error> {
        UnorderedWriter::stage_flush(self, prepared, batch)
    }

    fn publication_commit_error(&self, error: exoware_sdk::ClientError) -> Self::Error {
        QmdbError::Client(error)
    }

    fn mark_publication_persisted<'a>(
        &'a self,
        prepared: Self::PreparedPublication,
        sequence_number: u64,
    ) -> BoxFuture<'a, Self::PublicationReceipt>
    where
        Self: Sync + 'a,
        Self::PreparedPublication: 'a,
    {
        Box::pin(async move {
            UnorderedWriter::mark_flush_persisted(self, prepared, sequence_number).await
        })
    }
}

impl<H, K, V> StorePublicationFrontierWriter for UnorderedWriter<H, K, V>
where
    H: Hasher + Sync,
    K: QmdbKey + Codec + Sync,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    UnorderedQmdbOperation<commonware_storage::mmr::Family, K, V>: Encode,
{
    fn latest_publication_receipt<'a>(&'a self) -> BoxFuture<'a, Option<PublishedCheckpoint>>
    where
        Self: Sync + 'a,
    {
        Box::pin(async move { UnorderedWriter::latest_published_checkpoint(self).await })
    }

    fn prepare_publication<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Option<super::PreparedWatermark>, QmdbError>>
    where
        Self: Sync + 'a,
    {
        Box::pin(async move { UnorderedWriter::prepare_flush(self).await })
    }

    fn flush_publication_with_receipt<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Option<PublishedCheckpoint>, QmdbError>>
    where
        Self: Sync + 'a,
    {
        Box::pin(async move { UnorderedWriter::flush_with_receipt(self).await })
    }
}
