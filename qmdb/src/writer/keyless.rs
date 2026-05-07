//! Single-writer helper for the keyless QMDB variant.

use std::marker::PhantomData;

use commonware_codec::{Codec, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::merkle::{Family, Location, Position};
use commonware_storage::qmdb::keyless::variable::Operation as KeylessOperation;
use exoware_sdk::keys::Key;
use exoware_sdk::{
    StoreBatchPublication, StoreBatchUpload, StoreClient, StorePublicationFrontierWriter,
    StoreWriteBatch,
};
use futures::future::BoxFuture;

use crate::auth::{
    build_auth_upload_rows, encode_auth_node_key, encode_auth_watermark_key,
    AuthenticatedBackendNamespace,
};
use crate::core::extend_merkle_from_peaks;
use crate::error::QmdbError;
use crate::writer::core::{Cache, WriterCore};
use crate::{PublishedCheckpoint, UploadReceipt, WriterState};

const NAMESPACE: AuthenticatedBackendNamespace = AuthenticatedBackendNamespace::Keyless;

/// Deterministic output of a keyless row-build.
#[derive(Clone, Debug)]
pub struct BuiltKeylessUpload<D, F: Family> {
    pub rows: Vec<(Key, Vec<u8>)>,
    pub new_peaks: Vec<(Position<F>, u32, D)>,
    pub new_ops_size: Position<F>,
    pub new_root: D,
    pub latest_location: Location<F>,
    pub operation_count: u32,
    pub includes_watermark: bool,
}

/// Pure function: from the Merkle peaks preceding the batch, compute every
/// store row needed to persist `ops` as a single atomic PUT. No I/O.
///
/// `watermark_at`, if `Some(loc)`, emits a watermark row at that location.
/// The caller is responsible for ensuring `loc` is safe to publish (i.e. the
/// entire prefix up to `loc` has committed); `WriterCore::prepare` computes
/// this safely for in-writer use.
pub fn build_keyless_upload<F: Family, H: Hasher, V: Codec + Clone + Send + Sync>(
    peaks: Vec<(Position<F>, u32, H::Digest)>,
    prev_ops_size: Position<F>,
    latest_location: Location<F>,
    ops: &[KeylessOperation<F, V>],
    watermark_at: Option<Location<F>>,
) -> Result<BuiltKeylessUpload<H::Digest, F>, QmdbError>
where
    KeylessOperation<F, V>: Encode,
{
    if ops.is_empty() {
        return Err(QmdbError::EmptyBatch);
    }
    let encoded: Vec<Vec<u8>> = ops.iter().map(|op| op.encode().to_vec()).collect();
    let prepared = build_auth_upload_rows(NAMESPACE, latest_location, encoded)?;
    let ext = extend_merkle_from_peaks::<F, H, _>(peaks, prev_ops_size, prepared.op_bytes())?;
    let operation_count = prepared.operation_count;
    let mut rows = prepared.into_all_rows();
    for (pos, digest) in &ext.new_nodes {
        rows.push((
            encode_auth_node_key(NAMESPACE, *pos),
            digest.as_ref().to_vec(),
        ));
    }
    if let Some(loc) = watermark_at {
        rows.push((encode_auth_watermark_key(NAMESPACE, loc), Vec::new()));
    }
    Ok(BuiltKeylessUpload {
        rows,
        new_peaks: ext.peaks,
        new_ops_size: ext.size,
        new_root: ext.root,
        latest_location,
        operation_count,
        includes_watermark: watermark_at.is_some(),
    })
}

/// Sole-writer keyless QMDB helper.
///
/// ## Pipelining
///
/// Multiple [`prepare_upload`](Self::prepare_upload) calls can be in flight
/// simultaneously — the writer's mutex is released before any Store write
/// awaits, so independent Store batches can run concurrently on the transport.
///
/// Each dispatched batch's PUT carries a watermark row at the **latest safe
/// location**:
///
/// - Pipeline empty at dispatch → this batch's own `latest_location` (our PUT
///   is the only one in flight, so our own latest is safe to publish once the
///   PUT commits).
/// - Pipeline non-empty, some prefix ACKd → the last location of the
///   contiguous-acked prefix (every predecessor batch has returned Ok).
/// - Pipeline non-empty, nothing ACKd yet → no watermark row in this PUT.
///
/// Under steady-state saturation (bounded concurrency with ~constant ACK
/// latency) this keeps the published watermark lagging the dispatch frontier
/// by at most the pipeline depth — never unbounded. The [`flush`](Self::flush)
/// method is only needed to publish the trailing watermark after the final
/// batch dispatch and its ACKs drain.
///
/// ## Failure handling
///
/// Any PUT error poisons the writer. The caller must construct a fresh writer
/// from a caller-owned committed frontier before any further uploads can
/// proceed. PUT rows are
/// content-addressed and Merkle math is deterministic, so re-submitting the
/// batches the caller still considers pending is always safe.
///
/// ## Sole-writer contract
///
/// Concurrent publishers against the same store namespace race on peak
/// extension and will corrupt each other's Merkle state. The contract assumed
/// throughout is "one writer per namespace." The store's ingest layer is not
/// aware of this constraint; it's the caller's responsibility.
pub struct KeylessWriter<F: Family, H: Hasher, V: Codec + Clone + Send + Sync> {
    client: StoreClient,
    core: WriterCore<H::Digest, F>,
    _marker: PhantomData<(F, V)>,
}

impl<F, H, V> KeylessWriter<F, H, V>
where
    F: Family,
    H: Hasher,
    V: Codec + Clone + Send + Sync,
    KeylessOperation<F, V>: Encode,
{
    /// Construct a writer from caller-supplied frontier state. No store I/O.
    pub fn new(client: StoreClient, state: WriterState<H::Digest, F>) -> Self {
        Self {
            client,
            core: WriterCore::from_cache(Cache::from_writer_state(state)),
            _marker: PhantomData,
        }
    }

    pub fn empty(client: StoreClient) -> Self {
        Self::new(client, WriterState::empty())
    }

    pub async fn latest_published_watermark(&self) -> Option<Location<F>> {
        self.core.latest_published().await
    }

    pub async fn latest_published_checkpoint(&self) -> Option<PublishedCheckpoint<F>> {
        self.core.latest_published_checkpoint().await
    }

    pub async fn prepare_upload(
        &self,
        ops: &[KeylessOperation<F, V>],
    ) -> Result<super::PreparedUpload<F>, QmdbError> {
        let prepared = self
            .core
            .prepare(ops.len() as u64, |ctx| {
                let built = build_keyless_upload::<F, H, V>(
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
        Ok(super::PreparedUpload::<F> {
            dispatch_id: prepared.dispatch_id,
            latest_location: prepared.latest_location,
            writer_location_watermark: prepared.watermark_at,
            rows: prepared.output,
        })
    }

    pub fn stage_upload(
        &self,
        prepared: &super::PreparedUpload<F>,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), QmdbError> {
        super::stage_rows(&self.client, batch, &prepared.rows)
    }

    pub async fn mark_upload_persisted(
        &self,
        prepared: super::PreparedUpload<F>,
        sequence_number: u64,
    ) -> UploadReceipt<F> {
        self.core
            .ack_success(prepared.dispatch_id, sequence_number)
            .await;
        super::upload_receipt(&prepared, sequence_number)
    }

    pub async fn mark_upload_failed(&self, prepared: super::PreparedUpload<F>, err: impl ToString) {
        let msg = format!(
            "keyless upload ending at {} failed: {}",
            prepared.latest_location,
            err.to_string()
        );
        self.core.ack_failure(msg).await;
    }

    pub async fn prepare_flush(&self) -> Result<Option<super::PreparedWatermark<F>>, QmdbError> {
        let Some(target) = self.core.pending_watermark().await? else {
            return Ok(None);
        };
        Ok(Some(super::PreparedWatermark::<F> {
            location: target,
            row: (encode_auth_watermark_key(NAMESPACE, target), Vec::new()),
        }))
    }

    pub fn stage_flush(
        &self,
        prepared: &super::PreparedWatermark<F>,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), QmdbError> {
        super::stage_watermark(&self.client, batch, prepared)
    }

    pub async fn mark_flush_persisted(
        &self,
        prepared: super::PreparedWatermark<F>,
        sequence_number: u64,
    ) -> PublishedCheckpoint<F> {
        self.core
            .mark_watermark_published(prepared.location, sequence_number)
            .await;
        PublishedCheckpoint {
            location: prepared.location,
            sequence_number,
        }
    }

    pub async fn flush_with_receipt(&self) -> Result<Option<PublishedCheckpoint<F>>, QmdbError> {
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

impl<F, H, V> std::fmt::Debug for KeylessWriter<F, H, V>
where
    F: Family,
    H: Hasher,
    V: Codec + Clone + Send + Sync,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeylessWriter").finish_non_exhaustive()
    }
}

impl<F, H, V> StoreBatchUpload for KeylessWriter<F, H, V>
where
    F: Family,
    H: Hasher + Sync,
    V: Codec + Clone + Send + Sync,
    KeylessOperation<F, V>: Encode,
{
    type Prepared = super::PreparedUpload<F>;
    type Receipt = UploadReceipt<F>;
    type Error = QmdbError;

    fn stage_upload(
        &self,
        prepared: &Self::Prepared,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), Self::Error> {
        KeylessWriter::stage_upload(self, prepared, batch)
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
            KeylessWriter::mark_upload_persisted(self, prepared, sequence_number).await
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
            KeylessWriter::mark_upload_failed(self, prepared, error).await;
        })
    }
}

impl<F, H, V> StoreBatchPublication for KeylessWriter<F, H, V>
where
    F: Family,
    H: Hasher + Sync,
    V: Codec + Clone + Send + Sync,
    KeylessOperation<F, V>: Encode,
{
    type PreparedPublication = super::PreparedWatermark<F>;
    type PublicationReceipt = PublishedCheckpoint<F>;
    type Error = QmdbError;

    fn stage_publication(
        &self,
        prepared: &Self::PreparedPublication,
        batch: &mut StoreWriteBatch,
    ) -> Result<(), Self::Error> {
        KeylessWriter::stage_flush(self, prepared, batch)
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
            KeylessWriter::mark_flush_persisted(self, prepared, sequence_number).await
        })
    }
}

impl<F, H, V> StorePublicationFrontierWriter for KeylessWriter<F, H, V>
where
    F: Family,
    H: Hasher + Sync,
    V: Codec + Clone + Send + Sync,
    KeylessOperation<F, V>: Encode,
{
    fn latest_publication_receipt<'a>(&'a self) -> BoxFuture<'a, Option<PublishedCheckpoint<F>>>
    where
        Self: Sync + 'a,
    {
        Box::pin(async move { KeylessWriter::latest_published_checkpoint(self).await })
    }

    fn prepare_publication<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Option<super::PreparedWatermark<F>>, QmdbError>>
    where
        Self: Sync + 'a,
    {
        Box::pin(async move { KeylessWriter::prepare_flush(self).await })
    }

    fn flush_publication_with_receipt<'a>(
        &'a self,
    ) -> BoxFuture<'a, Result<Option<PublishedCheckpoint<F>>, QmdbError>>
    where
        Self: Sync + 'a,
    {
        Box::pin(async move { KeylessWriter::flush_with_receipt(self).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Sha256;
    use commonware_storage::merkle::mmr;

    type TestOp = KeylessOperation<mmr::Family, Vec<u8>>;

    fn op(v: &[u8]) -> TestOp {
        KeylessOperation::Append(v.to_vec())
    }

    #[test]
    fn build_from_empty_peaks_includes_all_expected_row_families() {
        let ops = vec![op(b"one"), op(b"two"), op(b"three")];
        let built = build_keyless_upload::<mmr::Family, Sha256, Vec<u8>>(
            Vec::new(),
            Position::new(0),
            Location::new(2),
            &ops,
            Some(Location::new(2)),
        )
        .expect("build");
        assert_eq!(built.operation_count, 3);
        assert_eq!(built.latest_location, Location::new(2));
        assert!(built.includes_watermark);
        assert!(built.rows.len() >= 5);
    }

    #[test]
    fn excluding_watermark_row_drops_exactly_one_row() {
        let ops = vec![op(b"x"), op(b"y")];
        let with_wm = build_keyless_upload::<mmr::Family, Sha256, Vec<u8>>(
            Vec::new(),
            Position::new(0),
            Location::new(1),
            &ops,
            Some(Location::new(1)),
        )
        .expect("with wm");
        let without_wm = build_keyless_upload::<mmr::Family, Sha256, Vec<u8>>(
            Vec::new(),
            Position::new(0),
            Location::new(1),
            &ops,
            None,
        )
        .expect("without wm");
        assert_eq!(with_wm.rows.len(), without_wm.rows.len() + 1);
    }

    #[test]
    fn build_is_deterministic_on_same_inputs() {
        let ops = vec![op(b"a"), op(b"b"), op(b"c"), op(b"d")];
        let a = build_keyless_upload::<mmr::Family, Sha256, Vec<u8>>(
            Vec::new(),
            Position::new(0),
            Location::new(3),
            &ops,
            Some(Location::new(3)),
        )
        .expect("a");
        let b = build_keyless_upload::<mmr::Family, Sha256, Vec<u8>>(
            Vec::new(),
            Position::new(0),
            Location::new(3),
            &ops,
            Some(Location::new(3)),
        )
        .expect("b");
        assert_eq!(a.rows, b.rows);
        assert_eq!(a.new_peaks, b.new_peaks);
        assert_eq!(a.new_ops_size, b.new_ops_size);
        assert_eq!(a.new_root, b.new_root);
    }

    #[test]
    fn incremental_fold_matches_single_fold() {
        let all = vec![op(b"p"), op(b"q"), op(b"r"), op(b"s")];
        let single = build_keyless_upload::<mmr::Family, Sha256, Vec<u8>>(
            Vec::new(),
            Position::new(0),
            Location::new(3),
            &all,
            None,
        )
        .expect("single");

        let first = build_keyless_upload::<mmr::Family, Sha256, Vec<u8>>(
            Vec::new(),
            Position::new(0),
            Location::new(1),
            &all[..2],
            None,
        )
        .expect("first");
        let second = build_keyless_upload::<mmr::Family, Sha256, Vec<u8>>(
            first.new_peaks.clone(),
            first.new_ops_size,
            Location::new(3),
            &all[2..],
            None,
        )
        .expect("second");

        assert_eq!(single.new_peaks, second.new_peaks);
        assert_eq!(single.new_ops_size, second.new_ops_size);
        assert_eq!(single.new_root, second.new_root);
    }

    #[test]
    fn empty_batch_rejected() {
        let res = build_keyless_upload::<mmr::Family, Sha256, Vec<u8>>(
            Vec::new(),
            Position::new(0),
            Location::new(0),
            &[],
            Some(Location::new(0)),
        );
        assert!(matches!(res, Err(QmdbError::EmptyBatch)));
    }
}
