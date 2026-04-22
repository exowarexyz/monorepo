use std::marker::PhantomData;
use std::sync::Arc;

use commonware_codec::{Codec, Decode, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::mmr::{verification, Location};
use exoware_sdk_rs::{SerializableReadSession, StoreClient};

use crate::codec::mmr_size_for_watermark;
use crate::core::HistoricalOpsClientCore;
use crate::error::QmdbError;
use crate::proof::{OperationRangeCheckpoint, VerifiedOperationRange};
use crate::storage::KvMmrStorage;
use crate::VersionedValue;

use commonware_storage::qmdb::{
    any::unordered::variable::Operation as UnorderedQmdbOperation, operation::Key as QmdbKey,
};

#[derive(Clone)]
pub struct UnorderedClient<H: Hasher, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync> {
    client: StoreClient,
    op_cfg: <UnorderedQmdbOperation<K, V> as commonware_codec::Read>::Cfg,
    update_row_cfg: (K::Cfg, V::Cfg),
    _marker: PhantomData<(H, K)>,
}

impl<H: Hasher, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync> std::fmt::Debug
    for UnorderedClient<H, K, V>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnorderedClient").finish_non_exhaustive()
    }
}

impl<H, K, V> UnorderedClient<H, K, V>
where
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    UnorderedQmdbOperation<K, V>: Encode + Decode,
{
    fn core(&self) -> HistoricalOpsClientCore<'_, H::Digest, K, V> {
        HistoricalOpsClientCore {
            client: &self.client,
            update_row_cfg: self.update_row_cfg.clone(),
            _marker: PhantomData,
        }
    }

    pub fn new(
        url: &str,
        op_cfg: <UnorderedQmdbOperation<K, V> as commonware_codec::Read>::Cfg,
        update_row_cfg: (K::Cfg, V::Cfg),
    ) -> Self {
        Self::from_client(StoreClient::new(url), op_cfg, update_row_cfg)
    }

    pub fn from_client(
        client: StoreClient,
        op_cfg: <UnorderedQmdbOperation<K, V> as commonware_codec::Read>::Cfg,
        update_row_cfg: (K::Cfg, V::Cfg),
    ) -> Self {
        Self {
            client,
            op_cfg,
            update_row_cfg,
            _marker: PhantomData,
        }
    }

    pub async fn writer_location_watermark(&self) -> Result<Option<Location>, QmdbError> {
        self.core().writer_location_watermark().await
    }

    pub async fn query_many_at<Q: AsRef<[u8]>>(
        &self,
        keys: &[Q],
        watermark: Location,
    ) -> Result<Vec<Option<VersionedValue<K, V>>>, QmdbError> {
        self.core().query_many_at(keys, watermark).await
    }

    pub async fn root_at(&self, watermark: Location) -> Result<H::Digest, QmdbError> {
        let session = self.client.create_session();
        self.core()
            .require_published_watermark(&session, watermark)
            .await?;
        self.core().compute_ops_root::<H>(&session, watermark).await
    }

    pub async fn operation_range_checkpoint(
        &self,
        watermark: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<OperationRangeCheckpoint<H::Digest>, QmdbError> {
        let session = self.client.create_session();
        self.operation_range_checkpoint_in_session(
            &session,
            watermark,
            start_location,
            max_locations,
        )
        .await
    }

    async fn operation_range_checkpoint_in_session(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<OperationRangeCheckpoint<H::Digest>, QmdbError> {
        if max_locations == 0 {
            return Err(QmdbError::InvalidRangeLength);
        }
        self.core()
            .require_published_watermark(&session, watermark)
            .await?;
        let count = watermark
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        if start_location >= count {
            return Err(QmdbError::RangeStartOutOfBounds {
                start: start_location,
                count,
            });
        }
        let end = start_location
            .saturating_add(max_locations as u64)
            .min(count);
        let storage = KvMmrStorage::<H::Digest> {
            session,
            mmr_size: mmr_size_for_watermark(watermark)?,
            _marker: PhantomData,
        };
        let proof = verification::range_proof(&storage, start_location..end)
            .await
            .map_err(|e| QmdbError::CommonwareMmr(e.to_string()))?;
        let checkpoint = OperationRangeCheckpoint {
            watermark,
            root: self
                .core()
                .compute_ops_root::<H>(session, watermark)
                .await?,
            start_location,
            proof: proof.into(),
            encoded_operations: self
                .core()
                .load_operation_bytes_range(session, start_location, end)
                .await?,
        };
        if !checkpoint.verify::<H>() {
            return Err(QmdbError::CorruptData(
                "unordered checkpoint proof failed verification".to_string(),
            ));
        }
        Ok(checkpoint)
    }

    async fn operation_range_proof_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<VerifiedOperationRange<H::Digest, UnorderedQmdbOperation<K, V>>, QmdbError> {
        let session = self
            .client
            .create_session_with_sequence(read_floor_sequence);
        let checkpoint = self
            .operation_range_checkpoint_in_session(
                &session,
                watermark,
                start_location,
                max_locations,
            )
            .await?;
        let mut operations = Vec::with_capacity(checkpoint.encoded_operations.len());
        for (offset, value) in checkpoint.encoded_operations.iter().enumerate() {
            let location = checkpoint.start_location + offset as u64;
            let op = UnorderedQmdbOperation::<K, V>::decode_cfg(value.as_slice(), &self.op_cfg)
                .map_err(|e| {
                    QmdbError::CorruptData(format!(
                        "failed to decode unordered operation at location {location}: {e}"
                    ))
                })?;
            operations.push(op);
        }
        Ok(VerifiedOperationRange {
            resume_sequence_number: Some(read_floor_sequence),
            watermark: checkpoint.watermark,
            root: checkpoint.root,
            start_location: checkpoint.start_location,
            operations,
        })
    }

    /// Verified contiguous range of operations.
    pub async fn operation_range_proof(
        &self,
        watermark: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<VerifiedOperationRange<H::Digest, UnorderedQmdbOperation<K, V>>, QmdbError> {
        let checkpoint = self
            .operation_range_checkpoint(watermark, start_location, max_locations)
            .await?;
        let mut operations = Vec::with_capacity(checkpoint.encoded_operations.len());
        for (offset, value) in checkpoint.encoded_operations.iter().enumerate() {
            let location = checkpoint.start_location + offset as u64;
            let op = UnorderedQmdbOperation::<K, V>::decode_cfg(value.as_slice(), &self.op_cfg)
                .map_err(|e| {
                    QmdbError::CorruptData(format!(
                        "failed to decode unordered operation at location {location}: {e}"
                    ))
                })?;
            operations.push(op);
        }
        Ok(VerifiedOperationRange {
            resume_sequence_number: None,
            watermark: checkpoint.watermark,
            root: checkpoint.root,
            start_location: checkpoint.start_location,
            operations,
        })
    }

    /// Open a stream of verified unordered operation ranges, one per uploaded
    /// batch. See [`OrderedClient::stream_batches`](crate::OrderedClient::stream_batches)
    /// for the full contract — `since` cursor, per-batch watermark stamping,
    /// auto-verification, and error recovery are identical. The only
    /// difference is the operation type (`UnorderedQmdbOperation<K, V>`).
    ///
    /// Proof reads are performed in a serializable session pinned to the
    /// later of the observed batch sequence and the authorizing watermark
    /// sequence, so stream delivery cannot race ahead of query visibility.
    pub async fn stream_batches(
        self: Arc<Self>,
        since: Option<u64>,
    ) -> Result<UnorderedBatchStream<H, K, V>, QmdbError>
    where
        Self: 'static,
        H: Send + Sync + 'static,
        K: Send + Sync + 'static,
        V: Send + Sync + 'static,
        K::Cfg: Send + Sync,
        V::Cfg: Send + Sync,
    {
        use crate::stream::driver::{self as drv, BatchProofStream};
        use futures::FutureExt;

        let (classify, filter) = drv::unauthenticated_classify_and_filter();
        let sub = drv::open_subscription(&self.client, filter, since).await?;

        let build_proof: drv::BuildProof<
            VerifiedOperationRange<H::Digest, UnorderedQmdbOperation<K, V>>,
        > = Arc::new(
            move |read_floor_sequence: u64, watermark: Location, start: Location, count: u32| {
                let me = self.clone();
                async move {
                    me.operation_range_proof_with_read_floor(
                        read_floor_sequence,
                        watermark,
                        start,
                        count,
                    )
                    .await
                }
                .boxed()
            },
        );

        Ok(BatchProofStream::new(sub, classify, build_proof))
    }
}

/// Async stream of verified operation ranges, one per uploaded batch.
pub type UnorderedBatchStream<H, K, V> = crate::stream::driver::BatchProofStream<
    VerifiedOperationRange<<H as Hasher>::Digest, UnorderedQmdbOperation<K, V>>,
>;
