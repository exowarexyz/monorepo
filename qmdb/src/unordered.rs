use std::marker::PhantomData;
use std::sync::{atomic::AtomicU64, Arc};

use commonware_codec::{Codec, Decode, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::mmr::{verification, Location};
use exoware_sdk_rs::StoreClient;

use crate::codec::{encode_presence_key, mmr_size_for_watermark};
use crate::core::{HistoricalOpsClientCore, PreparedUpload};
use crate::error::QmdbError;
use crate::proof::UnorderedOperationRangeProof;
use crate::storage::KvMmrStorage;
use crate::{UploadReceipt, VersionedValue};

use commonware_storage::qmdb::{
    any::unordered::variable::Operation as UnorderedQmdbOperation, operation::Key as QmdbKey,
};

#[derive(Clone)]
pub struct UnorderedClient<H: Hasher, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync> {
    client: StoreClient,
    op_cfg: <UnorderedQmdbOperation<K, V> as commonware_codec::Read>::Cfg,
    update_row_cfg: (K::Cfg, V::Cfg),
    query_visible_sequence: Option<Arc<AtomicU64>>,
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
            query_visible_sequence: self.query_visible_sequence.as_ref(),
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
            query_visible_sequence: None,
            _marker: PhantomData,
        }
    }

    pub fn with_query_visible_sequence(mut self, seq: Arc<AtomicU64>) -> Self {
        self.query_visible_sequence = Some(seq);
        self
    }

    pub fn inner(&self) -> &StoreClient {
        &self.client
    }

    pub fn sequence_number(&self) -> u64 {
        self.client.sequence_number()
    }

    pub async fn writer_location_watermark(&self) -> Result<Option<Location>, QmdbError> {
        self.core().writer_location_watermark().await
    }

    pub async fn publish_writer_location_watermark(
        &self,
        location: Location,
    ) -> Result<Location, QmdbError> {
        let session = self.client.create_session();
        let latest_watermark = self.core().read_latest_watermark(&session).await?;
        if let Some(watermark) = latest_watermark {
            if watermark >= location {
                return Ok(watermark);
            }
        }
        self.core()
            .require_batch_boundary(&session, location)
            .await?;
        let delta_start_location = latest_watermark.map_or(Location::new(0), |w| w + 1);
        let end_location_exclusive = location
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        let op_rows = self
            .core()
            .load_operation_bytes_range(&session, delta_start_location, end_location_exclusive)
            .await?;
        for (offset, bytes) in op_rows.iter().enumerate() {
            let op_location = delta_start_location + offset as u64;
            let _ = UnorderedQmdbOperation::<K, V>::decode_cfg(bytes.as_slice(), &self.op_cfg)
                .map_err(|e| {
                    QmdbError::CorruptData(format!(
                        "failed to decode unordered operation at location {op_location}: {e}"
                    ))
                })?;
        }
        self.core()
            .publish_writer_location_watermark_with_encoded_ops::<H>(
                &session,
                latest_watermark,
                location,
                &op_rows,
                "unordered",
            )
            .await
    }

    pub async fn upload_operations(
        &self,
        latest_location: Location,
        operations: &[UnorderedQmdbOperation<K, V>],
    ) -> Result<UploadReceipt, QmdbError> {
        if operations.is_empty() {
            return Err(QmdbError::EmptyBatch);
        }
        if self
            .client
            .query()
            .get(&encode_presence_key(latest_location))
            .await?
            .is_some()
        {
            return Err(QmdbError::DuplicateBatchWatermark { latest_location });
        }

        let prepared = PreparedUpload::build_unordered(latest_location, operations)?;
        let refs = prepared
            .rows
            .iter()
            .map(|(key, value)| (key, value.as_slice()))
            .collect::<Vec<_>>();
        self.client.ingest().put(&refs).await?;
        self.core().sync_after_ingest().await?;

        let writer_location_watermark = self.writer_location_watermark().await?;
        Ok(UploadReceipt {
            latest_location,
            operation_count: Location::from(prepared.operation_count as u64),
            keyed_operation_count: prepared.keyed_operation_count,
            writer_location_watermark,
            sequence_number: self.client.sequence_number(),
        })
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

    pub async fn operation_range_proof(
        &self,
        watermark: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<UnorderedOperationRangeProof<H::Digest, K, V>, QmdbError> {
        if max_locations == 0 {
            return Err(QmdbError::InvalidRangeLength);
        }
        let session = self.client.create_session();
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
            session: &session,
            mmr_size: mmr_size_for_watermark(watermark)?,
            _marker: PhantomData,
        };
        let proof = verification::range_proof(&storage, start_location..end)
            .await
            .map_err(|e| QmdbError::CommonwareMmr(e.to_string()))?;
        let root = self
            .core()
            .compute_ops_root::<H>(&session, watermark)
            .await?;
        let rows = self
            .core()
            .load_operation_bytes_range(&session, start_location, end)
            .await?;
        let mut operations = Vec::with_capacity(rows.len());
        for (offset, value) in rows.iter().enumerate() {
            let location = start_location + offset as u64;
            let op = UnorderedQmdbOperation::<K, V>::decode_cfg(value.as_slice(), &self.op_cfg)
                .map_err(|e| {
                    QmdbError::CorruptData(format!(
                        "failed to decode unordered operation at location {location}: {e}"
                    ))
                })?;
            operations.push(op);
        }

        Ok(UnorderedOperationRangeProof {
            watermark,
            root,
            start_location,
            proof,
            operations,
        })
    }

    /// Open a stream of `UnorderedOperationRangeProof` per uploaded batch.
    ///
    /// See `OrderedClient::stream_batches` — the semantics, cursor behavior,
    /// and error handling are identical; only the proof type differs.
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

        let build_proof: drv::BuildProof<UnorderedOperationRangeProof<H::Digest, K, V>> =
            Arc::new(move |watermark: Location, start: Location, count: u32| {
                let me = self.clone();
                async move { me.operation_range_proof(watermark, start, count).await }.boxed()
            });

        Ok(BatchProofStream::new(sub, classify, build_proof))
    }
}

/// Async stream of `UnorderedOperationRangeProof`s, one per uploaded batch.
pub type UnorderedBatchStream<H, K, V> = crate::stream::driver::BatchProofStream<
    UnorderedOperationRangeProof<<H as Hasher>::Digest, K, V>,
>;
