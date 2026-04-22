use std::marker::PhantomData;
use std::sync::Arc;

use commonware_codec::{Codec, Decode, Encode, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_storage::{
    mmr::{verification, Location},
    qmdb::immutable::Operation as ImmutableOperation,
};
use commonware_utils::Array;
use exoware_sdk_rs::{SerializableReadSession, StoreClient};

use crate::auth::AuthenticatedBackendNamespace;
use crate::auth::{
    compute_auth_root, decode_auth_immutable_update_location, load_auth_operation_at,
    load_auth_operation_bytes_range, load_latest_auth_immutable_update_row,
    read_latest_auth_watermark, require_published_auth_watermark,
};
use crate::codec::{mmr_size_for_watermark, UpdateRow};
use crate::core::retry_transient_post_ingest_query;
use crate::error::QmdbError;
use crate::proof::{OperationRangeCheckpoint, VerifiedOperationRange};
use crate::storage::AuthKvMmrStorage;
use crate::VersionedValue;

#[derive(Clone, Debug)]
pub struct ImmutableClient<H: Hasher, K: AsRef<[u8]> + Codec, V: Codec + Send + Sync> {
    client: StoreClient,
    value_cfg: V::Cfg,
    update_row_cfg: (K::Cfg, V::Cfg),
    _marker: PhantomData<(H, K)>,
}

impl<H, K, V> ImmutableClient<H, K, V>
where
    H: Hasher,
    K: Array + Codec + Clone + AsRef<[u8]>,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    K::Cfg: Clone,
    ImmutableOperation<K, V>: Encode + Decode<Cfg = V::Cfg> + Clone,
{
    pub fn new(url: &str, value_cfg: V::Cfg, update_row_cfg: (K::Cfg, V::Cfg)) -> Self {
        Self::from_client(StoreClient::new(url), value_cfg, update_row_cfg)
    }

    pub fn from_client(
        client: StoreClient,
        value_cfg: V::Cfg,
        update_row_cfg: (K::Cfg, V::Cfg),
    ) -> Self {
        Self {
            client,
            value_cfg,
            update_row_cfg,
            _marker: PhantomData,
        }
    }

    pub async fn writer_location_watermark(&self) -> Result<Option<Location>, QmdbError> {
        retry_transient_post_ingest_query(|| {
            let session = self.client.create_session();
            async move {
                read_latest_auth_watermark(&session, AuthenticatedBackendNamespace::Immutable).await
            }
        })
        .await
    }

    pub async fn root_at(&self, watermark: Location) -> Result<H::Digest, QmdbError> {
        let namespace = AuthenticatedBackendNamespace::Immutable;
        let session = self.client.create_session();
        require_published_auth_watermark(&session, namespace, watermark).await?;
        compute_auth_root::<H>(&session, namespace, watermark).await
    }

    pub async fn get_at(
        &self,
        key: &K,
        watermark: Location,
    ) -> Result<Option<VersionedValue<K, V>>, QmdbError> {
        let namespace = AuthenticatedBackendNamespace::Immutable;
        let session = self.client.create_session();
        require_published_auth_watermark(&session, namespace, watermark).await?;
        let Some((row_key, row_value)) =
            load_latest_auth_immutable_update_row(&session, watermark, key.as_ref()).await?
        else {
            return Ok(None);
        };
        let location = decode_auth_immutable_update_location(&row_key)?;
        let decoded =
            <UpdateRow<K, V> as CodecRead>::read_cfg(&mut row_value.as_ref(), &self.update_row_cfg)
                .map_err(|e| QmdbError::CorruptData(format!("update row decode: {e}")))?;
        if <K as AsRef<[u8]>>::as_ref(&decoded.key) != key.as_ref() {
            return Err(QmdbError::CorruptData(format!(
                "authenticated immutable update row key mismatch at location {location}"
            )));
        }
        let operation = load_auth_operation_at::<ImmutableOperation<K, V>>(
            &session,
            namespace,
            location,
            &self.value_cfg,
        )
        .await?;
        match operation {
            ImmutableOperation::Set(operation_key, value) if operation_key == *key => {
                Ok(Some(VersionedValue {
                    key: operation_key,
                    location,
                    value: Some(value),
                }))
            }
            ImmutableOperation::Set(_, _) => Err(QmdbError::CorruptData(format!(
                "authenticated immutable update row does not match operation key at location {location}"
            ))),
            ImmutableOperation::Commit(_) => Err(QmdbError::CorruptData(format!(
                "authenticated immutable update row points at commit location {location}"
            ))),
        }
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
        let namespace = AuthenticatedBackendNamespace::Immutable;
        require_published_auth_watermark(&session, namespace, watermark).await?;
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
        let storage = AuthKvMmrStorage {
            session,
            namespace,
            mmr_size: mmr_size_for_watermark(watermark)?,
            _marker: PhantomData::<H::Digest>,
        };
        let proof = verification::range_proof(&storage, start_location..end)
            .await
            .map_err(|e| QmdbError::CommonwareMmr(e.to_string()))?;
        let checkpoint = OperationRangeCheckpoint {
            watermark,
            root: compute_auth_root::<H>(session, namespace, watermark).await?,
            start_location,
            proof: proof.into(),
            encoded_operations: load_auth_operation_bytes_range(
                session,
                namespace,
                start_location,
                end,
            )
            .await?,
        };
        if !checkpoint.verify::<H>() {
            return Err(QmdbError::CorruptData(
                "immutable checkpoint proof failed verification".to_string(),
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
    ) -> Result<VerifiedOperationRange<H::Digest, ImmutableOperation<K, V>>, QmdbError> {
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
        let operations = checkpoint
            .encoded_operations
            .iter()
            .enumerate()
            .map(|(offset, bytes)| {
                let location = checkpoint.start_location + offset as u64;
                ImmutableOperation::<K, V>::decode_cfg(bytes.as_slice(), &self.value_cfg).map_err(
                    |e| {
                        QmdbError::CorruptData(format!(
                            "failed to decode authenticated operation at location {location}: {e}"
                        ))
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
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
    ) -> Result<VerifiedOperationRange<H::Digest, ImmutableOperation<K, V>>, QmdbError> {
        let checkpoint = self
            .operation_range_checkpoint(watermark, start_location, max_locations)
            .await?;
        let operations = checkpoint
            .encoded_operations
            .iter()
            .enumerate()
            .map(|(offset, bytes)| {
                let location = checkpoint.start_location + offset as u64;
                ImmutableOperation::<K, V>::decode_cfg(bytes.as_slice(), &self.value_cfg).map_err(
                    |e| {
                        QmdbError::CorruptData(format!(
                            "failed to decode authenticated operation at location {location}: {e}"
                        ))
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(VerifiedOperationRange {
            resume_sequence_number: None,
            watermark: checkpoint.watermark,
            root: checkpoint.root,
            start_location: checkpoint.start_location,
            operations,
        })
    }

    /// Open a stream of verified immutable operation ranges, one per uploaded
    /// batch. See [`OrderedClient::stream_batches`](crate::OrderedClient::stream_batches)
    /// for the full contract. The operation type is
    /// `ImmutableOperation<K, V>`, and the subscription filter is restricted
    /// to the Immutable namespace tag so Immutable and Keyless clients can
    /// share a store without cross-talk.
    ///
    /// Proof reads are performed in a serializable session pinned to the
    /// later of the observed batch sequence and the authorizing watermark
    /// sequence, so stream delivery cannot race ahead of query visibility.
    pub async fn stream_batches(
        self: Arc<Self>,
        since: Option<u64>,
    ) -> Result<ImmutableBatchStream<H, K, V>, QmdbError>
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

        let (classify, filter) =
            drv::authenticated_classify_and_filter(AuthenticatedBackendNamespace::Immutable);
        let sub = drv::open_subscription(&self.client, filter, since).await?;

        let build_proof: drv::BuildProof<
            VerifiedOperationRange<H::Digest, ImmutableOperation<K, V>>,
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

/// Async stream of verified immutable operation ranges, one per batch.
pub type ImmutableBatchStream<H, K, V> = crate::stream::driver::BatchProofStream<
    VerifiedOperationRange<<H as Hasher>::Digest, ImmutableOperation<K, V>>,
>;
