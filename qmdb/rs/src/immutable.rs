use std::marker::PhantomData;
use std::sync::Arc;

use commonware_codec::{Codec, Decode, Encode, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::{Family, Graftable, Location},
    qmdb::{
        any::value::{ValueEncoding, VariableEncoding},
        immutable,
        operation::Key as QmdbKey,
    },
};
use exoware_sdk::{PrefixedStoreClient, ReadSession};

use crate::codec::{decode_update_location, merkle_size_for_watermark};
use crate::connect::OperationKv;
use crate::core::{self, PublishedWatermark};
use crate::error::QmdbError;
use crate::proof::{OperationRangeCheckpoint, RawBatchMultiProof, VerifiedOperationRange};
use crate::storage::KvMerkleStorage;
use crate::VersionedValue;

pub struct ImmutableClient<
    F: Family,
    H: Hasher,
    K: QmdbKey,
    V: Codec + Send + Sync,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> where
    immutable::Operation<F, K, E>: CodecRead,
{
    store: PrefixedStoreClient,
    publication: Arc<core::PublicationCache<F>>,
    operation_cfg: <immutable::Operation<F, K, E> as CodecRead>::Cfg,
    _marker: PhantomData<(F, H, K, E)>,
}

impl<F, H, K, V, E> Clone for ImmutableClient<F, H, K, V, E>
where
    F: Family,
    H: Hasher,
    K: QmdbKey,
    V: Codec + Send + Sync,
    E: ValueEncoding<Value = V>,
    immutable::Operation<F, K, E>: CodecRead,
{
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            publication: self.publication.clone(),
            operation_cfg: self.operation_cfg.clone(),
            _marker: PhantomData,
        }
    }
}

impl<F, H, K, V, E> std::fmt::Debug for ImmutableClient<F, H, K, V, E>
where
    F: Family,
    H: Hasher,
    K: QmdbKey,
    V: Codec + Send + Sync,
    E: ValueEncoding<Value = V>,
    immutable::Operation<F, K, E>: CodecRead,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImmutableClient").finish_non_exhaustive()
    }
}

impl<F, H, K, V, E> ImmutableClient<F, H, K, V, E>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    immutable::Operation<F, K, E>: Encode + Decode + Clone,
{
    /// Read client for the Store namespace.
    pub fn new(
        store: PrefixedStoreClient,
        operation_cfg: <immutable::Operation<F, K, E> as CodecRead>::Cfg,
    ) -> Self {
        Self {
            store,
            publication: Arc::new(core::PublicationCache::default()),
            operation_cfg,
            _marker: PhantomData,
        }
    }

    pub(crate) fn extract_operation_kv(
        &self,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError>
    where
        V: AsRef<[u8]>,
    {
        let op = immutable::Operation::<F, K, E>::decode_cfg(bytes, &self.operation_cfg).map_err(
            |e| {
                QmdbError::CorruptData(format!(
                    "failed to decode immutable operation at location {location}: {e}"
                ))
            },
        )?;
        let key = op.key().map(|k| <K as AsRef<[u8]>>::as_ref(k).to_vec());
        let value = match &op {
            immutable::Operation::Set(_, value) => Some(value.as_ref().to_vec()),
            immutable::Operation::Commit(Some(value), _) => Some(value.as_ref().to_vec()),
            immutable::Operation::Commit(None, _) => None,
        };
        Ok(OperationKv { key, value })
    }

    /// Refresh publication evidence and return the greatest watermark observed by this client.
    pub async fn latest_published_watermark(&self) -> Result<Option<Location<F>>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), None);
        self.publication.refresh(&session).await
    }

    pub(crate) async fn resolve_watermark(
        &self,
        watermark: Location<F>,
        min_sequence_number: Option<u64>,
    ) -> Result<PublishedWatermark<F>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), min_sequence_number);
        self.publication.require(&session, watermark).await
    }

    pub async fn root_at(&self, watermark: Location<F>) -> Result<H::Digest, QmdbError> {
        let watermark = self.resolve_watermark(watermark, None).await?;
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        let inactive_peaks =
            inactive_peaks_at::<F, K, V, E>(&session, watermark.location, &self.operation_cfg)
                .await?;
        core::compute_ops_root::<F, H>(&session, watermark.location, inactive_peaks).await
    }

    pub async fn get_at(
        &self,
        key: &K,
        watermark: Location<F>,
    ) -> Result<Option<VersionedValue<K, V, F>>, QmdbError> {
        let watermark = self.resolve_watermark(watermark, None).await?;
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        let Some((row_key, _row_value)) =
            core::load_latest_update_row(&session, watermark.location, key.as_ref()).await?
        else {
            return Ok(None);
        };
        let location = decode_update_location::<F>(&row_key)?;
        let operation = core::load_operation_at::<F, immutable::Operation<F, K, E>>(
            &session,
            location,
            &self.operation_cfg,
        )
        .await?;
        match operation {
            immutable::Operation::Set(operation_key, value) if operation_key == *key => {
                Ok(Some(VersionedValue {
                    key: operation_key,
                    location,
                    value: Some(value),
                }))
            }
            immutable::Operation::Set(_, _) => Err(QmdbError::CorruptData(format!(
                "authenticated immutable update row does not match operation key at location {location}"
            ))),
            immutable::Operation::Commit(_, _) => Err(QmdbError::CorruptData(format!(
                "authenticated immutable update row points at commit location {location}"
            ))),
        }
    }

    pub async fn operation_range_checkpoint(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<OperationRangeCheckpoint<H::Digest, F>, QmdbError> {
        let watermark = self.resolve_watermark(watermark, None).await?;
        self.operation_range_checkpoint_at(watermark, start_location, max_locations)
            .await
    }

    pub(crate) async fn operation_range_checkpoint_at(
        &self,
        watermark: PublishedWatermark<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<OperationRangeCheckpoint<H::Digest, F>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        let end =
            crate::proof::resolve_range_bounds(watermark.location, start_location, max_locations)?;
        let storage = KvMerkleStorage::<F, H::Digest> {
            session: &session,
            size: merkle_size_for_watermark(watermark.location)?,
            _marker: PhantomData::<H::Digest>,
        };
        let inactive_peaks =
            inactive_peaks_at::<F, K, V, E>(&session, watermark.location, &self.operation_cfg)
                .await?;
        let root =
            core::compute_ops_root::<F, H>(&session, watermark.location, inactive_peaks).await?;
        let encoded_operations =
            core::load_operation_bytes_range(&session, start_location, end).await?;
        let proof = crate::proof::build_operation_range_checkpoint::<F, H, _>(
            &storage,
            watermark.location,
            start_location,
            end,
            root,
            inactive_peaks,
            encoded_operations,
        )
        .await?;
        Ok(proof)
    }

    pub(crate) async fn batch_multi_proof(
        &self,
        watermark: PublishedWatermark<F>,
        operations: Vec<(Location<F>, Vec<u8>)>,
    ) -> Result<RawBatchMultiProof<H::Digest, F>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        let storage = KvMerkleStorage::<F, H::Digest> {
            session: &session,
            size: merkle_size_for_watermark(watermark.location)?,
            _marker: PhantomData::<H::Digest>,
        };
        let inactive_peaks =
            inactive_peaks_at::<F, K, V, E>(&session, watermark.location, &self.operation_cfg)
                .await?;
        let root =
            core::compute_ops_root::<F, H>(&session, watermark.location, inactive_peaks).await?;
        crate::proof::build_batch_multi_proof::<F, H, _>(
            &storage,
            watermark.location,
            root,
            inactive_peaks,
            operations,
        )
        .await
    }

    /// Verified contiguous range of operations.
    pub async fn operation_range_proof(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<VerifiedOperationRange<H::Digest, immutable::Operation<F, K, E>, F>, QmdbError>
    {
        let checkpoint = self
            .operation_range_checkpoint(watermark, start_location, max_locations)
            .await?;
        let operations = checkpoint
            .encoded_operations
            .iter()
            .enumerate()
            .map(|(offset, bytes)| {
                let location = checkpoint.start_location + offset as u64;
                immutable::Operation::<F, K, E>::decode_cfg(bytes.as_slice(), &self.operation_cfg)
                    .map_err(|e| {
                        QmdbError::CorruptData(format!(
                            "failed to decode authenticated operation at location {location}: {e}"
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(VerifiedOperationRange {
            root: checkpoint.root,
            start_location: checkpoint.start_location,
            operations,
        })
    }
}

async fn inactive_peaks_at<F, K, V, E>(
    session: &ReadSession,
    watermark: Location<F>,
    operation_cfg: &<immutable::Operation<F, K, E> as CodecRead>::Cfg,
) -> Result<usize, QmdbError>
where
    F: Graftable,
    K: QmdbKey,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    immutable::Operation<F, K, E>: Decode,
{
    let operation = core::load_operation_at::<F, immutable::Operation<F, K, E>>(
        session,
        watermark,
        operation_cfg,
    )
    .await?;
    let immutable::Operation::Commit(_, floor) = operation else {
        return Err(QmdbError::CorruptData(format!(
            "immutable watermark {watermark} does not point at a Commit operation"
        )));
    };
    core::inactive_peaks(watermark, floor)
}
