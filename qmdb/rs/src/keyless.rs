use std::marker::PhantomData;
use std::sync::Arc;

use commonware_codec::{Codec, Decode, Encode, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::{Family, Graftable, Location},
    qmdb::{
        any::value::{ValueEncoding, VariableEncoding},
        keyless,
    },
};
use exoware_sdk::{PrefixedStoreClient, ReadSession};

use crate::codec::merkle_size_for_watermark;
use crate::connect::OperationKv;
use crate::core::{self, PublishedWatermark};
use crate::error::QmdbError;
use crate::proof::{OperationRangeCheckpoint, RawBatchMultiProof, VerifiedOperationRange};
use crate::storage::KvMerkleStorage;

pub struct KeylessClient<
    F: Family,
    H: Hasher,
    V: Codec + Send + Sync,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> where
    keyless::Operation<F, E>: CodecRead,
{
    store: PrefixedStoreClient,
    publication: Arc<core::PublicationCache<F>>,
    op_cfg: <keyless::Operation<F, E> as CodecRead>::Cfg,
    _marker: PhantomData<(F, H, E)>,
}

impl<F, H, V, E> Clone for KeylessClient<F, H, V, E>
where
    F: Family,
    H: Hasher,
    V: Codec + Send + Sync,
    E: ValueEncoding<Value = V>,
    keyless::Operation<F, E>: CodecRead,
{
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            publication: self.publication.clone(),
            op_cfg: self.op_cfg.clone(),
            _marker: PhantomData,
        }
    }
}

impl<F, H, V, E> std::fmt::Debug for KeylessClient<F, H, V, E>
where
    F: Family,
    H: Hasher,
    V: Codec + Send + Sync,
    E: ValueEncoding<Value = V>,
    keyless::Operation<F, E>: CodecRead,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeylessClient").finish_non_exhaustive()
    }
}

impl<F, H, V, E> KeylessClient<F, H, V, E>
where
    F: Graftable,
    H: Hasher,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    keyless::Operation<F, E>: Encode + Decode + Clone,
{
    /// Read client for the Store namespace.
    pub fn new(
        store: PrefixedStoreClient,
        op_cfg: <keyless::Operation<F, E> as CodecRead>::Cfg,
    ) -> Self {
        Self {
            store,
            publication: Arc::new(core::PublicationCache::default()),
            op_cfg,
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
        let op = keyless::Operation::<F, E>::decode_cfg(bytes, &self.op_cfg).map_err(|e| {
            QmdbError::CorruptData(format!(
                "failed to decode keyless operation at location {location}: {e}"
            ))
        })?;
        let value = match &op {
            keyless::Operation::Append(value) => Some(value.as_ref().to_vec()),
            keyless::Operation::Commit(Some(value), _) => Some(value.as_ref().to_vec()),
            keyless::Operation::Commit(None, _) => None,
        };
        Ok(OperationKv { key: None, value })
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
            inactive_peaks_at::<F, V, E>(&session, watermark.location, &self.op_cfg).await?;
        core::compute_ops_root::<F, H>(&session, watermark.location, inactive_peaks).await
    }

    pub async fn get_at(
        &self,
        location: Location<F>,
        watermark: Location<F>,
    ) -> Result<Option<V>, QmdbError> {
        let watermark = self.resolve_watermark(watermark, None).await?;
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        let count = watermark
            .location
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        if location >= count {
            return Err(QmdbError::RangeStartOutOfBounds {
                start: location.as_u64(),
                count: count.as_u64(),
            });
        }
        let operation = core::load_operation_at::<F, keyless::Operation<F, E>>(
            &session,
            location,
            &self.op_cfg,
        )
        .await?;
        Ok(operation.into_value())
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
            inactive_peaks_at::<F, V, E>(&session, watermark.location, &self.op_cfg).await?;
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
            inactive_peaks_at::<F, V, E>(&session, watermark.location, &self.op_cfg).await?;
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
    ) -> Result<VerifiedOperationRange<H::Digest, keyless::Operation<F, E>, F>, QmdbError> {
        let checkpoint = self
            .operation_range_checkpoint(watermark, start_location, max_locations)
            .await?;
        let operations = checkpoint
            .encoded_operations
            .iter()
            .enumerate()
            .map(|(offset, bytes)| {
                let location = checkpoint.start_location + offset as u64;
                keyless::Operation::<F, E>::decode_cfg(bytes.as_slice(), &self.op_cfg).map_err(
                    |e| {
                        QmdbError::CorruptData(format!(
                            "failed to decode authenticated operation at location {location}: {e}"
                        ))
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(VerifiedOperationRange {
            root: checkpoint.root,
            start_location: checkpoint.start_location,
            operations,
        })
    }
}

async fn inactive_peaks_at<F, V, E>(
    session: &ReadSession,
    watermark: Location<F>,
    op_cfg: &<keyless::Operation<F, E> as CodecRead>::Cfg,
) -> Result<usize, QmdbError>
where
    F: Graftable,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    keyless::Operation<F, E>: Decode,
{
    let operation =
        core::load_operation_at::<F, keyless::Operation<F, E>>(session, watermark, op_cfg).await?;
    let keyless::Operation::Commit(_, floor) = operation else {
        return Err(QmdbError::CorruptData(format!(
            "keyless watermark {watermark} does not point at a Commit operation"
        )));
    };
    core::inactive_peaks(watermark, floor)
}
