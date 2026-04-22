use std::collections::BTreeSet;
use std::marker::PhantomData;

use commonware_codec::{Codec, Decode, Encode, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_storage::{
    mmr::{verification, Location},
    qmdb::{
        any::ordered::variable::Operation as QmdbOperation,
        current::proof::RangeProof as CurrentRangeProof, operation::Key as QmdbKey,
    },
};
use exoware_sdk_rs::keys::Key;
use exoware_sdk_rs::{RangeMode, SerializableReadSession, StoreClient};

use crate::codec::{
    bitmap_chunk_bits, chunk_index_for_location, decode_digest, decode_update_location,
    encode_chunk_key, encode_current_meta_key, encode_update_key, mmr_size_for_watermark,
    UpdateRow, NO_PARTIAL_CHUNK,
};
use crate::core::HistoricalOpsClientCore;
use crate::error::QmdbError;
use crate::proof::{
    CurrentOperationRangeProofResult, OperationRangeCheckpoint, RawCurrentRangeProof,
    RawKeyValueProof, RawMultiProof, VariantRoot, VerifiedCurrentRange, VerifiedKeyValue,
    VerifiedMultiOperations, VerifiedOperationRange, VerifiedVariantRange,
};
use crate::storage::{KvCurrentStorage, KvMmrStorage};
use crate::{QmdbVariant, VersionedValue};

#[derive(Clone)]
pub struct OrderedClient<
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
> {
    client: StoreClient,
    op_cfg: <QmdbOperation<K, V> as commonware_codec::Read>::Cfg,
    update_row_cfg: (K::Cfg, V::Cfg),
    _marker: PhantomData<(H, K)>,
}

impl<H: Hasher, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync, const N: usize> std::fmt::Debug
    for OrderedClient<H, K, V, N>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrderedClient").finish_non_exhaustive()
    }
}

impl<H, K, V, const N: usize> OrderedClient<H, K, V, N>
where
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    QmdbOperation<K, V>: Encode + Decode,
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
        op_cfg: <QmdbOperation<K, V> as commonware_codec::Read>::Cfg,
        update_row_cfg: (K::Cfg, V::Cfg),
    ) -> Self {
        Self::from_client(StoreClient::new(url), op_cfg, update_row_cfg)
    }

    pub fn from_client(
        client: StoreClient,
        op_cfg: <QmdbOperation<K, V> as commonware_codec::Read>::Cfg,
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

    pub async fn root_at(&self, watermark: Location) -> Result<H::Digest, QmdbError> {
        Ok(self
            .root_for_variant(watermark, QmdbVariant::Any)
            .await?
            .root)
    }

    pub async fn current_root_at(&self, watermark: Location) -> Result<H::Digest, QmdbError> {
        Ok(self
            .root_for_variant(watermark, QmdbVariant::Current)
            .await?
            .root)
    }

    pub async fn root_for_variant(
        &self,
        watermark: Location,
        variant: QmdbVariant,
    ) -> Result<VariantRoot<H::Digest>, QmdbError> {
        let session = self.client.create_session();
        self.core()
            .require_published_watermark(&session, watermark)
            .await?;
        let root = match variant {
            QmdbVariant::Any => self.compute_ops_root(&session, watermark).await?,
            QmdbVariant::Current => {
                self.core()
                    .require_batch_boundary(&session, watermark)
                    .await?;
                self.load_current_boundary_root(&session, watermark).await?
            }
        };
        Ok(VariantRoot {
            watermark,
            variant,
            root,
        })
    }

    pub async fn query_many_at<Q: AsRef<[u8]>>(
        &self,
        keys: &[Q],
        max_location: Location,
    ) -> Result<Vec<Option<VersionedValue<K, V>>>, QmdbError> {
        self.core().query_many_at(keys, max_location).await
    }

    pub(crate) fn store_client(&self) -> &StoreClient {
        &self.client
    }

    pub(crate) fn decode_operation_bytes(
        &self,
        location: Location,
        bytes: &[u8],
    ) -> Result<QmdbOperation<K, V>, QmdbError> {
        QmdbOperation::<K, V>::decode_cfg(bytes, &self.op_cfg).map_err(|e| {
            QmdbError::CorruptData(format!(
                "failed to decode qmdb operation at location {location}: {e}"
            ))
        })
    }

    async fn multi_proof_raw_in_session<Q: AsRef<[u8]>>(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
        keys: &[Q],
    ) -> Result<RawMultiProof<H::Digest, K, V>, QmdbError> {
        if keys.is_empty() {
            return Err(QmdbError::EmptyProofRequest);
        }

        self.core()
            .require_published_watermark(session, watermark)
            .await?;
        let storage = KvMmrStorage::<H::Digest> {
            session,
            mmr_size: mmr_size_for_watermark(watermark)?,
            _marker: PhantomData,
        };
        let root = self.compute_ops_root(session, watermark).await?;

        let mut seen = BTreeSet::<Vec<u8>>::new();
        let mut locations = Vec::<Location>::with_capacity(keys.len());
        let mut operations = Vec::<(Location, QmdbOperation<K, V>)>::with_capacity(keys.len());
        for key in keys {
            let key_bytes = key.as_ref().to_vec();
            if !seen.insert(key_bytes.clone()) {
                return Err(QmdbError::DuplicateRequestedKey { key: key_bytes });
            }
            let start = encode_update_key(key.as_ref(), Location::new(0))?;
            let end = encode_update_key(key.as_ref(), watermark)?;
            let rows = session
                .range_with_mode(&start, &end, 1, RangeMode::Reverse)
                .await?;
            let Some((row_key, row_value)) = rows.into_iter().next() else {
                return Err(QmdbError::ProofKeyNotFound {
                    watermark,
                    key: key.as_ref().to_vec(),
                });
            };
            let global_loc = decode_update_location(&row_key)?;
            let decoded = <UpdateRow<K, V> as CodecRead>::read_cfg(
                &mut row_value.as_ref(),
                &self.update_row_cfg,
            )
            .map_err(|e| QmdbError::CorruptData(format!("update row decode: {e}")))?;
            if <K as AsRef<[u8]>>::as_ref(&decoded.key) != key.as_ref() {
                return Err(QmdbError::ProofKeyNotFound {
                    watermark,
                    key: key.as_ref().to_vec(),
                });
            }
            let operation = self.load_operation_at(session, global_loc).await?;
            locations.push(global_loc);
            operations.push((global_loc, operation));
        }
        operations.sort_by_key(|(loc, _)| *loc);
        locations.sort();

        let proof = verification::multi_proof(&storage, &locations)
            .await
            .map_err(|e| QmdbError::CommonwareMmr(e.to_string()))?;
        let raw = RawMultiProof {
            watermark,
            root,
            proof: proof.into(),
            operations,
        };
        if !raw.verify::<H>() {
            return Err(QmdbError::CorruptData(
                "multi proof failed verification".to_string(),
            ));
        }
        Ok(raw)
    }

    pub(crate) async fn multi_proof_raw_with_read_floor<Q: AsRef<[u8]>>(
        &self,
        read_floor_sequence: u64,
        watermark: Location,
        keys: &[Q],
    ) -> Result<RawMultiProof<H::Digest, K, V>, QmdbError> {
        let session = self
            .client
            .create_session_with_sequence(read_floor_sequence);
        self.multi_proof_raw_in_session(&session, watermark, keys)
            .await
    }

    /// Verified raw multi-proof over a set of keys.
    pub async fn multi_proof_raw_at<Q: AsRef<[u8]>>(
        &self,
        watermark: Location,
        keys: &[Q],
    ) -> Result<RawMultiProof<H::Digest, K, V>, QmdbError> {
        let session = self.client.create_session();
        self.multi_proof_raw_in_session(&session, watermark, keys)
            .await
    }

    /// Verified multi-proof over a set of keys.
    pub async fn multi_proof_at<Q: AsRef<[u8]>>(
        &self,
        watermark: Location,
        keys: &[Q],
    ) -> Result<VerifiedMultiOperations<H::Digest, K, V>, QmdbError> {
        let raw = self.multi_proof_raw_at(watermark, keys).await?;
        Ok(VerifiedMultiOperations {
            watermark: raw.watermark,
            root: raw.root,
            operations: raw.operations,
        })
    }

    /// Verified contiguous range of operations.
    pub async fn operation_range_proof(
        &self,
        watermark: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<VerifiedOperationRange<H::Digest, QmdbOperation<K, V>>, QmdbError> {
        match self
            .operation_range_proof_for_variant(
                watermark,
                QmdbVariant::Any,
                start_location,
                max_locations,
            )
            .await?
        {
            VerifiedVariantRange::Any(verified) => Ok(verified),
            VerifiedVariantRange::Current(_) => Err(QmdbError::CorruptData(
                "unexpected current proof returned for any variant request".to_string(),
            )),
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

    pub(crate) async fn operation_range_checkpoint_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<OperationRangeCheckpoint<H::Digest>, QmdbError> {
        let session = self
            .client
            .create_session_with_sequence(read_floor_sequence);
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
            .require_published_watermark(session, watermark)
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
            root: self.compute_ops_root(session, watermark).await?,
            start_location,
            proof: proof.into(),
            encoded_operations: self
                .core()
                .load_operation_bytes_range(session, start_location, end)
                .await?,
        };
        if !checkpoint.verify::<H>() {
            return Err(QmdbError::CorruptData(
                "range checkpoint proof failed verification".to_string(),
            ));
        }
        Ok(checkpoint)
    }

    /// Verified contiguous range of operations for the given variant.
    pub async fn operation_range_proof_for_variant(
        &self,
        watermark: Location,
        variant: QmdbVariant,
        start_location: Location,
        max_locations: u32,
    ) -> Result<VerifiedVariantRange<H::Digest, K, V, N>, QmdbError> {
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
        match variant {
            QmdbVariant::Any => {
                let checkpoint = self
                    .operation_range_checkpoint(watermark, start_location, max_locations)
                    .await?;
                let operations = checkpoint
                    .encoded_operations
                    .iter()
                    .enumerate()
                    .map(|(offset, bytes)| {
                        let location = checkpoint.start_location + offset as u64;
                        QmdbOperation::<K, V>::decode_cfg(bytes.as_slice(), &self.op_cfg).map_err(
                            |e| {
                                QmdbError::CorruptData(format!(
                                    "failed to decode qmdb operation at location {location}: {e}"
                                ))
                            },
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(VerifiedVariantRange::Any(VerifiedOperationRange {
                    watermark: checkpoint.watermark,
                    root: checkpoint.root,
                    start_location: checkpoint.start_location,
                    operations,
                }))
            }
            QmdbVariant::Current => {
                self.core()
                    .require_batch_boundary(&session, watermark)
                    .await?;
                let proof = self
                    .build_current_range_proof(&session, watermark, start_location, end)
                    .await?;
                let root = self.load_current_boundary_root(&session, watermark).await?;
                let operations = self
                    .load_operation_range(&session, start_location, end)
                    .await?;
                let chunks = self
                    .load_bitmap_chunks(&session, watermark, start_location, end)
                    .await?;
                let raw = CurrentOperationRangeProofResult {
                    watermark,
                    root,
                    start_location,
                    proof,
                    operations,
                    chunks,
                };
                if !raw.verify::<H>() {
                    return Err(QmdbError::CorruptData(
                        "current range proof failed verification".to_string(),
                    ));
                }
                Ok(VerifiedVariantRange::Current(VerifiedCurrentRange {
                    watermark: raw.watermark,
                    root: raw.root,
                    start_location: raw.start_location,
                    operations: raw.operations,
                    chunks: raw.chunks,
                }))
            }
        }
    }

    /// Verified contiguous range from the current-state variant (with bitmap chunks).
    pub async fn current_operation_range_proof(
        &self,
        watermark: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<VerifiedCurrentRange<H::Digest, K, V, N>, QmdbError> {
        match self
            .operation_range_proof_for_variant(
                watermark,
                QmdbVariant::Current,
                start_location,
                max_locations,
            )
            .await?
        {
            VerifiedVariantRange::Current(verified) => Ok(verified),
            VerifiedVariantRange::Any(_) => Err(QmdbError::CorruptData(
                "unexpected any proof returned for current variant request".to_string(),
            )),
        }
    }

    async fn key_value_proof_raw_in_session<Q: AsRef<[u8]>>(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
        key: Q,
    ) -> Result<RawKeyValueProof<H::Digest, K, V, N>, QmdbError> {
        self.core()
            .require_published_watermark(session, watermark)
            .await?;
        self.core()
            .require_batch_boundary(session, watermark)
            .await?;

        let key_bytes = key.as_ref().to_vec();
        let Some((row_key, row_value)) = self
            .load_latest_update_row(session, watermark, key.as_ref())
            .await?
        else {
            return Err(QmdbError::ProofKeyNotFound {
                watermark,
                key: key_bytes,
            });
        };
        let location = decode_update_location(&row_key)?;
        let decoded =
            <UpdateRow<K, V> as CodecRead>::read_cfg(&mut row_value.as_ref(), &self.update_row_cfg)
                .map_err(|e| QmdbError::CorruptData(format!("update row decode: {e}")))?;
        if <K as AsRef<[u8]>>::as_ref(&decoded.key) != key.as_ref() {
            return Err(QmdbError::ProofKeyNotFound {
                watermark,
                key: key.as_ref().to_vec(),
            });
        }
        if decoded.value.is_none() {
            return Err(QmdbError::KeyNotActive {
                watermark,
                key: key.as_ref().to_vec(),
            });
        }

        let operation = self.load_operation_at(session, location).await?;
        let QmdbOperation::Update(_) = &operation else {
            return Err(QmdbError::KeyNotActive {
                watermark,
                key: key.as_ref().to_vec(),
            });
        };
        let range_proof = self
            .build_current_range_proof(session, watermark, location, location + 1)
            .await?;
        let chunk = self
            .load_bitmap_chunk(session, watermark, chunk_index_for_location::<N>(location))
            .await?;
        let root = self.load_current_boundary_root(session, watermark).await?;

        let raw = RawKeyValueProof {
            watermark,
            root,
            location,
            chunk,
            range_proof: RawCurrentRangeProof::from(range_proof),
            operation,
        };
        if !raw.verify::<H>() {
            return Err(QmdbError::CorruptData(
                "key-value proof failed verification".to_string(),
            ));
        }
        Ok(raw)
    }

    /// Verified raw current-state proof for a single key.
    pub async fn key_value_proof_raw_at<Q: AsRef<[u8]>>(
        &self,
        watermark: Location,
        key: Q,
    ) -> Result<RawKeyValueProof<H::Digest, K, V, N>, QmdbError> {
        let session = self.client.create_session();
        self.key_value_proof_raw_in_session(&session, watermark, key)
            .await
    }

    /// Verified current-state proof for a single key. The returned
    /// `operation` is the matching `Update`; its `next_key` is the value
    /// the proof was verified against.
    pub async fn key_value_proof_at<Q: AsRef<[u8]>>(
        &self,
        watermark: Location,
        key: Q,
    ) -> Result<VerifiedKeyValue<H::Digest, K, V>, QmdbError> {
        let raw = self.key_value_proof_raw_at(watermark, key).await?;
        Ok(VerifiedKeyValue {
            watermark: raw.watermark,
            root: raw.root,
            location: raw.location,
            operation: raw.operation,
        })
    }

    async fn load_current_boundary_root(
        &self,
        session: &SerializableReadSession,
        location: Location,
    ) -> Result<H::Digest, QmdbError> {
        let Some(bytes) = session.get(&encode_current_meta_key(location)).await? else {
            return Err(QmdbError::CurrentBoundaryStateMissing { location });
        };
        decode_digest(
            bytes.as_ref(),
            format!("current boundary root at {location}"),
        )
    }

    pub(crate) async fn compute_ops_root(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
    ) -> Result<H::Digest, QmdbError> {
        self.core().compute_ops_root::<H>(session, watermark).await
    }

    async fn build_current_range_proof(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
        start_location: Location,
        end_location_exclusive: Location,
    ) -> Result<CurrentRangeProof<H::Digest>, QmdbError> {
        let storage = KvCurrentStorage::<H::Digest, N> {
            session,
            watermark,
            mmr_size: mmr_size_for_watermark(watermark)?,
            _marker: PhantomData,
        };
        let proof = verification::range_proof(&storage, start_location..end_location_exclusive)
            .await
            .map_err(|e| QmdbError::CommonwareMmr(e.to_string()))?;
        Ok(CurrentRangeProof {
            proof,
            partial_chunk_digest: self
                .load_partial_chunk_digest(session, watermark)
                .await?
                .map(|(_, digest)| digest),
            ops_root: self.compute_ops_root(session, watermark).await?,
        })
    }

    async fn load_bitmap_chunk(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
        chunk_index: u64,
    ) -> Result<[u8; N], QmdbError> {
        let start = encode_chunk_key(chunk_index, Location::new(0));
        let end = encode_chunk_key(chunk_index, watermark);
        let rows = session
            .range_with_mode(&start, &end, 1, RangeMode::Reverse)
            .await?;
        let Some((_, bytes)) = rows.into_iter().next() else {
            return Err(QmdbError::CorruptData(format!(
                "missing bitmap chunk {chunk_index} at watermark {watermark}"
            )));
        };
        if bytes.len() != N {
            return Err(QmdbError::CorruptData(format!(
                "bitmap chunk {chunk_index} has invalid length {}",
                bytes.len()
            )));
        }
        let mut chunk = [0u8; N];
        chunk.copy_from_slice(bytes.as_ref());
        Ok(chunk)
    }

    async fn load_bitmap_chunks(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
        start_location: Location,
        end_location_exclusive: Location,
    ) -> Result<Vec<[u8; N]>, QmdbError> {
        let start_chunk = chunk_index_for_location::<N>(start_location);
        let end_chunk = chunk_index_for_location::<N>(end_location_exclusive - 1);
        let mut chunks = Vec::with_capacity((end_chunk - start_chunk + 1) as usize);
        for chunk_index in start_chunk..=end_chunk {
            chunks.push(
                self.load_bitmap_chunk(session, watermark, chunk_index)
                    .await?,
            );
        }
        Ok(chunks)
    }

    async fn load_partial_chunk_digest(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
    ) -> Result<Option<(u64, H::Digest)>, QmdbError> {
        let leaves = watermark
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        let next_bit = *leaves % bitmap_chunk_bits::<N>();
        if next_bit == NO_PARTIAL_CHUNK {
            return Ok(None);
        }
        let chunk_index = *leaves / bitmap_chunk_bits::<N>();
        let chunk = self
            .load_bitmap_chunk(session, watermark, chunk_index)
            .await?;
        let mut hasher = H::default();
        hasher.update(&chunk);
        Ok(Some((next_bit, hasher.finalize())))
    }

    async fn load_operation_at(
        &self,
        session: &SerializableReadSession,
        location: Location,
    ) -> Result<QmdbOperation<K, V>, QmdbError> {
        let bytes = self
            .core()
            .load_operation_bytes_at(session, location)
            .await?;
        QmdbOperation::<K, V>::decode_cfg(bytes.as_slice(), &self.op_cfg).map_err(|e| {
            QmdbError::CorruptData(format!(
                "failed to decode qmdb operation at location {location}: {e}"
            ))
        })
    }

    async fn load_operation_range(
        &self,
        session: &SerializableReadSession,
        start_location: Location,
        end_location_exclusive: Location,
    ) -> Result<Vec<QmdbOperation<K, V>>, QmdbError> {
        let rows = self
            .core()
            .load_operation_bytes_range(session, start_location, end_location_exclusive)
            .await?;
        rows.into_iter()
            .enumerate()
            .map(|(offset, bytes)| {
                let location = start_location + offset as u64;
                QmdbOperation::<K, V>::decode_cfg(bytes.as_slice(), &self.op_cfg).map_err(|e| {
                    QmdbError::CorruptData(format!(
                        "failed to decode qmdb operation at location {location}: {e}"
                    ))
                })
            })
            .collect()
    }

    async fn load_latest_update_row(
        &self,
        session: &SerializableReadSession,
        watermark: Location,
        key: &[u8],
    ) -> Result<Option<(Key, Vec<u8>)>, QmdbError> {
        self.core()
            .load_latest_update_row(session, watermark, key)
            .await
    }
}
