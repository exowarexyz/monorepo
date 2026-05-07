use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

use commonware_codec::{Codec, Decode, Encode, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::{Family, Graftable, Location},
    qmdb::{
        any::ordered::variable::Operation as QmdbOperation,
        current::{
            ordered::{
                db::KeyValueProof as CurrentKeyValueProof, ExclusionProof as CurrentExclusionProof,
            },
            proof::{OperationProof as CurrentOperationProof, RangeProof as CurrentRangeProof},
        },
        operation::{Key as QmdbKey, Operation as _},
    },
};
use commonware_utils::bitmap::Readable as BitmapReadable;
use exoware_sdk::keys::Key;
use exoware_sdk::{RangeMode, SerializableReadSession, StoreClient};

use crate::codec::{
    bitmap_chunk_bits, chunk_index_for_location, clear_below_floor, decode_digest,
    decode_update_location, encode_chunk_key, encode_current_meta_key, encode_update_key,
    merkle_size_for_watermark, UpdateRow, UPDATE_CODEC,
};
use crate::connect::OperationKv;
use crate::core::HistoricalOpsClientCore;
use crate::error::QmdbError;
use crate::proof::{
    CurrentOperationRangeProofResult, OperationRangeCheckpoint, RawBatchMultiProof,
    RawKeyExclusionProof, RawKeyLookupProof, RawKeyRangeEntry, RawKeyRangeProof, RawKeyValueProof,
    RawMultiProof, VariantRoot, VerifiedCurrentRange, VerifiedKeyValue, VerifiedMultiOperations,
    VerifiedOperationRange, VerifiedVariantRange,
};
use crate::storage::{KvCurrentStorage, KvMerkleStorage};
use crate::{QmdbVariant, VersionedValue};

#[derive(Clone, Debug)]
struct MaterializedBitmapStatus<const N: usize> {
    len: u64,
    pruned_chunks: usize,
    chunks: std::collections::BTreeMap<usize, [u8; N]>,
}

#[derive(Clone, Debug)]
struct ActiveOrderedOperation<F: Family, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync> {
    key: Vec<u8>,
    location: Location<F>,
    operation: QmdbOperation<F, K, V>,
}

impl<const N: usize> BitmapReadable<N> for MaterializedBitmapStatus<N> {
    fn complete_chunks(&self) -> usize {
        (self.len / bitmap_chunk_bits::<N>()) as usize
    }

    fn get_chunk(&self, chunk: usize) -> [u8; N] {
        if chunk < self.pruned_chunks {
            [0u8; N]
        } else {
            *self
                .chunks
                .get(&chunk)
                .expect("materialized current bitmap status missing chunk")
        }
    }

    fn last_chunk(&self) -> ([u8; N], u64) {
        if self.len == 0 {
            return ([0u8; N], 0);
        }
        let chunk_bits = bitmap_chunk_bits::<N>();
        let rem = self.len % chunk_bits;
        let bits_in_last = if rem == 0 { chunk_bits } else { rem };
        let idx = if rem == 0 {
            self.complete_chunks().saturating_sub(1)
        } else {
            self.complete_chunks()
        };
        (self.get_chunk(idx), bits_in_last)
    }

    fn pruned_chunks(&self) -> usize {
        self.pruned_chunks
    }

    fn len(&self) -> u64 {
        self.len
    }
}

#[derive(Clone)]
pub struct OrderedClient<
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
> {
    client: StoreClient,
    op_cfg: <QmdbOperation<F, K, V> as commonware_codec::Read>::Cfg,
    update_row_cfg: (K::Cfg, V::Cfg),
    _marker: PhantomData<(F, H, K)>,
}

impl<
        F: Graftable,
        H: Hasher,
        K: QmdbKey + Codec,
        V: Codec + Clone + Send + Sync,
        const N: usize,
    > std::fmt::Debug for OrderedClient<F, H, K, V, N>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrderedClient").finish_non_exhaustive()
    }
}

impl<F, H, K, V, const N: usize> OrderedClient<F, H, K, V, N>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    V::Cfg: Clone,
    QmdbOperation<F, K, V>: Encode + Decode,
{
    fn core(&self) -> HistoricalOpsClientCore<'_, F, H::Digest, K, V> {
        HistoricalOpsClientCore {
            client: &self.client,
            update_row_cfg: self.update_row_cfg.clone(),
            _marker: PhantomData,
        }
    }

    pub fn new(
        url: &str,
        op_cfg: <QmdbOperation<F, K, V> as commonware_codec::Read>::Cfg,
        update_row_cfg: (K::Cfg, V::Cfg),
    ) -> Self {
        Self::from_client(StoreClient::new(url), op_cfg, update_row_cfg)
    }

    pub fn from_client(
        client: StoreClient,
        op_cfg: <QmdbOperation<F, K, V> as commonware_codec::Read>::Cfg,
        update_row_cfg: (K::Cfg, V::Cfg),
    ) -> Self {
        Self {
            client,
            op_cfg,
            update_row_cfg,
            _marker: PhantomData,
        }
    }

    pub async fn writer_location_watermark(&self) -> Result<Option<Location<F>>, QmdbError> {
        self.core().writer_location_watermark().await
    }

    pub async fn root_at(&self, watermark: Location<F>) -> Result<H::Digest, QmdbError> {
        Ok(self
            .root_for_variant(watermark, QmdbVariant::Any)
            .await?
            .root)
    }

    pub async fn current_root_at(&self, watermark: Location<F>) -> Result<H::Digest, QmdbError> {
        Ok(self
            .root_for_variant(watermark, QmdbVariant::Current)
            .await?
            .root)
    }

    pub async fn root_for_variant(
        &self,
        watermark: Location<F>,
        variant: QmdbVariant,
    ) -> Result<VariantRoot<H::Digest, F>, QmdbError> {
        let session = self.client.create_session();
        self.root_for_variant_in_session(&session, watermark, variant)
            .await
    }

    async fn root_for_variant_in_session(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
        variant: QmdbVariant,
    ) -> Result<VariantRoot<H::Digest, F>, QmdbError> {
        self.core()
            .require_published_watermark(session, watermark)
            .await?;
        let root = match variant {
            QmdbVariant::Any => self.compute_ops_root(session, watermark).await?,
            QmdbVariant::Current => {
                self.core()
                    .require_batch_boundary(session, watermark)
                    .await?;
                self.load_current_boundary_root(session, watermark).await?
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
        max_location: Location<F>,
    ) -> Result<Vec<Option<VersionedValue<K, V, F>>>, QmdbError> {
        self.core().query_many_at(keys, max_location).await
    }

    pub(crate) fn store_client(&self) -> &StoreClient {
        &self.client
    }

    pub(crate) fn decode_operation_bytes(
        &self,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<QmdbOperation<F, K, V>, QmdbError> {
        QmdbOperation::<F, K, V>::decode_cfg(bytes, &self.op_cfg).map_err(|e| {
            QmdbError::CorruptData(format!(
                "failed to decode qmdb operation at location {location}: {e}"
            ))
        })
    }

    pub(crate) fn extract_operation_kv(
        &self,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError>
    where
        V: AsRef<[u8]>,
    {
        let op = self.decode_operation_bytes(location, bytes)?;
        let key = op.key().map(|k| <K as AsRef<[u8]>>::as_ref(k).to_vec());
        let value = match &op {
            QmdbOperation::Update(update) => Some(update.value.as_ref().to_vec()),
            QmdbOperation::CommitFloor(Some(value), _) => Some(value.as_ref().to_vec()),
            QmdbOperation::Delete(_) | QmdbOperation::CommitFloor(None, _) => None,
        };
        Ok(OperationKv { key, value })
    }

    async fn multi_proof_raw_in_session<Q: AsRef<[u8]>>(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
        keys: &[Q],
    ) -> Result<RawMultiProof<H::Digest, K, V, F>, QmdbError> {
        if keys.is_empty() {
            return Err(QmdbError::EmptyProofRequest);
        }

        self.core()
            .require_published_watermark(session, watermark)
            .await?;
        let storage = KvMerkleStorage::<F, H::Digest> {
            session,
            size: merkle_size_for_watermark(watermark)?,
            _marker: PhantomData,
        };
        let root = self.compute_ops_root(session, watermark).await?;

        let mut seen = BTreeSet::<Vec<u8>>::new();
        let mut operation_bytes = Vec::<(Location<F>, Vec<u8>)>::with_capacity(keys.len());
        for key in keys {
            let key_bytes = key.as_ref().to_vec();
            if !seen.insert(key_bytes.clone()) {
                return Err(QmdbError::DuplicateRequestedKey { key: key_bytes });
            }
            let start = encode_update_key(key.as_ref(), Location::<F>::new(0))?;
            let end = encode_update_key(key.as_ref(), watermark)?;
            let rows = session
                .range_with_mode(&start, &end, 1, RangeMode::Reverse)
                .await?;
            let Some((row_key, row_value)) = rows.into_iter().next() else {
                return Err(QmdbError::ProofKeyNotFound {
                    watermark: watermark.as_u64(),
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
                    watermark: watermark.as_u64(),
                    key: key.as_ref().to_vec(),
                });
            }
            let encoded = self
                .core()
                .load_operation_bytes_at(session, global_loc)
                .await?;
            operation_bytes.push((global_loc, encoded));
        }
        operation_bytes.sort_by_key(|(loc, _)| *loc);

        let raw = crate::proof::build_batch_multi_proof::<F, H, _>(
            &storage,
            watermark,
            root,
            operation_bytes,
        )
        .await
        .map(|raw| {
            let operations = raw
                .operations
                .iter()
                .map(|(location, bytes)| {
                    self.decode_operation_bytes(*location, bytes)
                        .map(|operation| (*location, operation))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok::<_, QmdbError>(RawMultiProof {
                watermark: raw.watermark,
                root: raw.root,
                proof: raw.proof,
                operations,
            })
        })??;
        if !raw.verify::<H>() {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::HistoricalMultiKey,
            });
        }
        Ok(raw)
    }

    pub(crate) async fn batch_multi_proof_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location<F>,
        operations: Vec<(Location<F>, Vec<u8>)>,
    ) -> Result<RawBatchMultiProof<H::Digest, F>, QmdbError> {
        let session = self
            .client
            .create_session_with_sequence(read_floor_sequence);
        self.core()
            .require_published_watermark(&session, watermark)
            .await?;
        let storage = KvMerkleStorage::<F, H::Digest> {
            session: &session,
            size: merkle_size_for_watermark(watermark)?,
            _marker: PhantomData,
        };
        let root = self.compute_ops_root(&session, watermark).await?;
        crate::proof::build_batch_multi_proof::<F, H, _>(&storage, watermark, root, operations)
            .await
    }

    /// Verified raw multi-proof over a set of keys.
    pub async fn multi_proof_raw_at<Q: AsRef<[u8]>>(
        &self,
        watermark: Location<F>,
        keys: &[Q],
    ) -> Result<RawMultiProof<H::Digest, K, V, F>, QmdbError> {
        let session = self.client.create_session();
        self.multi_proof_raw_in_session(&session, watermark, keys)
            .await
    }

    /// Verified multi-proof over a set of keys.
    pub async fn multi_proof_at<Q: AsRef<[u8]>>(
        &self,
        watermark: Location<F>,
        keys: &[Q],
    ) -> Result<VerifiedMultiOperations<H::Digest, K, V, F>, QmdbError> {
        let raw = self.multi_proof_raw_at(watermark, keys).await?;
        Ok(VerifiedMultiOperations {
            root: raw.root,
            operations: raw.operations,
        })
    }

    /// Verified contiguous range of operations.
    pub async fn operation_range_proof(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<VerifiedOperationRange<H::Digest, QmdbOperation<F, K, V>, F>, QmdbError> {
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
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<OperationRangeCheckpoint<H::Digest, F>, QmdbError> {
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
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<OperationRangeCheckpoint<H::Digest, F>, QmdbError> {
        self.core()
            .require_published_watermark(session, watermark)
            .await?;
        let end = crate::proof::resolve_range_bounds(watermark, start_location, max_locations)?;
        let storage = KvMerkleStorage::<F, H::Digest> {
            session,
            size: merkle_size_for_watermark(watermark)?,
            _marker: PhantomData,
        };
        let root = self.compute_ops_root(session, watermark).await?;
        let encoded_operations = self
            .core()
            .load_operation_bytes_range(session, start_location, end)
            .await?;
        crate::proof::build_operation_range_checkpoint::<F, H, _>(
            &storage,
            watermark,
            start_location,
            end,
            root,
            encoded_operations,
        )
        .await
    }

    /// Verified contiguous range of operations for the given variant.
    pub async fn operation_range_proof_for_variant(
        &self,
        watermark: Location<F>,
        variant: QmdbVariant,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<VerifiedVariantRange<H::Digest, K, V, N, F>, QmdbError> {
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
                start: start_location.as_u64(),
                count: count.as_u64(),
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
                        QmdbOperation::<F, K, V>::decode_cfg(bytes.as_slice(), &self.op_cfg)
                            .map_err(|e| {
                                QmdbError::CorruptData(format!(
                                    "failed to decode qmdb operation at location {location}: {e}"
                                ))
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(VerifiedVariantRange::Any(VerifiedOperationRange {
                    root: checkpoint.root,
                    start_location: checkpoint.start_location,
                    operations,
                }))
            }
            QmdbVariant::Current => {
                let raw = self
                    .current_range_proof_raw_in_session(&session, watermark, start_location, end)
                    .await?;
                if !raw.verify::<H>() {
                    return Err(QmdbError::ProofVerification {
                        kind: crate::ProofKind::CurrentRange,
                    });
                }
                Ok(VerifiedVariantRange::Current(VerifiedCurrentRange {
                    root: raw.root,
                    start_location: raw.start_location,
                    operations: raw.operations,
                    chunks: raw.chunks,
                }))
            }
        }
    }

    async fn current_range_proof_raw_in_session(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
        start_location: Location<F>,
        end_location_exclusive: Location<F>,
    ) -> Result<CurrentOperationRangeProofResult<H::Digest, QmdbOperation<F, K, V>, N, F>, QmdbError>
    {
        self.core()
            .require_published_watermark(session, watermark)
            .await?;
        self.core()
            .require_batch_boundary(session, watermark)
            .await?;
        let proof = self
            .build_current_range_proof(session, watermark, start_location, end_location_exclusive)
            .await?;
        let root = self.load_current_boundary_root(session, watermark).await?;
        let operations = self
            .load_operation_range(session, start_location, end_location_exclusive)
            .await?;
        let chunks = self
            .load_bitmap_chunks(session, watermark, start_location, end_location_exclusive)
            .await?;
        Ok(CurrentOperationRangeProofResult {
            watermark,
            root,
            start_location,
            proof,
            operations,
            chunks,
        })
    }

    /// Verified raw current-state proof for a contiguous operation range.
    pub async fn current_operation_range_proof_raw_at(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<CurrentOperationRangeProofResult<H::Digest, QmdbOperation<F, K, V>, N, F>, QmdbError>
    {
        let session = self.client.create_session();
        let end = crate::proof::resolve_range_bounds(watermark, start_location, max_locations)?;
        let raw = self
            .current_range_proof_raw_in_session(&session, watermark, start_location, end)
            .await?;
        if !raw.verify::<H>() {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentRange,
            });
        }
        Ok(raw)
    }

    /// Verified contiguous range from the current-state variant (with bitmap chunks).
    pub async fn current_operation_range_proof(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<VerifiedCurrentRange<H::Digest, K, V, N, F>, QmdbError> {
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
        watermark: Location<F>,
        key: Q,
    ) -> Result<RawKeyValueProof<H::Digest, K, V, N, F>, QmdbError> {
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
                watermark: watermark.as_u64(),
                key: key_bytes,
            });
        };
        let location = decode_update_location(&row_key)?;
        let decoded =
            <UpdateRow<K, V> as CodecRead>::read_cfg(&mut row_value.as_ref(), &self.update_row_cfg)
                .map_err(|e| QmdbError::CorruptData(format!("update row decode: {e}")))?;
        if <K as AsRef<[u8]>>::as_ref(&decoded.key) != key.as_ref() {
            return Err(QmdbError::ProofKeyNotFound {
                watermark: watermark.as_u64(),
                key: key.as_ref().to_vec(),
            });
        }
        if decoded.value.is_none() {
            return Err(QmdbError::KeyNotActive {
                watermark: watermark.as_u64(),
                key: key.as_ref().to_vec(),
            });
        }

        let operation = self.load_operation_at(session, location).await?;
        let QmdbOperation::Update(update) = &operation else {
            return Err(QmdbError::KeyNotActive {
                watermark: watermark.as_u64(),
                key: key.as_ref().to_vec(),
            });
        };
        let root = self.load_current_boundary_root(session, watermark).await?;
        let operation_proof = self
            .build_current_operation_proof(session, watermark, location)
            .await?;
        let proof = CurrentKeyValueProof {
            proof: operation_proof,
            next_key: update.next_key.clone(),
        };

        let raw = RawKeyValueProof {
            watermark,
            root,
            proof,
            operation,
        };
        if !raw.verify::<H>() {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentKeyValue,
            });
        }
        Ok(raw)
    }

    /// Verified raw current-state proof for a single key.
    pub async fn key_value_proof_raw_at<Q: AsRef<[u8]>>(
        &self,
        watermark: Location<F>,
        key: Q,
    ) -> Result<RawKeyValueProof<H::Digest, K, V, N, F>, QmdbError> {
        let session = self.client.create_session();
        self.key_value_proof_raw_in_session(&session, watermark, key)
            .await
    }

    /// Verified current-state proof for a single key. The returned
    /// `operation` is the matching `Update`; its `next_key` is the value
    /// the proof was verified against.
    pub async fn key_value_proof_at<Q: AsRef<[u8]>>(
        &self,
        watermark: Location<F>,
        key: Q,
    ) -> Result<VerifiedKeyValue<H::Digest, K, V, F>, QmdbError> {
        let raw = self.key_value_proof_raw_at(watermark, key).await?;
        Ok(VerifiedKeyValue {
            root: raw.root,
            location: raw.proof.proof.loc,
            operation: raw.operation,
        })
    }

    async fn active_ordered_updates_in_session(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
    ) -> Result<Vec<ActiveOrderedOperation<F, K, V>>, QmdbError> {
        let (start, end) = UPDATE_CODEC.prefix_bounds();
        let mut rows = session.range_stream(&start, &end, usize::MAX, 1024).await?;
        let mut latest = BTreeMap::<Vec<u8>, (Location<F>, UpdateRow<K, V>)>::new();
        while let Some(chunk) = rows.next_chunk().await? {
            for (row_key, row_value) in chunk {
                let location = decode_update_location(&row_key)?;
                if location > watermark {
                    continue;
                }
                let decoded = <UpdateRow<K, V> as CodecRead>::read_cfg(
                    &mut row_value.as_ref(),
                    &self.update_row_cfg,
                )
                .map_err(|e| QmdbError::CorruptData(format!("update row decode: {e}")))?;
                let key = decoded.key.as_ref().to_vec();
                latest
                    .entry(key)
                    .and_modify(|(known_location, known_row)| {
                        if location > *known_location {
                            *known_location = location;
                            *known_row = decoded.clone();
                        }
                    })
                    .or_insert((location, decoded));
            }
        }

        let mut active = Vec::new();
        for (key, (location, row)) in latest {
            if row.value.is_none() {
                continue;
            }
            let operation = self.load_operation_at(session, location).await?;
            let QmdbOperation::Update(update) = &operation else {
                return Err(QmdbError::CorruptData(format!(
                    "latest active key row at {location} does not point to an update operation"
                )));
            };
            if update.key.as_ref() != key.as_slice() {
                return Err(QmdbError::CorruptData(format!(
                    "active update key mismatch at {location}"
                )));
            }
            active.push(ActiveOrderedOperation {
                key,
                location,
                operation,
            });
        }
        active.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(active)
    }

    fn span_contains_requested(span_start: &[u8], span_end: &[u8], requested_key: &[u8]) -> bool {
        if span_start >= span_end {
            requested_key >= span_start || requested_key < span_end
        } else {
            requested_key >= span_start && requested_key < span_end
        }
    }

    async fn key_exclusion_proof_raw_in_session(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
        key: &[u8],
    ) -> Result<RawKeyExclusionProof<H::Digest, K, V, N, F>, QmdbError> {
        self.core()
            .require_published_watermark(session, watermark)
            .await?;
        self.core()
            .require_batch_boundary(session, watermark)
            .await?;
        let root = self.load_current_boundary_root(session, watermark).await?;
        let active = self
            .active_ordered_updates_in_session(session, watermark)
            .await?;

        let proof = if active.is_empty() {
            let operation = self.load_operation_at(session, watermark).await?;
            let QmdbOperation::CommitFloor(value, floor) = operation else {
                return Err(QmdbError::CorruptData(format!(
                    "empty ordered exclusion proof expected CommitFloor at watermark {watermark}"
                )));
            };
            if floor != watermark {
                return Err(QmdbError::CorruptData(format!(
                    "empty ordered exclusion proof expected floor {watermark}, got {floor}"
                )));
            }
            let op_proof = self
                .build_current_operation_proof(session, watermark, watermark)
                .await?;
            CurrentExclusionProof::Commit(op_proof, value)
        } else {
            let mut span = None;
            for active in &active {
                let QmdbOperation::Update(update) = &active.operation else {
                    continue;
                };
                if update.key.as_ref() == key {
                    return Err(QmdbError::CorruptData(
                        "cannot build exclusion proof for active key".to_string(),
                    ));
                }
                if Self::span_contains_requested(update.key.as_ref(), update.next_key.as_ref(), key)
                {
                    span = Some((active.location, update.clone()));
                    break;
                }
            }
            let Some((location, update)) = span else {
                return Err(QmdbError::CorruptData(format!(
                    "no ordered active-key span contains requested key {key:?}"
                )));
            };
            let op_proof = self
                .build_current_operation_proof(session, watermark, location)
                .await?;
            CurrentExclusionProof::KeyValue(op_proof, update)
        };

        let raw = RawKeyExclusionProof {
            watermark,
            root,
            requested_key: key.to_vec(),
            proof,
        };
        if !raw.verify::<H>() {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentKeyExclusion,
            });
        }
        Ok(raw)
    }

    /// Verified raw current-state proof that a key is absent.
    pub async fn key_exclusion_proof_raw_at<Q: AsRef<[u8]>>(
        &self,
        watermark: Location<F>,
        key: Q,
    ) -> Result<RawKeyExclusionProof<H::Digest, K, V, N, F>, QmdbError> {
        let session = self.client.create_session();
        self.key_exclusion_proof_raw_in_session(&session, watermark, key.as_ref())
            .await
    }

    /// Verified current-state proofs for explicit keys, preserving request order.
    pub async fn key_lookup_proofs_raw_at<Q: AsRef<[u8]>>(
        &self,
        watermark: Location<F>,
        keys: &[Q],
    ) -> Result<Vec<RawKeyLookupProof<H::Digest, K, V, N, F>>, QmdbError> {
        if keys.is_empty() {
            return Err(QmdbError::EmptyProofRequest);
        }

        let session = self.client.create_session();
        let mut seen = BTreeSet::<Vec<u8>>::new();
        let mut proofs = Vec::with_capacity(keys.len());
        for key in keys {
            let key_bytes = key.as_ref().to_vec();
            if !seen.insert(key_bytes.clone()) {
                return Err(QmdbError::DuplicateRequestedKey { key: key_bytes });
            }
            match self
                .key_value_proof_raw_in_session(&session, watermark, key.as_ref())
                .await
            {
                Ok(proof) => proofs.push(RawKeyLookupProof::Hit(proof)),
                Err(QmdbError::ProofKeyNotFound { .. } | QmdbError::KeyNotActive { .. }) => {
                    let proof = self
                        .key_exclusion_proof_raw_in_session(&session, watermark, key.as_ref())
                        .await?;
                    proofs.push(RawKeyLookupProof::Miss(proof));
                }
                Err(err) => return Err(err),
            }
        }
        Ok(proofs)
    }

    /// Verified ordered current-state range proof for `[start_key, end_key)`.
    pub async fn key_range_proof_raw_at(
        &self,
        watermark: Location<F>,
        start_key: &[u8],
        end_key: Option<&[u8]>,
        limit: u32,
    ) -> Result<RawKeyRangeProof<H::Digest, K, V, N, F>, QmdbError> {
        if limit == 0 {
            return Err(QmdbError::InvalidRangeLength);
        }
        if end_key.is_some_and(|end| end <= start_key) {
            return Err(QmdbError::InvalidKeyRange {
                start_key: start_key.to_vec(),
                end_key: end_key.unwrap().to_vec(),
            });
        }

        let session = self.client.create_session();
        self.core()
            .require_published_watermark(&session, watermark)
            .await?;
        self.core()
            .require_batch_boundary(&session, watermark)
            .await?;

        let active = self
            .active_ordered_updates_in_session(&session, watermark)
            .await?;
        let matching: Vec<_> = active
            .into_iter()
            .filter(|entry| {
                entry.key.as_slice() >= start_key
                    && end_key.is_none_or(|end| entry.key.as_slice() < end)
            })
            .collect();
        let limit = limit as usize;
        let has_more = matching.len() > limit;
        let selected = matching.into_iter().take(limit).collect::<Vec<_>>();

        let mut entries = Vec::with_capacity(selected.len());
        for entry in &selected {
            let proof = self
                .key_value_proof_raw_in_session(&session, watermark, entry.key.as_slice())
                .await?;
            entries.push(RawKeyRangeEntry {
                key: entry.key.clone(),
                proof,
            });
        }

        let start_proof = if entries
            .first()
            .is_some_and(|entry| entry.key.as_slice() == start_key)
        {
            None
        } else {
            Some(
                self.key_exclusion_proof_raw_in_session(&session, watermark, start_key)
                    .await?,
            )
        };

        let next_start_key = if has_more {
            entries
                .last()
                .and_then(|entry| match &entry.proof.operation {
                    QmdbOperation::Update(update) => Some(update.next_key.as_ref().to_vec()),
                    _ => None,
                })
                .ok_or_else(|| {
                    QmdbError::CorruptData(
                        "truncated key range did not include a final update entry".to_string(),
                    )
                })?
        } else {
            Vec::new()
        };

        let end_proof = if !has_more {
            if let Some(end_key) = end_key {
                match self
                    .key_value_proof_raw_in_session(&session, watermark, end_key)
                    .await
                {
                    Ok(_) => None,
                    Err(QmdbError::ProofKeyNotFound { .. } | QmdbError::KeyNotActive { .. }) => {
                        Some(
                            self.key_exclusion_proof_raw_in_session(&session, watermark, end_key)
                                .await?,
                        )
                    }
                    Err(err) => return Err(err),
                }
            } else {
                None
            }
        } else {
            None
        };

        Ok(RawKeyRangeProof {
            watermark,
            entries,
            start_proof,
            end_proof,
            has_more,
            next_start_key,
        })
    }

    async fn load_current_boundary_root(
        &self,
        session: &SerializableReadSession,
        location: Location<F>,
    ) -> Result<H::Digest, QmdbError> {
        let Some(bytes) = session.get(&encode_current_meta_key(location)).await? else {
            return Err(QmdbError::CurrentBoundaryStateMissing {
                location: location.as_u64(),
            });
        };
        decode_digest(
            bytes.as_ref(),
            format!("current boundary root at {location}"),
        )
    }

    pub(crate) async fn compute_ops_root(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
    ) -> Result<H::Digest, QmdbError> {
        self.core().compute_ops_root::<H>(session, watermark).await
    }

    async fn materialize_bitmap_status(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
        inactivity_floor: Location<F>,
    ) -> Result<MaterializedBitmapStatus<N>, QmdbError> {
        let leaves = watermark
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        let len = *leaves;
        let chunk_bits = bitmap_chunk_bits::<N>();
        let pruned_chunks_u64 = *inactivity_floor / chunk_bits;
        let pruned_chunks = usize::try_from(pruned_chunks_u64).map_err(|_| {
            QmdbError::CorruptData("current bitmap pruned chunk count overflows usize".to_string())
        })?;
        let last_chunk = if len == 0 {
            None
        } else if len % chunk_bits == 0 {
            Some((len / chunk_bits).saturating_sub(1))
        } else {
            Some(len / chunk_bits)
        };

        let mut chunks = std::collections::BTreeMap::new();
        if let Some(last_chunk) = last_chunk.filter(|last| *last >= pruned_chunks_u64) {
            let loaded = futures::future::try_join_all((pruned_chunks_u64..=last_chunk).map(
                |chunk_index| async move {
                    let chunk = self
                        .load_bitmap_chunk_with_floor(
                            session,
                            watermark,
                            inactivity_floor,
                            chunk_index,
                        )
                        .await?;
                    let chunk_index = usize::try_from(chunk_index).map_err(|_| {
                        QmdbError::CorruptData(
                            "current bitmap chunk index overflows usize".to_string(),
                        )
                    })?;
                    Ok::<_, QmdbError>((chunk_index, chunk))
                },
            ))
            .await?;
            chunks.extend(loaded);
        }

        Ok(MaterializedBitmapStatus {
            len,
            pruned_chunks,
            chunks,
        })
    }

    async fn build_current_range_proof(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
        start_location: Location<F>,
        end_location_exclusive: Location<F>,
    ) -> Result<CurrentRangeProof<F, H::Digest>, QmdbError> {
        let inactivity_floor = self.load_inactivity_floor_at(session, watermark).await?;
        let status = self
            .materialize_bitmap_status(session, watermark, inactivity_floor)
            .await?;
        let storage = KvCurrentStorage::<F, H::Digest, N> {
            session,
            watermark,
            size: merkle_size_for_watermark(watermark)?,
            _marker: PhantomData,
        };
        let mut hasher = H::default();
        CurrentRangeProof::new(
            &mut hasher,
            &status,
            &storage,
            inactivity_floor,
            start_location..end_location_exclusive,
            self.compute_ops_root(session, watermark).await?,
        )
        .await
        .map_err(|e| QmdbError::CommonwareMerkle(e.to_string()))
    }

    async fn build_current_operation_proof(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
        location: Location<F>,
    ) -> Result<CurrentOperationProof<F, H::Digest, N>, QmdbError> {
        self.core()
            .require_published_watermark(session, watermark)
            .await?;
        self.core()
            .require_batch_boundary(session, watermark)
            .await?;
        let inactivity_floor = self.load_inactivity_floor_at(session, watermark).await?;
        let status = self
            .materialize_bitmap_status(session, watermark, inactivity_floor)
            .await?;
        let storage = KvCurrentStorage::<F, H::Digest, N> {
            session,
            watermark,
            size: merkle_size_for_watermark(watermark)?,
            _marker: PhantomData,
        };
        let mut hasher = H::default();
        CurrentOperationProof::new(
            &mut hasher,
            &status,
            &storage,
            inactivity_floor,
            location,
            self.compute_ops_root(session, watermark).await?,
        )
        .await
        .map_err(|e| QmdbError::CommonwareMerkle(e.to_string()))
    }

    async fn load_inactivity_floor_at(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
    ) -> Result<Location<F>, QmdbError> {
        let operation = self.load_operation_at(session, watermark).await?;
        match operation {
            QmdbOperation::CommitFloor(_, floor) => Ok(floor),
            _ => Err(QmdbError::CorruptData(format!(
                "expected CommitFloor at watermark {watermark}"
            ))),
        }
    }

    async fn load_bitmap_chunk_with_floor(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
        inactivity_floor: Location<F>,
        chunk_index: u64,
    ) -> Result<[u8; N], QmdbError> {
        let start = encode_chunk_key(chunk_index, Location::<F>::new(0));
        let end = encode_chunk_key(chunk_index, watermark);
        let rows = session
            .range_with_mode(&start, &end, 1, RangeMode::Reverse)
            .await?;
        let mut chunk = match rows.into_iter().next() {
            Some((_, bytes)) => {
                if bytes.len() != N {
                    return Err(QmdbError::CorruptData(format!(
                        "bitmap chunk {chunk_index} has invalid length {}",
                        bytes.len()
                    )));
                }
                let mut buf = [0u8; N];
                buf.copy_from_slice(bytes.as_ref());
                buf
            }
            None => {
                // The writer elides chunks whose entire bit range is below
                // the inactivity floor (see `changed_chunk_representatives`
                // in `boundary.rs`). For such chunks the server never has a
                // stored copy; the content is definitionally all zeros. For
                // any other missing chunk the upload genuinely dropped a row.
                let chunk_end_exclusive = chunk_index
                    .saturating_add(1)
                    .saturating_mul(bitmap_chunk_bits::<N>());
                if chunk_end_exclusive > *inactivity_floor {
                    return Err(QmdbError::CorruptData(format!(
                        "missing bitmap chunk {chunk_index} at watermark {watermark}"
                    )));
                }
                [0u8; N]
            }
        };
        clear_below_floor::<F, N>(&mut chunk, chunk_index, inactivity_floor);
        Ok(chunk)
    }

    async fn load_bitmap_chunks(
        &self,
        session: &SerializableReadSession,
        watermark: Location<F>,
        start_location: Location<F>,
        end_location_exclusive: Location<F>,
    ) -> Result<Vec<[u8; N]>, QmdbError> {
        let floor = self.load_inactivity_floor_at(session, watermark).await?;
        let start_chunk = chunk_index_for_location::<F, N>(start_location);
        let end_chunk = chunk_index_for_location::<F, N>(end_location_exclusive - 1);
        futures::future::try_join_all((start_chunk..=end_chunk).map(|chunk_index| {
            self.load_bitmap_chunk_with_floor(session, watermark, floor, chunk_index)
        }))
        .await
    }

    async fn load_operation_at(
        &self,
        session: &SerializableReadSession,
        location: Location<F>,
    ) -> Result<QmdbOperation<F, K, V>, QmdbError> {
        let bytes = self
            .core()
            .load_operation_bytes_at(session, location)
            .await?;
        QmdbOperation::<F, K, V>::decode_cfg(bytes.as_slice(), &self.op_cfg).map_err(|e| {
            QmdbError::CorruptData(format!(
                "failed to decode qmdb operation at location {location}: {e}"
            ))
        })
    }

    async fn load_operation_range(
        &self,
        session: &SerializableReadSession,
        start_location: Location<F>,
        end_location_exclusive: Location<F>,
    ) -> Result<Vec<QmdbOperation<F, K, V>>, QmdbError> {
        let rows = self
            .core()
            .load_operation_bytes_range(session, start_location, end_location_exclusive)
            .await?;
        rows.into_iter()
            .enumerate()
            .map(|(offset, bytes)| {
                let location = start_location + offset as u64;
                QmdbOperation::<F, K, V>::decode_cfg(bytes.as_slice(), &self.op_cfg).map_err(|e| {
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
        watermark: Location<F>,
        key: &[u8],
    ) -> Result<Option<(Key, Vec<u8>)>, QmdbError> {
        self.core()
            .load_latest_update_row(session, watermark, key)
            .await
    }
}
