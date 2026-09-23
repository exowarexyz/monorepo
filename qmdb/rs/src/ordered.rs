use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::sync::Arc;

use commonware_codec::{Codec, Decode, DecodeExt, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::{Graftable, Location},
    qmdb::{
        any::{
            ordered,
            value::{ValueEncoding, VariableEncoding},
        },
        current::{
            ordered::ExclusionProof,
            proof::{OperationProof, OpsRootWitness, RangeProof},
        },
        operation::{Key as QmdbKey, Operation as _},
    },
};
use exoware_sdk::{PrefixedStoreClient, RangeMode, ReadSession};

use crate::codec::{
    chunk_index_for_location, clear_below_floor, decode_current_boundary_metadata,
    decode_update_index_value_present, decode_update_location, decode_update_raw_key,
    encode_chunk_key, encode_current_meta_key, encode_operation_key, encode_ops_root_witness_key,
    encode_update_key, merkle_size_for_watermark, CurrentBoundaryMetadata, UPDATE_PREFIX,
};
use crate::connect::OperationKv;
use crate::core::{self, PublishedWatermark};
use crate::error::{error_key, QmdbError};
use crate::operation_range::load_operation_range_checkpoint;
use crate::proof::{
    CurrentOperationRangeProofResult, OperationRangeCheckpoint, RawBatchMultiProof,
    RawKeyExclusionProof, RawKeyLookupProof, RawKeyRangeProof, RawKeyValueProof, RawMultiProof,
    VerifiedCurrentRange, VerifiedKeyValue, VerifiedMultiOperations, VerifiedOperationRange,
};
use crate::read_cache::ReadCache;
use crate::request::span_contains;
use crate::storage::{KvCurrentStorage, KvMerkleStorage, ProofBitmap};
use crate::VersionedValue;

const ACTIVE_OPERATION_GET_MANY_BATCH: usize = 1024;

pub struct OrderedClient<
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> where
    ordered::Operation<F, K, E>: commonware_codec::Read,
{
    store: PrefixedStoreClient,
    publication: Arc<core::PublicationCache<F>>,
    op_cfg: <ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
    key_cfg: K::Cfg,
    read_cache: Arc<ReadCache<F, H::Digest>>,
    _marker: PhantomData<(F, H, K, E)>,
}

impl<
        F: Graftable,
        H: Hasher,
        K: QmdbKey + Codec,
        V: Codec + Clone + Send + Sync,
        const N: usize,
        E: ValueEncoding<Value = V>,
    > Clone for OrderedClient<F, H, K, V, N, E>
where
    ordered::Operation<F, K, E>: commonware_codec::Read,
{
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            publication: self.publication.clone(),
            op_cfg: self.op_cfg.clone(),
            key_cfg: self.key_cfg.clone(),
            read_cache: self.read_cache.clone(),
            _marker: PhantomData,
        }
    }
}

impl<
        F: Graftable,
        H: Hasher,
        K: QmdbKey + Codec,
        V: Codec + Clone + Send + Sync,
        const N: usize,
        E: ValueEncoding<Value = V>,
    > std::fmt::Debug for OrderedClient<F, H, K, V, N, E>
where
    ordered::Operation<F, K, E>: commonware_codec::Read,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrderedClient").finish_non_exhaustive()
    }
}

impl<F, H, K, V, const N: usize, E> crate::core::LatestValueResolver<F, K, V>
    for OrderedClient<F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    ordered::Operation<F, K, E>: Encode + Decode,
{
    fn resolve_latest_value(
        &self,
        location: Location<F>,
        requested_key: &[u8],
        op_bytes: Vec<u8>,
    ) -> Result<VersionedValue<K, V, F>, QmdbError> {
        let (key, value) = match Self::decode_operation(&self.op_cfg, location, &op_bytes)? {
            ordered::Operation::Update(update) => (update.key, Some(update.value)),
            ordered::Operation::Delete(key) => (key, None),
            ordered::Operation::CommitFloor(_, _) => {
                return Err(QmdbError::CorruptData(format!(
                    "latest update row at {location} points to a commit operation"
                )));
            }
        };
        if key.as_ref() != requested_key {
            return Err(QmdbError::CorruptData(format!(
                "latest update row at {location} points to a different key"
            )));
        }
        Ok(VersionedValue {
            key,
            location,
            value,
        })
    }
}

impl<F, H, K, V, const N: usize, E> OrderedClient<F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    ordered::Operation<F, K, E>: commonware_codec::Read,
{
    /// Read client for the Store namespace.
    pub fn new(
        store: PrefixedStoreClient,
        op_cfg: <ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        key_cfg: K::Cfg,
    ) -> Self {
        Self {
            store,
            publication: Arc::new(core::PublicationCache::default()),
            op_cfg,
            key_cfg,
            read_cache: Arc::new(ReadCache::new()),
            _marker: PhantomData,
        }
    }
}

impl<F, H, K, V, const N: usize, E> OrderedClient<F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    ordered::Operation<F, K, E>: Encode + Decode,
{
    pub(crate) fn decode_key(&self, encoded_key: &[u8]) -> Result<K, commonware_codec::Error> {
        K::decode_cfg(encoded_key, &self.key_cfg)
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
        Self::compute_ops_root(&session, &self.op_cfg, watermark.location).await
    }

    pub async fn current_root_at(&self, watermark: Location<F>) -> Result<H::Digest, QmdbError> {
        let watermark = self.resolve_watermark(watermark, None).await?;
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        core::require_batch_boundary(&session, watermark.location).await?;
        Self::load_current_boundary_root(&session, watermark.location).await
    }

    pub async fn query_many_at<Q: AsRef<[u8]>>(
        &self,
        keys: &[Q],
        max_location: Location<F>,
    ) -> Result<Vec<Option<VersionedValue<K, V, F>>>, QmdbError> {
        let watermark = self.resolve_watermark(max_location, None).await?;
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        core::query_many_at(&session, keys, watermark.location, self).await
    }

    fn decode_operation(
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<ordered::Operation<F, K, E>, QmdbError> {
        ordered::Operation::<F, K, E>::decode_cfg(bytes, op_cfg).map_err(|e| {
            QmdbError::CorruptData(format!(
                "failed to decode qmdb operation at location {location}: {e}"
            ))
        })
    }

    pub(crate) fn decode_operation_bytes(
        &self,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<ordered::Operation<F, K, E>, QmdbError> {
        Self::decode_operation(&self.op_cfg, location, bytes)
    }

    pub(crate) fn extract_operation_kv(
        &self,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError>
    where
        V: AsRef<[u8]>,
    {
        let op = Self::decode_operation(&self.op_cfg, location, bytes)?;
        let key = op.key().map(|k| <K as AsRef<[u8]>>::as_ref(k).to_vec());
        let value = match &op {
            ordered::Operation::Update(update) => Some(update.value.as_ref().to_vec()),
            ordered::Operation::CommitFloor(Some(value), _) => Some(value.as_ref().to_vec()),
            ordered::Operation::Delete(_) | ordered::Operation::CommitFloor(None, _) => None,
        };
        Ok(OperationKv { key, value })
    }

    async fn multi_proof_raw_at_watermark<Q: AsRef<[u8]>>(
        &self,
        watermark: PublishedWatermark<F>,
        keys: &[Q],
    ) -> Result<RawMultiProof<H::Digest, K, V, F, E>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        let storage = KvMerkleStorage::<F, H::Digest> {
            session: &session,
            size: merkle_size_for_watermark(watermark.location)?,
            _marker: PhantomData,
        };
        let inactive_peaks =
            Self::ops_inactive_peaks_at(&session, &self.op_cfg, watermark.location).await?;
        let root =
            core::compute_ops_root::<F, H>(&session, watermark.location, inactive_peaks).await?;

        let mut seen = BTreeSet::<Vec<u8>>::new();
        let mut operation_bytes = Vec::<(Location<F>, Vec<u8>)>::with_capacity(keys.len());
        for key in keys {
            let key_bytes = error_key(key);
            if !seen.insert(key_bytes.clone()) {
                return Err(QmdbError::DuplicateRequestedKey { key: key_bytes });
            }
            let start = encode_update_key(key.as_ref(), Location::<F>::new(0))?;
            let end = encode_update_key(key.as_ref(), watermark.location)?;
            let rows = session
                .range_with_mode(&start, &end, 1, RangeMode::Reverse)
                .await?;
            let Some((row_key, _row_value)) = rows.into_iter().next() else {
                return Err(QmdbError::ProofKeyNotFound {
                    watermark: watermark.location.as_u64(),
                    key: key_bytes.clone(),
                });
            };
            let global_loc = decode_update_location(&row_key)?;
            let encoded = core::load_operation_bytes_at(&session, global_loc).await?;
            operation_bytes.push((global_loc, encoded));
        }
        operation_bytes.sort_by_key(|(loc, _)| *loc);

        let raw = crate::proof::build_batch_multi_proof::<F, H, _>(
            &storage,
            watermark.location,
            root,
            inactive_peaks,
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

    pub(crate) async fn batch_multi_proof(
        &self,
        watermark: PublishedWatermark<F>,
        operations: Vec<(Location<F>, Vec<u8>)>,
    ) -> Result<RawBatchMultiProof<H::Digest, F>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        let storage = KvMerkleStorage::<F, H::Digest> {
            session: &session,
            size: merkle_size_for_watermark(watermark.location)?,
            _marker: PhantomData,
        };
        let inactive_peaks =
            Self::ops_inactive_peaks_at(&session, &self.op_cfg, watermark.location).await?;
        let root =
            core::compute_ops_root::<F, H>(&session, watermark.location, inactive_peaks).await?;
        let mut proof = crate::proof::build_batch_multi_proof::<F, H, _>(
            &storage,
            watermark.location,
            root,
            inactive_peaks,
            operations,
        )
        .await?;
        proof.ops_root_witness = Self::load_ops_root_witness(&session, watermark.location).await?;
        Ok(proof)
    }

    /// Verified raw multi-proof over a set of keys.
    pub async fn multi_proof_raw_at<Q: AsRef<[u8]>>(
        &self,
        watermark: Location<F>,
        keys: &[Q],
    ) -> Result<RawMultiProof<H::Digest, K, V, F, E>, QmdbError> {
        if keys.is_empty() {
            return Err(QmdbError::EmptyProofRequest);
        }
        let watermark = self.resolve_watermark(watermark, None).await?;
        self.multi_proof_raw_at_watermark(watermark, keys).await
    }

    /// Verified multi-proof over a set of keys.
    pub async fn multi_proof_at<Q: AsRef<[u8]>>(
        &self,
        watermark: Location<F>,
        keys: &[Q],
    ) -> Result<VerifiedMultiOperations<H::Digest, K, V, F, E>, QmdbError> {
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
    ) -> Result<VerifiedOperationRange<H::Digest, ordered::Operation<F, K, E>, F>, QmdbError> {
        let checkpoint = self
            .operation_range_checkpoint(watermark, start_location, max_locations)
            .await?;
        let operations = checkpoint
            .encoded_operations
            .iter()
            .enumerate()
            .map(|(offset, bytes)| {
                let location = checkpoint.start_location + offset as u64;
                self.decode_operation_bytes(location, bytes)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(VerifiedOperationRange {
            root: checkpoint.root,
            start_location: checkpoint.start_location,
            operations,
        })
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
        let watermark = watermark.location;
        let end = crate::proof::resolve_range_bounds(watermark, start_location, max_locations)?;
        let checkpoint = load_operation_range_checkpoint::<F, H, _>(
            &session,
            &self.read_cache,
            watermark,
            start_location,
            end,
            true,
            |bytes| async {
                let mut location = watermark;
                let mut operation = ordered::Operation::<F, K, E>::decode_cfg(bytes, &self.op_cfg)
                    .map_err(|error| {
                        QmdbError::CorruptData(format!(
                            "operation at {watermark} decode error: {error}"
                        ))
                    })?;
                let floor = loop {
                    if let ordered::Operation::CommitFloor(_, floor) = operation {
                        break floor;
                    }
                    if *location == 0 {
                        return Err(QmdbError::CorruptData(format!(
                            "no CommitFloor found at or before watermark {watermark}"
                        )));
                    }
                    location -= 1;
                    operation = Self::load_operation_at(&session, &self.op_cfg, location).await?;
                };
                core::inactive_peaks(watermark, floor)
            },
        )
        .await?;
        Ok(checkpoint)
    }

    /// Verified raw current-state proof for a contiguous operation range.
    pub async fn current_operation_range_proof_raw_at(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
        min_sequence_number: Option<u64>,
    ) -> Result<
        CurrentOperationRangeProofResult<H::Digest, ordered::Operation<F, K, E>, N, F>,
        QmdbError,
    > {
        let watermark = self
            .resolve_watermark(watermark, min_sequence_number)
            .await?;
        let end =
            crate::proof::resolve_range_bounds(watermark.location, start_location, max_locations)?;
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        core::require_batch_boundary(&session, watermark.location).await?;
        let proof = Self::build_current_range_proof(
            &session,
            &self.op_cfg,
            watermark.location,
            start_location,
            end,
        )
        .await?;
        let root = Self::load_current_boundary_root(&session, watermark.location).await?;
        let operations =
            Self::load_operation_range(&session, &self.op_cfg, start_location, end).await?;
        let chunks = Self::load_bitmap_chunks(
            &session,
            &self.op_cfg,
            watermark.location,
            start_location,
            end,
        )
        .await?;
        let raw = CurrentOperationRangeProofResult {
            watermark: watermark.location,
            root,
            start_location,
            proof,
            operations,
            chunks,
        };
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
        min_sequence_number: Option<u64>,
    ) -> Result<VerifiedCurrentRange<H::Digest, K, V, N, F, E>, QmdbError> {
        let raw = self
            .current_operation_range_proof_raw_at(
                watermark,
                start_location,
                max_locations,
                min_sequence_number,
            )
            .await?;
        Ok(VerifiedCurrentRange {
            root: raw.root,
            start_location: raw.start_location,
            operations: raw.operations,
            chunks: raw.chunks,
        })
    }

    async fn key_value_proof_raw<Q: AsRef<[u8]>>(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        watermark: Location<F>,
        key: Q,
    ) -> Result<RawKeyValueProof<H::Digest, ordered::Operation<F, K, E>, N, F>, QmdbError> {
        core::require_batch_boundary(session, watermark).await?;
        let key_bytes = error_key(&key);
        let Some((row_key, row_value)) =
            core::load_latest_update_row(session, watermark, key.as_ref()).await?
        else {
            return Err(QmdbError::ProofKeyNotFound {
                watermark: watermark.as_u64(),
                key: key_bytes,
            });
        };
        let location = decode_update_location(&row_key)?;
        let inactivity_floor = Self::load_inactivity_floor_at(session, op_cfg, watermark).await?;
        if location < inactivity_floor || !decode_update_index_value_present(row_value.as_ref())? {
            return Err(QmdbError::KeyNotActive {
                watermark: watermark.as_u64(),
                key: key_bytes,
            });
        }

        let operation = Self::load_operation_at(session, op_cfg, location).await?;
        let ordered::Operation::Update(update) = &operation else {
            return Err(QmdbError::KeyNotActive {
                watermark: watermark.as_u64(),
                key: key_bytes,
            });
        };
        if update.key.as_ref() != key.as_ref() {
            return Err(QmdbError::CorruptData(format!(
                "latest active ordered key row at {location} points to a different key"
            )));
        }
        let root = Self::load_current_boundary_root(session, watermark).await?;
        let proof =
            Self::build_current_operation_proof(session, op_cfg, watermark, location).await?;
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

    async fn key_value_proof_raw_at_watermark<Q: AsRef<[u8]>>(
        &self,
        watermark: PublishedWatermark<F>,
        key: Q,
    ) -> Result<RawKeyValueProof<H::Digest, ordered::Operation<F, K, E>, N, F>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        Self::key_value_proof_raw(&session, &self.op_cfg, watermark.location, key).await
    }

    /// Verified raw current-state proof for a single key.
    pub async fn key_value_proof_raw_at<Q: AsRef<[u8]>>(
        &self,
        watermark: Location<F>,
        key: Q,
        min_sequence_number: Option<u64>,
    ) -> Result<RawKeyValueProof<H::Digest, ordered::Operation<F, K, E>, N, F>, QmdbError> {
        let watermark = self
            .resolve_watermark(watermark, min_sequence_number)
            .await?;
        self.key_value_proof_raw_at_watermark(watermark, key).await
    }

    /// Verified current-state proof for a single key. The returned
    /// `operation` is the matching `Update`. Its `next_key` is the value
    /// the proof was verified against.
    pub async fn key_value_proof_at<Q: AsRef<[u8]>>(
        &self,
        watermark: Location<F>,
        key: Q,
        min_sequence_number: Option<u64>,
    ) -> Result<VerifiedKeyValue<H::Digest, ordered::Operation<F, K, E>, F>, QmdbError> {
        let raw = self
            .key_value_proof_raw_at(watermark, key, min_sequence_number)
            .await?;
        Ok(VerifiedKeyValue {
            root: raw.root,
            location: raw.proof.loc,
            operation: raw.operation,
        })
    }

    async fn active_ordered_updates(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        watermark: Location<F>,
    ) -> Result<Vec<(Location<F>, ordered::Update<K, E>)>, QmdbError> {
        let inactivity_floor = Self::load_inactivity_floor_at(session, op_cfg, watermark).await?;
        let (start, end) = UPDATE_PREFIX.bounds();
        let mut rows = session.range_stream(&start, &end, usize::MAX, 1024).await?;
        let mut latest = BTreeMap::<Vec<u8>, (Location<F>, bool)>::new();
        while let Some(chunk) = rows.next_chunk().await? {
            for (row_key, row_value) in chunk.rows {
                let location = decode_update_location(&row_key)?;
                if location < inactivity_floor || location > watermark {
                    continue;
                }
                let value_present = decode_update_index_value_present(&row_value)?;
                let key = decode_update_raw_key(&row_key)?;
                latest
                    .entry(key)
                    .and_modify(|(known_location, known_value_present)| {
                        if location > *known_location {
                            *known_location = location;
                            *known_value_present = value_present;
                        }
                    })
                    .or_insert((location, value_present));
            }
        }

        let active_locations = latest
            .into_iter()
            .filter_map(|(key, (location, value_present))| value_present.then_some((key, location)))
            .collect::<Vec<_>>();

        let mut loaded_operations =
            std::collections::HashMap::with_capacity(active_locations.len());
        for chunk in active_locations.chunks(ACTIVE_OPERATION_GET_MANY_BATCH) {
            let operation_keys = chunk
                .iter()
                .map(|(_, location)| encode_operation_key(*location))
                .collect::<Vec<_>>();
            let operation_key_refs = operation_keys.iter().collect::<Vec<_>>();
            let batch_size = u32::try_from(operation_key_refs.len()).map_err(|_| {
                QmdbError::CorruptData(
                    "active operation get_many batch size overflows u32".to_string(),
                )
            })?;
            let fetched = session
                .get_many(&operation_key_refs, batch_size)
                .await?
                .collect()
                .await?;
            loaded_operations.extend(fetched);
        }

        let mut active = Vec::new();
        for (key, location) in active_locations {
            let operation_key = encode_operation_key(location);
            let Some(encoded) = loaded_operations.remove(&operation_key) else {
                return Err(QmdbError::CorruptData(format!(
                    "missing operation row at location {location}"
                )));
            };
            let operation = Self::decode_operation(op_cfg, location, encoded.as_ref())?;
            let ordered::Operation::Update(update) = operation else {
                return Err(QmdbError::CorruptData(format!(
                    "latest active key row at {location} does not point to an update operation"
                )));
            };
            if update.key.as_ref() != key.as_slice() {
                return Err(QmdbError::CorruptData(format!(
                    "active update key mismatch at {location}"
                )));
            }
            active.push((location, update));
        }
        active.sort_by(|a, b| a.1.key.cmp(&b.1.key));
        Ok(active)
    }

    async fn active_ordered_updates_at_watermark(
        &self,
        watermark: PublishedWatermark<F>,
    ) -> Result<Vec<(Location<F>, ordered::Update<K, E>)>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        Self::active_ordered_updates(&session, &self.op_cfg, watermark.location).await
    }

    async fn key_exclusion_proof(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        watermark: Location<F>,
        key: &K,
    ) -> Result<RawKeyExclusionProof<H::Digest, K, V, N, F, E>, QmdbError> {
        core::require_batch_boundary(session, watermark).await?;
        let root = Self::load_current_boundary_root(session, watermark).await?;
        let active = Self::active_ordered_updates(session, op_cfg, watermark).await?;

        let proof = if active.is_empty() {
            let operation = Self::load_operation_at(session, op_cfg, watermark).await?;
            let ordered::Operation::CommitFloor(value, floor) = operation else {
                return Err(QmdbError::CorruptData(format!(
                    "empty ordered exclusion proof expected CommitFloor at watermark {watermark}"
                )));
            };
            if floor != watermark {
                return Err(QmdbError::CorruptData(format!(
                    "empty ordered exclusion proof expected floor {watermark}, got {floor}"
                )));
            }
            let op_proof =
                Self::build_current_operation_proof(session, op_cfg, watermark, watermark).await?;
            ExclusionProof::Commit(op_proof, value)
        } else {
            let mut span = None;
            for (location, update) in active {
                if update.key == *key {
                    return Err(QmdbError::CorruptData(
                        "cannot build exclusion proof for active key".to_string(),
                    ));
                }
                if span_contains(&update.key, &update.next_key, key) {
                    span = Some((location, update));
                    break;
                }
            }
            let Some((location, update)) = span else {
                return Err(QmdbError::CorruptData(format!(
                    "no ordered active-key span contains requested key {key:?}"
                )));
            };
            let op_proof =
                Self::build_current_operation_proof(session, op_cfg, watermark, location).await?;
            ExclusionProof::KeyValue(op_proof, update)
        };

        let raw = RawKeyExclusionProof {
            watermark,
            root,
            requested_key: key.clone(),
            proof,
        };
        if !raw.verify::<H>() {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentKeyExclusion,
            });
        }
        Ok(raw)
    }

    async fn key_exclusion_proof_at_watermark(
        &self,
        watermark: PublishedWatermark<F>,
        key: &K,
    ) -> Result<RawKeyExclusionProof<H::Digest, K, V, N, F, E>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        Self::key_exclusion_proof(&session, &self.op_cfg, watermark.location, key).await
    }

    /// Verified current-state lookup proofs for explicit keys, preserving request order.
    pub async fn key_lookup_proofs_raw_at(
        &self,
        watermark: Location<F>,
        keys: &[K],
        min_sequence_number: Option<u64>,
    ) -> Result<Vec<RawKeyLookupProof<H::Digest, K, V, N, F, E>>, QmdbError> {
        if keys.is_empty() {
            return Err(QmdbError::EmptyProofRequest);
        }

        let watermark = self
            .resolve_watermark(watermark, min_sequence_number)
            .await?;
        let mut seen = BTreeSet::<Vec<u8>>::new();
        let mut proofs = Vec::with_capacity(keys.len());
        for key in keys {
            let key_bytes = error_key(key);
            if !seen.insert(key_bytes.clone()) {
                return Err(QmdbError::DuplicateRequestedKey { key: key_bytes });
            }
            match self
                .key_value_proof_raw_at_watermark(watermark, key.as_ref())
                .await
            {
                Ok(proof) => proofs.push(RawKeyLookupProof::Hit(proof)),
                Err(QmdbError::ProofKeyNotFound { .. } | QmdbError::KeyNotActive { .. }) => {
                    let proof = self
                        .key_exclusion_proof_at_watermark(watermark, key)
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
        start_key: K,
        end_key: Option<K>,
        limit: u32,
        min_sequence_number: Option<u64>,
    ) -> Result<RawKeyRangeProof<H::Digest, K, V, N, F, E>, QmdbError> {
        if limit == 0 {
            return Err(QmdbError::InvalidRangeLength);
        }
        if let Some(end) = end_key.as_ref() {
            if end <= &start_key {
                return Err(QmdbError::InvalidKeyRange {
                    start_key: error_key(&start_key),
                    end_key: error_key(end),
                });
            }
        }

        let watermark = self
            .resolve_watermark(watermark, min_sequence_number)
            .await?;

        let active = self.active_ordered_updates_at_watermark(watermark).await?;
        let selected = active
            .into_iter()
            .filter(|(_, update)| {
                update.key >= start_key && end_key.as_ref().is_none_or(|end| update.key < *end)
            })
            .take(limit as usize)
            .collect::<Vec<_>>();

        let mut entries = Vec::with_capacity(selected.len());
        for (_, update) in &selected {
            let proof = self
                .key_value_proof_raw_at_watermark(watermark, update.key.as_ref())
                .await?;
            entries.push(proof);
        }

        let start_proof = if entries
            .first()
            .is_some_and(|entry| entry.operation.key() == Some(&start_key))
        {
            None
        } else {
            Some(
                self.key_exclusion_proof_at_watermark(watermark, &start_key)
                    .await?,
            )
        };

        Ok(RawKeyRangeProof {
            watermark: watermark.location,
            entries,
            start_proof,
        })
    }

    async fn load_current_boundary_metadata(
        session: &ReadSession,
        location: Location<F>,
    ) -> Result<CurrentBoundaryMetadata<H::Digest>, QmdbError> {
        let Some(bytes) = session.get(&encode_current_meta_key(location)).await? else {
            return Err(QmdbError::CurrentBoundaryStateMissing {
                location: location.as_u64(),
            });
        };
        decode_current_boundary_metadata::<H::Digest>(
            bytes.as_ref(),
            format!("current boundary metadata at {location}"),
        )
    }

    async fn load_current_boundary_root(
        session: &ReadSession,
        location: Location<F>,
    ) -> Result<H::Digest, QmdbError> {
        Ok(Self::load_current_boundary_metadata(session, location)
            .await?
            .root)
    }

    async fn load_ops_root_witness(
        session: &ReadSession,
        location: Location<F>,
    ) -> Result<Option<OpsRootWitness<F, H::Digest>>, QmdbError> {
        let Some(bytes) = session.get(&encode_ops_root_witness_key(location)).await? else {
            return Ok(None);
        };
        OpsRootWitness::<F, H::Digest>::decode(bytes.as_ref())
            .map(Some)
            .map_err(|e| {
                QmdbError::CorruptData(format!(
                    "current ops-root witness at {location} decode error: {e}"
                ))
            })
    }

    async fn compute_ops_root(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        watermark: Location<F>,
    ) -> Result<H::Digest, QmdbError> {
        let inactive_peaks = Self::ops_inactive_peaks_at(session, op_cfg, watermark).await?;
        core::compute_ops_root::<F, H>(session, watermark, inactive_peaks).await
    }

    async fn proof_bitmap(
        session: &ReadSession,
        watermark: Location<F>,
        inactivity_floor: Location<F>,
        location: Option<Location<F>>,
    ) -> Result<ProofBitmap<N>, QmdbError> {
        let metadata = Self::load_current_boundary_metadata(session, watermark).await?;
        ProofBitmap::load(watermark, metadata.pruned_chunks, location, |chunk| {
            Self::load_bitmap_chunk_with_floor(session, watermark, inactivity_floor, chunk)
        })
        .await
    }

    async fn build_current_range_proof(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        watermark: Location<F>,
        start_location: Location<F>,
        end_location_exclusive: Location<F>,
    ) -> Result<RangeProof<F, H::Digest>, QmdbError> {
        let inactivity_floor = Self::load_inactivity_floor_at(session, op_cfg, watermark).await?;
        let status = Self::proof_bitmap(session, watermark, inactivity_floor, None).await?;
        let storage = KvCurrentStorage::<F, H, N> {
            session,
            watermark,
            pruned_chunks: status.pruned_chunks as u64,
            size: merkle_size_for_watermark(watermark)?,
            _marker: PhantomData,
        };
        RangeProof::new::<H, _, N>(
            &status,
            &storage,
            inactivity_floor,
            start_location..end_location_exclusive,
            Self::compute_ops_root(session, op_cfg, watermark).await?,
        )
        .await
        .map_err(crate::error::current_proof_error)
    }

    async fn build_current_operation_proof(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        watermark: Location<F>,
        location: Location<F>,
    ) -> Result<OperationProof<F, H::Digest, N>, QmdbError> {
        core::require_batch_boundary(session, watermark).await?;
        let inactivity_floor = Self::load_inactivity_floor_at(session, op_cfg, watermark).await?;
        let status =
            Self::proof_bitmap(session, watermark, inactivity_floor, Some(location)).await?;
        let storage = KvCurrentStorage::<F, H, N> {
            session,
            watermark,
            pruned_chunks: status.pruned_chunks as u64,
            size: merkle_size_for_watermark(watermark)?,
            _marker: PhantomData,
        };
        OperationProof::new::<H, _>(
            &status,
            &storage,
            inactivity_floor,
            location,
            Self::compute_ops_root(session, op_cfg, watermark).await?,
        )
        .await
        .map_err(crate::error::current_proof_error)
    }

    async fn load_inactivity_floor_at(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        watermark: Location<F>,
    ) -> Result<Location<F>, QmdbError> {
        match Self::load_operation_at(session, op_cfg, watermark).await? {
            ordered::Operation::CommitFloor(_, floor) => Ok(floor),
            _ => Err(QmdbError::CorruptData(format!(
                "expected CommitFloor at watermark {watermark}"
            ))),
        }
    }

    async fn load_ops_inactivity_floor_at(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        watermark: Location<F>,
    ) -> Result<Location<F>, QmdbError> {
        let mut location = watermark;
        loop {
            if let ordered::Operation::CommitFloor(_, floor) =
                Self::load_operation_at(session, op_cfg, location).await?
            {
                return Ok(floor);
            }
            if *location == 0 {
                return Err(QmdbError::CorruptData(format!(
                    "no CommitFloor found at or before watermark {watermark}"
                )));
            }
            location -= 1;
        }
    }

    async fn ops_inactive_peaks_at(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        watermark: Location<F>,
    ) -> Result<usize, QmdbError> {
        let inactivity_floor =
            Self::load_ops_inactivity_floor_at(session, op_cfg, watermark).await?;
        core::inactive_peaks(watermark, inactivity_floor)
    }

    async fn load_bitmap_chunk_with_floor(
        session: &ReadSession,
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
            Some((_, bytes)) => <[u8; N]>::decode(bytes.as_ref()).map_err(|e| {
                QmdbError::CorruptData(format!("bitmap chunk {chunk_index} decode error: {e}"))
            })?,
            None => {
                return Err(QmdbError::CorruptData(format!(
                    "missing bitmap chunk {chunk_index} at watermark {watermark}"
                )));
            }
        };
        clear_below_floor::<F, N>(&mut chunk, chunk_index, inactivity_floor);
        Ok(chunk)
    }

    async fn load_bitmap_chunks(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        watermark: Location<F>,
        start_location: Location<F>,
        end_location_exclusive: Location<F>,
    ) -> Result<Vec<[u8; N]>, QmdbError> {
        let floor = Self::load_inactivity_floor_at(session, op_cfg, watermark).await?;
        let start_chunk = chunk_index_for_location::<F, N>(start_location);
        let end_chunk = chunk_index_for_location::<F, N>(end_location_exclusive - 1);
        futures::future::try_join_all((start_chunk..=end_chunk).map(|chunk_index| {
            Self::load_bitmap_chunk_with_floor(session, watermark, floor, chunk_index)
        }))
        .await
    }

    async fn load_operation_at(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        location: Location<F>,
    ) -> Result<ordered::Operation<F, K, E>, QmdbError> {
        let bytes = core::load_operation_bytes_at(session, location).await?;
        Self::decode_operation(op_cfg, location, &bytes)
    }

    async fn load_operation_range(
        session: &ReadSession,
        op_cfg: &<ordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
        start_location: Location<F>,
        end_location_exclusive: Location<F>,
    ) -> Result<Vec<ordered::Operation<F, K, E>>, QmdbError> {
        core::load_operation_bytes_range(session, start_location, end_location_exclusive)
            .await?
            .into_iter()
            .enumerate()
            .map(|(offset, bytes)| {
                Self::decode_operation(op_cfg, start_location + offset as u64, &bytes)
            })
            .collect()
    }
}
