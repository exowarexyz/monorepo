use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::sync::Arc;

use commonware_codec::{Codec, Copying, Decode, DecodeExt, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::merkle::{Graftable, Location};
use commonware_storage::qmdb::{
    any::{
        unordered,
        value::{ValueEncoding, VariableEncoding},
    },
    current::proof::OpsRootWitness,
    operation::{Key as QmdbKey, Operation as _},
};
use exoware_sdk::{PrefixedStoreClient, ReadSession};

use crate::adapter::codec::{
    decode_current_boundary_metadata, decode_update_index_value_present, decode_update_location,
    encode_current_meta_key, encode_ops_root_witness_key, CurrentBoundaryMetadata,
};
use crate::adapter::core;
use crate::adapter::current::{self, CurrentTip, ProofReads};
use crate::adapter::operation_range::{
    load_operation_range_checkpoint, load_operations_multi_proof,
};
use crate::adapter::read_cache::ReadCache;
use crate::error::{error_key, QmdbError};
use crate::proof::{
    CurrentOperationRangeProofResult, MultiProofOperations, OperationRangeCheckpoint,
    RawBatchMultiProof, RawKeyValueProof, VerifiedCurrentRange, VerifiedKeyValue,
    VerifiedOperationRange,
};
use crate::VersionedValue;
use crate::{OperationKv, PublishedWatermark};

pub struct Unordered<
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> where
    unordered::Operation<F, K, E>: commonware_codec::Read,
{
    store: PrefixedStoreClient,
    publication: Arc<core::PublicationCache<F>>,
    op_cfg: <unordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
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
    > Clone for Unordered<F, H, K, V, N, E>
where
    unordered::Operation<F, K, E>: commonware_codec::Read,
{
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            publication: self.publication.clone(),
            op_cfg: self.op_cfg.clone(),
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
    > std::fmt::Debug for Unordered<F, H, K, V, N, E>
where
    unordered::Operation<F, K, E>: commonware_codec::Read,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unordered").finish_non_exhaustive()
    }
}

impl<F, H, K, V, const N: usize, E> crate::adapter::core::LatestValueResolver<F, K, V>
    for Unordered<F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Encode + Decode,
{
    fn resolve_latest_value(
        &self,
        location: Location<F>,
        requested_key: &[u8],
        op_bytes: Vec<u8>,
    ) -> Result<VersionedValue<K, V, F>, QmdbError> {
        let operation = decode_operation::<F, K, V, E>(&self.op_cfg, location, &op_bytes)?;
        let (key, value) = match operation {
            unordered::Operation::Update(update) => (update.0, Some(update.1)),
            unordered::Operation::Delete(key) => (key, None),
            unordered::Operation::CommitFloor(_, _) => {
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

impl<F, H, K, V, const N: usize, E> Unordered<F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: commonware_codec::Read,
{
    /// Read client for the Store namespace.
    pub fn new(
        store: PrefixedStoreClient,
        op_cfg: <unordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
    ) -> Self {
        Self {
            store,
            publication: Arc::new(core::PublicationCache::default()),
            op_cfg,
            read_cache: Arc::new(ReadCache::new()),
            _marker: PhantomData,
        }
    }
}

impl<F, H, K, V, const N: usize, E> Unordered<F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Encode + Decode,
{
    pub(crate) fn extract_operation_kv(
        &self,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError>
    where
        V: AsRef<[u8]>,
    {
        let op = decode_operation::<F, K, V, E>(&self.op_cfg, location, bytes)?;
        let key = op.key().map(|k| <K as AsRef<[u8]>>::as_ref(k).to_vec());
        let value = match &op {
            unordered::Operation::Update(update) => Some(update.1.as_ref().to_vec()),
            unordered::Operation::CommitFloor(Some(value), _) => Some(value.as_ref().to_vec()),
            unordered::Operation::Delete(_) | unordered::Operation::CommitFloor(None, _) => None,
        };
        Ok(OperationKv { key, value })
    }

    /// Refresh publication evidence and return the greatest watermark observed by this client.
    pub async fn latest_published_watermark(&self) -> Result<Option<Location<F>>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), None);
        self.publication.refresh(&session).await
    }

    pub async fn query_many_at<Q: AsRef<[u8]>>(
        &self,
        keys: &[Q],
        watermark: Location<F>,
    ) -> Result<Vec<Option<VersionedValue<K, V, F>>>, QmdbError> {
        let watermark = self.resolve_watermark(watermark, None).await?;
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        core::query_many_at(&session, keys, watermark.location, self).await
    }

    /// Canonical root at `watermark`, as the source database's `root()` returns
    /// it: the current root when current-state rows were uploaded for this
    /// boundary, otherwise the operations-log root.
    pub async fn root_at(&self, watermark: Location<F>) -> Result<H::Digest, QmdbError> {
        let watermark = self.resolve_watermark(watermark, None).await?;
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        if load_ops_root_witness::<F, H>(&session, watermark.location)
            .await?
            .is_some()
        {
            return load_current_boundary_root::<F, H>(&session, watermark.location).await;
        }
        compute_ops_root::<F, H, K, V, E>(&self.op_cfg, &session, watermark.location).await
    }

    /// Operations-log root at `watermark`, as the source database's `ops_root()`
    /// returns it.
    pub async fn ops_root_at(&self, watermark: Location<F>) -> Result<H::Digest, QmdbError> {
        let watermark = self.resolve_watermark(watermark, None).await?;
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        compute_ops_root::<F, H, K, V, E>(&self.op_cfg, &session, watermark.location).await
    }

    /// Record a watermark published at `sequence`, as seen by a subscription.
    pub(crate) fn observe_published(&self, location: Location<F>, sequence: u64) {
        self.publication.observe(location, sequence);
    }

    pub(crate) async fn resolve_watermark(
        &self,
        watermark: Location<F>,
        min_sequence_number: Option<u64>,
    ) -> Result<PublishedWatermark<F>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), min_sequence_number);
        self.publication.require(&session, watermark).await
    }

    /// Operation-range checkpoint: the proof, pinned nodes, and encoded operations.
    pub async fn operation_range_checkpoint(
        &self,
        tip: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
        min_sequence_number: Option<u64>,
    ) -> Result<OperationRangeCheckpoint<H::Digest, F>, QmdbError> {
        let watermark = self.resolve_watermark(tip, min_sequence_number).await?;
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
        let session = &session;
        let checkpoint = load_operation_range_checkpoint::<F, H, _>(
            session,
            &self.read_cache,
            watermark,
            start_location,
            end,
            true,
            |bytes| async move {
                let operation =
                    decode_operation::<F, K, V, E>(&self.op_cfg, watermark, bytes.as_ref())?;
                let floor = load_ops_inactivity_floor_from::<F, K, V, E>(
                    &self.op_cfg,
                    session,
                    watermark,
                    operation,
                )
                .await?;
                core::inactive_peaks(watermark, floor)
            },
        )
        .await?;
        Ok(checkpoint)
    }

    /// Multi-proof at a published watermark, built from the same cached reads
    /// as [`Self::operation_range_checkpoint_at`].
    pub(crate) async fn multi_proof_at(
        &self,
        watermark: PublishedWatermark<F>,
        operations: MultiProofOperations<'_, F>,
    ) -> Result<RawBatchMultiProof<H::Digest, F>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        let watermark = watermark.location;
        let session = &session;
        load_operations_multi_proof::<F, H, _>(
            session,
            &self.read_cache,
            watermark,
            operations,
            true,
            |bytes| async move {
                let operation =
                    decode_operation::<F, K, V, E>(&self.op_cfg, watermark, bytes.as_ref())?;
                let floor = load_ops_inactivity_floor_from::<F, K, V, E>(
                    &self.op_cfg,
                    session,
                    watermark,
                    operation,
                )
                .await?;
                core::inactive_peaks(watermark, floor)
            },
        )
        .await
    }

    /// Verified contiguous range of operations.
    pub async fn operation_range(
        &self,
        tip: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
        min_sequence_number: Option<u64>,
    ) -> Result<VerifiedOperationRange<H::Digest, unordered::Operation<F, K, E>, F>, QmdbError>
    {
        let checkpoint = self
            .operation_range_checkpoint(tip, start_location, max_locations, min_sequence_number)
            .await?;
        let mut operations = Vec::with_capacity(checkpoint.encoded_operations.len());
        for (offset, value) in checkpoint.encoded_operations.iter().enumerate() {
            let location = checkpoint.start_location + offset as u64;
            let op = unordered::Operation::<F, K, E>::decode_cfg(
                Copying(value.as_slice()),
                &self.op_cfg,
            )
            .map_err(|e| {
                QmdbError::CorruptData(format!(
                    "failed to decode unordered operation at location {location}: {e}"
                ))
            })?;
            operations.push(op);
        }
        Ok(VerifiedOperationRange {
            tip: checkpoint.watermark,
            root: checkpoint.canonical_root::<H>(),
            start_location: checkpoint.start_location,
            operations,
        })
    }

    async fn current_operation_range_proof_raw_at_watermark(
        &self,
        watermark: PublishedWatermark<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<
        CurrentOperationRangeProofResult<H::Digest, unordered::Operation<F, K, E>, N, F>,
        QmdbError,
    > {
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        let watermark = watermark.location;
        let end = crate::proof::resolve_range_bounds(watermark, start_location, max_locations)?;
        let tip = self.current_tip(&session, watermark).await?;
        let (nodes, operations, chunks) = futures::try_join!(
            current::load_range_nodes::<F, H, N>(
                &session,
                &self.read_cache,
                &tip,
                start_location,
                end
            ),
            load_operation_range::<F, K, V, E>(&self.op_cfg, &session, start_location, end),
            current::load_chunks::<F, H::Digest, N>(&session, &tip, start_location, end),
        )?;
        let proof = current::range_proof::<F, H, N>(&tip, &nodes, start_location, end)?;
        let raw = CurrentOperationRangeProofResult {
            watermark,
            root: tip.root,
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

    /// Verified raw current-state proof for a contiguous operation range.
    pub async fn current_operation_range_raw(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
        min_sequence_number: Option<u64>,
    ) -> Result<
        CurrentOperationRangeProofResult<H::Digest, unordered::Operation<F, K, E>, N, F>,
        QmdbError,
    > {
        let watermark = self
            .resolve_watermark(watermark, min_sequence_number)
            .await?;
        self.current_operation_range_proof_raw_at_watermark(
            watermark,
            start_location,
            max_locations,
        )
        .await
    }

    /// The [`CurrentTip`] at the published batch boundary `watermark`.
    async fn current_tip(
        &self,
        session: &ReadSession,
        watermark: Location<F>,
    ) -> Result<CurrentTip<F, H::Digest>, QmdbError> {
        current::current_tip::<F, H, N>(session, &self.read_cache, watermark, |bytes| {
            match decode_operation::<F, K, V, E>(&self.op_cfg, watermark, bytes)? {
                unordered::Operation::CommitFloor(_, floor) => Ok(floor),
                _ => Err(QmdbError::CorruptData(format!(
                    "expected CommitFloor at watermark {watermark}"
                ))),
            }
        })
        .await
    }

    async fn key_value_proof_raw<Q: AsRef<[u8]>>(
        &self,
        session: &ReadSession,
        tip: &CurrentTip<F, H::Digest>,
        key: Q,
    ) -> Result<RawKeyValueProof<H::Digest, unordered::Operation<F, K, E>, N, F>, QmdbError> {
        let location = Self::locate_active_key(session, tip, key.as_ref()).await?;
        let reads =
            current::load_proof_reads::<F, H, N>(session, &self.read_cache, tip, location).await?;
        self.active_key_proof(tip, &reads, key, location)
    }

    /// Current proof for `key`, whose latest update at the tip is at `location`.
    fn active_key_proof<Q: AsRef<[u8]>>(
        &self,
        tip: &CurrentTip<F, H::Digest>,
        reads: &ProofReads<F, N>,
        key: Q,
        location: Location<F>,
    ) -> Result<RawKeyValueProof<H::Digest, unordered::Operation<F, K, E>, N, F>, QmdbError> {
        let watermark = tip.watermark;
        let key_bytes = error_key(&key);
        let operation = decode_operation::<F, K, V, E>(&self.op_cfg, location, &reads.operation)?;
        let unordered::Operation::Update(update) = &operation else {
            return Err(QmdbError::KeyNotActive {
                watermark: watermark.as_u64(),
                key: key_bytes,
            });
        };
        if update.0.as_ref() != key.as_ref() {
            return Err(QmdbError::CorruptData(format!(
                "latest active unordered key row at {location} points to a different key"
            )));
        }

        let proof = current::operation_proof::<F, H, N>(tip, reads)?;
        let raw = RawKeyValueProof {
            watermark,
            root: tip.root,
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

    /// Location of `key`'s latest update, which must hold a value at the tip.
    async fn locate_active_key(
        session: &ReadSession,
        tip: &CurrentTip<F, H::Digest>,
        key: &[u8],
    ) -> Result<Location<F>, QmdbError> {
        let watermark = tip.watermark;
        let key_bytes = key.to_vec();
        let Some((row_key, row_value)) =
            core::load_latest_update_row(session, watermark, key).await?
        else {
            return Err(QmdbError::ProofKeyNotFound {
                watermark: watermark.as_u64(),
                key: key_bytes,
            });
        };
        let location = decode_update_location(&row_key)?;
        if !decode_update_index_value_present(row_value.as_ref())? {
            return Err(QmdbError::KeyNotActive {
                watermark: watermark.as_u64(),
                key: key_bytes,
            });
        }
        Ok(location)
    }

    /// Verified raw current-state proof for a single active unordered key.
    pub async fn get_raw<Q: AsRef<[u8]>>(
        &self,
        watermark: Location<F>,
        key: Q,
        min_sequence_number: Option<u64>,
    ) -> Result<RawKeyValueProof<H::Digest, unordered::Operation<F, K, E>, N, F>, QmdbError> {
        let watermark = self
            .resolve_watermark(watermark, min_sequence_number)
            .await?;
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        let tip = self.current_tip(&session, watermark.location).await?;
        self.key_value_proof_raw(&session, &tip, key).await
    }

    /// Verified current-state proof for a single active unordered key.
    pub async fn get(
        &self,
        tip: Location<F>,
        key: &K,
        min_sequence_number: Option<u64>,
    ) -> Result<VerifiedKeyValue<H::Digest, unordered::Operation<F, K, E>, F>, QmdbError> {
        let raw = self.get_raw(tip, key.as_ref(), min_sequence_number).await?;
        Ok(verified_key_value(raw))
    }

    /// Verified current-state hits for `keys`, in request order. Missing or
    /// inactive keys are omitted: unordered QMDB has no exclusion proofs.
    pub async fn get_many(
        &self,
        tip: Location<F>,
        keys: &[K],
        min_sequence_number: Option<u64>,
    ) -> Result<Vec<VerifiedKeyValue<H::Digest, unordered::Operation<F, K, E>, F>>, QmdbError> {
        let raw = self.get_many_raw(tip, keys, min_sequence_number).await?;
        Ok(raw.into_iter().map(verified_key_value).collect())
    }

    /// Verified contiguous range from the current-state variant (with bitmap chunks).
    pub async fn current_operation_range(
        &self,
        tip: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
        min_sequence_number: Option<u64>,
    ) -> Result<VerifiedCurrentRange<H::Digest, unordered::Operation<F, K, E>, N, F>, QmdbError>
    {
        let raw = self
            .current_operation_range_raw(tip, start_location, max_locations, min_sequence_number)
            .await?;
        Ok(VerifiedCurrentRange {
            tip: raw.watermark,
            root: raw.root,
            start_location: raw.start_location,
            operations: raw.operations,
            chunks: raw.chunks,
        })
    }

    /// Verified current-state hit proofs for explicit active keys, preserving
    /// request order among returned hits. Unordered QMDB does not have
    /// missing-key exclusion proofs, so missing or inactive requested keys are
    /// omitted rather than proven.
    pub async fn get_many_raw<Q: AsRef<[u8]>>(
        &self,
        watermark: Location<F>,
        keys: &[Q],
        min_sequence_number: Option<u64>,
    ) -> Result<Vec<RawKeyValueProof<H::Digest, unordered::Operation<F, K, E>, N, F>>, QmdbError>
    {
        if keys.is_empty() {
            return Err(QmdbError::EmptyProofRequest);
        }

        let watermark = self
            .resolve_watermark(watermark, min_sequence_number)
            .await?;
        let session = ReadSession::fixed(self.store.clone(), Some(watermark.sequence_number));
        let tip = self.current_tip(&session, watermark.location).await?;
        let mut seen = BTreeSet::<Vec<u8>>::new();
        let mut proofs = Vec::with_capacity(keys.len());
        for key in keys {
            let key_bytes = error_key(key);
            if !seen.insert(key_bytes.clone()) {
                return Err(QmdbError::DuplicateRequestedKey { key: key_bytes });
            }
            match self.key_value_proof_raw(&session, &tip, key.as_ref()).await {
                Ok(proof) => proofs.push(proof),
                Err(QmdbError::ProofKeyNotFound { .. } | QmdbError::KeyNotActive { .. }) => {
                    continue;
                }
                Err(err) => return Err(err),
            }
        }
        Ok(proofs)
    }
}

fn decode_operation<F, K, V, E>(
    op_cfg: &<unordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
    location: Location<F>,
    bytes: &[u8],
) -> Result<unordered::Operation<F, K, E>, QmdbError>
where
    F: Graftable,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Encode + Decode,
{
    unordered::Operation::<F, K, E>::decode_cfg(Copying(bytes), op_cfg).map_err(|e| {
        QmdbError::CorruptData(format!(
            "failed to decode unordered operation at location {location}: {e}"
        ))
    })
}

async fn load_current_boundary_metadata<F: Graftable, H: Hasher>(
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

async fn load_current_boundary_root<F: Graftable, H: Hasher>(
    session: &ReadSession,
    location: Location<F>,
) -> Result<H::Digest, QmdbError> {
    Ok(load_current_boundary_metadata::<F, H>(session, location)
        .await?
        .root)
}

async fn load_ops_root_witness<F: Graftable, H: Hasher>(
    session: &ReadSession,
    location: Location<F>,
) -> Result<Option<OpsRootWitness<F, H::Digest>>, QmdbError> {
    let Some(bytes) = session.get(&encode_ops_root_witness_key(location)).await? else {
        return Ok(None);
    };
    OpsRootWitness::<F, H::Digest>::decode(Copying(bytes.as_ref()))
        .map(Some)
        .map_err(|e| {
            QmdbError::CorruptData(format!(
                "current ops-root witness at {location} decode error: {e}"
            ))
        })
}

async fn load_ops_inactivity_floor_at<F, K, V, E>(
    op_cfg: &<unordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
    session: &ReadSession,
    watermark: Location<F>,
) -> Result<Location<F>, QmdbError>
where
    F: Graftable,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Encode + Decode,
{
    let operation = load_operation_at::<F, K, V, E>(op_cfg, session, watermark).await?;
    load_ops_inactivity_floor_from::<F, K, V, E>(op_cfg, session, watermark, operation).await
}

async fn load_ops_inactivity_floor_from<F, K, V, E>(
    op_cfg: &<unordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
    session: &ReadSession,
    watermark: Location<F>,
    mut operation: unordered::Operation<F, K, E>,
) -> Result<Location<F>, QmdbError>
where
    F: Graftable,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Encode + Decode,
{
    let mut location = watermark;
    loop {
        if let unordered::Operation::CommitFloor(_, floor) = operation {
            return Ok(floor);
        }
        if *location == 0 {
            return Err(QmdbError::CorruptData(format!(
                "no CommitFloor found at or before watermark {watermark}"
            )));
        }
        location -= 1;
        operation = load_operation_at::<F, K, V, E>(op_cfg, session, location).await?;
    }
}

async fn compute_ops_root<F, H, K, V, E>(
    op_cfg: &<unordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
    session: &ReadSession,
    watermark: Location<F>,
) -> Result<H::Digest, QmdbError>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Encode + Decode,
{
    let inactive_peaks = ops_inactive_peaks_at::<F, K, V, E>(op_cfg, session, watermark).await?;
    core::compute_ops_root::<F, H>(session, watermark, inactive_peaks).await
}

async fn ops_inactive_peaks_at<F, K, V, E>(
    op_cfg: &<unordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
    session: &ReadSession,
    watermark: Location<F>,
) -> Result<usize, QmdbError>
where
    F: Graftable,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Encode + Decode,
{
    let inactivity_floor =
        load_ops_inactivity_floor_at::<F, K, V, E>(op_cfg, session, watermark).await?;
    core::inactive_peaks(watermark, inactivity_floor)
}

async fn load_operation_at<F, K, V, E>(
    op_cfg: &<unordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
    session: &ReadSession,
    location: Location<F>,
) -> Result<unordered::Operation<F, K, E>, QmdbError>
where
    F: Graftable,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Encode + Decode,
{
    let bytes = core::load_operation_bytes_at(session, location).await?;
    decode_operation::<F, K, V, E>(op_cfg, location, &bytes)
}

async fn load_operation_range<F, K, V, E>(
    op_cfg: &<unordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
    session: &ReadSession,
    start_location: Location<F>,
    end_location_exclusive: Location<F>,
) -> Result<Vec<unordered::Operation<F, K, E>>, QmdbError>
where
    F: Graftable,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Encode + Decode,
{
    core::load_operation_bytes_range(session, start_location, end_location_exclusive)
        .await?
        .into_iter()
        .enumerate()
        .map(|(offset, bytes)| {
            decode_operation::<F, K, V, E>(op_cfg, start_location + offset as u64, &bytes)
        })
        .collect()
}

fn verified_key_value<D: commonware_cryptography::Digest, Op, F: Graftable, const N: usize>(
    raw: RawKeyValueProof<D, Op, N, F>,
) -> VerifiedKeyValue<D, Op, F> {
    VerifiedKeyValue {
        root: raw.root,
        location: raw.proof.loc,
        operation: raw.operation,
    }
}
