use crate::{
    adapter::{
        core,
        current::{self, CurrentTip, ProofReads},
        operation_range::{load_operation_range_proof, load_operations_multi_proof},
        read_cache::ReadCache,
    },
    error::{error_key, QmdbError},
    proof::{
        CurrentOperationRangeProof, KeyValueProof, MultiProofOperations, OperationMultiProof,
        OperationRangeProof, VerifiedCurrentOperationRange, VerifiedKeyValue,
        VerifiedOperationRange, VerifiedOperations,
    },
    request::OperationLocations,
    ResolvedTip, VersionedValue,
};
use commonware_codec::{Codec, Copying, Decode, Encode};
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::{Graftable, Location},
    qmdb::{
        any::unordered,
        operation::{Key as QmdbKey, Operation as _},
        value::{ValueEncoding, VariableEncoding},
    },
};
use exoware_sdk::{PrefixedStoreClient, ReadSession};
use std::{collections::BTreeSet, marker::PhantomData, sync::Arc};

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
    pub(crate) fn inspect_operation_kv<T>(
        &self,
        location: Location<F>,
        bytes: &[u8],
        inspect: impl FnOnce(Option<&[u8]>, Option<&[u8]>) -> T,
    ) -> Result<T, QmdbError>
    where
        V: AsRef<[u8]>,
    {
        let op = decode_operation::<F, K, V, E>(&self.op_cfg, location, bytes)?;
        let key = op.key().map(<K as AsRef<[u8]>>::as_ref);
        let value: Option<&[u8]> = match &op {
            unordered::Operation::Update(update) => Some(update.1.as_ref()),
            unordered::Operation::CommitFloor(Some(value), _) => Some(value.as_ref()),
            unordered::Operation::Delete(_) | unordered::Operation::CommitFloor(None, _) => None,
        };
        Ok(inspect(key, value))
    }

    /// Refresh the watermark evidence and return the greatest watermark observed by this client.
    pub async fn latest_published_watermark(&self) -> Result<Option<Location<F>>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), None);
        self.publication.refresh(&session).await
    }

    /// Latest version of each key at or below `tip`, read from the update
    /// index without a proof, in request order.
    pub async fn get_many_at(
        &self,
        tip: Location<F>,
        keys: &[K],
        min_sequence_number: Option<u64>,
    ) -> Result<Vec<Option<VersionedValue<K, V, F>>>, QmdbError> {
        let resolved = self.resolve_tip(tip, min_sequence_number).await?;
        let session = ReadSession::fixed(self.store.clone(), Some(resolved.sequence_number));
        core::get_many_at(&session, keys, resolved.tip, self).await
    }

    /// Canonical root at `tip`, as the source database's `root()` returns
    /// it: the current root when current-state rows were uploaded for this
    /// boundary, otherwise the operations-log root.
    pub async fn root_at(
        &self,
        tip: Location<F>,
        min_sequence_number: Option<u64>,
    ) -> Result<H::Digest, QmdbError> {
        let resolved = self.resolve_tip(tip, min_sequence_number).await?;
        let session = ReadSession::fixed(self.store.clone(), Some(resolved.sequence_number));
        if current::load_ops_root_witness::<F, H>(&session, resolved.tip)
            .await?
            .is_some()
        {
            return current::load_current_boundary_root::<F, H>(&session, resolved.tip).await;
        }
        compute_ops_root::<F, H, K, V, E>(&self.op_cfg, &session, resolved.tip).await
    }

    /// Operations-log root at `tip`, as the source database's `ops_root()`
    /// returns it.
    pub async fn ops_root_at(
        &self,
        tip: Location<F>,
        min_sequence_number: Option<u64>,
    ) -> Result<H::Digest, QmdbError> {
        let resolved = self.resolve_tip(tip, min_sequence_number).await?;
        let session = ReadSession::fixed(self.store.clone(), Some(resolved.sequence_number));
        compute_ops_root::<F, H, K, V, E>(&self.op_cfg, &session, resolved.tip).await
    }

    /// Record a watermark published at `sequence`, as seen by a subscription.
    pub(crate) fn observe_published(&self, location: Location<F>, sequence: u64) {
        self.publication.observe(location, sequence);
    }

    pub(crate) async fn resolve_tip(
        &self,
        tip: Location<F>,
        min_sequence_number: Option<u64>,
    ) -> Result<ResolvedTip<F>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), min_sequence_number);
        self.publication.require(&session, tip).await
    }

    /// Verified proof for a contiguous operation range, with the pinned nodes
    /// and encoded operations needed to verify and extend it.
    pub async fn operation_range_proof(
        &self,
        tip: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
        min_sequence_number: Option<u64>,
    ) -> Result<OperationRangeProof<H::Digest, F>, QmdbError> {
        let resolved = self.resolve_tip(tip, min_sequence_number).await?;
        self.operation_range_proof_at(resolved, start_location, max_locations)
            .await
    }

    pub(crate) async fn operation_range_proof_at(
        &self,
        resolved: ResolvedTip<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> Result<OperationRangeProof<H::Digest, F>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), Some(resolved.sequence_number));
        let tip = resolved.tip;
        let end = crate::proof::resolve_range_bounds(tip, start_location, max_locations)?;
        let session = &session;
        let proof = load_operation_range_proof::<F, H, _>(
            session,
            &self.read_cache,
            tip,
            start_location,
            end,
            true,
            |bytes| async move {
                let operation = decode_operation::<F, K, V, E>(&self.op_cfg, tip, bytes.as_ref())?;
                let floor = load_ops_inactivity_floor_from::<F, K, V, E>(
                    &self.op_cfg,
                    session,
                    tip,
                    operation,
                )
                .await?;
                core::inactive_peaks(tip, floor)
            },
        )
        .await?;
        Ok(proof)
    }

    /// Prove a nonempty set of strictly ascending operation locations at or below `tip`.
    /// `min_sequence_number` is the minimum Store sequence for the watermark lookup.
    pub async fn operation_multi_proof(
        &self,
        tip: Location<F>,
        locations: &[Location<F>],
        min_sequence_number: Option<u64>,
    ) -> Result<OperationMultiProof<H::Digest, F>, QmdbError> {
        // Validate the request and Merkle family bounds before reading the Store.
        let requested = locations
            .iter()
            .map(|location| location.as_u64())
            .collect::<Vec<_>>();
        OperationLocations::with_max_leaves(tip.as_u64(), &requested, F::MAX_LEAVES.as_u64())?;

        // `min_sequence_number` bounds the watermark lookup. Proof reads use
        // the observed watermark sequence as their minimum.
        let resolved = self.resolve_tip(tip, min_sequence_number).await?;
        self.operation_multi_proof_at(resolved, MultiProofOperations::Read(locations))
            .await
    }

    /// Multi-proof at a resolved tip, built from the same cached reads
    /// as [`Self::operation_range_proof_at`].
    pub(crate) async fn operation_multi_proof_at(
        &self,
        resolved: ResolvedTip<F>,
        operations: MultiProofOperations<'_, F>,
    ) -> Result<OperationMultiProof<H::Digest, F>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), Some(resolved.sequence_number));
        let tip = resolved.tip;
        let session = &session;
        load_operations_multi_proof::<F, H, _>(
            session,
            &self.read_cache,
            tip,
            operations,
            true,
            |bytes| async move {
                let operation = decode_operation::<F, K, V, E>(&self.op_cfg, tip, bytes.as_ref())?;
                let floor = load_ops_inactivity_floor_from::<F, K, V, E>(
                    &self.op_cfg,
                    session,
                    tip,
                    operation,
                )
                .await?;
                core::inactive_peaks(tip, floor)
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
        let proof = self
            .operation_range_proof(tip, start_location, max_locations, min_sequence_number)
            .await?;
        let operations = proof
            .encoded_operations
            .iter()
            .enumerate()
            .map(|(offset, bytes)| {
                let location = proof.start_location + offset as u64;
                decode_operation::<F, K, V, E>(&self.op_cfg, location, bytes)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(VerifiedOperationRange {
            tip: proof.tip,
            root: proof.canonical_root::<H>(),
            start_location: proof.start_location,
            operations,
        })
    }

    /// Verified operations at `locations` of `tip`, in request order.
    pub async fn operations(
        &self,
        tip: Location<F>,
        locations: &[Location<F>],
        min_sequence_number: Option<u64>,
    ) -> Result<VerifiedOperations<H::Digest, unordered::Operation<F, K, E>, F>, QmdbError> {
        let proof = self
            .operation_multi_proof(tip, locations, min_sequence_number)
            .await?;
        let root = proof.canonical_root::<H>();
        let operations = proof
            .encoded_operations
            .into_iter()
            .map(|(location, bytes)| {
                Ok((
                    location,
                    decode_operation::<F, K, V, E>(&self.op_cfg, location, &bytes)?,
                ))
            })
            .collect::<Result<Vec<_>, QmdbError>>()?;
        Ok(VerifiedOperations {
            tip: proof.tip,
            root,
            operations,
        })
    }

    /// Verified current-state proof for a contiguous operation range.
    pub async fn current_operation_range_proof(
        &self,
        tip: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
        min_sequence_number: Option<u64>,
    ) -> Result<CurrentOperationRangeProof<H::Digest, unordered::Operation<F, K, E>, N, F>, QmdbError>
    {
        let resolved = self.resolve_tip(tip, min_sequence_number).await?;
        let end = crate::proof::resolve_range_bounds(resolved.tip, start_location, max_locations)?;
        let session = ReadSession::fixed(self.store.clone(), Some(resolved.sequence_number));
        let tip = self.current_tip(&session, resolved.tip).await?;
        let (reads, operations, chunks) = futures::try_join!(
            current::load_range_reads::<F, H, N>(
                &session,
                &self.read_cache,
                &tip,
                start_location,
                end
            ),
            load_operation_range::<F, K, V, E>(&self.op_cfg, &session, start_location, end),
            current::load_chunks::<F, H::Digest, N>(&session, &tip, start_location, end),
        )?;
        let proof = current::range_proof::<F, H, N>(&tip, reads)?;
        let proof = CurrentOperationRangeProof {
            tip: resolved.tip,
            root: tip.root,
            start_location,
            proof,
            operations,
            chunks,
        };
        if !proof.verify::<H>() {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentOperationRange,
            });
        }
        Ok(proof)
    }

    /// The [`CurrentTip`] at `tip`, which must be a published batch boundary.
    async fn current_tip(
        &self,
        session: &ReadSession,
        tip: Location<F>,
    ) -> Result<CurrentTip<F, H::Digest>, QmdbError> {
        current::current_tip::<F, H, N>(session, &self.read_cache, tip, |bytes| {
            match decode_operation::<F, K, V, E>(&self.op_cfg, tip, bytes)? {
                unordered::Operation::CommitFloor(_, floor) => Ok(floor),
                _ => Err(QmdbError::CorruptData(format!(
                    "expected CommitFloor at tip {tip}"
                ))),
            }
        })
        .await
    }

    async fn key_value_proof<Q: AsRef<[u8]>>(
        &self,
        session: &ReadSession,
        tip: &CurrentTip<F, H::Digest>,
        key: Q,
    ) -> Result<KeyValueProof<H::Digest, unordered::Operation<F, K, E>, N, F>, QmdbError> {
        let location = current::locate_active_key(session, tip, key.as_ref()).await?;
        let reads =
            current::load_proof_reads::<F, H, N>(session, &self.read_cache, tip, location).await?;
        self.active_key_proof(tip, reads, key, location)
    }

    /// Current proof for `key`, whose latest update at the tip is at `location`.
    fn active_key_proof<Q: AsRef<[u8]>>(
        &self,
        current_tip: &CurrentTip<F, H::Digest>,
        reads: ProofReads<F, N>,
        key: Q,
        location: Location<F>,
    ) -> Result<KeyValueProof<H::Digest, unordered::Operation<F, K, E>, N, F>, QmdbError> {
        let tip = current_tip.tip;
        let key_bytes = error_key(&key);
        let operation = decode_operation::<F, K, V, E>(&self.op_cfg, location, &reads.operation)?;
        let unordered::Operation::Update(update) = &operation else {
            return Err(QmdbError::KeyNotActive {
                tip: tip.as_u64(),
                key: key_bytes,
            });
        };
        if update.0.as_ref() != key.as_ref() {
            return Err(QmdbError::CorruptData(format!(
                "latest active unordered key row at {location} points to a different key"
            )));
        }

        let proof = current::operation_proof::<F, H, N>(current_tip, reads)?;
        let proof = KeyValueProof {
            tip,
            root: current_tip.root,
            proof,
            operation,
        };
        if !proof.verify::<H>() {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::KeyValue,
            });
        }
        Ok(proof)
    }

    /// Verified current-state proof for a single active unordered key.
    pub async fn get_proof(
        &self,
        tip: Location<F>,
        key: &K,
        min_sequence_number: Option<u64>,
    ) -> Result<KeyValueProof<H::Digest, unordered::Operation<F, K, E>, N, F>, QmdbError> {
        let resolved = self.resolve_tip(tip, min_sequence_number).await?;
        let session = ReadSession::fixed(self.store.clone(), Some(resolved.sequence_number));
        let tip = self.current_tip(&session, resolved.tip).await?;
        self.key_value_proof(&session, &tip, key).await
    }

    /// Verified current-state value for a single active unordered key, with
    /// its proof checked and dropped.
    pub async fn get(
        &self,
        tip: Location<F>,
        key: &K,
        min_sequence_number: Option<u64>,
    ) -> Result<VerifiedKeyValue<H::Digest, unordered::Operation<F, K, E>, F>, QmdbError> {
        let proof = self.get_proof(tip, key, min_sequence_number).await?;
        Ok(current::verified_key_value(proof))
    }

    /// Verified current-state hits for `keys`, in request order. Missing or
    /// inactive keys are omitted: unordered QMDB has no exclusion proofs.
    pub async fn get_hits(
        &self,
        tip: Location<F>,
        keys: &[K],
        min_sequence_number: Option<u64>,
    ) -> Result<Vec<VerifiedKeyValue<H::Digest, unordered::Operation<F, K, E>, F>>, QmdbError> {
        let proofs = self.get_hit_proofs(tip, keys, min_sequence_number).await?;
        Ok(proofs
            .into_iter()
            .map(current::verified_key_value)
            .collect())
    }

    /// Verified contiguous range from the current-state variant (with bitmap chunks).
    pub async fn current_operation_range(
        &self,
        tip: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
        min_sequence_number: Option<u64>,
    ) -> Result<
        VerifiedCurrentOperationRange<H::Digest, unordered::Operation<F, K, E>, N, F>,
        QmdbError,
    > {
        let proof = self
            .current_operation_range_proof(tip, start_location, max_locations, min_sequence_number)
            .await?;
        Ok(VerifiedCurrentOperationRange {
            tip: proof.tip,
            root: proof.root,
            start_location: proof.start_location,
            operations: proof.operations,
            chunks: proof.chunks,
        })
    }

    /// Verified current-state hit proofs for explicit active keys, preserving
    /// request order among returned hits. Unordered QMDB does not have
    /// missing-key exclusion proofs, so missing or inactive requested keys are
    /// omitted rather than proven.
    pub async fn get_hit_proofs(
        &self,
        tip: Location<F>,
        keys: &[K],
        min_sequence_number: Option<u64>,
    ) -> Result<Vec<KeyValueProof<H::Digest, unordered::Operation<F, K, E>, N, F>>, QmdbError> {
        if keys.is_empty() {
            return Err(QmdbError::EmptyProofRequest);
        }

        let resolved = self.resolve_tip(tip, min_sequence_number).await?;
        let session = ReadSession::fixed(self.store.clone(), Some(resolved.sequence_number));
        let tip = self.current_tip(&session, resolved.tip).await?;
        let mut seen = BTreeSet::<Vec<u8>>::new();
        let mut proofs = Vec::with_capacity(keys.len());
        for key in keys {
            let key_bytes = error_key(key);
            if !seen.insert(key_bytes.clone()) {
                return Err(QmdbError::DuplicateRequestedKey { key: key_bytes });
            }
            match self.key_value_proof(&session, &tip, key.as_ref()).await {
                Ok(proof) => proofs.push(proof),
                Err(QmdbError::KeyNotFound { .. } | QmdbError::KeyNotActive { .. }) => {
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

async fn load_ops_inactivity_floor_at<F, K, V, E>(
    op_cfg: &<unordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
    session: &ReadSession,
    tip: Location<F>,
) -> Result<Location<F>, QmdbError>
where
    F: Graftable,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Encode + Decode,
{
    let operation = load_operation_at::<F, K, V, E>(op_cfg, session, tip).await?;
    load_ops_inactivity_floor_from::<F, K, V, E>(op_cfg, session, tip, operation).await
}

async fn load_ops_inactivity_floor_from<F, K, V, E>(
    op_cfg: &<unordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
    session: &ReadSession,
    tip: Location<F>,
    mut operation: unordered::Operation<F, K, E>,
) -> Result<Location<F>, QmdbError>
where
    F: Graftable,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Encode + Decode,
{
    let mut location = tip;
    loop {
        if let unordered::Operation::CommitFloor(_, floor) = operation {
            return Ok(floor);
        }
        if *location == 0 {
            return Err(QmdbError::CorruptData(format!(
                "no CommitFloor found at or before tip {tip}"
            )));
        }
        location -= 1;
        operation = load_operation_at::<F, K, V, E>(op_cfg, session, location).await?;
    }
}

async fn compute_ops_root<F, H, K, V, E>(
    op_cfg: &<unordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
    session: &ReadSession,
    tip: Location<F>,
) -> Result<H::Digest, QmdbError>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Encode + Decode,
{
    let inactive_peaks = ops_inactive_peaks_at::<F, K, V, E>(op_cfg, session, tip).await?;
    core::compute_ops_root::<F, H>(session, tip, inactive_peaks).await
}

async fn ops_inactive_peaks_at<F, K, V, E>(
    op_cfg: &<unordered::Operation<F, K, E> as commonware_codec::Read>::Cfg,
    session: &ReadSession,
    tip: Location<F>,
) -> Result<usize, QmdbError>
where
    F: Graftable,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Encode + Decode,
{
    let inactivity_floor = load_ops_inactivity_floor_at::<F, K, V, E>(op_cfg, session, tip).await?;
    core::inactive_peaks(tip, inactivity_floor)
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
