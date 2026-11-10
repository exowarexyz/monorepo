use crate::{
    adapter::{
        codec::decode_update_location,
        core,
        operation_range::{load_operation_range_proof, load_operations_multi_proof},
        read_cache::ReadCache,
    },
    error::QmdbError,
    proof::{
        MultiProofOperations, OperationMultiProof, OperationRangeProof, VerifiedOperationRange,
        VerifiedOperations,
    },
    request::OperationLocations,
    ResolvedTip, VersionedValue,
};
use commonware_codec::{Codec, Copying, Decode, Encode, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::{Family, Graftable, Location},
    qmdb::{
        immutable,
        operation::Key as QmdbKey,
        value::{ValueEncoding, VariableEncoding},
    },
};
use exoware_sdk::{PrefixedStoreClient, ReadSession};
use std::{marker::PhantomData, sync::Arc};

pub struct Immutable<
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
    op_cfg: <immutable::Operation<F, K, E> as CodecRead>::Cfg,
    read_cache: Arc<ReadCache<F, H::Digest>>,
    _marker: PhantomData<(F, H, K, E)>,
}

impl<F, H, K, V, E> Clone for Immutable<F, H, K, V, E>
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
            op_cfg: self.op_cfg.clone(),
            read_cache: self.read_cache.clone(),
            _marker: PhantomData,
        }
    }
}

impl<F, H, K, V, E> std::fmt::Debug for Immutable<F, H, K, V, E>
where
    F: Family,
    H: Hasher,
    K: QmdbKey,
    V: Codec + Send + Sync,
    E: ValueEncoding<Value = V>,
    immutable::Operation<F, K, E>: CodecRead,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Immutable").finish_non_exhaustive()
    }
}

impl<F, H, K, V, E> Immutable<F, H, K, V, E>
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
        op_cfg: <immutable::Operation<F, K, E> as CodecRead>::Cfg,
    ) -> Self {
        Self {
            store,
            publication: Arc::new(core::PublicationCache::default()),
            op_cfg,
            read_cache: Arc::new(ReadCache::new()),
            _marker: PhantomData,
        }
    }

    pub(crate) fn inspect_operation_kv<T>(
        &self,
        location: Location<F>,
        bytes: &[u8],
        inspect: impl FnOnce(Option<&[u8]>, Option<&[u8]>) -> T,
    ) -> Result<T, QmdbError>
    where
        V: AsRef<[u8]>,
    {
        let op = immutable::Operation::<F, K, E>::decode_cfg(Copying(bytes), &self.op_cfg)
            .map_err(|e| {
                QmdbError::CorruptData(format!(
                    "failed to decode immutable operation at location {location}: {e}"
                ))
            })?;
        let key = op.key().map(<K as AsRef<[u8]>>::as_ref);
        let value: Option<&[u8]> = match &op {
            immutable::Operation::Set(_, value) => Some(value.as_ref()),
            immutable::Operation::Commit(Some(value), _) => Some(value.as_ref()),
            immutable::Operation::Commit(None, _) => None,
        };
        Ok(inspect(key, value))
    }

    /// Refresh the watermark evidence and return the greatest watermark observed by this client.
    pub async fn latest_published_watermark(&self) -> Result<Option<Location<F>>, QmdbError> {
        let session = ReadSession::fixed(self.store.clone(), None);
        self.publication.refresh(&session).await
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

    /// Root at `tip`, as the source database's `root()` returns it.
    pub async fn root_at(
        &self,
        tip: Location<F>,
        min_sequence_number: Option<u64>,
    ) -> Result<H::Digest, QmdbError> {
        let resolved = self.resolve_tip(tip, min_sequence_number).await?;
        let session = ReadSession::fixed(self.store.clone(), Some(resolved.sequence_number));
        let inactive_peaks =
            inactive_peaks_at::<F, K, V, E>(&session, resolved.tip, &self.op_cfg).await?;
        core::compute_ops_root::<F, H>(&session, resolved.tip, inactive_peaks).await
    }

    /// Latest value of `key` at or below `tip`, read from the update index
    /// without a proof.
    pub async fn get_at(
        &self,
        tip: Location<F>,
        key: &K,
        min_sequence_number: Option<u64>,
    ) -> Result<Option<VersionedValue<K, V, F>>, QmdbError> {
        let resolved = self.resolve_tip(tip, min_sequence_number).await?;
        let session = ReadSession::fixed(self.store.clone(), Some(resolved.sequence_number));
        let Some((row_key, _row_value)) =
            core::load_latest_update_row(&session, resolved.tip, key.as_ref()).await?
        else {
            return Ok(None);
        };
        let location = decode_update_location::<F>(&row_key)?;
        let operation = core::load_operation_at::<F, immutable::Operation<F, K, E>>(
            &session,
            location,
            &self.op_cfg,
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
        let proof = load_operation_range_proof::<F, H, _>(
            &session,
            &self.read_cache,
            tip,
            start_location,
            end,
            false,
            |bytes| async move {
                let operation = core::decode_operation_at::<F, immutable::Operation<F, K, E>>(
                    bytes.as_ref(),
                    tip,
                    &self.op_cfg,
                )?;
                inactive_peaks_from_operation::<F, K, V, E>(tip, operation)
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
        load_operations_multi_proof::<F, H, _>(
            &session,
            &self.read_cache,
            tip,
            operations,
            false,
            |bytes| async move {
                let operation = core::decode_operation_at::<F, immutable::Operation<F, K, E>>(
                    bytes.as_ref(),
                    tip,
                    &self.op_cfg,
                )?;
                inactive_peaks_from_operation::<F, K, V, E>(tip, operation)
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
    ) -> Result<VerifiedOperationRange<H::Digest, immutable::Operation<F, K, E>, F>, QmdbError>
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
                core::decode_operation_at::<F, immutable::Operation<F, K, E>>(
                    bytes.as_ref(),
                    location,
                    &self.op_cfg,
                )
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
    ) -> Result<VerifiedOperations<H::Digest, immutable::Operation<F, K, E>, F>, QmdbError> {
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
                    core::decode_operation_at::<F, immutable::Operation<F, K, E>>(
                        bytes.as_ref(),
                        location,
                        &self.op_cfg,
                    )?,
                ))
            })
            .collect::<Result<Vec<_>, QmdbError>>()?;
        Ok(VerifiedOperations {
            tip: proof.tip,
            root,
            operations,
        })
    }
}

async fn inactive_peaks_at<F, K, V, E>(
    session: &ReadSession,
    tip: Location<F>,
    op_cfg: &<immutable::Operation<F, K, E> as CodecRead>::Cfg,
) -> Result<usize, QmdbError>
where
    F: Graftable,
    K: QmdbKey,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    immutable::Operation<F, K, E>: Decode,
{
    let operation =
        core::load_operation_at::<F, immutable::Operation<F, K, E>>(session, tip, op_cfg).await?;
    inactive_peaks_from_operation::<F, K, V, E>(tip, operation)
}

fn inactive_peaks_from_operation<F, K, V, E>(
    tip: Location<F>,
    operation: immutable::Operation<F, K, E>,
) -> Result<usize, QmdbError>
where
    F: Graftable,
    K: QmdbKey,
    V: Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
{
    let immutable::Operation::Commit(_, floor) = operation else {
        return Err(QmdbError::CorruptData(format!(
            "immutable tip {tip} does not point at a Commit operation"
        )));
    };
    core::inactive_peaks(tip, floor)
}
