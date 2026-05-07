use bytes::BufMut;
use commonware_codec::{Codec, Encode, EncodeSize, Write};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::{
    merkle::{
        self, storage::Storage as MerkleStorage, Family, Graftable, Location, Position, Proof,
    },
    qmdb::{
        any::ordered::variable::Operation as QmdbOperation,
        any::unordered::variable::Operation as UnorderedQmdbOperation,
        any::value::VariableEncoding,
        current::{
            ordered::db::KeyValueProof as CurrentKeyValueProof,
            ordered::ExclusionProof as CurrentExclusionProof,
            proof::{OperationProof as CurrentOperationProof, RangeProof as CurrentRangeProof},
        },
        operation::Key as QmdbKey,
        verify::{verify_multi_proof, verify_proof, verify_proof_and_extract_digests},
    },
};

use crate::QmdbError;
use crate::QmdbVariant;

struct EncodedOperation<'a>(&'a [u8]);

impl Write for EncodedOperation<'_> {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(self.0);
    }
}

impl EncodeSize for EncodedOperation<'_> {
    fn encode_size(&self) -> usize {
        self.0.len()
    }
}

/// Historical operation range plus the raw Merkle proof material used to verify
/// it. This is suitable for checkpointing and writer-frontier recovery.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct OperationRangeCheckpoint<D: Digest, F: Family> {
    pub watermark: Location<F>,
    pub root: D,
    pub start_location: Location<F>,
    pub proof: Proof<F, D>,
    pub encoded_operations: Vec<Vec<u8>>,
}

impl<D: Digest, F: Family> OperationRangeCheckpoint<D, F> {
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        let hasher = commonware_storage::qmdb::hasher::<H>();
        let operations = self
            .encoded_operations
            .iter()
            .map(|bytes| EncodedOperation(bytes.as_slice()))
            .collect::<Vec<_>>();
        verify_proof(
            &hasher,
            &self.proof,
            self.start_location,
            &operations,
            &self.root,
        )
    }

    pub fn reconstruct_peaks<H: Hasher<Digest = D>>(
        &self,
    ) -> Result<Vec<(Position<F>, u32, D)>, QmdbError> {
        let size = Position::try_from(self.proof.leaves)
            .map_err(|e| QmdbError::CorruptData(format!("invalid checkpoint leaf count: {e}")))?;
        let peak_entries: Vec<(Position<F>, u32)> = F::peaks(size).collect();
        if self.start_location == Location::new(0)
            && self.encoded_operations.len() as u64 == self.proof.leaves.as_u64()
        {
            return Ok(crate::core::extend_merkle_from_peaks::<F, H, _>(
                Vec::new(),
                Position::new(0),
                self.encoded_operations.iter().map(Vec::as_slice),
            )?
            .peaks);
        }

        let hasher = commonware_storage::qmdb::hasher::<H>();
        let operations = self
            .encoded_operations
            .iter()
            .map(|bytes| EncodedOperation(bytes.as_slice()))
            .collect::<Vec<_>>();
        let digests = verify_proof_and_extract_digests(
            &hasher,
            &self.proof,
            self.start_location,
            &operations,
            &self.root,
        )
        .map_err(|e| QmdbError::CorruptData(format!("reconstruct checkpoint peaks failed: {e}")))?;
        let digest_map: std::collections::BTreeMap<Position<F>, D> = digests.into_iter().collect();
        peak_entries
            .into_iter()
            .map(|(pos, height)| {
                let digest = digest_map.get(&pos).copied().ok_or_else(|| {
                    QmdbError::CorruptData(format!(
                        "checkpoint proof did not expose peak digest at position {pos}"
                    ))
                })?;
                Ok((pos, height, digest))
            })
            .collect()
    }
}

/// Historical multi-proof plus the exact operations it authenticates.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct RawMultiProof<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync, F: Family> {
    pub watermark: Location<F>,
    pub root: D,
    pub proof: Proof<F, D>,
    pub operations: Vec<(Location<F>, QmdbOperation<F, K, V>)>,
}

impl<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync, F: Family>
    RawMultiProof<D, K, V, F>
where
    QmdbOperation<F, K, V>: Encode,
{
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        let hasher = commonware_storage::qmdb::hasher::<H>();
        verify_multi_proof(&hasher, &self.proof, &self.operations, &self.root)
    }
}

/// Backend-agnostic historical multi-proof keyed to an authorized batch. The
/// operations are stored as encoded bytes so this type is shared across
/// ordered, unordered, immutable, and keyless backends.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct RawBatchMultiProof<D: Digest, F: Family> {
    pub watermark: Location<F>,
    pub root: D,
    pub proof: Proof<F, D>,
    pub operations: Vec<(Location<F>, Vec<u8>)>,
}

impl<D: Digest, F: Family> RawBatchMultiProof<D, F> {
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        let hasher = commonware_storage::qmdb::hasher::<H>();
        let operations: Vec<_> = self
            .operations
            .iter()
            .map(|(loc, bytes)| (*loc, EncodedOperation(bytes.as_slice())))
            .collect();
        verify_multi_proof(&hasher, &self.proof, &operations, &self.root)
    }
}

/// Validate a `[start, start + max_locations)` window against the published
/// watermark. Returns the exclusive end bound clamped to the watermark's
/// available count (watermark + 1).
pub(crate) fn resolve_range_bounds<F: Family>(
    watermark: Location<F>,
    start_location: Location<F>,
    max_locations: u32,
) -> Result<Location<F>, crate::QmdbError> {
    if max_locations == 0 {
        return Err(crate::QmdbError::InvalidRangeLength);
    }
    let count = watermark
        .checked_add(1)
        .ok_or_else(|| crate::QmdbError::CorruptData("watermark overflow".to_string()))?;
    if start_location >= count {
        return Err(crate::QmdbError::RangeStartOutOfBounds {
            start: start_location.as_u64(),
            count: count.as_u64(),
        });
    }
    Ok(start_location
        .saturating_add(max_locations as u64)
        .min(count))
}

/// Build and self-verify a `RawBatchMultiProof` over the given operations,
/// sourcing Merkle nodes from `storage` and using the caller-supplied `root`.
pub(crate) async fn build_batch_multi_proof<F, H, S>(
    storage: &S,
    watermark: Location<F>,
    root: H::Digest,
    operations: Vec<(Location<F>, Vec<u8>)>,
) -> Result<RawBatchMultiProof<H::Digest, F>, crate::QmdbError>
where
    F: Family,
    H: Hasher,
    S: MerkleStorage<F, Digest = H::Digest>,
{
    if operations.is_empty() {
        return Err(crate::QmdbError::EmptyProofRequest);
    }
    let locations: Vec<Location<F>> = operations.iter().map(|(loc, _)| *loc).collect();
    let hasher = commonware_storage::qmdb::hasher::<H>();
    let proof = merkle::verification::multi_proof(storage, 0, hasher.root_bagging(), &locations)
        .await
        .map_err(|e| crate::QmdbError::CommonwareMerkle(e.to_string()))?;
    let raw = RawBatchMultiProof {
        watermark,
        root,
        proof,
        operations,
    };
    if !raw.verify::<H>() {
        return Err(crate::QmdbError::ProofVerification {
            kind: crate::ProofKind::BatchMulti,
        });
    }
    Ok(raw)
}

/// Build and self-verify an `OperationRangeCheckpoint` over the given
/// contiguous span, sourcing Merkle nodes from `storage` and using the
/// caller-supplied `root` and pre-loaded `encoded_operations`.
pub(crate) async fn build_operation_range_checkpoint<F, H, S>(
    storage: &S,
    watermark: Location<F>,
    start_location: Location<F>,
    end_location_exclusive: Location<F>,
    root: H::Digest,
    encoded_operations: Vec<Vec<u8>>,
) -> Result<OperationRangeCheckpoint<H::Digest, F>, crate::QmdbError>
where
    F: Family,
    H: Hasher,
    S: MerkleStorage<F, Digest = H::Digest>,
{
    let hasher = commonware_storage::qmdb::hasher::<H>();
    let proof = merkle::verification::range_proof(
        &hasher,
        storage,
        start_location..end_location_exclusive,
        0,
    )
    .await
    .map_err(|e| crate::QmdbError::CommonwareMerkle(e.to_string()))?;
    let checkpoint = OperationRangeCheckpoint {
        watermark,
        root,
        start_location,
        proof,
        encoded_operations,
    };
    if !checkpoint.verify::<H>() {
        return Err(crate::QmdbError::ProofVerification {
            kind: crate::ProofKind::RangeCheckpoint,
        });
    }
    Ok(checkpoint)
}

/// Current ordered key-value proof payload.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct RawKeyValueProof<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
    F: Family,
> {
    pub watermark: Location<F>,
    pub root: D,
    pub proof: CurrentKeyValueProof<F, K, D, N>,
    pub operation: QmdbOperation<F, K, V>,
}

impl<
        D: Digest,
        K: QmdbKey + Codec,
        V: Codec + Clone + Send + Sync,
        const N: usize,
        F: Graftable,
    > RawKeyValueProof<D, K, V, N, F>
where
    QmdbOperation<F, K, V>: Encode + Clone,
{
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        let QmdbOperation::Update(update) = &self.operation else {
            return false;
        };
        if self.proof.next_key != update.next_key {
            return false;
        }
        let mut hasher = H::default();
        self.proof
            .proof
            .verify(&mut hasher, self.operation.clone(), &self.root)
    }
}

/// Current ordered key-exclusion proof payload.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct RawKeyExclusionProof<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
    F: Graftable,
> {
    pub watermark: Location<F>,
    pub root: D,
    pub requested_key: Vec<u8>,
    pub proof: CurrentExclusionProof<F, K, VariableEncoding<V>, D, N>,
}

impl<
        D: Digest,
        K: QmdbKey + Codec,
        V: Codec + Clone + Send + Sync,
        const N: usize,
        F: Graftable,
    > RawKeyExclusionProof<D, K, V, N, F>
where
    QmdbOperation<F, K, V>: Encode + Clone,
{
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        let (op_proof, operation) = match &self.proof {
            CurrentExclusionProof::KeyValue(op_proof, update) => {
                let span_start = update.key.as_ref();
                let span_end = update.next_key.as_ref();
                let key = self.requested_key.as_slice();
                if span_start == key {
                    return false;
                }
                let in_span = if span_start >= span_end {
                    key >= span_start || key < span_end
                } else {
                    key >= span_start && key < span_end
                };
                if !in_span {
                    return false;
                }
                (op_proof, QmdbOperation::Update(update.clone()))
            }
            CurrentExclusionProof::Commit(op_proof, value) => (
                op_proof,
                QmdbOperation::CommitFloor(value.clone(), op_proof.loc),
            ),
        };

        let mut hasher = H::default();
        op_proof.verify(&mut hasher, operation, &self.root)
    }
}

#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub enum RawKeyLookupProof<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
    F: Graftable,
> {
    Hit(RawKeyValueProof<D, K, V, N, F>),
    Miss(RawKeyExclusionProof<D, K, V, N, F>),
}

#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct RawKeyRangeEntry<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
    F: Graftable,
> {
    pub key: Vec<u8>,
    pub proof: RawKeyValueProof<D, K, V, N, F>,
}

#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct RawKeyRangeProof<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
    F: Graftable,
> {
    pub watermark: Location<F>,
    pub entries: Vec<RawKeyRangeEntry<D, K, V, N, F>>,
    pub start_proof: Option<RawKeyExclusionProof<D, K, V, N, F>>,
    pub end_proof: Option<RawKeyExclusionProof<D, K, V, N, F>>,
    pub has_more: bool,
    pub next_start_key: Vec<u8>,
}

/// Current unordered proof for one active key. Missing-key proofs are
/// intentionally unsupported for unordered QMDB because Commonware does not
/// expose exclusion semantics for that variant.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct RawUnorderedKeyValueProof<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
    F: Graftable,
> {
    pub watermark: Location<F>,
    pub root: D,
    pub proof: CurrentOperationProof<F, D, N>,
    pub operation: UnorderedQmdbOperation<F, K, V>,
}

impl<
        D: Digest,
        K: QmdbKey + Codec,
        V: Codec + Clone + Send + Sync,
        const N: usize,
        F: Graftable,
    > RawUnorderedKeyValueProof<D, K, V, N, F>
where
    UnorderedQmdbOperation<F, K, V>: Encode + Clone,
{
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        if !matches!(self.operation, UnorderedQmdbOperation::Update(_)) {
            return false;
        }
        let mut hasher = H::default();
        self.proof
            .verify(&mut hasher, self.operation.clone(), &self.root)
    }
}

// `Verified*` types below all share one invariant: the Merkle proof has already
// been checked against the store's root and the proof blob has been dropped.
// Callers work with the plain payload fields.

/// Contiguous range of operations verified against the store's root. Shared
/// across ordered, unordered, immutable, and keyless variants.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedOperationRange<D: Digest, Op, F: Family> {
    pub root: D,
    pub start_location: Location<F>,
    pub operations: Vec<Op>,
}

/// Set of (location, operation) pairs verified as a multi-proof.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedMultiOperations<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    F: Family,
> {
    pub root: D,
    pub operations: Vec<(Location<F>, QmdbOperation<F, K, V>)>,
}

/// A single key's `Update` operation verified against the current-state root.
/// `operation.next_key` is the value that verification was checked against.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedKeyValue<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    F: Family,
> {
    pub root: D,
    pub location: Location<F>,
    pub operation: QmdbOperation<F, K, V>,
}

/// One current unordered key-value proof verified against the current root.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedUnorderedKeyValue<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    F: Family,
> {
    pub root: D,
    pub location: Location<F>,
    pub operation: UnorderedQmdbOperation<F, K, V>,
}

/// A verified current lookup result for one requested key.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub enum VerifiedKeyLookup<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync, F: Family>
{
    Hit(VerifiedKeyValue<D, K, V, F>),
    Miss { key: Vec<u8> },
}

/// A verified ordered current key range.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedKeyRange<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    F: Family,
> {
    pub entries: Vec<VerifiedKeyValue<D, K, V, F>>,
    pub has_more: bool,
    pub next_start_key: Vec<u8>,
}

/// Contiguous range of operations plus bitmap chunks verified against the
/// current-state root.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedCurrentRange<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
    F: Family,
> {
    pub root: D,
    pub start_location: Location<F>,
    pub operations: Vec<QmdbOperation<F, K, V>>,
    pub chunks: Vec<[u8; N]>,
}

/// Variant-tagged verified range: either the historical (`Any`) shape without
/// chunks, or the current-state shape with bitmap chunks.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub enum VerifiedVariantRange<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
    F: Family,
> {
    Any(VerifiedOperationRange<D, QmdbOperation<F, K, V>, F>),
    Current(VerifiedCurrentRange<D, K, V, N, F>),
}

impl<
        D: Digest,
        K: QmdbKey + Codec,
        V: Codec + Clone + Send + Sync,
        const N: usize,
        F: Graftable,
    > VerifiedVariantRange<D, K, V, N, F>
{
    pub fn variant(&self) -> QmdbVariant {
        match self {
            Self::Any(_) => QmdbVariant::Any,
            Self::Current(_) => QmdbVariant::Current,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariantRoot<D: Digest, F: Family> {
    pub watermark: Location<F>,
    pub variant: QmdbVariant,
    pub root: D,
}

#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub(crate) struct MultiProofResult<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    F: Family,
> {
    pub watermark: Location<F>,
    pub root: D,
    pub proof: Proof<F, D>,
    pub operations: Vec<(Location<F>, QmdbOperation<F, K, V>)>,
}

impl<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync, F: Family>
    From<MultiProofResult<D, K, V, F>> for RawMultiProof<D, K, V, F>
{
    fn from(value: MultiProofResult<D, K, V, F>) -> Self {
        Self {
            watermark: value.watermark,
            root: value.root,
            proof: value.proof,
            operations: value.operations,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct CurrentOperationRangeProofResult<D: Digest, Op, const N: usize, F: Family> {
    pub watermark: Location<F>,
    pub root: D,
    pub start_location: Location<F>,
    pub proof: CurrentRangeProof<F, D>,
    pub operations: Vec<Op>,
    pub chunks: Vec<[u8; N]>,
}

impl<D: Digest, Op, const N: usize, F: Graftable> CurrentOperationRangeProofResult<D, Op, N, F>
where
    Op: Codec,
{
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        let mut hasher = H::default();
        self.proof.verify(
            &mut hasher,
            self.start_location,
            &self.operations,
            &self.chunks,
            &self.root,
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub(crate) struct KeyValueProofResult<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
    F: Family,
> {
    pub watermark: Location<F>,
    pub root: D,
    pub proof: CurrentKeyValueProof<F, K, D, N>,
    pub operation: QmdbOperation<F, K, V>,
}

impl<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync, const N: usize, F: Family>
    From<KeyValueProofResult<D, K, V, N, F>> for RawKeyValueProof<D, K, V, N, F>
{
    fn from(value: KeyValueProofResult<D, K, V, N, F>) -> Self {
        Self {
            watermark: value.watermark,
            root: value.root,
            proof: value.proof,
            operation: value.operation,
        }
    }
}
