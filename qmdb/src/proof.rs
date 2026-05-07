use commonware_codec::{Codec, Encode};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::{
    merkle::{self, storage::Storage as MerkleStorage},
    mmr::{self, iterator::PeakIterator, Location, Position},
    qmdb::{
        any::ordered::variable::Operation as QmdbOperation,
        current::{
            ordered::db::KeyValueProof as CurrentKeyValueProof,
            proof::{OperationProof as CurrentOperationProof, RangeProof as CurrentRangeProof},
        },
        operation::Key as QmdbKey,
        verify::verify_multi_proof,
    },
};

use crate::QmdbError;
use crate::QmdbVariant;

/// Historical operation range plus the raw MMR proof material used to verify
/// it. This is suitable for checkpointing and writer-frontier recovery.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct OperationRangeCheckpoint<D: Digest> {
    pub watermark: Location,
    pub root: D,
    pub start_location: Location,
    pub proof: mmr::Proof<D>,
    pub encoded_operations: Vec<Vec<u8>>,
}

impl<D: Digest> OperationRangeCheckpoint<D> {
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        let hasher = commonware_storage::qmdb::hasher::<H>();
        self.proof.verify_range_inclusion(
            &hasher,
            &self.encoded_operations,
            self.start_location,
            &self.root,
        )
    }

    pub fn reconstruct_peaks<H: Hasher<Digest = D>>(
        &self,
    ) -> Result<Vec<(Position, u32, D)>, QmdbError> {
        let size = Position::try_from(self.proof.leaves)
            .map_err(|e| QmdbError::CorruptData(format!("invalid checkpoint leaf count: {e}")))?;
        let peak_entries: Vec<(Position, u32)> = PeakIterator::new(size).collect();
        if self.start_location == Location::new(0)
            && self.encoded_operations.len() as u64 == self.proof.leaves.as_u64()
        {
            return Ok(crate::core::extend_mmr_from_peaks::<H, _>(
                Vec::new(),
                Position::new(0),
                self.encoded_operations.iter().map(Vec::as_slice),
            )?
            .peaks);
        }

        let hasher = commonware_storage::qmdb::hasher::<H>();
        let digests = self
            .proof
            .verify_range_inclusion_and_extract_digests(
                &hasher,
                &self.encoded_operations,
                self.start_location,
                &self.root,
            )
            .map_err(|e| {
                QmdbError::CorruptData(format!("reconstruct checkpoint peaks failed: {e}"))
            })?;
        let digest_map: std::collections::BTreeMap<Position, D> = digests.into_iter().collect();
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
pub struct RawMultiProof<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync> {
    pub watermark: Location,
    pub root: D,
    pub proof: mmr::Proof<D>,
    pub operations: Vec<(
        Location,
        QmdbOperation<commonware_storage::mmr::Family, K, V>,
    )>,
}

impl<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync> RawMultiProof<D, K, V>
where
    QmdbOperation<commonware_storage::mmr::Family, K, V>: Encode,
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
pub struct RawBatchMultiProof<D: Digest> {
    pub watermark: Location,
    pub root: D,
    pub proof: mmr::Proof<D>,
    pub operations: Vec<(Location, Vec<u8>)>,
}

impl<D: Digest> RawBatchMultiProof<D> {
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        let hasher = commonware_storage::qmdb::hasher::<H>();
        let elements: Vec<(&[u8], Location)> = self
            .operations
            .iter()
            .map(|(loc, bytes)| (bytes.as_slice(), *loc))
            .collect();
        self.proof
            .verify_multi_inclusion(&hasher, &elements, &self.root)
    }
}

/// Validate a `[start, start + max_locations)` window against the published
/// watermark. Returns the exclusive end bound clamped to the watermark's
/// available count (watermark + 1).
pub(crate) fn resolve_range_bounds(
    watermark: Location,
    start_location: Location,
    max_locations: u32,
) -> Result<Location, crate::QmdbError> {
    if max_locations == 0 {
        return Err(crate::QmdbError::InvalidRangeLength);
    }
    let count = watermark
        .checked_add(1)
        .ok_or_else(|| crate::QmdbError::CorruptData("watermark overflow".to_string()))?;
    if start_location >= count {
        return Err(crate::QmdbError::RangeStartOutOfBounds {
            start: start_location,
            count,
        });
    }
    Ok(start_location
        .saturating_add(max_locations as u64)
        .min(count))
}

/// Build and self-verify a `RawBatchMultiProof` over the given operations,
/// sourcing MMR nodes from `storage` and using the caller-supplied `root`.
pub(crate) async fn build_batch_multi_proof<H, S>(
    storage: &S,
    watermark: Location,
    root: H::Digest,
    operations: Vec<(Location, Vec<u8>)>,
) -> Result<RawBatchMultiProof<H::Digest>, crate::QmdbError>
where
    H: Hasher,
    S: MerkleStorage<commonware_storage::mmr::Family, Digest = H::Digest>,
{
    if operations.is_empty() {
        return Err(crate::QmdbError::EmptyProofRequest);
    }
    let locations: Vec<Location> = operations.iter().map(|(loc, _)| *loc).collect();
    let hasher = commonware_storage::qmdb::hasher::<H>();
    let proof = merkle::verification::multi_proof(storage, 0, hasher.root_bagging(), &locations)
        .await
        .map_err(|e| crate::QmdbError::CommonwareMmr(e.to_string()))?;
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
/// contiguous span, sourcing MMR nodes from `storage` and using the
/// caller-supplied `root` and pre-loaded `encoded_operations`.
pub(crate) async fn build_operation_range_checkpoint<H, S>(
    storage: &S,
    watermark: Location,
    start_location: Location,
    end_location_exclusive: Location,
    root: H::Digest,
    encoded_operations: Vec<Vec<u8>>,
) -> Result<OperationRangeCheckpoint<H::Digest>, crate::QmdbError>
where
    H: Hasher,
    S: MerkleStorage<commonware_storage::mmr::Family, Digest = H::Digest>,
{
    let hasher = commonware_storage::qmdb::hasher::<H>();
    let proof = merkle::verification::range_proof(
        &hasher,
        storage,
        start_location..end_location_exclusive,
        0,
    )
    .await
    .map_err(|e| crate::QmdbError::CommonwareMmr(e.to_string()))?;
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
> {
    pub watermark: Location,
    pub root: D,
    pub proof: CurrentOperationProof<commonware_storage::mmr::Family, D, N>,
    pub operation: QmdbOperation<commonware_storage::mmr::Family, K, V>,
}

impl<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync, const N: usize>
    RawKeyValueProof<D, K, V, N>
where
    QmdbOperation<commonware_storage::mmr::Family, K, V>: Encode + Clone,
{
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        let QmdbOperation::Update(_) = &self.operation else {
            return false;
        };
        let mut hasher = H::default();
        self.proof
            .verify(&mut hasher, self.operation.clone(), &self.root)
    }
}

// `Verified*` types below all share one invariant: the MMR proof has already
// been checked against the store's root and the proof blob has been dropped.
// Callers work with the plain payload fields.

/// Contiguous range of operations verified against the store's root. Shared
/// across ordered, unordered, immutable, and keyless variants.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedOperationRange<D: Digest, Op> {
    pub root: D,
    pub start_location: Location,
    pub operations: Vec<Op>,
}

/// Set of (location, operation) pairs verified as a multi-proof.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedMultiOperations<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync> {
    pub root: D,
    pub operations: Vec<(
        Location,
        QmdbOperation<commonware_storage::mmr::Family, K, V>,
    )>,
}

/// A single key's `Update` operation verified against the current-state root.
/// `operation.next_key` is the value that verification was checked against.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedKeyValue<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync> {
    pub root: D,
    pub location: Location,
    pub operation: QmdbOperation<commonware_storage::mmr::Family, K, V>,
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
> {
    pub root: D,
    pub start_location: Location,
    pub operations: Vec<QmdbOperation<commonware_storage::mmr::Family, K, V>>,
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
> {
    Any(VerifiedOperationRange<D, QmdbOperation<commonware_storage::mmr::Family, K, V>>),
    Current(VerifiedCurrentRange<D, K, V, N>),
}

impl<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync, const N: usize>
    VerifiedVariantRange<D, K, V, N>
{
    pub fn variant(&self) -> QmdbVariant {
        match self {
            Self::Any(_) => QmdbVariant::Any,
            Self::Current(_) => QmdbVariant::Current,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariantRoot<D: Digest> {
    pub watermark: Location,
    pub variant: QmdbVariant,
    pub root: D,
}

#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub(crate) struct MultiProofResult<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync> {
    pub watermark: Location,
    pub root: D,
    pub proof: mmr::Proof<D>,
    pub operations: Vec<(
        Location,
        QmdbOperation<commonware_storage::mmr::Family, K, V>,
    )>,
}

impl<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync> From<MultiProofResult<D, K, V>>
    for RawMultiProof<D, K, V>
{
    fn from(value: MultiProofResult<D, K, V>) -> Self {
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
pub(crate) struct CurrentOperationRangeProofResult<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
> {
    pub watermark: Location,
    pub root: D,
    pub start_location: Location,
    pub proof: CurrentRangeProof<commonware_storage::mmr::Family, D>,
    pub operations: Vec<QmdbOperation<commonware_storage::mmr::Family, K, V>>,
    pub chunks: Vec<[u8; N]>,
}

impl<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync, const N: usize>
    CurrentOperationRangeProofResult<D, K, V, N>
where
    QmdbOperation<commonware_storage::mmr::Family, K, V>: Encode,
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
> {
    pub watermark: Location,
    pub root: D,
    pub proof: CurrentKeyValueProof<commonware_storage::mmr::Family, K, D, N>,
    pub operation: QmdbOperation<commonware_storage::mmr::Family, K, V>,
}

impl<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync, const N: usize>
    From<KeyValueProofResult<D, K, V, N>> for RawKeyValueProof<D, K, V, N>
{
    fn from(value: KeyValueProofResult<D, K, V, N>) -> Self {
        Self {
            watermark: value.watermark,
            root: value.root,
            proof: value.proof.proof,
            operation: value.operation,
        }
    }
}
