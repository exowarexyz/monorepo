use commonware_codec::{Codec, Encode};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::{
    mmr::{self, iterator::PeakIterator, Location, Position, StandardHasher},
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

/// Stable mirror of Commonware's MMR proof payload.
///
/// This lets callers retain or transport historical proof material without
/// depending on the upstream `mmr::Proof` shape directly.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct RawMmrProof<D: Digest> {
    pub leaves: Location,
    pub digests: Vec<D>,
}

impl<D: Digest> From<mmr::Proof<D>> for RawMmrProof<D> {
    fn from(value: mmr::Proof<D>) -> Self {
        Self {
            leaves: value.leaves,
            digests: value.digests,
        }
    }
}

impl<D: Digest> From<RawMmrProof<D>> for mmr::Proof<D> {
    fn from(value: RawMmrProof<D>) -> Self {
        Self {
            leaves: value.leaves,
            digests: value.digests,
        }
    }
}

impl<D: Digest + Clone> From<&RawMmrProof<D>> for mmr::Proof<D> {
    fn from(value: &RawMmrProof<D>) -> Self {
        Self {
            leaves: value.leaves,
            digests: value.digests.clone(),
        }
    }
}

/// Historical operation range plus the raw MMR proof material used to verify
/// it. This is suitable for checkpointing and writer-frontier recovery.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct OperationRangeCheckpoint<D: Digest> {
    pub watermark: Location,
    pub root: D,
    pub start_location: Location,
    pub proof: RawMmrProof<D>,
    pub encoded_operations: Vec<Vec<u8>>,
}

impl<D: Digest> OperationRangeCheckpoint<D> {
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        let mut hasher = StandardHasher::<H>::new();
        let proof = mmr::Proof::from(&self.proof);
        proof.verify_range_inclusion(
            &mut hasher,
            &self.encoded_operations,
            self.start_location,
            &self.root,
        )
    }

    pub fn reconstruct_peaks<H: Hasher<Digest = D>>(
        &self,
    ) -> Result<Vec<(Position, u32, D)>, QmdbError> {
        let mut hasher = StandardHasher::<H>::new();
        let proof = mmr::Proof::from(&self.proof);
        let peak_digests = proof
            .reconstruct_peak_digests(
                &mut hasher,
                &self.encoded_operations,
                self.start_location,
                None,
            )
            .map_err(|e| {
                QmdbError::CorruptData(format!("reconstruct checkpoint peaks failed: {e}"))
            })?;
        let size = Position::try_from(self.proof.leaves)
            .map_err(|e| QmdbError::CorruptData(format!("invalid checkpoint leaf count: {e}")))?;
        let peak_entries: Vec<(Position, u32)> = PeakIterator::new(size).collect();
        if peak_entries.len() != peak_digests.len() {
            return Err(QmdbError::CorruptData(format!(
                "checkpoint peak count mismatch: expected {}, got {}",
                peak_entries.len(),
                peak_digests.len()
            )));
        }
        Ok(peak_entries
            .into_iter()
            .zip(peak_digests)
            .map(|((pos, height), digest)| (pos, height, digest))
            .collect())
    }
}

/// Stable mirror of the current ordered range-proof payload.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct RawCurrentRangeProof<D: Digest> {
    pub proof: RawMmrProof<D>,
    pub partial_chunk_digest: Option<D>,
    pub ops_root: D,
}

impl<D: Digest> From<CurrentRangeProof<D>> for RawCurrentRangeProof<D> {
    fn from(value: CurrentRangeProof<D>) -> Self {
        Self {
            proof: value.proof.into(),
            partial_chunk_digest: value.partial_chunk_digest,
            ops_root: value.ops_root,
        }
    }
}

impl<D: Digest> From<RawCurrentRangeProof<D>> for CurrentRangeProof<D> {
    fn from(value: RawCurrentRangeProof<D>) -> Self {
        Self {
            proof: value.proof.into(),
            partial_chunk_digest: value.partial_chunk_digest,
            ops_root: value.ops_root,
        }
    }
}

impl<D: Digest + Clone> From<&RawCurrentRangeProof<D>> for CurrentRangeProof<D> {
    fn from(value: &RawCurrentRangeProof<D>) -> Self {
        Self {
            proof: (&value.proof).into(),
            partial_chunk_digest: value.partial_chunk_digest.clone(),
            ops_root: value.ops_root.clone(),
        }
    }
}

/// Historical multi-proof plus the exact operations it authenticates.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct RawMultiProof<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync> {
    pub watermark: Location,
    pub root: D,
    pub proof: RawMmrProof<D>,
    pub operations: Vec<(Location, QmdbOperation<K, V>)>,
}

impl<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync> RawMultiProof<D, K, V>
where
    QmdbOperation<K, V>: Encode,
{
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        let mut hasher = StandardHasher::<H>::new();
        let proof = mmr::Proof::from(&self.proof);
        verify_multi_proof(&mut hasher, &proof, &self.operations, &self.root)
    }
}

/// Stable mirror of the current ordered key-value proof payload.
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
    pub location: Location,
    pub chunk: [u8; N],
    pub range_proof: RawCurrentRangeProof<D>,
    pub operation: QmdbOperation<K, V>,
}

impl<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync, const N: usize>
    RawKeyValueProof<D, K, V, N>
where
    QmdbOperation<K, V>: Encode + Clone,
{
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        let QmdbOperation::Update(_) = &self.operation else {
            return false;
        };
        let proof = CurrentOperationProof {
            loc: self.location,
            chunk: self.chunk,
            range_proof: (&self.range_proof).into(),
        };
        let mut hasher = H::default();
        proof.verify(&mut hasher, self.operation.clone(), &self.root)
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
    pub watermark: Location,
    pub root: D,
    pub start_location: Location,
    pub operations: Vec<Op>,
}

/// Set of (location, operation) pairs verified as a multi-proof.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedMultiOperations<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync> {
    pub watermark: Location,
    pub root: D,
    pub operations: Vec<(Location, QmdbOperation<K, V>)>,
}

/// A single key's `Update` operation verified against the current-state root.
/// `operation.next_key` is the value that verification was checked against.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedKeyValue<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync> {
    pub watermark: Location,
    pub root: D,
    pub location: Location,
    pub operation: QmdbOperation<K, V>,
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
    pub watermark: Location,
    pub root: D,
    pub start_location: Location,
    pub operations: Vec<QmdbOperation<K, V>>,
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
    Any(VerifiedOperationRange<D, QmdbOperation<K, V>>),
    Current(VerifiedCurrentRange<D, K, V, N>),
}

impl<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync, const N: usize>
    VerifiedVariantRange<D, K, V, N>
{
    pub fn watermark(&self) -> Location {
        match self {
            Self::Any(proof) => proof.watermark,
            Self::Current(proof) => proof.watermark,
        }
    }

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
    pub operations: Vec<(Location, QmdbOperation<K, V>)>,
}

impl<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync> From<MultiProofResult<D, K, V>>
    for RawMultiProof<D, K, V>
{
    fn from(value: MultiProofResult<D, K, V>) -> Self {
        Self {
            watermark: value.watermark,
            root: value.root,
            proof: value.proof.into(),
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
    pub proof: CurrentRangeProof<D>,
    pub operations: Vec<QmdbOperation<K, V>>,
    pub chunks: Vec<[u8; N]>,
}

impl<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync, const N: usize>
    CurrentOperationRangeProofResult<D, K, V, N>
where
    QmdbOperation<K, V>: Encode,
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
    pub proof: CurrentKeyValueProof<K, D, N>,
    pub operation: QmdbOperation<K, V>,
}

impl<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync, const N: usize>
    From<KeyValueProofResult<D, K, V, N>> for RawKeyValueProof<D, K, V, N>
{
    fn from(value: KeyValueProofResult<D, K, V, N>) -> Self {
        Self {
            watermark: value.watermark,
            root: value.root,
            location: value.proof.proof.loc,
            chunk: value.proof.proof.chunk,
            range_proof: value.proof.proof.range_proof.into(),
            operation: value.operation,
        }
    }
}
