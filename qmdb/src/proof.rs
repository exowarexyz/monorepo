use commonware_codec::{Codec, Encode};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::{
    mmr::{self, Location, StandardHasher},
    qmdb::{
        any::ordered::{variable::Operation as QmdbOperation, Update as QmdbUpdate},
        any::unordered::variable::Operation as UnorderedQmdbOperation,
        current::{
            ordered::db::KeyValueProof as CurrentKeyValueProof,
            proof::RangeProof as CurrentRangeProof,
        },
        operation::Key as QmdbKey,
        verify::{verify_multi_proof, verify_proof},
    },
};

use crate::QmdbVariant;

/// A set of (location, operation) pairs whose MMR multi-proof has already been
/// verified against the store's root. The proof blob is consumed during
/// verification and not exposed.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedMultiOperations<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync> {
    pub watermark: Location,
    pub root: D,
    pub operations: Vec<(Location, QmdbOperation<K, V>)>,
}

/// A single key's Update operation whose current-state proof has already been
/// verified against the store's current-root at `watermark`. The proof blob is
/// consumed during verification and not exposed — the `Update` inside
/// `operation` carries the verified `next_key`.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedKeyValue<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync> {
    pub watermark: Location,
    pub root: D,
    pub location: Location,
    pub operation: QmdbOperation<K, V>,
}

/// A contiguous range of operations plus bitmap chunks whose current-state
/// range proof has already been verified against the store's current-root.
/// The proof blob is consumed during verification and not exposed.
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

/// Variant-tagged verified range proof: either the historical `Any` shape
/// (no chunks) or the current-state shape (with bitmap chunks).
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

/// A contiguous range of operations whose MMR proof has already been verified
/// against the store's root. The proof blob is consumed during verification
/// and not exposed — callers work with `operations` directly.
///
/// Ordered, unordered, immutable, and keyless variants all produce this shape
/// (with different `Op` types). Use `QmdbClient::operation_range_proof` to
/// obtain one.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedOperationRange<D: Digest, Op> {
    pub watermark: Location,
    pub root: D,
    pub start_location: Location,
    pub operations: Vec<Op>,
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

impl<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync> MultiProofResult<D, K, V>
where
    QmdbOperation<K, V>: Encode,
{
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        let mut hasher = StandardHasher::<H>::new();
        verify_multi_proof(&mut hasher, &self.proof, &self.operations, &self.root)
    }
}

#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub(crate) struct OperationRangeProof<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
> {
    pub watermark: Location,
    pub root: D,
    pub start_location: Location,
    pub proof: mmr::Proof<D>,
    pub operations: Vec<QmdbOperation<K, V>>,
}

impl<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync> OperationRangeProof<D, K, V>
where
    QmdbOperation<K, V>: Encode,
{
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        let mut hasher = StandardHasher::<H>::new();
        verify_proof(
            &mut hasher,
            &self.proof,
            self.start_location,
            &self.operations,
            &self.root,
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub(crate) struct UnorderedOperationRangeProof<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
> {
    pub watermark: Location,
    pub root: D,
    pub start_location: Location,
    pub proof: mmr::Proof<D>,
    pub operations: Vec<UnorderedQmdbOperation<K, V>>,
}

impl<D: Digest, K: QmdbKey + Codec, V: Codec + Clone + Send + Sync>
    UnorderedOperationRangeProof<D, K, V>
where
    UnorderedQmdbOperation<K, V>: Encode,
{
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        let mut hasher = StandardHasher::<H>::new();
        verify_proof(
            &mut hasher,
            &self.proof,
            self.start_location,
            &self.operations,
            &self.root,
        )
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
    KeyValueProofResult<D, K, V, N>
where
    QmdbOperation<K, V>: Encode,
{
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        let QmdbOperation::Update(update) = &self.operation else {
            return false;
        };
        let operation = QmdbOperation::Update(QmdbUpdate {
            key: update.key.clone(),
            value: update.value.clone(),
            next_key: self.proof.next_key.clone(),
        });
        let mut hasher = H::default();
        self.proof.proof.verify(&mut hasher, operation, &self.root)
    }
}

#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub(crate) struct AuthenticatedOperationRangeProof<D: Digest, Op> {
    pub watermark: Location,
    pub root: D,
    pub start_location: Location,
    pub proof: mmr::Proof<D>,
    pub operations: Vec<Op>,
}

impl<D: Digest, Op: Encode> AuthenticatedOperationRangeProof<D, Op> {
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        let mut hasher = StandardHasher::<H>::new();
        verify_proof(
            &mut hasher,
            &self.proof,
            self.start_location,
            &self.operations,
            &self.root,
        )
    }
}
