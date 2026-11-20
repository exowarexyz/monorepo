pub use crate::service::server::encode::{
    encode_operation_multi_proof, encode_operation_range_proof,
};
use crate::{adapter::codec::op_count_for_tip, QmdbError};
use bytes::Bytes;
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::{Sequential, Strategy};
use commonware_storage::{
    merkle::{self, Family, Graftable, Location, Position, Proof, RangePlan},
    qmdb::{
        any::ordered,
        current::{
            ordered::proof::constant::ExclusionProof,
            proof::{constant::OperationProof, OpsRootWitness, RangeProof},
        },
        operation::{Key as QmdbKey, Operation},
        value::{ValueEncoding, VariableEncoding},
    },
};
use std::collections::HashMap;

/// Operation range plus the Merkle proof material used to verify
/// it. This is suitable for local Merkle continuation.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct OperationRangeProof<D: Digest, F: Graftable> {
    pub tip: Location<F>,
    /// Operations-log root the proof is checked against.
    pub ops_root: D,
    /// Links `ops_root` to the canonical root of a database with current state.
    pub ops_root_witness: Option<OpsRootWitness<F, D>>,
    pub start_location: Location<F>,
    pub pinned_nodes: Vec<D>,
    pub proof: Proof<F, D>,
    pub encoded_operations: Vec<Bytes>,
}

/// Canonical root committing to `ops_root`: the current root when `witness` is
/// present (a database with current state), otherwise `ops_root` itself.
pub(crate) fn canonical_root<F: Graftable, H: Hasher>(
    ops_root: &H::Digest,
    witness: Option<&OpsRootWitness<F, H::Digest>>,
) -> H::Digest {
    witness.map_or(*ops_root, |witness| witness.root::<H>(ops_root))
}

impl<D: Digest, F: Graftable> OperationRangeProof<D, F> {
    /// Canonical root at `tip`: the current root when `ops_root_witness` is
    /// present, otherwise `ops_root`.
    pub fn canonical_root<H: Hasher<Digest = D>>(&self) -> D {
        canonical_root::<F, H>(&self.ops_root, self.ops_root_witness.as_ref())
    }

    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        let hasher = commonware_storage::qmdb::hasher::<H>();
        self.proof.verify_range_inclusion_with_pinned_nodes(
            &hasher,
            self.start_location,
            &self.encoded_operations,
            &self.pinned_nodes,
            &self.ops_root,
        )
    }

    /// Reconstruct the Merkle frontier from an authenticated range ending at the tip.
    pub fn reconstruct_peaks<H: Hasher<Digest = D>>(
        &self,
    ) -> Result<Vec<(Position<F>, u32, D)>, QmdbError> {
        self.reconstruct_peaks_with_strategy::<H, Sequential>(&Sequential)
    }

    /// Reconstruct the Merkle frontier using `strategy` for Merkle hashing.
    pub fn reconstruct_peaks_with_strategy<H, S>(
        &self,
        strategy: &S,
    ) -> Result<Vec<(Position<F>, u32, D)>, QmdbError>
    where
        H: Hasher<Digest = D>,
        S: Strategy,
    {
        let size = Position::try_from(self.proof.leaves).map_err(|e| {
            QmdbError::CorruptData(format!("invalid operation range proof leaf count: {e}"))
        })?;

        let tip_leaves = self.tip.checked_add(1).ok_or_else(|| {
            QmdbError::CorruptData("operation range proof tip exceeds the location domain".into())
        })?;
        if tip_leaves != self.proof.leaves {
            return Err(QmdbError::CorruptData(format!(
                "operation range proof tip implies {tip_leaves} leaves, proof has {}",
                self.proof.leaves
            )));
        }

        let operation_count = u64::try_from(self.encoded_operations.len()).map_err(|_| {
            QmdbError::CorruptData("operation range proof operation count exceeds u64".into())
        })?;
        let end_location = self
            .start_location
            .checked_add(operation_count)
            .ok_or_else(|| QmdbError::CorruptData("operation range proof end overflow".into()))?;
        if end_location != self.proof.leaves {
            return Err(QmdbError::CorruptData(format!(
                "operation range proof ends at {end_location}, expected {}",
                self.proof.leaves
            )));
        }

        if !self.verify::<H>() {
            return Err(QmdbError::CorruptData(
                "reconstruct operation range proof peaks failed because the proof or pins are invalid".into(),
            ));
        }

        let extension = crate::adapter::core::extend_merkle_from_pinned_nodes::<F, H, S, _>(
            self.pinned_nodes.clone(),
            self.start_location,
            self.encoded_operations.iter().map(Bytes::as_ref),
            self.proof.inactive_peaks,
            strategy,
        )?;
        if extension.size != size {
            return Err(QmdbError::CorruptData(format!(
                "operation range proof extension size mismatch. Expected {size}, got {}",
                extension.size
            )));
        }
        if extension.root != self.ops_root {
            return Err(QmdbError::CorruptData(
                "operation range proof extension root mismatch".into(),
            ));
        }

        Ok(extension.peaks)
    }
}

/// Operation-log membership proof for encoded operations at selected locations.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct OperationMultiProof<D: Digest, F: Graftable> {
    pub tip: Location<F>,
    /// Operations-log root the proof is checked against.
    pub ops_root: D,
    /// Links `ops_root` to the canonical root of a database with current state.
    pub ops_root_witness: Option<OpsRootWitness<F, D>>,
    pub proof: Proof<F, D>,
    pub encoded_operations: Vec<(Location<F>, Bytes)>,
}

impl<D: Digest, F: Graftable> OperationMultiProof<D, F> {
    /// Canonical root at `tip`: the current root when `ops_root_witness` is
    /// present, otherwise `ops_root`.
    pub fn canonical_root<H: Hasher<Digest = D>>(&self) -> D {
        canonical_root::<F, H>(&self.ops_root, self.ops_root_witness.as_ref())
    }

    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        let hasher = commonware_storage::qmdb::hasher::<H>();
        self.proof
            .verify_multi_inclusion(&hasher, &self.encoded_operations, &self.ops_root)
    }
}

/// Validate a `[start, start + max_locations)` window against the requested
/// tip. Returns the exclusive end bound clamped to the tip's available count
/// (tip + 1).
pub(crate) fn resolve_range_bounds<F: Family>(
    tip: Location<F>,
    start_location: Location<F>,
    max_locations: u32,
) -> Result<Location<F>, crate::QmdbError> {
    if max_locations == 0 {
        return Err(crate::QmdbError::InvalidRangeLength);
    }
    let count = op_count_for_tip(tip)?;
    if start_location >= count {
        return Err(crate::QmdbError::LocationOutOfBounds {
            location: start_location.as_u64(),
            count: count.as_u64(),
        });
    }
    Ok(start_location
        .saturating_add(max_locations as u64)
        .min(count))
}

/// Operations a cached multi-proof covers: rows still to read at `Read`
/// locations, or rows the caller already holds, such as a subscription frame.
/// Locations are strictly ascending and at most the proof's tip.
pub(crate) enum MultiProofOperations<'a, F: Family> {
    Read(&'a [Location<F>]),
    Given(Vec<(Location<F>, Bytes)>),
}

/// Build and self-verify an `OperationMultiProof` over the given operations from
/// the digests at `positions`, the operations' multi-proof plan, and the
/// caller-supplied `root`.
pub(crate) fn build_operation_multi_proof<F, H>(
    positions: &[Position<F>],
    digests: &HashMap<Position<F>, H::Digest>,
    tip: Location<F>,
    root: H::Digest,
    inactive_peaks: usize,
    encoded_operations: Vec<(Location<F>, Bytes)>,
) -> Result<OperationMultiProof<H::Digest, F>, crate::QmdbError>
where
    F: Graftable,
    H: Hasher,
{
    if encoded_operations.is_empty() {
        return Err(crate::QmdbError::EmptyProofRequest);
    }
    let leaves = op_count_for_tip(tip)?;
    let size = Position::try_from(leaves).map_err(crate::error::merkle_error)?;
    if inactive_peaks > F::peaks(size).count() {
        return Err(crate::error::merkle_error(merkle::Error::<F>::InvalidProof));
    }
    let digests = positions
        .iter()
        .map(|position| {
            digests
                .get(position)
                .copied()
                .ok_or(merkle::Error::ElementPruned(*position))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(crate::error::merkle_error)?;
    let proof = OperationMultiProof {
        tip,
        ops_root: root,
        ops_root_witness: None,
        proof: Proof {
            leaves,
            inactive_peaks,
            digests,
        },
        encoded_operations,
    };
    if !proof.verify::<H>() {
        return Err(crate::QmdbError::ProofVerification {
            kind: crate::ProofKind::OperationMulti,
        });
    }
    Ok(proof)
}

/// Build and self-verify an `OperationRangeProof` over `plan`'s range from
/// the digests at its positions and the pins before `start_location`, using the
/// caller-supplied `root` and pre-loaded `encoded_operations`.
pub(crate) fn build_operation_range_proof<F, H>(
    plan: RangePlan<F>,
    digests: &HashMap<Position<F>, H::Digest>,
    tip: Location<F>,
    start_location: Location<F>,
    root: H::Digest,
    inactive_peaks: usize,
    encoded_operations: Vec<Bytes>,
) -> Result<OperationRangeProof<H::Digest, F>, crate::QmdbError>
where
    F: Graftable,
    H: Hasher,
{
    let hasher = commonware_storage::qmdb::hasher::<H>();
    let proof = plan
        .build(&hasher, inactive_peaks, |position| {
            digests.get(&position).copied()
        })
        .map_err(crate::error::merkle_error)?;
    let pinned_nodes = F::nodes_to_pin(start_location)
        .map(|position| {
            digests.get(&position).copied().ok_or_else(|| {
                crate::QmdbError::CommonwareMerkle(format!(
                    "missing pinned node at position {position}"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let range_proof = OperationRangeProof {
        tip,
        ops_root: root,
        ops_root_witness: None,
        start_location,
        pinned_nodes,
        proof,
        encoded_operations,
    };
    if !range_proof.verify::<H>() {
        return Err(crate::QmdbError::ProofVerification {
            kind: crate::ProofKind::OperationRange,
        });
    }
    Ok(range_proof)
}

/// Current proof for one active key's update operation.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct KeyValueProof<D: Digest, Op, const N: usize, F: Graftable> {
    pub tip: Location<F>,
    pub root: D,
    pub proof: OperationProof<F, D, N>,
    pub operation: Op,
}

impl<D: Digest, Op, const N: usize, F: Graftable> KeyValueProof<D, Op, N, F>
where
    Op: Codec + Clone + Operation<F>,
{
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        self.operation.is_update()
            && self
                .proof
                .verify::<H, _>(self.operation.clone(), &self.root)
    }
}

/// Current ordered key-exclusion proof payload.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct KeyExclusionProof<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
    F: Graftable,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> {
    pub tip: Location<F>,
    pub root: D,
    pub requested_key: K,
    pub proof: ExclusionProof<F, K, E, D, N>,
}

impl<
        D: Digest,
        K: QmdbKey + Codec,
        V: Codec + Clone + Send + Sync,
        const N: usize,
        F: Graftable,
        E: ValueEncoding<Value = V>,
    > KeyExclusionProof<D, K, V, N, F, E>
where
    ordered::Operation<F, K, E>: Codec + Clone,
{
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        self.proof.verify::<H>(&self.requested_key, &self.root)
    }
}

#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub enum KeyLookupProof<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
    F: Graftable,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> {
    Hit(KeyValueProof<D, ordered::Operation<F, K, E>, N, F>),
    Miss(KeyExclusionProof<D, K, V, N, F, E>),
}

#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct KeyRangeProof<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    const N: usize,
    F: Graftable,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> {
    pub tip: Location<F>,
    pub entries: Vec<KeyValueProof<D, ordered::Operation<F, K, E>, N, F>>,
    pub start_proof: Option<KeyExclusionProof<D, K, V, N, F, E>>,
}

// `Verified*` types below all share one invariant: the Merkle proof has already
// been checked and the proof blob has been dropped. Service clients check against
// the caller's trusted root; adapter readers check against the root stored with
// the proof. Callers work with the plain payload fields.

/// Contiguous range of operations ending at or before `tip`. Shared across
/// ordered, unordered, immutable, and keyless variants.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedOperationRange<D: Digest, Op, F: Family> {
    pub tip: Location<F>,
    /// Canonical root at `tip`, as returned by the source database's `root()`:
    /// the current root for a database with current state, otherwise the
    /// operations-log root.
    pub root: D,
    pub start_location: Location<F>,
    pub operations: Vec<Op>,
}

/// Operations at the requested locations of `tip`, in request order. Shared
/// across ordered, unordered, immutable, and keyless variants.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedOperations<D: Digest, Op, F: Family> {
    pub tip: Location<F>,
    /// Canonical root at `tip`; see [`VerifiedOperationRange::root`].
    pub root: D,
    pub operations: Vec<(Location<F>, Op)>,
}

/// A single key's `Update` operation verified against the current-state root.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedKeyValue<D: Digest, Op, F: Family> {
    pub root: D,
    pub location: Location<F>,
    pub operation: Op,
}

/// A verified current lookup result for one requested key.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub enum VerifiedKeyLookup<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    F: Family,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> {
    Hit(VerifiedKeyValue<D, ordered::Operation<F, K, E>, F>),
    Miss { key: K },
}

/// A verified ordered current key range.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedKeyRange<
    D: Digest,
    K: QmdbKey + Codec,
    V: Codec + Clone + Send + Sync,
    F: Family,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> {
    pub entries: Vec<VerifiedKeyValue<D, ordered::Operation<F, K, E>, F>>,
    /// First key of the next page, if the range continues past `limit` entries.
    pub next_start_key: Option<K>,
}

/// Contiguous range of operations plus bitmap chunks verified against the
/// current-state root.
#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct VerifiedCurrentOperationRange<D: Digest, Op, const N: usize, F: Family> {
    pub tip: Location<F>,
    pub root: D,
    pub start_location: Location<F>,
    pub operations: Vec<Op>,
    pub chunks: Vec<[u8; N]>,
}

#[derive(Clone, Debug, PartialEq)]
#[must_use]
pub struct CurrentOperationRangeProof<D: Digest, Op, const N: usize, F: Graftable> {
    pub tip: Location<F>,
    pub root: D,
    pub start_location: Location<F>,
    pub proof: RangeProof<F, D>,
    pub operations: Vec<Op>,
    pub chunks: Vec<[u8; N]>,
}

impl<D: Digest, Op, const N: usize, F: Graftable> CurrentOperationRangeProof<D, Op, N, F>
where
    Op: Codec,
{
    pub fn verify<H: Hasher<Digest = D>>(&self) -> bool {
        self.proof.verify::<H, _, N>(
            self.start_location,
            &self.operations,
            &self.chunks,
            &self.root,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::proto::qmdb::v1::{
        MultiProofOperation, OperationMultiProof as ProtoOperationMultiProof,
        OperationRangeProof as ProtoOperationRangeProof,
    };
    use buffa::Message;
    use commonware_codec::{Copying, Decode, DecodeExt, Encode};
    use commonware_cryptography::{sha256, Sha256};
    use commonware_storage::merkle::{mmb, mmr};

    fn operation_encodings_roundtrip<F: Graftable + PartialEq>() {
        let digest = Sha256::hash(&[b"operation proof encoding"]);

        // Exercise locations beyond JavaScript's exact integer range and optional witnesses.
        // Operation payloads include empty values and bytes with the high bit set.
        for start in [0, (1u64 << 53) + 1] {
            for with_witness in [false, true] {
                let witness = with_witness.then(|| OpsRootWitness::<F, sha256::Digest> {
                    grafted_root: digest,
                    pending_chunk_digest: None.try_into().unwrap(),
                    partial_chunk: Some((start + 1, digest)),
                });
                let range = OperationRangeProof {
                    tip: Location::new(start + 1),
                    ops_root: digest,
                    ops_root_witness: witness.clone(),
                    start_location: Location::new(start),
                    pinned_nodes: vec![digest, digest],
                    proof: Proof {
                        leaves: Location::new(start + 2),
                        inactive_peaks: 1,
                        digests: vec![digest, digest],
                    },
                    encoded_operations: vec![Bytes::new(), Bytes::from_static(&[0, 127, 128, 255])],
                };

                // Encoding must match the generated protobuf and preserve every field.
                let encoded_witness = witness.as_ref().map(Encode::encode).unwrap_or_default();
                let expected = ProtoOperationRangeProof {
                    proof: range.proof.encode(),
                    start_location: start,
                    encoded_operations: range.encoded_operations.clone(),
                    ops_root: digest.encode(),
                    ops_root_witness: encoded_witness.clone(),
                    pinned_nodes: range.pinned_nodes.iter().map(Encode::encode).collect(),
                    ..Default::default()
                };
                let encoded = encode_operation_range_proof(&range);
                let decoded = ProtoOperationRangeProof::decode_from_slice(&encoded).unwrap();
                assert_eq!(encoded, expected.encode_to_vec());
                assert_eq!(decoded, expected);
                assert_eq!(
                    Proof::<F, sha256::Digest>::decode_cfg(Copying(decoded.proof.as_ref()), &32)
                        .unwrap(),
                    range.proof
                );
                if let Some(witness) = witness {
                    assert_eq!(
                        OpsRootWitness::<F, sha256::Digest>::decode(Copying(
                            decoded.ops_root_witness.as_ref()
                        ))
                        .unwrap(),
                        witness
                    );
                }

                // Multi-proof encoding must preserve each operation's location and bytes.
                let multi = OperationMultiProof {
                    tip: range.tip,
                    ops_root: digest,
                    ops_root_witness: range.ops_root_witness,
                    proof: range.proof,
                    encoded_operations: range
                        .encoded_operations
                        .into_iter()
                        .enumerate()
                        .map(|(offset, bytes)| (Location::new(start + offset as u64), bytes))
                        .collect(),
                };
                let expected = ProtoOperationMultiProof {
                    proof: multi.proof.encode(),
                    operations: multi
                        .encoded_operations
                        .iter()
                        .map(|(location, bytes)| MultiProofOperation {
                            location: location.as_u64(),
                            encoded_operation: bytes.clone(),
                            ..Default::default()
                        })
                        .collect(),
                    ops_root: digest.encode(),
                    ops_root_witness: encoded_witness,
                    ..Default::default()
                };
                let encoded = encode_operation_multi_proof(&multi);
                let decoded = ProtoOperationMultiProof::decode_from_slice(&encoded).unwrap();
                assert_eq!(encoded, expected.encode_to_vec());
                assert_eq!(decoded, expected);
            }
        }
    }

    #[test]
    fn operation_proof_encodings_roundtrip_without_response_envelopes() {
        operation_encodings_roundtrip::<mmr::Family>();
        operation_encodings_roundtrip::<mmb::Family>();
    }
}
