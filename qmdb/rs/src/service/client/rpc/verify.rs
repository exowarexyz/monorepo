//! Proof checks shared by the key lookup and key range clients.

use commonware_codec::{Decode, DecodeExt, Encode, Read};
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::Graftable,
    qmdb::{
        any::{ordered, value::ValueEncoding},
        current::ordered::ExclusionProof,
        current::proof::OperationProof,
        operation::{Key as QmdbKey, Operation},
    },
};

use crate::proof::{verify_ordered_exclusion_proof, VerifiedKeyValue};
use crate::service::proto::qmdb::v1::{
    CurrentKeyExclusionProof as ProtoCurrentKeyExclusionProof,
    CurrentKeyValueProof as ProtoCurrentKeyValueProof,
};
use crate::QmdbError;

use super::proof_digest_cap;

pub(crate) fn verify_key_value_from_proto<F, H, Op, const N: usize>(
    proto: &ProtoCurrentKeyValueProof,
    root: &H::Digest,
    op_cfg: &Op::Cfg,
) -> Result<VerifiedKeyValue<H::Digest, Op, F>, QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: commonware_codec::Codec + Clone + Operation<F>,
{
    let operation = Op::decode_cfg(proto.encoded_operation.as_ref(), op_cfg).map_err(|err| {
        QmdbError::CorruptData(format!(
            "failed to decode current key-value operation: {err}",
        ))
    })?;
    if !operation.is_update() {
        return Err(QmdbError::CorruptData(
            "current key-value proof operation must be an update".to_string(),
        ));
    }
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof = OperationProof::<F, H::Digest, N>::decode_cfg(proto.proof.as_ref(), &max_digests)
        .map_err(|err| {
        QmdbError::CorruptData(format!("failed to decode current key-value proof: {err}"))
    })?;
    if !proof.verify::<H, _>(operation.clone(), root) {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::CurrentKeyValue,
        });
    }
    Ok(VerifiedKeyValue {
        root: *root,
        location: proof.loc,
        operation,
    })
}

/// Verify an exclusion proof and return the authenticated successor of the requested key
/// (`None` when the proof shows an empty database)
pub(crate) fn verify_key_exclusion_from_proto<F, H, K, V, const N: usize, E>(
    proto: &ProtoCurrentKeyExclusionProof,
    requested_key: &[u8],
    root: &H::Digest,
    update_cfg: &<ordered::Update<K, E> as Read>::Cfg,
    key_cfg: &K::Cfg,
    value_cfg: &V::Cfg,
) -> Result<Option<K>, QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    ordered::Operation<F, K, E>: Decode + Encode + Read,
    ordered::Update<K, E>: Read,
    ExclusionProof<F, K, E, H::Digest, N>:
        Read<Cfg = (usize, <ordered::Update<K, E> as Read>::Cfg, V::Cfg)>,
{
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof = ExclusionProof::<F, K, E, H::Digest, N>::decode_cfg(
        proto.proof.as_ref(),
        &(max_digests, update_cfg.clone(), value_cfg.clone()),
    )
    .map_err(|err| {
        QmdbError::CorruptData(format!(
            "failed to decode current key-exclusion proof: {err}"
        ))
    })?;
    let requested_key = K::decode_cfg(requested_key, key_cfg).map_err(|err| {
        QmdbError::CorruptData(format!("failed to decode requested exclusion key: {err}"))
    })?;
    if !verify_ordered_exclusion_proof::<F, H, K, E, N>(&requested_key, &proof, root) {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::CurrentKeyExclusion,
        });
    }
    Ok(match proof {
        ExclusionProof::KeyValue(_, update) => Some(update.next_key),
        ExclusionProof::Commit(_, _) => None,
    })
}
