use commonware_codec::{Decode, DecodeExt, Encode, Read};
use commonware_consensus::{
    simplex::{
        scheme::{
            bls12381_multisig,
            bls12381_threshold::{standard as threshold_standard, vrf as threshold_vrf},
            ed25519 as simplex_ed25519, secp256r1 as simplex_secp256r1,
        },
        types::{Finalization, Notarization},
    },
    Viewable,
};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinPk, MinSig, Variant},
    ed25519, secp256r1, sha256,
};
use commonware_parallel::Sequential;
use commonware_utils::ordered::{BiMap, Set};
use core::hash::Hash;
use rand::rngs::OsRng;
use serde::Serialize;
use wasm_bindgen::prelude::*;

const MAX_PARTICIPANTS: usize = 10_000;
const MAX_HEADER_BYTES: usize = 16 * 1024 * 1024;
type Sha256Digest = sha256::Digest;
type Identity = ed25519::PublicKey;
type Secp256r1PublicKey = secp256r1::standard::PublicKey;

#[derive(Serialize)]
struct VerifiedCertificate {
    scheme: String,
    view: u64,
    parent: u64,
    payload: Vec<u8>,
    certificate: Vec<u8>,
    header: Vec<u8>,
}

fn to_value(value: VerifiedCertificate) -> Result<JsValue, JsValue> {
    let serializer =
        serde_wasm_bindgen::Serializer::new().serialize_large_number_types_as_bigints(true);
    value.serialize(&serializer).map_err(|err| {
        JsValue::from_str(&format!("failed to serialize verified certificate: {err}"))
    })
}

fn read_header(bytes: &[u8], artifact: &str) -> Result<Vec<u8>, String> {
    if bytes.len() > MAX_HEADER_BYTES {
        return Err(format!("{artifact} header exceeds maximum size"));
    }
    Ok(bytes.to_vec())
}

fn participant_set<T>(bytes: &[u8]) -> Result<Set<T>, commonware_codec::Error>
where
    T: Read<Cfg = ()> + Ord,
{
    Set::<T>::decode_cfg(bytes, &((0..=MAX_PARTICIPANTS).into(), ()))
}

fn participant_map<K, V>(bytes: &[u8]) -> Result<BiMap<K, V>, commonware_codec::Error>
where
    K: Read<Cfg = ()> + Ord,
    V: Read<Cfg = ()> + Eq + Hash,
{
    BiMap::<K, V>::decode_cfg(bytes, &((0..=MAX_PARTICIPANTS).into(), (), ()))
}

fn read_identity<V: Variant>(bytes: &[u8]) -> Result<V::Public, commonware_codec::Error>
where
    V::Public: DecodeExt<()>,
{
    V::Public::decode(bytes)
}

fn verify_notarized<S>(
    scheme_name: &str,
    scheme: S,
    bytes: &[u8],
) -> Result<VerifiedCertificate, String>
where
    S: commonware_consensus::simplex::scheme::Scheme<Sha256Digest>,
    <S::Certificate as Read>::Cfg: Clone,
{
    let mut reader = bytes;
    let proof =
        Notarization::<S, Sha256Digest>::read_cfg(&mut reader, &scheme.certificate_codec_config())
            .map_err(|err| format!("failed to decode notarized artifact: {err}"))?;
    if !proof.verify(&mut OsRng, &scheme, &Sequential) {
        return Err("notarization certificate verification failed".to_string());
    }
    let header = read_header(reader, "notarized artifact")?;
    Ok(VerifiedCertificate {
        scheme: scheme_name.to_string(),
        view: proof.view().get(),
        parent: proof.proposal.parent.get(),
        payload: proof.proposal.payload.as_ref().to_vec(),
        certificate: proof.certificate.encode().to_vec(),
        header,
    })
}

fn verify_finalized<S>(
    scheme_name: &str,
    scheme: S,
    bytes: &[u8],
) -> Result<VerifiedCertificate, String>
where
    S: commonware_consensus::simplex::scheme::Scheme<Sha256Digest>,
    <S::Certificate as Read>::Cfg: Clone,
{
    let mut reader = bytes;
    let proof =
        Finalization::<S, Sha256Digest>::read_cfg(&mut reader, &scheme.certificate_codec_config())
            .map_err(|err| format!("failed to decode finalized artifact: {err}"))?;
    if !proof.verify(&mut OsRng, &scheme, &Sequential) {
        return Err("finalization certificate verification failed".to_string());
    }
    let header = read_header(reader, "finalized artifact")?;
    Ok(VerifiedCertificate {
        scheme: scheme_name.to_string(),
        view: proof.view().get(),
        parent: proof.proposal.parent.get(),
        payload: proof.proposal.payload.as_ref().to_vec(),
        certificate: proof.certificate.encode().to_vec(),
        header,
    })
}

#[derive(Clone, Copy)]
enum ArtifactKind {
    Notarized,
    Finalized,
}

fn verify_artifact<S>(
    artifact: ArtifactKind,
    scheme_name: &str,
    scheme: S,
    bytes: &[u8],
) -> Result<VerifiedCertificate, String>
where
    S: commonware_consensus::simplex::scheme::Scheme<Sha256Digest>,
    <S::Certificate as Read>::Cfg: Clone,
{
    match artifact {
        ArtifactKind::Notarized => verify_notarized(scheme_name, scheme, bytes),
        ArtifactKind::Finalized => verify_finalized(scheme_name, scheme, bytes),
    }
}

fn verify_for_scheme(
    scheme_name: &str,
    namespace: &[u8],
    verification_material: &[u8],
    bytes: &[u8],
    artifact: ArtifactKind,
) -> Result<VerifiedCertificate, String> {
    match scheme_name {
        "ed25519" => {
            let participants = participant_set::<ed25519::PublicKey>(verification_material)
                .map_err(|err| format!("failed to decode ed25519 participants: {err}"))?;
            verify_artifact(
                artifact,
                scheme_name,
                simplex_ed25519::Scheme::verifier(namespace, participants),
                bytes,
            )
        }
        "secp256r1" => {
            let participants =
                participant_map::<Identity, Secp256r1PublicKey>(verification_material)
                    .map_err(|err| format!("failed to decode secp256r1 participants: {err}"))?;
            verify_artifact(
                artifact,
                scheme_name,
                simplex_secp256r1::Scheme::<Identity>::verifier(namespace, participants),
                bytes,
            )
        }
        "bls12381-multisig-min-pk" => {
            let participants =
                participant_map::<Identity, <MinPk as Variant>::Public>(verification_material)
                    .map_err(|err| format!("failed to decode multisig participants: {err}"))?;
            verify_artifact(
                artifact,
                scheme_name,
                bls12381_multisig::Scheme::<Identity, MinPk>::verifier(namespace, participants),
                bytes,
            )
        }
        "bls12381-multisig-min-sig" => {
            let participants =
                participant_map::<Identity, <MinSig as Variant>::Public>(verification_material)
                    .map_err(|err| format!("failed to decode multisig participants: {err}"))?;
            verify_artifact(
                artifact,
                scheme_name,
                bls12381_multisig::Scheme::<Identity, MinSig>::verifier(namespace, participants),
                bytes,
            )
        }
        "bls12381-threshold-standard-min-pk" => {
            let identity = read_identity::<MinPk>(verification_material)
                .map_err(|err| format!("failed to decode threshold identity: {err}"))?;
            verify_artifact(
                artifact,
                scheme_name,
                threshold_standard::Scheme::<Identity, MinPk>::certificate_verifier(
                    namespace, identity,
                ),
                bytes,
            )
        }
        "bls12381-threshold-standard-min-sig" => {
            let identity = read_identity::<MinSig>(verification_material)
                .map_err(|err| format!("failed to decode threshold identity: {err}"))?;
            verify_artifact(
                artifact,
                scheme_name,
                threshold_standard::Scheme::<Identity, MinSig>::certificate_verifier(
                    namespace, identity,
                ),
                bytes,
            )
        }
        "bls12381-threshold-vrf-min-pk" => {
            let identity = read_identity::<MinPk>(verification_material)
                .map_err(|err| format!("failed to decode threshold VRF identity: {err}"))?;
            verify_artifact(
                artifact,
                scheme_name,
                threshold_vrf::Scheme::<Identity, MinPk>::certificate_verifier(namespace, identity),
                bytes,
            )
        }
        "bls12381-threshold-vrf-min-sig" => {
            let identity = read_identity::<MinSig>(verification_material)
                .map_err(|err| format!("failed to decode threshold VRF identity: {err}"))?;
            verify_artifact(
                artifact,
                scheme_name,
                threshold_vrf::Scheme::<Identity, MinSig>::certificate_verifier(
                    namespace, identity,
                ),
                bytes,
            )
        }
        other => Err(format!("unsupported Commonware Simplex scheme: {other}")),
    }
}

fn verify_notarized_for_scheme(
    scheme_name: &str,
    namespace: &[u8],
    verification_material: &[u8],
    bytes: &[u8],
) -> Result<VerifiedCertificate, String> {
    verify_for_scheme(
        scheme_name,
        namespace,
        verification_material,
        bytes,
        ArtifactKind::Notarized,
    )
}

fn verify_finalized_for_scheme(
    scheme_name: &str,
    namespace: &[u8],
    verification_material: &[u8],
    bytes: &[u8],
) -> Result<VerifiedCertificate, String> {
    verify_for_scheme(
        scheme_name,
        namespace,
        verification_material,
        bytes,
        ArtifactKind::Finalized,
    )
}

/// Verify an opaque `{ notarization proof, header }` artifact.
///
/// `scheme` selects one of the Commonware Simplex certificate schemes. The
/// verification material is an encoded participant set for Ed25519, an encoded
/// identity-to-signing-key map for Secp256r1 and BLS multisig, and an encoded
/// threshold identity for threshold schemes.
#[wasm_bindgen]
pub fn verify_notarized_commonware(
    scheme: String,
    namespace: Vec<u8>,
    verification_material: Vec<u8>,
    bytes: Vec<u8>,
) -> Result<JsValue, JsValue> {
    verify_notarized_for_scheme(&scheme, &namespace, &verification_material, &bytes)
        .map_err(|err| JsValue::from_str(&err))
        .and_then(to_value)
}

/// Verify an opaque `{ finalization proof, header }` artifact.
#[wasm_bindgen]
pub fn verify_finalized_commonware(
    scheme: String,
    namespace: Vec<u8>,
    verification_material: Vec<u8>,
    bytes: Vec<u8>,
) -> Result<JsValue, JsValue> {
    verify_finalized_for_scheme(&scheme, &namespace, &verification_material, &bytes)
        .map_err(|err| JsValue::from_str(&err))
        .and_then(to_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::{
        simplex::{
            scheme::Scheme,
            types::{Finalization, Finalize, Notarization, Notarize, Proposal},
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        bls12381::primitives::{group::Private, ops::compute_public},
        certificate::mocks::Fixture,
        Hasher, Sha256, Signer as _,
    };
    use commonware_math::algebra::Random;
    use commonware_utils::TryCollect;
    use rand::{rngs::StdRng, SeedableRng};

    const DEMO_NAMESPACE: &[u8] = b"_EXOWARE_SIMPLEX_DEMO";

    fn digest_header(header: &[u8]) -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(header);
        hasher.finalize()
    }

    fn proposal(header: &[u8]) -> Proposal<Sha256Digest> {
        Proposal::new(
            Round::new(Epoch::zero(), View::new(2)),
            View::new(1),
            digest_header(header),
        )
    }

    fn verify_round_trip<S>(scheme_name: &str, schemes: &[S], verification_material: Vec<u8>)
    where
        S: Scheme<Sha256Digest>,
        <S::Certificate as Read>::Cfg: Clone,
    {
        let notarized_header = b"notarized-header";
        let proposal_value = proposal(notarized_header);
        let notarizes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal_value.clone()).expect("notarize"))
            .collect();
        let notarization =
            Notarization::from_notarizes(&schemes[0], &notarizes, &Sequential).unwrap();
        let mut artifact = notarization.encode().to_vec();
        artifact.extend_from_slice(notarized_header);

        let verified = verify_notarized_for_scheme(
            scheme_name,
            DEMO_NAMESPACE,
            &verification_material,
            &artifact,
        )
        .expect("verify notarization");

        assert_eq!(verified.scheme, scheme_name);
        assert_eq!(verified.view, 2);
        assert_eq!(verified.parent, 1);
        assert_eq!(verified.header, notarized_header);

        let finalized_header = b"finalized-header";
        let proposal_value = proposal(finalized_header);
        let finalizes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal_value.clone()).expect("finalize"))
            .collect();
        let finalization =
            Finalization::from_finalizes(&schemes[0], &finalizes, &Sequential).unwrap();
        let mut artifact = finalization.encode().to_vec();
        artifact.extend_from_slice(finalized_header);

        let verified = verify_finalized_for_scheme(
            scheme_name,
            DEMO_NAMESPACE,
            &verification_material,
            &artifact,
        )
        .expect("verify finalization");

        assert_eq!(verified.scheme, scheme_name);
        assert_eq!(verified.view, 2);
        assert_eq!(verified.parent, 1);
        assert_eq!(verified.header, finalized_header);
    }

    fn identities<R>(rng: &mut R) -> (Vec<ed25519::PrivateKey>, Set<Identity>)
    where
        R: rand::RngCore + rand::CryptoRng,
    {
        let private_keys: Vec<_> = (0..4)
            .map(|_| ed25519::PrivateKey::random(&mut *rng))
            .collect();
        let participants = Set::from_iter_dedup(
            private_keys
                .iter()
                .map(|private_key| private_key.public_key()),
        );
        (private_keys, participants)
    }

    fn ed25519_fixture() -> (Vec<simplex_ed25519::Scheme>, Vec<u8>) {
        let mut rng = StdRng::seed_from_u64(1);
        let (private_keys, participants) = identities(&mut rng);
        let schemes = private_keys
            .into_iter()
            .map(|private_key| {
                simplex_ed25519::Scheme::signer(DEMO_NAMESPACE, participants.clone(), private_key)
                    .unwrap()
            })
            .collect();
        (schemes, participants.encode().to_vec())
    }

    fn secp256r1_fixture() -> (Vec<simplex_secp256r1::Scheme<Identity>>, Vec<u8>) {
        let mut rng = StdRng::seed_from_u64(2);
        let (_identity_keys, participants) = identities(&mut rng);
        let secp_private_keys: Vec<_> = (0..participants.len())
            .map(|_| secp256r1::standard::PrivateKey::random(&mut rng))
            .collect();
        let signers: BiMap<_, _> = participants
            .iter()
            .cloned()
            .zip(
                secp_private_keys
                    .iter()
                    .map(|private_key| private_key.public_key()),
            )
            .try_collect()
            .unwrap();
        let schemes = secp_private_keys
            .into_iter()
            .map(|private_key| {
                simplex_secp256r1::Scheme::<Identity>::signer(
                    DEMO_NAMESPACE,
                    signers.clone(),
                    private_key,
                )
                .unwrap()
            })
            .collect();
        (schemes, signers.encode().to_vec())
    }

    fn multisig_fixture<V>() -> (Vec<bls12381_multisig::Scheme<Identity, V>>, Vec<u8>)
    where
        V: Variant,
    {
        let mut rng = StdRng::seed_from_u64(3);
        let (_identity_keys, participants) = identities(&mut rng);
        let bls_private_keys: Vec<_> = (0..participants.len())
            .map(|_| Private::random(&mut rng))
            .collect();
        let signers: BiMap<_, _> = participants
            .iter()
            .cloned()
            .zip(bls_private_keys.iter().map(compute_public::<V>))
            .try_collect()
            .unwrap();
        let schemes = bls_private_keys
            .into_iter()
            .map(|private_key| {
                bls12381_multisig::Scheme::<Identity, V>::signer(
                    DEMO_NAMESPACE,
                    signers.clone(),
                    private_key,
                )
                .unwrap()
            })
            .collect();
        (schemes, signers.encode().to_vec())
    }

    fn threshold_standard_fixture<V>() -> (Vec<threshold_standard::Scheme<Identity, V>>, Vec<u8>)
    where
        V: Variant,
    {
        let mut rng = StdRng::seed_from_u64(4);
        let fixture: Fixture<_> = threshold_standard::fixture::<V, _>(&mut rng, DEMO_NAMESPACE, 4);
        let material = fixture.schemes[0].identity().encode().to_vec();
        (fixture.schemes, material)
    }

    fn threshold_vrf_fixture<V>() -> (Vec<threshold_vrf::Scheme<Identity, V>>, Vec<u8>)
    where
        V: Variant,
    {
        let mut rng = StdRng::seed_from_u64(5);
        let fixture: Fixture<_> = threshold_vrf::fixture::<V, _>(&mut rng, DEMO_NAMESPACE, 4);
        let material = fixture.schemes[0].identity().encode().to_vec();
        (fixture.schemes, material)
    }

    #[test]
    fn verifies_all_commonware_simplex_schemes() {
        let (schemes, material) = ed25519_fixture();
        verify_round_trip("ed25519", &schemes, material);

        let (schemes, material) = secp256r1_fixture();
        verify_round_trip("secp256r1", &schemes, material);

        let (schemes, material) = multisig_fixture::<MinPk>();
        verify_round_trip("bls12381-multisig-min-pk", &schemes, material);

        let (schemes, material) = multisig_fixture::<MinSig>();
        verify_round_trip("bls12381-multisig-min-sig", &schemes, material);

        let (schemes, material) = threshold_standard_fixture::<MinPk>();
        verify_round_trip("bls12381-threshold-standard-min-pk", &schemes, material);

        let (schemes, material) = threshold_standard_fixture::<MinSig>();
        verify_round_trip("bls12381-threshold-standard-min-sig", &schemes, material);

        let (schemes, material) = threshold_vrf_fixture::<MinPk>();
        verify_round_trip("bls12381-threshold-vrf-min-pk", &schemes, material);

        let (schemes, material) = threshold_vrf_fixture::<MinSig>();
        verify_round_trip("bls12381-threshold-vrf-min-sig", &schemes, material);
    }
}
