use commonware_codec::DecodeExt;
use commonware_consensus::simplex::{
    scheme::bls12381_threshold::vrf,
    types::{Finalization, Notarization},
};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinSig, Variant},
    ed25519,
    sha256::Digest as Sha256Digest,
};
use commonware_parallel::Sequential;
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

type PublicKey = ed25519::PublicKey;
type Scheme = vrf::Scheme<PublicKey, MinSig>;
type Identity = <MinSig as Variant>::Public;
type SimplexNotarization = Notarization<Scheme, Sha256Digest>;
type SimplexFinalization = Finalization<Scheme, Sha256Digest>;

fn decode_digest(bytes: &[u8]) -> Option<Sha256Digest> {
    Sha256Digest::decode(bytes).ok()
}

fn verify_notarization(
    namespace: &[u8],
    identity: &[u8],
    encoded_certificate: &[u8],
    block_digest: &[u8],
) -> bool {
    let Some(identity) = Identity::decode(identity).ok() else {
        return false;
    };
    let Some(block_digest) = decode_digest(block_digest) else {
        return false;
    };
    let Some(notarization) = SimplexNotarization::decode(encoded_certificate).ok() else {
        return false;
    };
    if notarization.proposal.payload != block_digest {
        return false;
    }
    let verifier = Scheme::certificate_verifier(namespace, identity);
    notarization.verify(&mut OsRng, &verifier, &Sequential)
}

fn verify_finalization(
    namespace: &[u8],
    identity: &[u8],
    encoded_certificate: &[u8],
    block_digest: &[u8],
) -> bool {
    let Some(identity) = Identity::decode(identity).ok() else {
        return false;
    };
    let Some(block_digest) = decode_digest(block_digest) else {
        return false;
    };
    let Some(finalization) = SimplexFinalization::decode(encoded_certificate).ok() else {
        return false;
    };
    if finalization.proposal.payload != block_digest {
        return false;
    }
    let verifier = Scheme::certificate_verifier(namespace, identity);
    finalization.verify(&mut OsRng, &verifier, &Sequential)
}

#[wasm_bindgen]
pub fn verify_certified_block(
    kind: &str,
    namespace: Vec<u8>,
    identity: Vec<u8>,
    encoded_certificate: Vec<u8>,
    block_digest: Vec<u8>,
) -> bool {
    match kind {
        "notarized" => {
            verify_notarization(&namespace, &identity, &encoded_certificate, &block_digest)
        }
        "finalized" => {
            verify_finalization(&namespace, &identity, &encoded_certificate, &block_digest)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode;
    use commonware_consensus::{
        simplex::{
            scheme::bls12381_threshold::vrf as bls12381_threshold,
            types::{Finalize, Notarize, Proposal},
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::MinSig, certificate::mocks::Fixture, Hasher, Sha256,
    };
    use rand::{rngs::StdRng, SeedableRng};

    const NAMESPACE: &[u8] = b"_ALTO";

    fn fixture() -> (Vec<Scheme>, Identity, Proposal<Sha256Digest>) {
        let mut rng = StdRng::seed_from_u64(7);
        let Fixture { schemes, .. } =
            bls12381_threshold::fixture::<MinSig, _>(&mut rng, NAMESPACE, 4);
        let identity = *schemes[0].identity();
        let digest = Sha256::hash(b"block");
        let proposal = Proposal::new(
            Round::new(Epoch::zero(), View::new(3)),
            View::new(2),
            digest,
        );
        (schemes, identity, proposal)
    }

    #[test]
    fn verifies_notarization() {
        let (schemes, identity, proposal) = fixture();
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let cert = SimplexNotarization::from_notarizes(&schemes[0], &votes, &Sequential).unwrap();

        assert!(verify_certified_block(
            "notarized",
            NAMESPACE.to_vec(),
            identity.encode().to_vec(),
            cert.encode().to_vec(),
            proposal.payload.encode().to_vec(),
        ));
    }

    #[test]
    fn rejects_tampered_notarization() {
        let (schemes, identity, proposal) = fixture();
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let cert = SimplexNotarization::from_notarizes(&schemes[0], &votes, &Sequential).unwrap();
        let mut encoded = cert.encode().to_vec();
        let last = encoded.len() - 1;
        encoded[last] ^= 0x01;

        assert!(!verify_certified_block(
            "notarized",
            NAMESPACE.to_vec(),
            identity.encode().to_vec(),
            encoded,
            proposal.payload.encode().to_vec(),
        ));
    }

    #[test]
    fn rejects_wrong_digest() {
        let (schemes, identity, proposal) = fixture();
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let cert = SimplexFinalization::from_finalizes(&schemes[0], &votes, &Sequential).unwrap();
        let wrong = Sha256::hash(b"other");

        assert!(!verify_certified_block(
            "finalized",
            NAMESPACE.to_vec(),
            identity.encode().to_vec(),
            cert.encode().to_vec(),
            wrong.encode().to_vec(),
        ));
    }

    #[test]
    fn rejects_wrong_kind() {
        let (schemes, identity, proposal) = fixture();
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let cert = SimplexFinalization::from_finalizes(&schemes[0], &votes, &Sequential).unwrap();

        assert!(!verify_certified_block(
            "notarized",
            NAMESPACE.to_vec(),
            identity.encode().to_vec(),
            cert.encode().to_vec(),
            proposal.payload.encode().to_vec(),
        ));
    }
}
