//! Check the public API with the bounds available to a generic caller.

use commonware_codec::{Encode, Read};
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_storage::{
    merkle::{mmr, Location},
    qmdb::{
        any::{
            ordered, unordered,
            value::{ValueEncoding, VariableEncoding},
        },
        current::{ordered::proof::constant::ExclusionProof, proof::RangeProof},
        operation::Operation,
    },
};
use connectrpc::client::ClientTransport;
use exoware_qmdb::{
    adapter::upload::recover_boundary_state,
    service::{
        client::rpc::{CurrentOperationClient, OperationLogClient},
        server::{
            ordered_operation_log_stack, ordered_stack, unordered_operation_log_stack,
            unordered_stack,
        },
    },
    QmdbError,
};
use exoware_sdk::proto::PreferZstdHttpClient;
use http_body::Body;
use std::{fmt::Display, future::Ready};

type Family = mmr::Family;
const N: usize = 32;

#[test]
fn sha256_client_is_cloneable_for_any_readable_operation() {
    fn assert_clone<T: Clone>() {}
    fn check<Op: Read>() {
        assert_clone::<CurrentOperationClient<PreferZstdHttpClient, Family, Sha256, Op, N>>();
    }
    check::<u8>();
}

#[test]
fn unary_calls_accept_pinned_response_bodies() {
    fn check<T: ClientTransport>()
    where
        <T::ResponseBody as Body>::Error: Display,
    {
        let _ = OperationLogClient::<T, Family, Sha256, u8>::new;
        let _ = OperationLogClient::<T, Family, Sha256, u8>::get_operation_range;
    }
    check::<PreferZstdHttpClient>();
}

#[test]
fn stack_factories_use_the_value_bounds_from_the_encoding() {
    fn check<V, E>()
    where
        V: AsRef<[u8]> + 'static,
        E: ValueEncoding<Value = V>,
        ordered::Operation<Family, Vec<u8>, E>: Encode + Read,
        unordered::Operation<Family, Vec<u8>, E>: Encode + Read,
        ExclusionProof<Family, Vec<u8>, E, Digest, N>: Encode,
    {
        let _ = ordered_stack::<Family, Sha256, Vec<u8>, V, N, E>;
        let _ = ordered_operation_log_stack::<Family, Sha256, Vec<u8>, V, N, E>;
        let _ = unordered_stack::<Family, Sha256, Vec<u8>, V, N, E>;
        let _ = unordered_operation_log_stack::<Family, Sha256, Vec<u8>, V, N, E>;
    }
    check::<Vec<u8>, VariableEncoding<Vec<u8>>>();
}

#[test]
fn boundary_recovery_accepts_encode_only_operations() {
    type Proof = (RangeProof<Family, Digest>, [u8; N]);
    type Prover = fn(Location<Family>) -> Ready<Result<Proof, QmdbError>>;

    fn check<Op: Operation<Family> + Encode>() {
        let _ = recover_boundary_state::<Family, Sha256, Op, N, Prover, _>;
    }
    check::<ordered::variable::Operation<Family, Vec<u8>, Vec<u8>>>();
}
