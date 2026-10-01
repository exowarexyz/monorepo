//! Verifying clients for individual `qmdb.v1` services.
//!
//! The per-kind clients in [`super`] compose these. Use them directly to reach
//! one service, for example only the operation log.

mod current_operation;
mod key_lookup;
mod key_range;
mod operation_log;
pub(crate) mod verify;

pub use super::ordered::OrderedLookupVerifier;
pub use super::unordered::UnorderedLookupVerifier;
pub use current_operation::CurrentOperationClient;
pub use key_lookup::{KeyLookupClient, LookupVerifier};
pub use key_range::KeyRangeClient;
pub use operation_log::{OperationLogClient, OperationLogSubscribeProof, OperationLogSubscription};

use commonware_cryptography::Digest;
use connectrpc::ConnectError;
use exoware_sdk::ClientError;

use crate::QmdbError;

pub(crate) fn connect_error_to_qmdb(err: ConnectError) -> QmdbError {
    QmdbError::Client(ClientError::Rpc(Box::new(err)))
}

pub(crate) fn proof_digest_cap<D: Digest>(encoded_proof: &[u8]) -> usize {
    encoded_proof.len() / D::SIZE + 1
}
