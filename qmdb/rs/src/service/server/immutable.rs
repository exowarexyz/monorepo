//! Immutable QMDB services: the operation log only. Key reads are Rust
//! helpers on [`crate::adapter::Immutable`].

use super::{OperationLogReader, OperationLogServer};
use crate::{
    adapter::Immutable,
    proof::{MultiProofOperations, OperationMultiProof, OperationRangeProof},
    service::proto::qmdb::v1::OperationLogServiceServer,
    QmdbError, ResolvedTip,
};
use commonware_codec::{Decode, Encode, Read};
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::{Graftable, Location},
    qmdb::{immutable, operation::Key as QmdbKey, value::ValueEncoding},
};
use connectrpc::ConnectRpcService;
use exoware_sdk::PrefixedStoreClient;
use std::{future::Future, sync::Arc};

impl<F, H, K, V, E> OperationLogReader for Immutable<F, H, K, V, E>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: QmdbKey + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
    immutable::Operation<F, K, E>: Encode + Decode + Clone,
{
    type Family = F;
    type Digest = H::Digest;

    fn inspect_operation_kv<T>(
        &self,
        location: Location<F>,
        bytes: &[u8],
        inspect: impl FnOnce(Option<&[u8]>, Option<&[u8]>) -> T,
    ) -> Result<T, QmdbError> {
        Self::inspect_operation_kv(self, location, bytes, inspect)
    }

    fn resolve_tip(
        &self,
        tip: Location<F>,
        min_sequence_number: Option<u64>,
    ) -> impl Future<Output = Result<ResolvedTip<F>, QmdbError>> + Send {
        Self::resolve_tip(self, tip, min_sequence_number)
    }

    fn observe_published(&self, location: Location<F>, sequence: u64) {
        Self::observe_published(self, location, sequence)
    }

    fn operation_range_proof_at(
        &self,
        resolved: ResolvedTip<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> impl Future<Output = Result<OperationRangeProof<Self::Digest, F>, QmdbError>> + Send {
        Self::operation_range_proof_at(self, resolved, start_location, max_locations)
    }

    fn operation_multi_proof_at(
        &self,
        resolved: ResolvedTip<F>,
        operations: MultiProofOperations<'_, F>,
    ) -> impl Future<Output = Result<OperationMultiProof<Self::Digest, F>, QmdbError>> + Send {
        Self::operation_multi_proof_at(self, resolved, operations)
    }
}

/// Mount the immutable-QMDB operation log, the only service immutable QMDB serves.
pub fn immutable_operation_log_stack<
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: QmdbKey + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
>(
    store: PrefixedStoreClient,
    op_cfg: <immutable::Operation<F, K, E> as Read>::Cfg,
) -> ConnectRpcService<impl ::connectrpc::Dispatcher>
where
    immutable::Operation<F, K, E>: Encode + Decode + Clone,
{
    let reader = Arc::new(Immutable::<F, H, K, V, E>::new(store.clone(), op_cfg));
    super::stack(OperationLogServiceServer::new(OperationLogServer::new(
        reader, store,
    )))
}
