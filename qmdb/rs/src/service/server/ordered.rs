//! Ordered QMDB services: operation log, current operation ranges, key
//! lookups (hits and misses), and ordered key ranges.

use super::{
    CurrentOperationReader, CurrentOperationServer, KeyLookupReader, KeyLookupServer,
    KeyRangeReader, KeyRangeServer, OperationLogReader, OperationLogServer,
};
use crate::{
    adapter::Ordered,
    proof::{
        CurrentOperationRangeProof, KeyLookupProof, KeyRangeProof, KeyValueProof,
        MultiProofOperations, OperationMultiProof, OperationRangeProof,
    },
    service::proto::qmdb::v1::{
        CurrentOperationServiceServer, KeyLookupServiceServer, OperationLogServiceServer,
        OrderedKeyRangeServiceServer,
    },
    QmdbError, ResolvedTip,
};
use commonware_codec::{Decode, Encode, Read};
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::{Graftable, Location},
    qmdb::{
        any::ordered, current::ordered::proof::constant::ExclusionProof, operation::Key as QmdbKey,
        value::ValueEncoding,
    },
};
use connectrpc::{Chain, ConnectRpcService};
use exoware_sdk::PrefixedStoreClient;
use std::{future::Future, sync::Arc};

impl<F, H, K, V, const N: usize, E> OperationLogReader for Ordered<F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: QmdbKey + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
    ordered::Operation<F, K, E>: Encode + Decode,
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

impl<F, H, K, V, const N: usize, E> CurrentOperationReader<N> for Ordered<F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: QmdbKey + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
    ordered::Operation<F, K, E>: Encode + Decode,
{
    type Family = F;
    type Digest = H::Digest;
    type Operation = ordered::Operation<F, K, E>;

    fn current_operation_range_proof(
        &self,
        tip: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
        min_sequence_number: Option<u64>,
    ) -> impl Future<
        Output = Result<CurrentOperationRangeProof<Self::Digest, Self::Operation, N, F>, QmdbError>,
    > + Send {
        Self::current_operation_range_proof(
            self,
            tip,
            start_location,
            max_locations,
            min_sequence_number,
        )
    }
}

impl<F, H, K, V, const N: usize, E> KeyLookupReader<N> for Ordered<F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: QmdbKey + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
    ordered::Operation<F, K, E>: Encode + Decode,
    ExclusionProof<F, K, E, H::Digest, N>: Encode,
{
    type Family = F;
    type Digest = H::Digest;
    type Key = K;
    type Operation = ordered::Operation<F, K, E>;
    type Lookup = KeyLookupProof<H::Digest, K, V, N, F, E>;

    fn key_value_proof(
        &self,
        tip: Location<F>,
        key: &K,
        min_sequence_number: Option<u64>,
    ) -> impl Future<Output = Result<KeyValueProof<Self::Digest, Self::Operation, N, F>, QmdbError>> + Send
    {
        Self::get_proof(self, tip, key, min_sequence_number)
    }

    fn key_lookup_proofs(
        &self,
        tip: Location<F>,
        keys: &[K],
        min_sequence_number: Option<u64>,
    ) -> impl Future<Output = Result<Vec<Self::Lookup>, QmdbError>> + Send {
        Self::get_many_proofs(self, tip, keys, min_sequence_number)
    }
}

impl<F, H, K, V, const N: usize, E> KeyRangeReader<N> for Ordered<F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: QmdbKey + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
    ordered::Operation<F, K, E>: Encode + Decode,
    ExclusionProof<F, K, E, H::Digest, N>: Encode,
{
    type Family = F;
    type Digest = H::Digest;
    type Key = K;
    type Value = V;
    type Encoding = E;

    fn key_range_proof(
        &self,
        tip: Location<F>,
        start_key: K,
        end_key: Option<K>,
        limit: u32,
        min_sequence_number: Option<u64>,
    ) -> impl Future<Output = Result<KeyRangeProof<H::Digest, K, V, N, F, E>, QmdbError>> + Send
    {
        Self::get_range_proof(self, tip, start_key, end_key, limit, min_sequence_number)
    }
}

/// Mount all ordered-QMDB services on one endpoint: key lookups, ordered key
/// ranges, current operation ranges, and the operation log.
pub fn ordered_stack<
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: QmdbKey + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    const N: usize,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
>(
    store: PrefixedStoreClient,
    op_cfg: <ordered::Operation<F, K, E> as Read>::Cfg,
    key_cfg: K::Cfg,
) -> ConnectRpcService<impl ::connectrpc::Dispatcher>
where
    ordered::Operation<F, K, E>: Encode + Decode,
    ExclusionProof<F, K, E, H::Digest, N>: Encode,
{
    let reader = Arc::new(Ordered::<F, H, K, V, N, E>::new(
        store.clone(),
        op_cfg,
        key_cfg.clone(),
    ));
    super::stack(Chain(
        KeyLookupServiceServer::new(KeyLookupServer::<_, N>::new(
            reader.clone(),
            key_cfg.clone(),
        )),
        Chain(
            OrderedKeyRangeServiceServer::new(KeyRangeServer::<_, N>::new(reader.clone(), key_cfg)),
            Chain(
                CurrentOperationServiceServer::new(CurrentOperationServer::<_, N>::new(
                    reader.clone(),
                )),
                OperationLogServiceServer::new(OperationLogServer::new(reader, store)),
            ),
        ),
    ))
}

/// Mount only the ordered-QMDB operation log.
pub fn ordered_operation_log_stack<
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: QmdbKey + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    const N: usize,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
>(
    store: PrefixedStoreClient,
    op_cfg: <ordered::Operation<F, K, E> as Read>::Cfg,
    key_cfg: K::Cfg,
) -> ConnectRpcService<impl ::connectrpc::Dispatcher>
where
    ordered::Operation<F, K, E>: Encode + Decode,
{
    let reader = Arc::new(Ordered::<F, H, K, V, N, E>::new(
        store.clone(),
        op_cfg,
        key_cfg,
    ));
    super::stack(OperationLogServiceServer::new(OperationLogServer::new(
        reader, store,
    )))
}
