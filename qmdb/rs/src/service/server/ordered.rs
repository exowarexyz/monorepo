//! Ordered QMDB services: operation log, current operation ranges, key
//! lookups (hits and misses), and ordered key ranges.

use std::future::Future;
use std::sync::Arc;

use commonware_codec::{Decode, Encode, Read};
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::{Graftable, Location},
    qmdb::{
        any::{ordered, value::ValueEncoding},
        current::ordered::proof::constant::ExclusionProof,
        operation::Key as QmdbKey,
    },
};
use connectrpc::{Chain, ConnectRpcService};
use exoware_sdk::PrefixedStoreClient;

use super::{
    CurrentOperationReader, CurrentOperationServer, KeyLookupReader, KeyLookupServer,
    KeyRangeReader, KeyRangeServer, OperationLogReader, OperationLogServer,
};
use crate::adapter::Ordered;
use crate::proof::{
    CurrentOperationRangeProofResult, MultiProofOperations, OperationRangeCheckpoint,
    RawBatchMultiProof, RawKeyLookupProof, RawKeyRangeProof, RawKeyValueProof,
};
use crate::service::proto::qmdb::v1::{
    CurrentOperationServiceServer, KeyLookupServiceServer, OperationLogServiceServer,
    OrderedKeyRangeServiceServer,
};
use crate::{OperationKv, PublishedWatermark, QmdbError};

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

    fn extract_operation_kv(
        &self,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError> {
        Ordered::extract_operation_kv(self, location, bytes)
    }

    fn resolve_watermark(
        &self,
        watermark: Location<F>,
        min_sequence_number: Option<u64>,
    ) -> impl Future<Output = Result<PublishedWatermark<F>, QmdbError>> + Send {
        Ordered::resolve_watermark(self, watermark, min_sequence_number)
    }

    fn operation_range_checkpoint_at(
        &self,
        watermark: PublishedWatermark<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> impl Future<Output = Result<OperationRangeCheckpoint<Self::Digest, F>, QmdbError>> + Send
    {
        Ordered::operation_range_checkpoint_at(self, watermark, start_location, max_locations)
    }

    fn multi_proof_at(
        &self,
        watermark: PublishedWatermark<F>,
        operations: MultiProofOperations<'_, F>,
    ) -> impl Future<Output = Result<RawBatchMultiProof<Self::Digest, F>, QmdbError>> + Send {
        Ordered::multi_proof_at(self, watermark, operations)
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

    fn current_operation_range(
        &self,
        watermark: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
        min_sequence_number: Option<u64>,
    ) -> impl Future<
        Output = Result<
            CurrentOperationRangeProofResult<Self::Digest, Self::Operation, N, F>,
            QmdbError,
        >,
    > + Send {
        Ordered::current_operation_range_raw(
            self,
            watermark,
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
    type Lookup = RawKeyLookupProof<H::Digest, K, V, N, F, E>;

    fn key_value_proof(
        &self,
        tip: Location<F>,
        key: &K,
        min_sequence_number: Option<u64>,
    ) -> impl Future<Output = Result<RawKeyValueProof<Self::Digest, Self::Operation, N, F>, QmdbError>>
           + Send {
        Ordered::get_raw(self, tip, key.as_ref(), min_sequence_number)
    }

    fn key_lookup_proofs(
        &self,
        tip: Location<F>,
        keys: &[K],
        min_sequence_number: Option<u64>,
    ) -> impl Future<Output = Result<Vec<Self::Lookup>, QmdbError>> + Send {
        Ordered::get_many_raw(self, tip, keys, min_sequence_number)
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
    ) -> impl Future<Output = Result<RawKeyRangeProof<H::Digest, K, V, N, F, E>, QmdbError>> + Send
    {
        Ordered::get_range_raw(self, tip, start_key, end_key, limit, min_sequence_number)
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
    raw_store: PrefixedStoreClient,
    op_cfg: <ordered::Operation<F, K, E> as Read>::Cfg,
    key_cfg: K::Cfg,
) -> ConnectRpcService<impl ::connectrpc::Dispatcher>
where
    ordered::Operation<F, K, E>: Encode + Decode,
    ExclusionProof<F, K, E, H::Digest, N>: Encode,
{
    let reader = Arc::new(Ordered::<F, H, K, V, N, E>::new(
        raw_store.clone(),
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
                OperationLogServiceServer::new(OperationLogServer::new(reader, raw_store)),
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
    raw_store: PrefixedStoreClient,
    op_cfg: <ordered::Operation<F, K, E> as Read>::Cfg,
    key_cfg: K::Cfg,
) -> ConnectRpcService<impl ::connectrpc::Dispatcher>
where
    ordered::Operation<F, K, E>: Encode + Decode,
{
    let reader = Arc::new(Ordered::<F, H, K, V, N, E>::new(
        raw_store.clone(),
        op_cfg,
        key_cfg,
    ));
    super::stack(OperationLogServiceServer::new(OperationLogServer::new(
        reader, raw_store,
    )))
}
