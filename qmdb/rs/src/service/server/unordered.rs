//! Unordered QMDB services: operation log, current operation ranges, and
//! key lookups. Lookups prove hits only: unordered QMDB has no exclusion proofs,
//! so missing keys are omitted from `GetMany`.

use std::future::Future;
use std::sync::Arc;

use commonware_codec::{Decode, Encode, Read};
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::{Graftable, Location},
    qmdb::{
        any::{unordered, value::ValueEncoding},
        operation::Key as QmdbKey,
    },
};
use connectrpc::{Chain, ConnectRpcService};
use exoware_sdk::PrefixedStoreClient;

use super::{
    CurrentOperationReader, CurrentOperationServer, KeyLookupReader, KeyLookupServer,
    OperationLogReader, OperationLogServer,
};
use crate::adapter::Unordered;
use crate::proof::{
    CurrentOperationRangeProofResult, OperationRangeCheckpoint, RawBatchMultiProof,
    RawKeyValueProof,
};
use crate::service::proto::qmdb::v1::{
    CurrentOperationServiceServer, KeyLookupServiceServer, OperationLogServiceServer,
};
use crate::{OperationKv, PublishedWatermark, QmdbError};

impl<F, H, K, V, E> OperationLogReader for Unordered<F, H, K, V, E>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: QmdbKey + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
    unordered::Operation<F, K, E>: Encode + Decode,
{
    type Family = F;
    type Digest = H::Digest;

    fn extract_operation_kv(
        &self,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError> {
        Unordered::extract_operation_kv(self, location, bytes)
    }

    fn resolve_watermark(
        &self,
        watermark: Location<F>,
        min_sequence_number: Option<u64>,
    ) -> impl Future<Output = Result<PublishedWatermark<F>, QmdbError>> + Send {
        Unordered::resolve_watermark(self, watermark, min_sequence_number)
    }

    fn batch_multi_proof(
        &self,
        watermark: PublishedWatermark<F>,
        operations: Vec<(Location<F>, Vec<u8>)>,
    ) -> impl Future<Output = Result<RawBatchMultiProof<Self::Digest, F>, QmdbError>> + Send {
        Unordered::batch_multi_proof(self, watermark, operations)
    }

    fn operation_range_checkpoint_at(
        &self,
        watermark: PublishedWatermark<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> impl Future<Output = Result<OperationRangeCheckpoint<Self::Digest, F>, QmdbError>> + Send
    {
        Unordered::operation_range_checkpoint_at(self, watermark, start_location, max_locations)
    }
}

impl<F, H, K, V, const N: usize, E> CurrentOperationReader<N> for Unordered<F, H, K, V, E>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: QmdbKey + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
    unordered::Operation<F, K, E>: Encode + Decode,
{
    type Family = F;
    type Digest = H::Digest;
    type Operation = unordered::Operation<F, K, E>;

    fn current_operation_range_proof(
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
        Unordered::current_operation_range_proof_raw_at::<N>(
            self,
            watermark,
            start_location,
            max_locations,
            min_sequence_number,
        )
    }
}

impl<F, H, K, V, const N: usize, E> KeyLookupReader<N> for Unordered<F, H, K, V, E>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: QmdbKey + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
    unordered::Operation<F, K, E>: Encode + Decode,
{
    type Family = F;
    type Digest = H::Digest;
    type Key = K;
    type Operation = unordered::Operation<F, K, E>;
    type Lookup = RawKeyValueProof<H::Digest, unordered::Operation<F, K, E>, N, F>;

    fn key_value_proof(
        &self,
        tip: Location<F>,
        key: &K,
        min_sequence_number: Option<u64>,
    ) -> impl Future<Output = Result<RawKeyValueProof<Self::Digest, Self::Operation, N, F>, QmdbError>>
           + Send {
        Unordered::key_value_proof_raw_at::<N, _>(self, tip, key.as_ref(), min_sequence_number)
    }

    fn key_lookup_proofs(
        &self,
        tip: Location<F>,
        keys: &[K],
        min_sequence_number: Option<u64>,
    ) -> impl Future<Output = Result<Vec<Self::Lookup>, QmdbError>> + Send {
        Unordered::key_lookup_proofs_raw_at::<N, _>(self, tip, keys, min_sequence_number)
    }
}

/// Mount all unordered-QMDB services on one endpoint: key lookups (hits
/// only), current operation ranges, and the operation log.
pub fn unordered_stack<
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: QmdbKey + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    const N: usize,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
>(
    raw_store: PrefixedStoreClient,
    op_cfg: <unordered::Operation<F, K, E> as Read>::Cfg,
    key_cfg: K::Cfg,
) -> ConnectRpcService<impl ::connectrpc::Dispatcher>
where
    unordered::Operation<F, K, E>: Encode + Decode,
{
    let reader = Arc::new(Unordered::<F, H, K, V, E>::new(raw_store.clone(), op_cfg));
    super::stack(Chain(
        KeyLookupServiceServer::new(KeyLookupServer::<_, N>::new(reader.clone(), key_cfg)),
        Chain(
            CurrentOperationServiceServer::new(CurrentOperationServer::<_, N>::new(reader.clone())),
            OperationLogServiceServer::new(OperationLogServer::new(reader, raw_store)),
        ),
    ))
}

/// Mount only the unordered-QMDB operation log.
pub fn unordered_operation_log_stack<
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    K: QmdbKey + commonware_codec::Codec + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
>(
    raw_store: PrefixedStoreClient,
    op_cfg: <unordered::Operation<F, K, E> as Read>::Cfg,
) -> ConnectRpcService<impl ::connectrpc::Dispatcher>
where
    unordered::Operation<F, K, E>: Encode + Decode,
{
    let reader = Arc::new(Unordered::<F, H, K, V, E>::new(raw_store.clone(), op_cfg));
    super::stack(OperationLogServiceServer::new(OperationLogServer::new(
        reader, raw_store,
    )))
}
