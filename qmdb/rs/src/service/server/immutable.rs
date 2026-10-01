//! Immutable QMDB services: the operation log only. Key reads are Rust
//! helpers on [`crate::adapter::Immutable`].

use std::future::Future;
use std::sync::Arc;

use commonware_codec::{Decode, Encode, Read};
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::{Graftable, Location},
    qmdb::{any::value::ValueEncoding, immutable, operation::Key as QmdbKey},
};
use connectrpc::ConnectRpcService;
use exoware_sdk::PrefixedStoreClient;

use super::{OperationLogReader, OperationLogServer};
use crate::adapter::Immutable;
use crate::proof::{OperationRangeCheckpoint, RawBatchMultiProof};
use crate::service::proto::qmdb::v1::OperationLogServiceServer;
use crate::{OperationKv, PublishedWatermark, QmdbError};

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

    fn extract_operation_kv(
        &self,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError> {
        Immutable::extract_operation_kv(self, location, bytes)
    }

    fn resolve_watermark(
        &self,
        watermark: Location<F>,
        min_sequence_number: Option<u64>,
    ) -> impl Future<Output = Result<PublishedWatermark<F>, QmdbError>> + Send {
        Immutable::resolve_watermark(self, watermark, min_sequence_number)
    }

    fn batch_multi_proof(
        &self,
        watermark: PublishedWatermark<F>,
        operations: Vec<(Location<F>, Vec<u8>)>,
    ) -> impl Future<Output = Result<RawBatchMultiProof<Self::Digest, F>, QmdbError>> + Send {
        Immutable::batch_multi_proof(self, watermark, operations)
    }

    fn operation_range_checkpoint_at(
        &self,
        watermark: PublishedWatermark<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> impl Future<Output = Result<OperationRangeCheckpoint<Self::Digest, F>, QmdbError>> + Send
    {
        Immutable::operation_range_checkpoint_at(self, watermark, start_location, max_locations)
    }

    fn operations_multi_proof_at(
        &self,
        watermark: PublishedWatermark<F>,
        locations: &[Location<F>],
    ) -> impl Future<Output = Result<RawBatchMultiProof<Self::Digest, F>, QmdbError>> + Send {
        Immutable::operations_multi_proof_at(self, watermark, locations)
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
    raw_store: PrefixedStoreClient,
    op_cfg: <immutable::Operation<F, K, E> as Read>::Cfg,
) -> ConnectRpcService<impl ::connectrpc::Dispatcher>
where
    immutable::Operation<F, K, E>: Encode + Decode + Clone,
{
    let reader = Arc::new(Immutable::<F, H, K, V, E>::new(raw_store.clone(), op_cfg));
    super::stack(OperationLogServiceServer::new(OperationLogServer::new(
        reader, raw_store,
    )))
}
