//! Keyless QMDB services: the operation log only; subscriptions reject key
//! filters because keyless operations have no logical key. Location reads are
//! Rust helpers on [`crate::adapter::Keyless`].

use std::future::Future;
use std::sync::Arc;

use commonware_codec::{Decode, Encode, Read};
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::{Graftable, Location},
    qmdb::{any::value::ValueEncoding, keyless},
};
use connectrpc::ConnectRpcService;
use exoware_sdk::PrefixedStoreClient;

use super::{OperationLogReader, OperationLogServer};
use crate::adapter::Keyless;
use crate::proof::{MultiProofOperations, OperationRangeCheckpoint, RawBatchMultiProof};
use crate::service::proto::qmdb::v1::OperationLogServiceServer;
use crate::{OperationKv, PublishedWatermark, QmdbError};

impl<F, H, V, E> OperationLogReader for Keyless<F, H, V, E>
where
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
    keyless::Operation<F, E>: Encode + Decode + Clone,
{
    type Family = F;
    type Digest = H::Digest;
    const REJECTS_KEY_FILTERS: bool = true;

    fn extract_operation_kv(
        &self,
        location: Location<F>,
        bytes: &[u8],
    ) -> Result<OperationKv, QmdbError> {
        Keyless::extract_operation_kv(self, location, bytes)
    }

    fn resolve_watermark(
        &self,
        watermark: Location<F>,
        min_sequence_number: Option<u64>,
    ) -> impl Future<Output = Result<PublishedWatermark<F>, QmdbError>> + Send {
        Keyless::resolve_watermark(self, watermark, min_sequence_number)
    }

    fn operation_range_checkpoint_at(
        &self,
        watermark: PublishedWatermark<F>,
        start_location: Location<F>,
        max_locations: u32,
    ) -> impl Future<Output = Result<OperationRangeCheckpoint<Self::Digest, F>, QmdbError>> + Send
    {
        Keyless::operation_range_checkpoint_at(self, watermark, start_location, max_locations)
    }

    fn multi_proof_at(
        &self,
        watermark: PublishedWatermark<F>,
        operations: MultiProofOperations<'_, F>,
    ) -> impl Future<Output = Result<RawBatchMultiProof<Self::Digest, F>, QmdbError>> + Send {
        Keyless::multi_proof_at(self, watermark, operations)
    }
}

/// Mount the keyless-QMDB operation log, the only service keyless QMDB serves.
/// Subscriptions reject key filters because keyless operations have no logical
/// key.
pub fn keyless_operation_log_stack<
    F: Graftable,
    H: Hasher + Send + Sync + 'static,
    V: commonware_codec::Codec + Clone + AsRef<[u8]> + Send + Sync + 'static,
    E: ValueEncoding<Value = V> + Send + Sync + 'static,
>(
    raw_store: PrefixedStoreClient,
    op_cfg: <keyless::Operation<F, E> as Read>::Cfg,
) -> ConnectRpcService<impl ::connectrpc::Dispatcher>
where
    keyless::Operation<F, E>: Encode + Decode + Clone,
{
    let reader = Arc::new(Keyless::<F, H, V, E>::new(raw_store.clone(), op_cfg));
    super::stack(OperationLogServiceServer::new(OperationLogServer::new(
        reader, raw_store,
    )))
}
