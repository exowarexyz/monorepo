//! Verifying client for immutable QMDB.

use std::fmt::Display;

use bytes::Bytes;
use commonware_codec::{Decode, DecodeExt, Encode, Read};
use commonware_cryptography::Hasher;
use commonware_storage::merkle::Location;
use commonware_storage::{
    merkle::Graftable,
    qmdb::{any::value::ValueEncoding, immutable, operation::Key as QmdbKey},
};
use connectrpc::client::{ClientConfig, ClientTransport};
use exoware_sdk::proto::PreferZstdHttpClient;
use http_body::Body;

use super::rpc::OperationLogSubscription;
use crate::proof::VerifiedOperationRange;
use crate::service::proto::qmdb::v1::{GetOperationRangeRequest, SubscribeRequest};
use crate::QmdbError;

use super::rpc::OperationLogClient;

/// Verifying client for an immutable-QMDB endpoint: the operation log.
pub struct Immutable<T, F, H, K, V, E>
where
    F: Graftable,
    H: Hasher,
    K: QmdbKey,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    immutable::Operation<F, K, E>: Encode + Read,
{
    operation_log: OperationLogClient<T, F, H, immutable::Operation<F, K, E>>,
}

impl<F, H, K, V, E> Immutable<PreferZstdHttpClient, F, H, K, V, E>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    immutable::Operation<F, K, E>: Decode + Encode + Read,
{
    pub fn plaintext(base: &str, op_cfg: <immutable::Operation<F, K, E> as Read>::Cfg) -> Self {
        Self::new(
            PreferZstdHttpClient::plaintext(),
            ClientConfig::new(base.parse().expect("qmdb uri")),
            op_cfg,
        )
    }
}

impl<T, F, H, K, V, E> Immutable<T, F, H, K, V, E>
where
    T: ClientTransport,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    immutable::Operation<F, K, E>: Decode + Encode + Read,
{
    pub fn new(
        transport: T,
        config: ClientConfig,
        op_cfg: <immutable::Operation<F, K, E> as Read>::Cfg,
    ) -> Self {
        Self {
            operation_log: OperationLogClient::new(transport, config, op_cfg),
        }
    }

    /// Verified contiguous operations `[start_location, start_location + max_locations)`,
    /// capped at `tip`.
    pub async fn operation_range(
        &self,
        tip: Location<F>,
        start_location: Location<F>,
        max_locations: u32,
        min_sequence_number: Option<u64>,
        root: &H::Digest,
    ) -> Result<VerifiedOperationRange<H::Digest, immutable::Operation<F, K, E>, F>, QmdbError>
    {
        self.operation_log
            .get_operation_range(
                GetOperationRangeRequest {
                    tip: tip.as_u64(),
                    start_location: start_location.as_u64(),
                    max_locations,
                    min_sequence_number,
                    ..Default::default()
                },
                root,
            )
            .await
    }

    /// Subscribe to proof-carrying batches of the operation log.
    pub async fn subscribe(
        &self,
        request: SubscribeRequest,
    ) -> Result<
        OperationLogSubscription<T::ResponseBody, F, H, immutable::Operation<F, K, E>>,
        QmdbError,
    > {
        self.operation_log.subscribe(request).await
    }
}
