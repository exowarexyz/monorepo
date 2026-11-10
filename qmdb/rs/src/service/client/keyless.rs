//! Verifying client for keyless QMDB.

use super::rpc::{OperationLogClient, OperationLogSubscription};
use crate::{
    proof::{VerifiedOperationRange, VerifiedOperations},
    service::proto::qmdb::v1::{GetOperationRangeRequest, GetOperationsRequest, SubscribeRequest},
    QmdbError,
};
use bytes::Bytes;
use commonware_codec::{Decode, DecodeExt, Encode, Read};
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::{Graftable, Location},
    qmdb::{
        keyless,
        value::{ValueEncoding, VariableEncoding},
    },
};
use connectrpc::client::{ClientConfig, ClientTransport};
use exoware_sdk::proto::PreferZstdHttpClient;
use http_body::Body;
use std::fmt::Display;

/// Verifying client for a keyless-QMDB endpoint: the operation log.
pub struct Keyless<
    T,
    F: Graftable,
    H: Hasher,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> where
    keyless::Operation<F, E>: Encode + Read,
{
    operation_log: OperationLogClient<T, F, H, keyless::Operation<F, E>>,
}

impl<F, H, V, E> Keyless<PreferZstdHttpClient, F, H, V, E>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    keyless::Operation<F, E>: Decode + Encode + Read,
{
    /// Client for the endpoint at `base` over plaintext HTTP.
    ///
    /// # Panics
    ///
    /// Panics if `base` is not a valid URI.
    pub fn plaintext(base: &str, op_cfg: <keyless::Operation<F, E> as Read>::Cfg) -> Self {
        Self::new(
            PreferZstdHttpClient::plaintext(),
            ClientConfig::new(base.parse().expect("qmdb uri")),
            op_cfg,
        )
    }
}

impl<T, F, H, V, E> Keyless<T, F, H, V, E>
where
    T: ClientTransport,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    keyless::Operation<F, E>: Decode + Encode + Read,
{
    pub fn new(
        transport: T,
        config: ClientConfig,
        op_cfg: <keyless::Operation<F, E> as Read>::Cfg,
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
        expected_root: &H::Digest,
    ) -> Result<VerifiedOperationRange<H::Digest, keyless::Operation<F, E>, F>, QmdbError> {
        self.operation_log
            .operation_range(
                GetOperationRangeRequest {
                    tip: tip.as_u64(),
                    start_location: start_location.as_u64(),
                    max_locations,
                    min_sequence_number,
                    ..Default::default()
                },
                expected_root,
            )
            .await
    }

    /// Verified operations at `locations` of `tip`, in request order.
    pub async fn operations(
        &self,
        tip: Location<F>,
        locations: &[Location<F>],
        min_sequence_number: Option<u64>,
        expected_root: &H::Digest,
    ) -> Result<VerifiedOperations<H::Digest, keyless::Operation<F, E>, F>, QmdbError> {
        self.operation_log
            .operations(
                GetOperationsRequest {
                    tip: tip.as_u64(),
                    locations: locations.iter().map(|location| location.as_u64()).collect(),
                    min_sequence_number,
                    ..Default::default()
                },
                expected_root,
            )
            .await
    }

    /// Subscribe to proof-carrying batches of the operation log. `request` is passed
    /// through to the service unchanged.
    pub async fn subscribe(
        &self,
        request: SubscribeRequest,
    ) -> Result<OperationLogSubscription<T::ResponseBody, F, H, keyless::Operation<F, E>>, QmdbError>
    {
        self.operation_log.subscribe(request).await
    }
}
