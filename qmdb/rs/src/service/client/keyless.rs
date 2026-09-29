//! Verifying client for keyless QMDB.

use std::fmt::Display;

use bytes::Bytes;
use commonware_codec::{Decode, DecodeExt, Encode, Read};
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::Graftable,
    qmdb::{any::value::ValueEncoding, keyless},
};
use connectrpc::client::{ClientConfig, ClientTransport};
use exoware_sdk::proto::PreferZstdHttpClient;
use http_body::Body;

use super::rpc::OperationLogClient;

/// Verifying client for a keyless-QMDB endpoint: the operation log.
pub struct Keyless<T, F, H, V, E>
where
    F: Graftable,
    H: Hasher,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    keyless::Operation<F, E>: Encode + Read,
{
    pub operation_log: OperationLogClient<T, F, H, keyless::Operation<F, E>>,
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
}
