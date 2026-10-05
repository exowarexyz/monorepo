//! `qmdb.v1.KeyLookupService`: current-state proofs for explicit keys.

use std::future::Future;
use std::sync::Arc;

use commonware_codec::{Copying, Decode, Encode, Read};
use commonware_storage::merkle::{Graftable, Location};
use connectrpc::{ConnectError, PreEncoded, RequestContext as Context, ServiceRequest};

use crate::proof::RawKeyValueProof;
use crate::service::proto::qmdb::v1::{
    GetManyRequest, GetManyResponse, GetRequest, GetResponse, KeyLookupService,
};
use crate::QmdbError;

pub(crate) use super::encode::LookupResult;
use super::{encode, qmdb_error_to_connect};

/// Read capabilities needed by [`KeyLookupServer`].
pub(crate) trait KeyLookupReader<const N: usize>: Send + Sync + 'static {
    type Family: Graftable;
    type Digest: commonware_cryptography::Digest;
    type Key: Read + Send + Sync + 'static;
    type Operation: Encode;
    /// One `GetMany` result: ordered QMDB proves hits and misses, unordered
    /// QMDB proves hits only.
    type Lookup: LookupResult + Send;

    fn key_value_proof(
        &self,
        tip: Location<Self::Family>,
        key: &Self::Key,
        min_sequence_number: Option<u64>,
    ) -> impl Future<
        Output = Result<
            RawKeyValueProof<Self::Digest, Self::Operation, N, Self::Family>,
            QmdbError,
        >,
    > + Send;

    fn key_lookup_proofs(
        &self,
        tip: Location<Self::Family>,
        keys: &[Self::Key],
        min_sequence_number: Option<u64>,
    ) -> impl Future<Output = Result<Vec<Self::Lookup>, QmdbError>> + Send;
}

/// `KeyLookupService` handler over any [`KeyLookupReader`].
pub(crate) struct KeyLookupServer<R: KeyLookupReader<N>, const N: usize> {
    reader: Arc<R>,
    key_cfg: Arc<<R::Key as Read>::Cfg>,
}

impl<R: KeyLookupReader<N>, const N: usize> Clone for KeyLookupServer<R, N> {
    fn clone(&self) -> Self {
        Self {
            reader: self.reader.clone(),
            key_cfg: self.key_cfg.clone(),
        }
    }
}

impl<R: KeyLookupReader<N>, const N: usize> KeyLookupServer<R, N> {
    pub(crate) fn new(reader: Arc<R>, key_cfg: <R::Key as Read>::Cfg) -> Self {
        Self {
            reader,
            key_cfg: Arc::new(key_cfg),
        }
    }
}

pub(super) fn decode_key<K: Read>(bytes: &[u8], cfg: &K::Cfg) -> Result<K, ConnectError> {
    K::decode_cfg(Copying(bytes), cfg)
        .map_err(|error| ConnectError::invalid_argument(format!("invalid QMDB key: {error}")))
}

impl<R: KeyLookupReader<N>, const N: usize> KeyLookupService for KeyLookupServer<R, N> {
    fn get(
        &self,
        _ctx: Context,
        request: ServiceRequest<'_, GetRequest>,
    ) -> impl Future<Output = connectrpc::ServiceResult<PreEncoded<GetResponse>>> + Send {
        let reader = self.reader.clone();
        let key_cfg = self.key_cfg.clone();
        async move {
            let key = decode_key::<R::Key>(request.key, &key_cfg)?;
            let proof = reader
                .key_value_proof(
                    Location::new(request.tip),
                    &key,
                    request.min_sequence_number,
                )
                .await
                .map_err(qmdb_error_to_connect)?;
            connectrpc::Response::ok(encode::get_response(&proof))
        }
    }

    fn get_many(
        &self,
        _ctx: Context,
        request: ServiceRequest<'_, GetManyRequest>,
    ) -> impl Future<Output = connectrpc::ServiceResult<PreEncoded<GetManyResponse>>> + Send {
        let reader = self.reader.clone();
        let key_cfg = self.key_cfg.clone();
        async move {
            let keys = request
                .keys
                .iter()
                .map(|key| decode_key::<R::Key>(key, &key_cfg))
                .collect::<Result<Vec<_>, _>>()?;
            let proofs = reader
                .key_lookup_proofs(
                    Location::new(request.tip),
                    &keys,
                    request.min_sequence_number,
                )
                .await
                .map_err(qmdb_error_to_connect)?;
            connectrpc::Response::ok(encode::get_many_response(&proofs))
        }
    }
}
