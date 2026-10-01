//! `qmdb.v1.OrderedKeyRangeService`: current-state proofs for key ranges.

use std::future::Future;
use std::sync::Arc;

use commonware_codec::{Codec, Encode, Read};
use commonware_storage::{
    merkle::{Graftable, Location},
    qmdb::{
        any::{ordered, value::ValueEncoding},
        current::ordered::ExclusionProof,
        operation::Key as QmdbKey,
    },
};
use connectrpc::{PreEncoded, RequestContext as Context, ServiceRequest};

use crate::proof::RawKeyRangeProof;
use crate::service::proto::qmdb::v1::{GetRangeRequest, GetRangeResponse, OrderedKeyRangeService};
use crate::QmdbError;

use super::key_lookup::decode_key;
use super::{encode, qmdb_error_to_connect};

/// Read capabilities needed by [`KeyRangeServer`].
pub(crate) trait KeyRangeReader<const N: usize>: Send + Sync + 'static {
    type Family: Graftable;
    type Digest: commonware_cryptography::Digest;
    type Key: QmdbKey + Codec + Send + Sync + 'static;
    type Value: Codec + Clone + Send + Sync;
    type Encoding: ValueEncoding<Value = Self::Value>;

    fn key_range_proof(
        &self,
        tip: Location<Self::Family>,
        start_key: Self::Key,
        end_key: Option<Self::Key>,
        limit: u32,
        min_sequence_number: Option<u64>,
    ) -> impl Future<
        Output = Result<
            RawKeyRangeProof<Self::Digest, Self::Key, Self::Value, N, Self::Family, Self::Encoding>,
            QmdbError,
        >,
    > + Send;
}

/// `OrderedKeyRangeService` handler over any [`KeyRangeReader`].
pub(crate) struct KeyRangeServer<R: KeyRangeReader<N>, const N: usize> {
    reader: Arc<R>,
    key_cfg: Arc<<R::Key as Read>::Cfg>,
}

impl<R: KeyRangeReader<N>, const N: usize> Clone for KeyRangeServer<R, N> {
    fn clone(&self) -> Self {
        Self {
            reader: self.reader.clone(),
            key_cfg: self.key_cfg.clone(),
        }
    }
}

impl<R: KeyRangeReader<N>, const N: usize> KeyRangeServer<R, N> {
    pub(crate) fn new(reader: Arc<R>, key_cfg: <R::Key as Read>::Cfg) -> Self {
        Self {
            reader,
            key_cfg: Arc::new(key_cfg),
        }
    }
}

impl<R: KeyRangeReader<N>, const N: usize> OrderedKeyRangeService for KeyRangeServer<R, N>
where
    ordered::Operation<R::Family, R::Key, R::Encoding>: Encode,
    ExclusionProof<R::Family, R::Key, R::Encoding, R::Digest, N>: Encode,
{
    fn get_range(
        &self,
        _ctx: Context,
        request: ServiceRequest<'_, GetRangeRequest>,
    ) -> impl Future<Output = connectrpc::ServiceResult<PreEncoded<GetRangeResponse>>> + Send {
        let reader = self.reader.clone();
        let key_cfg = self.key_cfg.clone();
        async move {
            let start_key = decode_key::<R::Key>(request.start_key, &key_cfg)?;
            let end_key = request
                .end_key
                .map(|key| decode_key::<R::Key>(key, &key_cfg))
                .transpose()?;
            let proof = reader
                .key_range_proof(
                    Location::new(request.tip),
                    start_key,
                    end_key,
                    request.limit,
                    request.min_sequence_number,
                )
                .await
                .map_err(qmdb_error_to_connect)?;
            connectrpc::Response::ok(encode::get_range_response(&proof))
        }
    }
}
