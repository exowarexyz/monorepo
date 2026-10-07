//! Verifying client for `qmdb.v1.OrderedKeyRangeService`.

use std::fmt::Display;
use std::marker::PhantomData;
use std::sync::Arc;

use bytes::Bytes;
use commonware_codec::{Copying, Decode, DecodeExt, Encode, Read};
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::Graftable,
    qmdb::{
        any::{
            ordered,
            value::{ValueEncoding, VariableEncoding},
        },
        current::ordered::proof::constant::ExclusionProof,
        operation::Key as QmdbKey,
    },
};
use connectrpc::client::{ClientConfig, ClientTransport};
use http_body::Body;

use crate::proof::VerifiedKeyRange;
use crate::request::validate_key_range;
use crate::service::proto::qmdb::v1::{
    GetRangeRequest, GetRangeResponse, OrderedKeyRangeServiceClient,
};
use crate::QmdbError;

use super::connect_error_to_qmdb;
use super::verify::{verify_key_exclusion_from_proto, verify_key_value_from_proto};

/// Client for `qmdb.v1.OrderedKeyRangeService`.
pub struct KeyRangeClient<
    T,
    F: Graftable,
    H: Hasher,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> where
    ordered::Operation<F, K, E>: Read,
    ordered::Update<K, E>: Read,
{
    rpc: OrderedKeyRangeServiceClient<T>,
    op_cfg: Arc<<ordered::Operation<F, K, E> as Read>::Cfg>,
    update_cfg: Arc<<ordered::Update<K, E> as Read>::Cfg>,
    key_cfg: Arc<K::Cfg>,
    value_cfg: Arc<V::Cfg>,
    _marker: PhantomData<(F, H, K, V, E)>,
}

impl<T, F, H, K, V, const N: usize, E> Clone for KeyRangeClient<T, F, H, K, V, N, E>
where
    T: Clone,
    F: Graftable,
    H: Hasher,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    ordered::Operation<F, K, E>: Read,
    ordered::Update<K, E>: Read,
{
    fn clone(&self) -> Self {
        Self {
            rpc: self.rpc.clone(),
            op_cfg: self.op_cfg.clone(),
            update_cfg: self.update_cfg.clone(),
            key_cfg: self.key_cfg.clone(),
            value_cfg: self.value_cfg.clone(),
            _marker: PhantomData,
        }
    }
}

impl<T, F, H, K, V, const N: usize, E> KeyRangeClient<T, F, H, K, V, N, E>
where
    T: ClientTransport,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    ordered::Operation<F, K, E>: Decode + Encode + Read,
    ordered::Update<K, E>: Read,
    ExclusionProof<F, K, E, H::Digest, N>:
        Read<Cfg = (usize, <ordered::Update<K, E> as Read>::Cfg, V::Cfg)>,
{
    pub fn new(
        transport: T,
        config: ClientConfig,
        op_cfg: <ordered::Operation<F, K, E> as Read>::Cfg,
        update_cfg: <ordered::Update<K, E> as Read>::Cfg,
        key_cfg: K::Cfg,
        value_cfg: V::Cfg,
    ) -> Self {
        Self::from_service_client(
            OrderedKeyRangeServiceClient::new(transport, config),
            op_cfg,
            update_cfg,
            key_cfg,
            value_cfg,
        )
    }

    pub fn from_service_client(
        rpc: OrderedKeyRangeServiceClient<T>,
        op_cfg: <ordered::Operation<F, K, E> as Read>::Cfg,
        update_cfg: <ordered::Update<K, E> as Read>::Cfg,
        key_cfg: K::Cfg,
        value_cfg: V::Cfg,
    ) -> Self {
        Self {
            rpc,
            op_cfg: Arc::new(op_cfg),
            update_cfg: Arc::new(update_cfg),
            key_cfg: Arc::new(key_cfg),
            value_cfg: Arc::new(value_cfg),
            _marker: PhantomData,
        }
    }

    pub async fn get_range(
        &self,
        request: GetRangeRequest,
        expected_root: &H::Digest,
    ) -> Result<VerifiedKeyRange<H::Digest, K, V, F, E>, QmdbError> {
        let start_key = request.start_key.clone();
        let end_key = request.end_key.clone();
        let limit = request.limit;
        let response = self
            .rpc
            .get_range(request)
            .await
            .map_err(connect_error_to_qmdb)?
            .into_view()
            .to_owned_message();
        verify_get_range_from_proto::<F, H, K, V, N, E>(
            &response,
            expected_root,
            start_key.as_ref(),
            end_key.as_deref(),
            limit,
            self.op_cfg.as_ref(),
            self.update_cfg.as_ref(),
            self.key_cfg.as_ref(),
            self.value_cfg.as_ref(),
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_get_range_from_proto<F, H, K, V, const N: usize, E>(
    response: &GetRangeResponse,
    root: &H::Digest,
    start_key: &[u8],
    end_key: Option<&[u8]>,
    limit: u32,
    op_cfg: &<ordered::Operation<F, K, E> as Read>::Cfg,
    update_cfg: &<ordered::Update<K, E> as Read>::Cfg,
    key_cfg: &K::Cfg,
    value_cfg: &V::Cfg,
) -> Result<VerifiedKeyRange<H::Digest, K, V, F, E>, QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    ordered::Operation<F, K, E>: Decode + Encode + Read,
    ordered::Update<K, E>: Read,
    ExclusionProof<F, K, E, H::Digest, N>:
        Read<Cfg = (usize, <ordered::Update<K, E> as Read>::Cfg, V::Cfg)>,
{
    let encoded_start_key = start_key;
    let encoded_end_key = end_key;
    let start_key = K::decode_cfg(Copying(encoded_start_key), key_cfg).map_err(|err| {
        QmdbError::CorruptData(format!("failed to decode range start key: {err}"))
    })?;
    let end_key = encoded_end_key
        .map(|key| {
            K::decode_cfg(Copying(key), key_cfg).map_err(|err| {
                QmdbError::CorruptData(format!("failed to decode range end key: {err}"))
            })
        })
        .transpose()?;
    let mut entries = Vec::with_capacity(response.entries.len());
    for proof in &response.entries {
        entries.push(verify_key_value_from_proto::<
            F,
            H,
            ordered::Operation<F, K, E>,
            N,
        >(proof, root, op_cfg)?);
    }

    let keys = entries
        .iter()
        .map(|entry| match &entry.operation {
            ordered::Operation::Update(update) => (&update.key, &update.next_key),
            _ => unreachable!("range entries were checked as updates"),
        })
        .collect::<Vec<_>>();
    let start_successor = if keys.first().is_none_or(|(key, _)| **key != start_key) {
        let proof = response.start_proof.as_option().ok_or_else(|| {
            QmdbError::CorruptData("key range missing start boundary proof".into())
        })?;
        verify_key_exclusion_from_proto::<F, H, K, V, N, E>(
            proof,
            encoded_start_key,
            root,
            update_cfg,
            key_cfg,
            value_cfg,
        )?
    } else {
        None
    };
    let next_start_key = validate_key_range(
        &start_key,
        end_key.as_ref(),
        limit,
        &keys,
        start_successor.as_ref(),
    )
    .map_err(QmdbError::RangeMismatch)?
    .cloned();

    Ok(VerifiedKeyRange {
        entries,
        next_start_key,
    })
}
