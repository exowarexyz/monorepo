use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::marker::PhantomData;
use std::num::NonZeroU64;
use std::sync::Arc;

use crate::proto::qmdb::v1::{
    current_key_lookup_result, CurrentKeyExclusionProof as ProtoCurrentKeyExclusionProof,
    CurrentKeyValueProof as ProtoCurrentKeyValueProof,
    CurrentOperationRangeProof as ProtoCurrentOperationRangeProof, CurrentOperationServiceClient,
    GetCurrentOperationRangeRequest, GetManyRequest, GetOperationRangeRequest, GetRangeRequest,
    GetRangeResponse, GetRequest, HistoricalMultiProof, HistoricalOperationRangeProof,
    KeyLookupServiceClient, OperationLogServiceClient, OrderedKeyRangeServiceClient,
    SubscribeRequest, SubscribeResponseView,
};
use bytes::Bytes;
use commonware_codec::{Decode, DecodeExt, Encode, Read};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::{
    merkle::{Family, Graftable, Location, Proof},
    qmdb::{
        any::{
            ordered, sync as any_sync, unordered,
            value::{ValueEncoding, VariableEncoding},
        },
        current::ordered::{db::KeyValueProof, ExclusionProof},
        current::proof::{OpsRootWitness, RangeProof},
        current::sync as current_sync,
        current::unordered::db::KeyValueProof as UnorderedKeyValueProof,
        operation::Key as QmdbKey,
        sync::resolver::{FetchResult, Resolver},
        verify::{verify_multi_proof, verify_proof_and_pinned_nodes},
    },
};
use commonware_utils::channel::oneshot;
use connectrpc::client::{ClientConfig, ClientTransport, ServerStream};
use connectrpc::ConnectError;
use exoware_sdk::proto::PreferZstdHttpClient;
use exoware_sdk::ClientError;
use http_body::Body;

use crate::proof::{
    verify_ordered_exclusion_proof, verify_ordered_key_value_proof, VerifiedKeyLookup,
    VerifiedKeyRange, VerifiedKeyValue, VerifiedUnorderedKeyValue,
};
use crate::QmdbError;

#[derive(Clone)]
pub struct OrderedConnectClient<
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
    rpc: KeyLookupServiceClient<T>,
    range_rpc: OrderedKeyRangeServiceClient<T>,
    op_cfg: Arc<<ordered::Operation<F, K, E> as Read>::Cfg>,
    update_cfg: Arc<<ordered::Update<K, E> as Read>::Cfg>,
    key_cfg: Arc<K::Cfg>,
    value_cfg: Arc<V::Cfg>,
    _marker: PhantomData<(F, H, K, V, E)>,
}

impl<F, H, K, V, const N: usize, E> OrderedConnectClient<PreferZstdHttpClient, F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    K::Cfg: Clone,
    <ordered::Update<K, E> as Read>::Cfg: Clone,
    V::Cfg: Clone,
    ordered::Operation<F, K, E>: Decode + Encode + Read,
    ordered::Update<K, E>: Read,
    ExclusionProof<F, K, E, H::Digest, N>:
        Read<Cfg = (usize, <ordered::Update<K, E> as Read>::Cfg, V::Cfg)>,
{
    pub fn plaintext(
        base: &str,
        op_cfg: <ordered::Operation<F, K, E> as Read>::Cfg,
        update_cfg: <ordered::Update<K, E> as Read>::Cfg,
        key_cfg: K::Cfg,
        value_cfg: V::Cfg,
    ) -> Self {
        Self::new(
            PreferZstdHttpClient::plaintext(),
            ClientConfig::new(base.parse().expect("qmdb uri")),
            op_cfg,
            update_cfg,
            key_cfg,
            value_cfg,
        )
    }
}

impl<T, F, H, K, V, const N: usize, E> OrderedConnectClient<T, F, H, K, V, N, E>
where
    T: ClientTransport + Clone,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    K::Cfg: Clone,
    <ordered::Update<K, E> as Read>::Cfg: Clone,
    V::Cfg: Clone,
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
        Self::from_service_clients(
            KeyLookupServiceClient::new(transport.clone(), config.clone()),
            OrderedKeyRangeServiceClient::new(transport, config),
            op_cfg,
            update_cfg,
            key_cfg,
            value_cfg,
        )
    }

    pub fn from_service_clients(
        rpc: KeyLookupServiceClient<T>,
        range_rpc: OrderedKeyRangeServiceClient<T>,
        op_cfg: <ordered::Operation<F, K, E> as Read>::Cfg,
        update_cfg: <ordered::Update<K, E> as Read>::Cfg,
        key_cfg: K::Cfg,
        value_cfg: V::Cfg,
    ) -> Self {
        Self {
            rpc,
            range_rpc,
            op_cfg: Arc::new(op_cfg),
            update_cfg: Arc::new(update_cfg),
            key_cfg: Arc::new(key_cfg),
            value_cfg: Arc::new(value_cfg),
            _marker: PhantomData,
        }
    }

    pub async fn get(
        &self,
        request: GetRequest,
        expected_root: &H::Digest,
    ) -> Result<VerifiedKeyValue<H::Digest, K, V, F, E>, QmdbError> {
        let requested_key = request.key.clone();
        let decoded_requested_key = K::decode_cfg(requested_key.as_slice(), self.key_cfg.as_ref())
            .map_err(|err| {
                QmdbError::CorruptData(format!("failed to decode requested QMDB key: {err}"))
            })?;
        let response = self
            .rpc
            .get(request)
            .await
            .map_err(connect_error_to_qmdb)?
            .into_view()
            .to_owned_message();
        let proof = response
            .proof
            .as_option()
            .ok_or_else(|| QmdbError::CorruptData("qmdb get response missing proof".to_string()))?;
        let verified = verify_key_value_from_proto::<F, H, K, V, N, E>(
            proof,
            expected_root,
            self.op_cfg.as_ref(),
            self.key_cfg.as_ref(),
        )?;
        let ordered::Operation::Update(update) = &verified.operation else {
            return Err(QmdbError::CorruptData(
                "qmdb get proof did not verify an update".to_string(),
            ));
        };
        if update.key != decoded_requested_key {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentKeyValue,
            });
        }
        Ok(verified)
    }

    pub async fn get_many(
        &self,
        request: GetManyRequest,
        expected_root: &H::Digest,
    ) -> Result<Vec<VerifiedKeyLookup<H::Digest, K, V, F, E>>, QmdbError> {
        let requested_keys = request.keys.clone();
        let mut requested = BTreeSet::<&[u8]>::new();
        for key in &requested_keys {
            if !requested.insert(key.as_slice()) {
                return Err(QmdbError::DuplicateRequestedKey { key: key.clone() });
            }
        }
        let response = self
            .rpc
            .get_many(request)
            .await
            .map_err(connect_error_to_qmdb)?
            .into_view()
            .to_owned_message();
        if response.results.len() != requested_keys.len() {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentKeyValue,
            });
        }
        response
            .results
            .iter()
            .zip(requested_keys.iter())
            .map(|(result, requested_key)| {
                if result.key.as_slice() != requested_key.as_slice() {
                    return Err(QmdbError::ProofVerification {
                        kind: crate::ProofKind::CurrentKeyValue,
                    });
                }
                let decoded_requested_key = K::decode_cfg(
                    requested_key.as_slice(),
                    self.key_cfg.as_ref(),
                )
                .map_err(|err| {
                    QmdbError::CorruptData(format!("failed to decode requested QMDB key: {err}"))
                })?;
                match result.result.as_ref() {
                    Some(current_key_lookup_result::Result::Hit(proof)) => {
                        let verified = verify_key_value_from_proto::<F, H, K, V, N, E>(
                            proof,
                            expected_root,
                            self.op_cfg.as_ref(),
                            self.key_cfg.as_ref(),
                        )?;
                        let ordered::Operation::Update(update) = &verified.operation else {
                            return Err(QmdbError::CorruptData(
                                "qmdb get_many hit proof did not verify an update".to_string(),
                            ));
                        };
                        if update.key != decoded_requested_key {
                            return Err(QmdbError::ProofVerification {
                                kind: crate::ProofKind::CurrentKeyValue,
                            });
                        }
                        Ok(VerifiedKeyLookup::Hit(verified))
                    }
                    Some(current_key_lookup_result::Result::Miss(proof)) => {
                        verify_key_exclusion_from_proto::<F, H, K, V, N, E>(
                            proof,
                            requested_key.as_slice(),
                            expected_root,
                            self.update_cfg.as_ref(),
                            self.key_cfg.as_ref(),
                            self.value_cfg.as_ref(),
                        )?;
                        Ok(VerifiedKeyLookup::Miss {
                            key: requested_key.clone(),
                        })
                    }
                    None => Err(QmdbError::CorruptData(
                        "qmdb get_many result missing hit/miss proof".to_string(),
                    )),
                }
            })
            .collect()
    }

    pub async fn get_range(
        &self,
        request: GetRangeRequest,
        expected_root: &H::Digest,
    ) -> Result<VerifiedKeyRange<H::Digest, K, V, F, E>, QmdbError> {
        let start_key = request.start_key.clone();
        let end_key = request.end_key.clone();
        let response = self
            .range_rpc
            .get_range(request)
            .await
            .map_err(connect_error_to_qmdb)?
            .into_view()
            .to_owned_message();
        verify_get_range_from_proto::<F, H, K, V, N, E>(
            &response,
            expected_root,
            start_key.as_slice(),
            end_key.as_deref(),
            self.op_cfg.as_ref(),
            self.update_cfg.as_ref(),
            self.key_cfg.as_ref(),
            self.value_cfg.as_ref(),
        )
    }
}

#[derive(Clone)]
pub struct UnorderedConnectClient<
    T,
    F: Graftable,
    H: Hasher,
    K: commonware_utils::Array + QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
    E: ValueEncoding<Value = V> = VariableEncoding<V>,
> where
    unordered::Operation<F, K, E>: Read,
{
    rpc: KeyLookupServiceClient<T>,
    op_cfg: Arc<<unordered::Operation<F, K, E> as Read>::Cfg>,
    _marker: PhantomData<(F, H, K, V, E)>,
}

impl<F, H, K, V, const N: usize, E> UnorderedConnectClient<PreferZstdHttpClient, F, H, K, V, N, E>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: commonware_utils::Array + QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Decode + Encode + Read,
{
    pub fn plaintext(base: &str, op_cfg: <unordered::Operation<F, K, E> as Read>::Cfg) -> Self {
        Self::new(
            PreferZstdHttpClient::plaintext(),
            ClientConfig::new(base.parse().expect("qmdb uri")),
            op_cfg,
        )
    }
}

impl<T, F, H, K, V, const N: usize, E> UnorderedConnectClient<T, F, H, K, V, N, E>
where
    T: ClientTransport + Clone,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: commonware_utils::Array + QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Decode + Encode + Read,
{
    pub fn new(
        transport: T,
        config: ClientConfig,
        op_cfg: <unordered::Operation<F, K, E> as Read>::Cfg,
    ) -> Self {
        Self::from_service_client(KeyLookupServiceClient::new(transport, config), op_cfg)
    }

    pub fn from_service_client(
        rpc: KeyLookupServiceClient<T>,
        op_cfg: <unordered::Operation<F, K, E> as Read>::Cfg,
    ) -> Self {
        Self {
            rpc,
            op_cfg: Arc::new(op_cfg),
            _marker: PhantomData,
        }
    }

    pub async fn get(
        &self,
        request: GetRequest,
        expected_root: &H::Digest,
    ) -> Result<VerifiedUnorderedKeyValue<H::Digest, K, V, F, E>, QmdbError> {
        let requested_key = request.key.clone();
        let response = self
            .rpc
            .get(request)
            .await
            .map_err(connect_error_to_qmdb)?
            .into_view()
            .to_owned_message();
        let proof = response
            .proof
            .as_option()
            .ok_or_else(|| QmdbError::CorruptData("qmdb get response missing proof".to_string()))?;
        verify_unordered_key_value_from_proto::<F, H, K, V, N, E>(
            proof,
            requested_key.as_slice(),
            expected_root,
            self.op_cfg.as_ref(),
        )
    }

    pub async fn get_many(
        &self,
        request: GetManyRequest,
        expected_root: &H::Digest,
    ) -> Result<Vec<VerifiedUnorderedKeyValue<H::Digest, K, V, F, E>>, QmdbError> {
        let requested_keys = request.keys.clone();
        let response = self
            .rpc
            .get_many(request)
            .await
            .map_err(connect_error_to_qmdb)?
            .into_view()
            .to_owned_message();
        let mut requested = BTreeMap::<&[u8], usize>::new();
        for (index, key) in requested_keys.iter().enumerate() {
            if requested.insert(key.as_slice(), index).is_some() {
                return Err(QmdbError::DuplicateRequestedKey { key: key.clone() });
            }
        }
        let mut returned = BTreeSet::<&[u8]>::new();
        let mut last_index = None;
        response
            .results
            .iter()
            .map(|result| {
                let Some(&request_index) = requested.get(result.key.as_slice()) else {
                    return Err(QmdbError::ProofVerification {
                        kind: crate::ProofKind::CurrentKeyValue,
                    });
                };
                if !returned.insert(result.key.as_slice()) {
                    return Err(QmdbError::ProofVerification {
                        kind: crate::ProofKind::CurrentKeyValue,
                    });
                }
                if last_index.is_some_and(|last| request_index <= last) {
                    return Err(QmdbError::ProofVerification {
                        kind: crate::ProofKind::CurrentKeyValue,
                    });
                }
                last_index = Some(request_index);
                match result.result.as_ref() {
                    Some(current_key_lookup_result::Result::Hit(proof)) => {
                        verify_unordered_key_value_from_proto::<F, H, K, V, N, E>(
                            proof,
                            result.key.as_slice(),
                            expected_root,
                            self.op_cfg.as_ref(),
                        )
                    }
                    Some(current_key_lookup_result::Result::Miss(_)) => {
                        Err(QmdbError::CorruptData(
                            "unordered get_many response must not include miss proofs".to_string(),
                        ))
                    }
                    None => Err(QmdbError::CorruptData(
                        "qmdb get_many result missing hit proof".to_string(),
                    )),
                }
            })
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct OperationLogSubscribeProof<D: Digest, Op, F: Family> {
    pub resume_sequence_number: u64,
    pub tip: Location<F>,
    pub root: D,
    pub operations: Vec<(Location<F>, Op)>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OperationLogRangeProof<D: Digest, Op, F: Family> {
    pub tip: Location<F>,
    pub root: D,
    pub start_location: Location<F>,
    pub operations: Vec<(Location<F>, Op)>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CurrentOperationRangeProof<D: Digest, Op, const N: usize, F: Graftable> {
    pub tip: Location<F>,
    pub root: D,
    pub start_location: Location<F>,
    pub operations: Vec<(Location<F>, Op)>,
    pub chunks: Vec<[u8; N]>,
}

/// Store-backed resolver for Commonware QMDB sync over Exoware QMDB's
/// operation-log API.
///
/// This resolver covers the operation-log portion shared by ordered,
/// unordered, immutable, and keyless QMDBs.
pub struct OperationLogSyncResolver<T, F: Graftable, H: Hasher, Op: Encode + Read> {
    rpc: OperationLogServiceClient<T>,
    op_cfg: Arc<Op::Cfg>,
    _marker: PhantomData<(F, H, Op)>,
}

impl<T, F, H, Op> Clone for OperationLogSyncResolver<T, F, H, Op>
where
    F: Graftable,
    H: Hasher,
    Op: Encode + Read,
    OperationLogServiceClient<T>: Clone,
{
    fn clone(&self) -> Self {
        Self {
            rpc: self.rpc.clone(),
            op_cfg: Arc::clone(&self.op_cfg),
            _marker: PhantomData,
        }
    }
}

impl<F, H, Op> OperationLogSyncResolver<PreferZstdHttpClient, F, H, Op>
where
    F: Graftable + Send + Sync + 'static,
    H: Hasher + Send + Sync + 'static,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read + Send + Sync + 'static,
{
    pub fn plaintext(base: &str, op_cfg: Op::Cfg) -> Self {
        Self::new(
            PreferZstdHttpClient::plaintext(),
            ClientConfig::new(base.parse().expect("qmdb uri")),
            op_cfg,
        )
    }
}

impl<T, F, H, Op> OperationLogSyncResolver<T, F, H, Op>
where
    T: ClientTransport + Clone + Send + Sync + 'static,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    F: Graftable + Send + Sync + 'static,
    H: Hasher + Send + Sync + 'static,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read + Send + Sync + 'static,
{
    pub fn new(transport: T, config: ClientConfig, op_cfg: Op::Cfg) -> Self {
        Self::from_service_client(OperationLogServiceClient::new(transport, config), op_cfg)
    }

    pub fn from_service_client(rpc: OperationLogServiceClient<T>, op_cfg: Op::Cfg) -> Self {
        Self {
            rpc,
            op_cfg: Arc::new(op_cfg),
            _marker: PhantomData,
        }
    }

    pub async fn target(
        &self,
        op_count: Location<F>,
    ) -> Result<any_sync::Target<F, H::Digest>, QmdbError> {
        self.target_range(Location::new(0), op_count).await
    }

    pub async fn target_range(
        &self,
        start_loc: Location<F>,
        op_count: Location<F>,
    ) -> Result<any_sync::Target<F, H::Digest>, QmdbError> {
        if start_loc >= op_count {
            return Err(QmdbError::CorruptData(
                "sync target range must be non-empty".to_string(),
            ));
        }
        let proto = self
            .operation_range_proto(op_count, start_loc, NonZeroU64::MIN)
            .await?;
        let root = decode_digest::<H>(proto.ops_root.as_slice(), "operation sync root")?;
        Ok(any_sync::Target::new(
            root,
            commonware_utils::non_empty_range!(start_loc, op_count),
        ))
    }

    async fn operation_range_proto(
        &self,
        op_count: Location<F>,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> Result<HistoricalOperationRangeProof, QmdbError> {
        let count = op_count.as_u64();
        let Some(tip) = count.checked_sub(1) else {
            return Err(QmdbError::CorruptData(
                "cannot fetch sync operations for an empty target".to_string(),
            ));
        };
        let max_locations = u32::try_from(max_ops.get()).map_err(|err| {
            QmdbError::CorruptData(format!("sync fetch batch size exceeds API limit: {err}"))
        })?;
        let response = self
            .rpc
            .get_operation_range(GetOperationRangeRequest {
                tip,
                start_location: start_loc.as_u64(),
                max_locations,
                ..Default::default()
            })
            .await
            .map_err(connect_error_to_qmdb)?
            .into_view()
            .to_owned_message();
        response.proof.as_option().cloned().ok_or_else(|| {
            QmdbError::CorruptData("sync operation range response missing proof".to_string())
        })
    }

    fn fetch_result(
        &self,
        proto: HistoricalOperationRangeProof,
        _start_loc: Location<F>,
        include_pinned_nodes: bool,
    ) -> Result<FetchResult<F, Op, H::Digest>, QmdbError> {
        let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
        let proof = Proof::<F, H::Digest>::decode_cfg(proto.proof.as_slice(), &max_digests)
            .map_err(|err| {
                QmdbError::CorruptData(format!(
                    "failed to decode sync operation range proof: {err}"
                ))
            })?;
        let operations = proto
            .encoded_operations
            .iter()
            .map(|bytes| {
                Op::decode_cfg(bytes.as_slice(), self.op_cfg.as_ref()).map_err(|err| {
                    QmdbError::CorruptData(format!("failed to decode sync operation: {err}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let pinned_nodes = if include_pinned_nodes {
            Some(
                proto
                    .pinned_nodes
                    .iter()
                    .map(|bytes| decode_digest::<H>(bytes.as_slice(), "operation sync pinned node"))
                    .collect::<Result<Vec<_>, _>>()?,
            )
        } else {
            None
        };
        Ok(FetchResult {
            proof,
            operations,
            success_tx: oneshot::channel().0,
            pinned_nodes,
        })
    }
}

impl<T, F, H, Op> Resolver for OperationLogSyncResolver<T, F, H, Op>
where
    T: ClientTransport + Clone + Send + Sync + 'static,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    F: Graftable + Send + Sync + 'static,
    H: Hasher + Send + Sync + 'static,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read + Send + Sync + 'static,
{
    type Family = F;
    type Digest = H::Digest;
    type Op = Op;
    type Error = QmdbError;

    async fn get_operations(
        &self,
        op_count: Location<Self::Family>,
        start_loc: Location<Self::Family>,
        max_ops: NonZeroU64,
        include_pinned_nodes: bool,
        _cancel_rx: oneshot::Receiver<()>,
    ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
        let proto = self
            .operation_range_proto(op_count, start_loc, max_ops)
            .await?;
        self.fetch_result(proto, start_loc, include_pinned_nodes)
    }
}

/// Store-backed resolver for Commonware `current::sync` over Exoware QMDB's
/// operation-log API.
///
/// The resolver fetches operation-log batches using [`OperationLogSyncResolver`]
/// and builds `current::sync` targets by authenticating the operation root with
/// the current-root witness returned by Exoware's current operation-log API.
pub struct CurrentSyncResolver<T, F: Graftable, H: Hasher, Op: Encode + Read> {
    operation_log: OperationLogSyncResolver<T, F, H, Op>,
    current_root: H::Digest,
}

impl<T, F, H, Op> Clone for CurrentSyncResolver<T, F, H, Op>
where
    F: Graftable,
    H: Hasher,
    H::Digest: Clone,
    Op: Encode + Read,
    OperationLogSyncResolver<T, F, H, Op>: Clone,
{
    fn clone(&self) -> Self {
        Self {
            operation_log: self.operation_log.clone(),
            current_root: self.current_root,
        }
    }
}

impl<F, H, Op> CurrentSyncResolver<PreferZstdHttpClient, F, H, Op>
where
    F: Graftable + Send + Sync + 'static,
    H: Hasher + Send + Sync + 'static,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read + Send + Sync + 'static,
{
    pub fn plaintext(base: &str, current_root: H::Digest, op_cfg: Op::Cfg) -> Self {
        Self::new(
            PreferZstdHttpClient::plaintext(),
            ClientConfig::new(base.parse().expect("qmdb uri")),
            current_root,
            op_cfg,
        )
    }
}

impl<T, F, H, Op> CurrentSyncResolver<T, F, H, Op>
where
    T: ClientTransport + Clone + Send + Sync + 'static,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    F: Graftable + Send + Sync + 'static,
    H: Hasher + Send + Sync + 'static,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read + Send + Sync + 'static,
{
    pub fn new(
        transport: T,
        config: ClientConfig,
        current_root: H::Digest,
        op_cfg: Op::Cfg,
    ) -> Self {
        Self {
            operation_log: OperationLogSyncResolver::new(transport, config, op_cfg),
            current_root,
        }
    }

    pub fn from_operation_log(
        operation_log: OperationLogSyncResolver<T, F, H, Op>,
        current_root: H::Digest,
    ) -> Self {
        Self {
            operation_log,
            current_root,
        }
    }

    pub fn operation_log(&self) -> &OperationLogSyncResolver<T, F, H, Op> {
        &self.operation_log
    }

    pub async fn target(
        &self,
        op_count: Location<F>,
    ) -> Result<current_sync::Target<F, H::Digest>, QmdbError> {
        self.target_range(Location::new(0), op_count).await
    }

    pub async fn target_range(
        &self,
        start_loc: Location<F>,
        op_count: Location<F>,
    ) -> Result<current_sync::Target<F, H::Digest>, QmdbError> {
        if start_loc >= op_count {
            return Err(QmdbError::CorruptData(
                "sync target range must be non-empty".to_string(),
            ));
        }
        let proto = self
            .operation_log
            .operation_range_proto(op_count, start_loc, NonZeroU64::MIN)
            .await?;
        let ops_root = decode_digest::<H>(proto.ops_root.as_slice(), "current sync ops root")?;
        let witness = decode_ops_root_witness::<F, H>(proto.ops_root_witness.as_slice())?;
        Ok(current_sync::Target::new(
            self.current_root,
            ops_root,
            witness,
            commonware_utils::non_empty_range!(start_loc, op_count),
        ))
    }
}

impl<T, F, H, Op> Resolver for CurrentSyncResolver<T, F, H, Op>
where
    T: ClientTransport + Clone + Send + Sync + 'static,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    F: Graftable + Send + Sync + 'static,
    H: Hasher + Send + Sync + 'static,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read + Send + Sync + 'static,
{
    type Family = F;
    type Digest = H::Digest;
    type Op = Op;
    type Error = QmdbError;

    async fn get_operations(
        &self,
        op_count: Location<Self::Family>,
        start_loc: Location<Self::Family>,
        max_ops: NonZeroU64,
        include_pinned_nodes: bool,
        cancel_rx: oneshot::Receiver<()>,
    ) -> Result<FetchResult<Self::Family, Self::Op, Self::Digest>, Self::Error> {
        self.operation_log
            .get_operations(
                op_count,
                start_loc,
                max_ops,
                include_pinned_nodes,
                cancel_rx,
            )
            .await
    }
}

pub struct OperationLogSubscription<B, F: Graftable, H: Hasher, Op: Decode + Encode + Read> {
    stream: ServerStream<B, SubscribeResponseView<'static>>,
    op_cfg: Arc<Op::Cfg>,
    _marker: PhantomData<(F, H, Op)>,
}

impl<B, F, H, Op> OperationLogSubscription<B, F, H, Op>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Display,
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read,
{
    pub async fn message_with_root<R>(
        &mut self,
        root_for_tip: R,
    ) -> Result<Option<OperationLogSubscribeProof<H::Digest, Op, F>>, QmdbError>
    where
        R: FnOnce(Location<F>) -> Result<H::Digest, QmdbError>,
    {
        let Some(frame) = self.stream.message().await.map_err(connect_error_to_qmdb)? else {
            return Ok(None);
        };
        let frame = frame.to_owned_message();
        let proof = frame.proof.as_option().ok_or_else(|| {
            QmdbError::CorruptData("qmdb subscribe response missing proof".to_string())
        })?;
        let tip = Location::<F>::new(frame.tip);
        let expected_root = root_for_tip(tip)?;
        let (root, operations) = verify_multi_from_proto::<F, H, _, _>(
            proof,
            self.op_cfg.as_ref(),
            crate::ProofKind::BatchMulti,
            &expected_root,
            |bytes, cfg| Op::decode_cfg(bytes, cfg),
        )?;
        Ok(Some(OperationLogSubscribeProof {
            resume_sequence_number: frame.resume_sequence_number,
            tip,
            root,
            operations,
        }))
    }
}

/// Client for `qmdb.v1.CurrentOperationService`, parameterized on the Merkle
/// family and current-state operation type.
#[derive(Clone)]
pub struct CurrentOperationClient<T, F: Graftable, H: Hasher, Op: Encode + Read, const N: usize> {
    rpc: CurrentOperationServiceClient<T>,
    op_cfg: Arc<Op::Cfg>,
    _marker: PhantomData<(F, H, Op)>,
}

impl<F, H, Op, const N: usize> CurrentOperationClient<PreferZstdHttpClient, F, H, Op, N>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read,
{
    pub fn plaintext(base: &str, op_cfg: Op::Cfg) -> Self {
        Self::new(
            PreferZstdHttpClient::plaintext(),
            ClientConfig::new(base.parse().expect("qmdb uri")),
            op_cfg,
        )
    }
}

impl<T, F, H, Op, const N: usize> CurrentOperationClient<T, F, H, Op, N>
where
    T: ClientTransport,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read,
{
    pub fn new(transport: T, config: ClientConfig, op_cfg: Op::Cfg) -> Self {
        Self::from_service_client(
            CurrentOperationServiceClient::new(transport, config),
            op_cfg,
        )
    }

    pub fn from_service_client(rpc: CurrentOperationServiceClient<T>, op_cfg: Op::Cfg) -> Self {
        Self {
            rpc,
            op_cfg: Arc::new(op_cfg),
            _marker: PhantomData,
        }
    }

    pub async fn get_current_operation_range(
        &self,
        request: GetCurrentOperationRangeRequest,
        expected_root: &H::Digest,
    ) -> Result<CurrentOperationRangeProof<H::Digest, Op, N, F>, QmdbError> {
        let tip = Location::<F>::new(request.tip);
        let response = self
            .rpc
            .get_current_operation_range(request)
            .await
            .map_err(connect_error_to_qmdb)?
            .into_view()
            .to_owned_message();
        let proof = response.proof.as_option().ok_or_else(|| {
            QmdbError::CorruptData(
                "qmdb get_current_operation_range response missing proof".to_string(),
            )
        })?;
        let (root, operations, chunks) = verify_current_operation_range_from_proto::<F, H, _, _, N>(
            proof,
            self.op_cfg.as_ref(),
            expected_root,
            |bytes, cfg| Op::decode_cfg(bytes, cfg),
        )?;
        Ok(CurrentOperationRangeProof {
            tip,
            root,
            start_location: Location::<F>::new(proof.start_location),
            operations,
            chunks,
        })
    }
}

/// Client for `qmdb.v1.OperationLogService`, parameterized on the Merkle
/// family and backend operation type.
#[derive(Clone)]
pub struct OperationLogClient<T, F: Graftable, H: Hasher, Op: Encode + Read> {
    rpc: OperationLogServiceClient<T>,
    op_cfg: Arc<Op::Cfg>,
    _marker: PhantomData<(F, H, Op)>,
}

impl<F, H, Op> OperationLogClient<PreferZstdHttpClient, F, H, Op>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read,
{
    pub fn plaintext(base: &str, op_cfg: Op::Cfg) -> Self {
        Self::new(
            PreferZstdHttpClient::plaintext(),
            ClientConfig::new(base.parse().expect("qmdb uri")),
            op_cfg,
        )
    }
}

impl<T, F, H, Op> OperationLogClient<T, F, H, Op>
where
    T: ClientTransport,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read,
{
    pub fn new(transport: T, config: ClientConfig, op_cfg: Op::Cfg) -> Self {
        Self::from_service_client(OperationLogServiceClient::new(transport, config), op_cfg)
    }

    pub fn from_service_client(rpc: OperationLogServiceClient<T>, op_cfg: Op::Cfg) -> Self {
        Self {
            rpc,
            op_cfg: Arc::new(op_cfg),
            _marker: PhantomData,
        }
    }

    pub async fn get_operation_range(
        &self,
        request: GetOperationRangeRequest,
        expected_root: &H::Digest,
    ) -> Result<OperationLogRangeProof<H::Digest, Op, F>, QmdbError> {
        let tip = Location::<F>::new(request.tip);
        let response = self
            .rpc
            .get_operation_range(request)
            .await
            .map_err(connect_error_to_qmdb)?
            .into_view()
            .to_owned_message();
        let proof = response.proof.as_option().ok_or_else(|| {
            QmdbError::CorruptData("qmdb get_operation_range response missing proof".to_string())
        })?;
        let (root, operations) = verify_operation_range_from_proto::<F, H, _, _>(
            proof,
            self.op_cfg.as_ref(),
            expected_root,
            |bytes, cfg| Op::decode_cfg(bytes, cfg),
        )?;
        Ok(OperationLogRangeProof {
            tip,
            root,
            start_location: Location::<F>::new(proof.start_location),
            operations,
        })
    }

    pub async fn subscribe(
        &self,
        request: SubscribeRequest,
    ) -> Result<OperationLogSubscription<T::ResponseBody, F, H, Op>, QmdbError> {
        let stream = self
            .rpc
            .subscribe(request)
            .await
            .map_err(connect_error_to_qmdb)?;
        Ok(OperationLogSubscription {
            stream,
            op_cfg: Arc::clone(&self.op_cfg),
            _marker: PhantomData,
        })
    }
}

fn connect_error_to_qmdb(err: ConnectError) -> QmdbError {
    QmdbError::Client(ClientError::Rpc(Box::new(err)))
}

fn proof_digest_cap<D: Digest>(encoded_proof: &[u8]) -> usize {
    encoded_proof.len() / D::SIZE + 1
}

fn decode_digest<H>(bytes: &[u8], label: &'static str) -> Result<H::Digest, QmdbError>
where
    H: Hasher,
    H::Digest: DecodeExt<()>,
{
    H::Digest::decode_cfg(bytes, &())
        .map_err(|err| QmdbError::CorruptData(format!("failed to decode {label}: {err}")))
}

fn decode_ops_root_witness<F, H>(bytes: &[u8]) -> Result<OpsRootWitness<F, H::Digest>, QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
{
    OpsRootWitness::<F, H::Digest>::decode_cfg(bytes, &()).map_err(|err| {
        QmdbError::CorruptData(format!(
            "failed to decode current sync ops-root witness: {err}"
        ))
    })
}

fn historical_target_root<F, H>(
    ops_root: &[u8],
    ops_root_witness: &[u8],
    expected_root: &H::Digest,
) -> Result<H::Digest, QmdbError>
where
    F: Graftable,
    H::Digest: DecodeExt<()>,
    H: Hasher,
{
    match (ops_root.is_empty(), ops_root_witness.is_empty()) {
        (true, true) => Ok(*expected_root),
        (false, true) => {
            let ops_root = H::Digest::decode_cfg(ops_root, &()).map_err(|err| {
                QmdbError::CorruptData(format!("failed to decode historical ops root: {err}"))
            })?;
            if ops_root != *expected_root {
                return Err(QmdbError::ProofVerification {
                    kind: crate::ProofKind::BatchMulti,
                });
            }
            Ok(ops_root)
        }
        (false, false) => {
            let ops_root = H::Digest::decode_cfg(ops_root, &()).map_err(|err| {
                QmdbError::CorruptData(format!("failed to decode historical ops root: {err}"))
            })?;
            let witness = OpsRootWitness::<F, H::Digest>::decode_cfg(ops_root_witness, &())
                .map_err(|err| {
                    QmdbError::CorruptData(format!(
                        "failed to decode historical ops-root witness: {err}"
                    ))
                })?;
            let hasher = commonware_storage::qmdb::hasher::<H>();
            if !witness.verify(&hasher, &ops_root, expected_root) {
                return Err(QmdbError::ProofVerification {
                    kind: crate::ProofKind::BatchMulti,
                });
            }
            Ok(ops_root)
        }
        _ => Err(QmdbError::CorruptData(
            "historical proof missing ops_root for ops_root_witness".to_string(),
        )),
    }
}

enum ExclusionBoundary<K> {
    Span { start: K, end: K },
    Empty,
}

fn verify_multi_from_proto<F, H, Op, DecodeOp>(
    proto: &HistoricalMultiProof,
    op_cfg: &Op::Cfg,
    kind: crate::ProofKind,
    root: &H::Digest,
    decode: DecodeOp,
) -> Result<(H::Digest, Vec<(Location<F>, Op)>), QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Encode + Read,
    DecodeOp: Fn(&[u8], &Op::Cfg) -> Result<Op, commonware_codec::Error>,
{
    let operations = proto
        .operations
        .iter()
        .map(|op| {
            let decoded = decode(op.encoded_operation.as_slice(), op_cfg).map_err(|err| {
                QmdbError::CorruptData(format!(
                    "failed to decode multi-proof operation at {}: {err}",
                    op.location
                ))
            })?;
            Ok((Location::<F>::new(op.location), decoded))
        })
        .collect::<Result<Vec<_>, QmdbError>>()?;
    let target_root =
        historical_target_root::<F, H>(&proto.ops_root, &proto.ops_root_witness, root)?;
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof =
        Proof::<F, H::Digest>::decode_cfg(proto.proof.as_slice(), &max_digests).map_err(|err| {
            QmdbError::CorruptData(format!("failed to decode historical multi proof: {err}"))
        })?;
    let hasher = commonware_storage::qmdb::hasher::<H>();
    if !verify_multi_proof(&hasher, &proof, &operations, &target_root) {
        return Err(QmdbError::ProofVerification { kind });
    }
    Ok((*root, operations))
}

fn verify_operation_range_from_proto<F, H, Op, DecodeOp>(
    proto: &HistoricalOperationRangeProof,
    op_cfg: &Op::Cfg,
    root: &H::Digest,
    decode: DecodeOp,
) -> Result<(H::Digest, Vec<(Location<F>, Op)>), QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Encode + Read,
    DecodeOp: Fn(&[u8], &Op::Cfg) -> Result<Op, commonware_codec::Error>,
{
    if proto.encoded_operations.is_empty() {
        return Err(QmdbError::CorruptData(
            "historical operation range proof has no operations".to_string(),
        ));
    }
    let target_root =
        historical_target_root::<F, H>(&proto.ops_root, &proto.ops_root_witness, root)?;
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof =
        Proof::<F, H::Digest>::decode_cfg(proto.proof.as_slice(), &max_digests).map_err(|err| {
            QmdbError::CorruptData(format!(
                "failed to decode historical operation range proof: {err}"
            ))
        })?;
    let start = Location::<F>::new(proto.start_location);
    let decoded_operations = proto
        .encoded_operations
        .iter()
        .map(|bytes| {
            let decoded = decode(bytes.as_slice(), op_cfg).map_err(|err| {
                QmdbError::CorruptData(format!("failed to decode operation range entry: {err}"))
            })?;
            Ok(decoded)
        })
        .collect::<Result<Vec<_>, QmdbError>>()?;
    let pinned_nodes = proto
        .pinned_nodes
        .iter()
        .map(|bytes| decode_digest::<H>(bytes.as_slice(), "historical operation range pinned node"))
        .collect::<Result<Vec<_>, QmdbError>>()?;
    let hasher = commonware_storage::qmdb::hasher::<H>();
    if !verify_proof_and_pinned_nodes(
        &hasher,
        &proof,
        start,
        &decoded_operations,
        &pinned_nodes,
        &target_root,
    ) {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::RangeCheckpoint,
        });
    }
    let operations = decoded_operations
        .into_iter()
        .enumerate()
        .map(|(offset, operation)| {
            let offset = u64::try_from(offset).map_err(|err| {
                QmdbError::CorruptData(format!("operation range offset overflow: {err}"))
            })?;
            let location = start.checked_add(offset).ok_or_else(|| {
                QmdbError::CorruptData("operation range location overflow".to_string())
            })?;
            Ok((location, operation))
        })
        .collect::<Result<Vec<_>, QmdbError>>()?;
    Ok((*root, operations))
}

fn verify_current_operation_range_from_proto<F, H, Op, DecodeOp, const N: usize>(
    proto: &ProtoCurrentOperationRangeProof,
    op_cfg: &Op::Cfg,
    root: &H::Digest,
    decode: DecodeOp,
) -> Result<(H::Digest, Vec<(Location<F>, Op)>, Vec<[u8; N]>), QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Encode + Read,
    DecodeOp: Fn(&[u8], &Op::Cfg) -> Result<Op, commonware_codec::Error>,
{
    if proto.encoded_operations.is_empty() {
        return Err(QmdbError::CorruptData(
            "current operation range proof has no operations".to_string(),
        ));
    }
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof = RangeProof::<F, H::Digest>::decode_cfg(proto.proof.as_slice(), &max_digests)
        .map_err(|err| {
            QmdbError::CorruptData(format!(
                "failed to decode current operation range proof: {err}"
            ))
        })?;
    let start = Location::<F>::new(proto.start_location);
    let decoded_operations = proto
        .encoded_operations
        .iter()
        .map(|bytes| {
            let decoded = decode(bytes.as_slice(), op_cfg).map_err(|err| {
                QmdbError::CorruptData(format!(
                    "failed to decode current operation range entry: {err}"
                ))
            })?;
            Ok(decoded)
        })
        .collect::<Result<Vec<_>, QmdbError>>()?;
    let chunks = proto
        .chunks
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            <[u8; N]>::decode(bytes.as_ref()).map_err(|e| {
                QmdbError::CorruptData(format!(
                    "current operation range chunk {index} decode error: {e}"
                ))
            })
        })
        .collect::<Result<Vec<_>, QmdbError>>()?;
    let hasher = commonware_storage::qmdb::hasher::<H>();
    if !proof.verify(&hasher, start, &decoded_operations, &chunks, root) {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::CurrentRange,
        });
    }
    let operations = decoded_operations
        .into_iter()
        .enumerate()
        .map(|(offset, operation)| {
            let offset = u64::try_from(offset).map_err(|err| {
                QmdbError::CorruptData(format!("current operation range offset overflow: {err}"))
            })?;
            let location = start.checked_add(offset).ok_or_else(|| {
                QmdbError::CorruptData("current operation range location overflow".to_string())
            })?;
            Ok((location, operation))
        })
        .collect::<Result<Vec<_>, QmdbError>>()?;
    Ok((*root, operations, chunks))
}

fn verify_key_value_from_proto<F, H, K, V, const N: usize, E>(
    proto: &ProtoCurrentKeyValueProof,
    root: &H::Digest,
    op_cfg: &<ordered::Operation<F, K, E> as Read>::Cfg,
    key_cfg: &K::Cfg,
) -> Result<VerifiedKeyValue<H::Digest, K, V, F, E>, QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    K::Cfg: Clone,
    ordered::Operation<F, K, E>: Decode + Encode + Read,
{
    let operation =
        ordered::Operation::<F, K, E>::decode_cfg(proto.encoded_operation.as_slice(), op_cfg)
            .map_err(|err| {
                QmdbError::CorruptData(format!(
                    "failed to decode current key-value operation: {err}",
                ))
            })?;
    let ordered::Operation::Update(update) = &operation else {
        return Err(QmdbError::CorruptData(
            "current key-value proof operation must be an update".to_string(),
        ));
    };
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof = KeyValueProof::<F, K, H::Digest, N>::decode_cfg(
        proto.proof.as_slice(),
        &(max_digests, key_cfg.clone()),
    )
    .map_err(|err| {
        QmdbError::CorruptData(format!("failed to decode current key-value proof: {err}"))
    })?;
    if proof.next_key != update.next_key {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::CurrentKeyValue,
        });
    }
    if !verify_ordered_key_value_proof::<F, H, K, E, N>(
        update.key.clone(),
        update.value.clone(),
        &proof,
        root,
    ) {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::CurrentKeyValue,
        });
    }
    Ok(VerifiedKeyValue {
        root: *root,
        location: proof.proof.loc,
        operation,
    })
}

fn verify_unordered_key_value_from_proto<F, H, K, V, const N: usize, E>(
    proto: &ProtoCurrentKeyValueProof,
    requested_key: &[u8],
    root: &H::Digest,
    op_cfg: &<unordered::Operation<F, K, E> as Read>::Cfg,
) -> Result<VerifiedUnorderedKeyValue<H::Digest, K, V, F, E>, QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: commonware_utils::Array + QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    unordered::Operation<F, K, E>: Decode + Encode + Read,
{
    let operation =
        unordered::Operation::<F, K, E>::decode_cfg(proto.encoded_operation.as_slice(), op_cfg)
            .map_err(|err| {
                QmdbError::CorruptData(format!(
                    "failed to decode unordered current key-value operation: {err}",
                ))
            })?;
    let unordered::Operation::Update(update) = &operation else {
        return Err(QmdbError::CorruptData(
            "unordered current key-value proof operation must be an update".to_string(),
        ));
    };
    if update.0.as_ref() != requested_key {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::CurrentKeyValue,
        });
    }
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof =
        UnorderedKeyValueProof::<F, H::Digest, N>::decode_cfg(proto.proof.as_slice(), &max_digests)
            .map_err(|err| {
                QmdbError::CorruptData(format!("failed to decode unordered current proof: {err}"))
            })?;
    let hasher = commonware_storage::qmdb::hasher::<H>();
    if !proof.verify(&hasher, operation.clone(), root) {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::CurrentKeyValue,
        });
    }
    Ok(VerifiedUnorderedKeyValue {
        root: *root,
        location: proof.loc,
        operation,
    })
}

fn verify_key_exclusion_from_proto<F, H, K, V, const N: usize, E>(
    proto: &ProtoCurrentKeyExclusionProof,
    requested_key: &[u8],
    root: &H::Digest,
    update_cfg: &<ordered::Update<K, E> as Read>::Cfg,
    key_cfg: &K::Cfg,
    value_cfg: &V::Cfg,
) -> Result<ExclusionBoundary<K>, QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    E: ValueEncoding<Value = V>,
    <ordered::Update<K, E> as Read>::Cfg: Clone,
    V::Cfg: Clone,
    ordered::Operation<F, K, E>: Decode + Encode + Read,
    ordered::Update<K, E>: Read,
    ExclusionProof<F, K, E, H::Digest, N>:
        Read<Cfg = (usize, <ordered::Update<K, E> as Read>::Cfg, V::Cfg)>,
{
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof = ExclusionProof::<F, K, E, H::Digest, N>::decode_cfg(
        proto.proof.as_slice(),
        &(max_digests, update_cfg.clone(), value_cfg.clone()),
    )
    .map_err(|err| {
        QmdbError::CorruptData(format!(
            "failed to decode current key-exclusion proof: {err}"
        ))
    })?;
    let requested_key = K::decode_cfg(requested_key, key_cfg).map_err(|err| {
        QmdbError::CorruptData(format!("failed to decode requested exclusion key: {err}"))
    })?;
    if !verify_ordered_exclusion_proof::<F, H, K, E, N>(&requested_key, &proof, root) {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::CurrentKeyExclusion,
        });
    }
    let boundary = match proof {
        ExclusionProof::KeyValue(_, update) => ExclusionBoundary::Span {
            start: update.key,
            end: update.next_key,
        },
        ExclusionProof::Commit(_, _) => ExclusionBoundary::Empty,
    };
    Ok(boundary)
}

fn span_contains_key<K: Ord>(span_start: &K, span_end: &K, key: &K) -> bool {
    if span_start >= span_end {
        key >= span_start || key < span_end
    } else {
        key >= span_start && key < span_end
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_get_range_from_proto<F, H, K, V, const N: usize, E>(
    response: &GetRangeResponse,
    root: &H::Digest,
    start_key: &[u8],
    end_key: Option<&[u8]>,
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
    K::Cfg: Clone,
    <ordered::Update<K, E> as Read>::Cfg: Clone,
    V::Cfg: Clone,
    ordered::Operation<F, K, E>: Decode + Encode + Read,
    ordered::Update<K, E>: Read,
    ExclusionProof<F, K, E, H::Digest, N>:
        Read<Cfg = (usize, <ordered::Update<K, E> as Read>::Cfg, V::Cfg)>,
{
    let encoded_start_key = start_key;
    let encoded_end_key = end_key;
    let start_key = K::decode_cfg(encoded_start_key, key_cfg).map_err(|err| {
        QmdbError::CorruptData(format!("failed to decode range start key: {err}"))
    })?;
    let end_key = encoded_end_key
        .map(|key| {
            K::decode_cfg(key, key_cfg).map_err(|err| {
                QmdbError::CorruptData(format!("failed to decode range end key: {err}"))
            })
        })
        .transpose()?;
    let mut entries = Vec::with_capacity(response.entries.len());
    for entry in &response.entries {
        let proof = entry.proof.as_option().ok_or_else(|| {
            QmdbError::CorruptData("qmdb get_range entry missing proof".to_string())
        })?;
        let verified =
            verify_key_value_from_proto::<F, H, K, V, N, E>(proof, root, op_cfg, key_cfg)?;
        let ordered::Operation::Update(update) = &verified.operation else {
            return Err(QmdbError::CorruptData(
                "qmdb get_range entry proof did not verify an update".to_string(),
            ));
        };
        let entry_key = K::decode_cfg(entry.key.as_slice(), key_cfg).map_err(|err| {
            QmdbError::CorruptData(format!("failed to decode range entry key: {err}"))
        })?;
        if update.key != entry_key {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentKeyValue,
            });
        }
        entries.push(verified);
    }

    if let Some(first) = entries.first() {
        let ordered::Operation::Update(first_update) = &first.operation else {
            unreachable!("range entries were checked as updates");
        };
        if first_update.key != start_key {
            let start_proof = response.start_proof.as_option().ok_or_else(|| {
                QmdbError::CorruptData(
                    "qmdb get_range response missing start boundary proof".to_string(),
                )
            })?;
            match verify_key_exclusion_from_proto::<F, H, K, V, N, E>(
                start_proof,
                encoded_start_key,
                root,
                update_cfg,
                key_cfg,
                value_cfg,
            )? {
                ExclusionBoundary::Span { end, .. } if end == first_update.key => {}
                ExclusionBoundary::Span { .. } | ExclusionBoundary::Empty => {
                    return Err(QmdbError::ProofVerification {
                        kind: crate::ProofKind::CurrentKeyExclusion,
                    })
                }
            }
        }
    } else {
        let start_proof = response.start_proof.as_option().ok_or_else(|| {
            QmdbError::CorruptData(
                "empty qmdb get_range response missing start boundary proof".to_string(),
            )
        })?;
        let boundary = verify_key_exclusion_from_proto::<F, H, K, V, N, E>(
            start_proof,
            encoded_start_key,
            root,
            update_cfg,
            key_cfg,
            value_cfg,
        )?;
        match (end_key.as_ref(), boundary) {
            (Some(end_key), ExclusionBoundary::Span { start, end })
                if !span_contains_key(&start, &end, end_key) && end != *end_key =>
            {
                return Err(QmdbError::ProofVerification {
                    kind: crate::ProofKind::CurrentKeyExclusion,
                });
            }
            (None, ExclusionBoundary::Span { end, .. }) if end > start_key => {
                return Err(QmdbError::ProofVerification {
                    kind: crate::ProofKind::CurrentKeyExclusion,
                });
            }
            _ => {}
        }
    }

    for pair in entries.windows(2) {
        let ordered::Operation::Update(left) = &pair[0].operation else {
            unreachable!("range entries were checked as updates");
        };
        let ordered::Operation::Update(right) = &pair[1].operation else {
            unreachable!("range entries were checked as updates");
        };
        if left.next_key != right.key {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentKeyValue,
            });
        }
    }

    if response.has_more {
        let Some(last) = entries.last() else {
            return Err(QmdbError::CorruptData(
                "truncated qmdb get_range response has no final entry".to_string(),
            ));
        };
        let ordered::Operation::Update(last_update) = &last.operation else {
            unreachable!("range entries were checked as updates");
        };
        let next_start_key =
            K::decode_cfg(response.next_start_key.as_slice(), key_cfg).map_err(|err| {
                QmdbError::CorruptData(format!("failed to decode range next_start_key: {err}"))
            })?;
        if next_start_key != last_update.next_key {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentKeyValue,
            });
        }
    } else if let Some(first) = entries.first() {
        let last = entries.last().expect("first exists");
        let ordered::Operation::Update(first_update) = &first.operation else {
            unreachable!("range entries were checked as updates");
        };
        let ordered::Operation::Update(last_update) = &last.operation else {
            unreachable!("range entries were checked as updates");
        };
        if let Some(end_key) = end_key.as_ref() {
            if last_update.next_key != *end_key
                && !span_contains_key(&last_update.key, &last_update.next_key, end_key)
            {
                return Err(QmdbError::ProofVerification {
                    kind: crate::ProofKind::CurrentKeyValue,
                });
            }
        } else if last_update.next_key > first_update.key {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentKeyValue,
            });
        }
    }

    Ok(VerifiedKeyRange {
        entries,
        has_more: response.has_more,
        next_start_key: response.next_start_key.clone(),
    })
}
