use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::marker::PhantomData;
use std::sync::Arc;

use bytes::Bytes;
use commonware_codec::{Decode, DecodeExt, Read};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::{
    mmr::{self, Location},
    qmdb::{
        any::{
            ordered::variable::Operation as QmdbOperation,
            unordered::variable::Operation as UnorderedQmdbOperation, value::VariableEncoding,
        },
        current::ordered::{
            db::KeyValueProof as CurrentKeyValueProof, ExclusionProof as CurrentExclusionProof,
        },
        current::proof::OperationProof as CurrentOperationProof,
        immutable::variable::Operation as ImmutableOperation,
        keyless::variable::Operation as KeylessOperation,
        operation::Key as QmdbKey,
    },
};
use connectrpc::client::{ClientConfig, ClientTransport, ServerStream};
use connectrpc::ConnectError;
use exoware_sdk::proto::PreferZstdHttpClient;
use exoware_sdk::qmdb::v1::{
    current_key_lookup_result, CurrentKeyExclusionProof as ProtoCurrentKeyExclusionProof,
    CurrentKeyValueProof as ProtoCurrentKeyValueProof, GetManyRequest, GetRangeRequest,
    GetRangeResponse, GetRequest, HistoricalMultiProof, KeyLookupServiceClient,
    OrderedKeyRangeServiceClient, RangeServiceClient, SubscribeRequest, SubscribeResponseView,
};
use exoware_sdk::ClientError;
use http_body::Body;

use crate::proof::{
    VerifiedKeyLookup, VerifiedKeyRange, VerifiedKeyValue, VerifiedUnorderedKeyValue,
};
use crate::QmdbError;

#[derive(Clone)]
pub struct OrderedConnectClient<
    T,
    H: Hasher,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
> {
    rpc: KeyLookupServiceClient<T>,
    range_rpc: OrderedKeyRangeServiceClient<T>,
    op_cfg: Arc<<QmdbOperation<commonware_storage::mmr::Family, K, V> as Read>::Cfg>,
    _marker: PhantomData<(H, K, V)>,
}

impl<H, K, V, const N: usize> OrderedConnectClient<PreferZstdHttpClient, H, K, V, N>
where
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    QmdbOperation<commonware_storage::mmr::Family, K, V>: Decode + Read<Cfg = (K::Cfg, V::Cfg)>,
{
    pub fn plaintext(
        base: &str,
        op_cfg: <QmdbOperation<commonware_storage::mmr::Family, K, V> as Read>::Cfg,
    ) -> Self {
        Self::new(
            PreferZstdHttpClient::plaintext(),
            ClientConfig::new(base.parse().expect("qmdb uri")),
            op_cfg,
        )
    }
}

impl<T, H, K, V, const N: usize> OrderedConnectClient<T, H, K, V, N>
where
    T: ClientTransport + Clone,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    QmdbOperation<commonware_storage::mmr::Family, K, V>: Decode + Read<Cfg = (K::Cfg, V::Cfg)>,
{
    pub fn new(
        transport: T,
        config: ClientConfig,
        op_cfg: <QmdbOperation<commonware_storage::mmr::Family, K, V> as Read>::Cfg,
    ) -> Self {
        Self::from_service_clients(
            KeyLookupServiceClient::new(transport.clone(), config.clone()),
            OrderedKeyRangeServiceClient::new(transport, config),
            op_cfg,
        )
    }

    pub fn from_service_clients(
        rpc: KeyLookupServiceClient<T>,
        range_rpc: OrderedKeyRangeServiceClient<T>,
        op_cfg: <QmdbOperation<commonware_storage::mmr::Family, K, V> as Read>::Cfg,
    ) -> Self {
        Self {
            rpc,
            range_rpc,
            op_cfg: Arc::new(op_cfg),
            _marker: PhantomData,
        }
    }

    pub async fn get(
        &self,
        request: GetRequest,
        expected_root: &H::Digest,
    ) -> Result<VerifiedKeyValue<H::Digest, K, V>, QmdbError> {
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
        verify_key_value_from_proto::<H, K, V, N>(proof, expected_root, self.op_cfg.as_ref())
    }

    pub async fn get_many(
        &self,
        request: GetManyRequest,
        expected_root: &H::Digest,
    ) -> Result<Vec<VerifiedKeyLookup<H::Digest, K, V>>, QmdbError> {
        let response = self
            .rpc
            .get_many(request)
            .await
            .map_err(connect_error_to_qmdb)?
            .into_view()
            .to_owned_message();
        response
            .results
            .iter()
            .map(|result| match result.result.as_ref() {
                Some(current_key_lookup_result::Result::Hit(proof)) => {
                    verify_key_value_from_proto::<H, K, V, N>(
                        proof,
                        expected_root,
                        self.op_cfg.as_ref(),
                    )
                    .map(VerifiedKeyLookup::Hit)
                }
                Some(current_key_lookup_result::Result::Miss(proof)) => {
                    verify_key_exclusion_from_proto::<H, K, V, N>(
                        proof,
                        result.key.as_slice(),
                        expected_root,
                        self.op_cfg.as_ref(),
                    )?;
                    Ok(VerifiedKeyLookup::Miss {
                        key: result.key.clone(),
                    })
                }
                None => Err(QmdbError::CorruptData(
                    "qmdb get_many result missing hit/miss proof".to_string(),
                )),
            })
            .collect()
    }

    pub async fn get_range(
        &self,
        request: GetRangeRequest,
        expected_root: &H::Digest,
    ) -> Result<VerifiedKeyRange<H::Digest, K, V>, QmdbError> {
        let start_key = request.start_key.clone();
        let end_key = request.end_key.clone();
        let response = self
            .range_rpc
            .get_range(request)
            .await
            .map_err(connect_error_to_qmdb)?
            .into_view()
            .to_owned_message();
        verify_get_range_from_proto::<H, K, V, N>(
            &response,
            expected_root,
            start_key.as_slice(),
            end_key.as_deref(),
            self.op_cfg.as_ref(),
        )
    }
}

#[derive(Clone)]
pub struct UnorderedConnectClient<
    T,
    H: Hasher,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
> {
    rpc: KeyLookupServiceClient<T>,
    op_cfg: Arc<<UnorderedQmdbOperation<commonware_storage::mmr::Family, K, V> as Read>::Cfg>,
    _marker: PhantomData<(H, K, V)>,
}

impl<H, K, V, const N: usize> UnorderedConnectClient<PreferZstdHttpClient, H, K, V, N>
where
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    UnorderedQmdbOperation<commonware_storage::mmr::Family, K, V>:
        Decode + Read<Cfg = (K::Cfg, V::Cfg)>,
{
    pub fn plaintext(
        base: &str,
        op_cfg: <UnorderedQmdbOperation<commonware_storage::mmr::Family, K, V> as Read>::Cfg,
    ) -> Self {
        Self::new(
            PreferZstdHttpClient::plaintext(),
            ClientConfig::new(base.parse().expect("qmdb uri")),
            op_cfg,
        )
    }
}

impl<T, H, K, V, const N: usize> UnorderedConnectClient<T, H, K, V, N>
where
    T: ClientTransport + Clone,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    UnorderedQmdbOperation<commonware_storage::mmr::Family, K, V>:
        Decode + Read<Cfg = (K::Cfg, V::Cfg)>,
{
    pub fn new(
        transport: T,
        config: ClientConfig,
        op_cfg: <UnorderedQmdbOperation<commonware_storage::mmr::Family, K, V> as Read>::Cfg,
    ) -> Self {
        Self::from_service_client(KeyLookupServiceClient::new(transport, config), op_cfg)
    }

    pub fn from_service_client(
        rpc: KeyLookupServiceClient<T>,
        op_cfg: <UnorderedQmdbOperation<commonware_storage::mmr::Family, K, V> as Read>::Cfg,
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
    ) -> Result<VerifiedUnorderedKeyValue<H::Digest, K, V>, QmdbError> {
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
        verify_unordered_key_value_from_proto::<H, K, V, N>(
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
    ) -> Result<Vec<VerifiedUnorderedKeyValue<H::Digest, K, V>>, QmdbError> {
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
                        verify_unordered_key_value_from_proto::<H, K, V, N>(
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
pub struct RangeSubscribeProof<D: Digest, Op> {
    pub resume_sequence_number: u64,
    pub root: D,
    pub operations: Vec<(Location, Op)>,
}

pub struct RangeConnectSubscription<B, H: Hasher, Op: Decode + Read> {
    stream: ServerStream<B, SubscribeResponseView<'static>>,
    op_cfg: Arc<Op::Cfg>,
    _marker: PhantomData<(H, Op)>,
}

impl<B, H, Op> RangeConnectSubscription<B, H, Op>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Display,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Decode + Read,
{
    pub async fn message(
        &mut self,
    ) -> Result<Option<RangeSubscribeProof<H::Digest, Op>>, QmdbError> {
        let Some(frame) = self.stream.message().await.map_err(connect_error_to_qmdb)? else {
            return Ok(None);
        };
        let frame = frame.to_owned_message();
        let proof = frame.proof.as_option().ok_or_else(|| {
            QmdbError::CorruptData("qmdb subscribe response missing proof".to_string())
        })?;
        let (root, operations) = verify_multi_from_proto::<H, _, _>(
            proof,
            self.op_cfg.as_ref(),
            crate::ProofKind::BatchMulti,
            &decode_digest(&frame.root, "subscribe proof root")?,
            |bytes, cfg| Op::decode_cfg(bytes, cfg),
        )?;
        Ok(Some(RangeSubscribeProof {
            resume_sequence_number: frame.resume_sequence_number,
            root,
            operations,
        }))
    }
}

/// Client for `qmdb.v1.RangeService`, parameterized on the backend
/// operation type. The per-backend wrappers below are type aliases that pin
/// `Op` to `QmdbOperation<K,V>` / `UnorderedQmdbOperation<K,V>` / etc.
#[derive(Clone)]
pub struct RangeConnectClient<T, H: Hasher, Op: Read> {
    rpc: RangeServiceClient<T>,
    op_cfg: Arc<Op::Cfg>,
    _marker: PhantomData<(H, Op)>,
}

impl<H, Op> RangeConnectClient<PreferZstdHttpClient, H, Op>
where
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Decode + Read,
{
    pub fn plaintext(base: &str, op_cfg: Op::Cfg) -> Self {
        Self::new(
            PreferZstdHttpClient::plaintext(),
            ClientConfig::new(base.parse().expect("qmdb uri")),
            op_cfg,
        )
    }
}

impl<T, H, Op> RangeConnectClient<T, H, Op>
where
    T: ClientTransport,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Decode + Read,
{
    pub fn new(transport: T, config: ClientConfig, op_cfg: Op::Cfg) -> Self {
        Self::from_service_client(RangeServiceClient::new(transport, config), op_cfg)
    }

    pub fn from_service_client(rpc: RangeServiceClient<T>, op_cfg: Op::Cfg) -> Self {
        Self {
            rpc,
            op_cfg: Arc::new(op_cfg),
            _marker: PhantomData,
        }
    }

    pub async fn subscribe(
        &self,
        request: SubscribeRequest,
    ) -> Result<RangeConnectSubscription<T::ResponseBody, H, Op>, QmdbError> {
        let stream = self
            .rpc
            .subscribe(request)
            .await
            .map_err(connect_error_to_qmdb)?;
        Ok(RangeConnectSubscription {
            stream,
            op_cfg: Arc::clone(&self.op_cfg),
            _marker: PhantomData,
        })
    }
}

pub type OrderedRangeConnectClient<T, H, K, V> =
    RangeConnectClient<T, H, QmdbOperation<commonware_storage::mmr::Family, K, V>>;
pub type UnorderedRangeConnectClient<T, H, K, V> =
    RangeConnectClient<T, H, UnorderedQmdbOperation<commonware_storage::mmr::Family, K, V>>;
pub type ImmutableRangeConnectClient<T, H, K, V> =
    RangeConnectClient<T, H, ImmutableOperation<commonware_storage::mmr::Family, K, V>>;
pub type KeylessRangeConnectClient<T, H, V> =
    RangeConnectClient<T, H, KeylessOperation<commonware_storage::mmr::Family, V>>;

fn connect_error_to_qmdb(err: ConnectError) -> QmdbError {
    QmdbError::Client(ClientError::Rpc(Box::new(err)))
}

fn decode_digest<D: Digest + DecodeExt<()>>(bytes: &[u8], label: &str) -> Result<D, QmdbError> {
    D::decode(bytes)
        .map_err(|err| QmdbError::CorruptData(format!("failed to decode {label}: {err}")))
}

fn proof_digest_cap(proven_elements: usize) -> Result<usize, QmdbError> {
    commonware_storage::mmr::MAX_PROOF_DIGESTS_PER_ELEMENT
        .checked_mul(proven_elements.max(1))
        .ok_or_else(|| QmdbError::CorruptData("proof digest cap overflow".to_string()))
}

type RootAndOps<H, Op> = (<H as Hasher>::Digest, Vec<(Location, Op)>);

enum ExclusionBoundary {
    Span { start: Vec<u8>, end: Vec<u8> },
    Empty,
}

fn verify_multi_from_proto<H, Op, F>(
    proto: &HistoricalMultiProof,
    op_cfg: &Op::Cfg,
    kind: crate::ProofKind,
    root: &H::Digest,
    decode: F,
) -> Result<RootAndOps<H, Op>, QmdbError>
where
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Read,
    F: Fn(&[u8], &Op::Cfg) -> Result<Op, commonware_codec::Error>,
{
    let encoded: Vec<(&[u8], Location)> = proto
        .operations
        .iter()
        .map(|op| (op.encoded_operation.as_slice(), Location::new(op.location)))
        .collect();
    let max_digests = proof_digest_cap(proto.operations.len())?;
    let mmr_proof = mmr::Proof::<H::Digest>::decode_cfg(proto.proof.as_slice(), &max_digests)
        .map_err(|err| {
            QmdbError::CorruptData(format!("failed to decode historical multi proof: {err}"))
        })?;
    let hasher = commonware_storage::qmdb::hasher::<H>();
    if !mmr_proof.verify_multi_inclusion(&hasher, &encoded, root) {
        return Err(QmdbError::ProofVerification { kind });
    }
    let operations = proto
        .operations
        .iter()
        .map(|operation| {
            let decoded =
                decode(operation.encoded_operation.as_slice(), op_cfg).map_err(|err| {
                    QmdbError::CorruptData(format!(
                        "failed to decode multi-proof operation at {}: {err}",
                        operation.location
                    ))
                })?;
            Ok((Location::new(operation.location), decoded))
        })
        .collect::<Result<Vec<_>, QmdbError>>()?;
    Ok((*root, operations))
}

fn verify_key_value_from_proto<H, K, V, const N: usize>(
    proto: &ProtoCurrentKeyValueProof,
    root: &H::Digest,
    op_cfg: &(K::Cfg, V::Cfg),
) -> Result<VerifiedKeyValue<H::Digest, K, V>, QmdbError>
where
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    QmdbOperation<commonware_storage::mmr::Family, K, V>: Decode + Read<Cfg = (K::Cfg, V::Cfg)>,
{
    let operation = QmdbOperation::<commonware_storage::mmr::Family, K, V>::decode_cfg(
        proto.encoded_operation.as_slice(),
        op_cfg,
    )
    .map_err(|err| {
        QmdbError::CorruptData(format!(
            "failed to decode current key-value operation: {err}",
        ))
    })?;
    let QmdbOperation::Update(update) = &operation else {
        return Err(QmdbError::CorruptData(
            "current key-value proof operation must be an update".to_string(),
        ));
    };
    let max_digests = proof_digest_cap(4)?;
    let proof =
        CurrentKeyValueProof::<commonware_storage::mmr::Family, K, H::Digest, N>::decode_cfg(
            proto.proof.as_slice(),
            &(max_digests, op_cfg.0.clone()),
        )
        .map_err(|err| {
            QmdbError::CorruptData(format!("failed to decode current key-value proof: {err}"))
        })?;
    if proof.next_key != update.next_key {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::CurrentKeyValue,
        });
    }
    let mut hasher = H::default();
    if !proof.proof.verify(&mut hasher, operation.clone(), root) {
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

fn verify_unordered_key_value_from_proto<H, K, V, const N: usize>(
    proto: &ProtoCurrentKeyValueProof,
    requested_key: &[u8],
    root: &H::Digest,
    op_cfg: &(K::Cfg, V::Cfg),
) -> Result<VerifiedUnorderedKeyValue<H::Digest, K, V>, QmdbError>
where
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    UnorderedQmdbOperation<commonware_storage::mmr::Family, K, V>:
        Decode + Read<Cfg = (K::Cfg, V::Cfg)>,
{
    let operation = UnorderedQmdbOperation::<commonware_storage::mmr::Family, K, V>::decode_cfg(
        proto.encoded_operation.as_slice(),
        op_cfg,
    )
    .map_err(|err| {
        QmdbError::CorruptData(format!(
            "failed to decode unordered current key-value operation: {err}",
        ))
    })?;
    let UnorderedQmdbOperation::Update(update) = &operation else {
        return Err(QmdbError::CorruptData(
            "unordered current key-value proof operation must be an update".to_string(),
        ));
    };
    if update.0.as_ref() != requested_key {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::CurrentKeyValue,
        });
    }
    let max_digests = proof_digest_cap(4)?;
    let proof = CurrentOperationProof::<commonware_storage::mmr::Family, H::Digest, N>::decode_cfg(
        proto.proof.as_slice(),
        &max_digests,
    )
    .map_err(|err| {
        QmdbError::CorruptData(format!("failed to decode unordered current proof: {err}"))
    })?;
    let mut hasher = H::default();
    if !proof.verify(&mut hasher, operation.clone(), root) {
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

fn verify_key_exclusion_from_proto<H, K, V, const N: usize>(
    proto: &ProtoCurrentKeyExclusionProof,
    requested_key: &[u8],
    root: &H::Digest,
    op_cfg: &(K::Cfg, V::Cfg),
) -> Result<ExclusionBoundary, QmdbError>
where
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    QmdbOperation<commonware_storage::mmr::Family, K, V>: Decode + Read<Cfg = (K::Cfg, V::Cfg)>,
{
    let max_digests = proof_digest_cap(4)?;
    let proof = CurrentExclusionProof::<
        commonware_storage::mmr::Family,
        K,
        VariableEncoding<V>,
        H::Digest,
        N,
    >::decode_cfg(
        proto.proof.as_slice(),
        &(max_digests, op_cfg.clone(), op_cfg.1.clone()),
    )
    .map_err(|err| {
        QmdbError::CorruptData(format!(
            "failed to decode current key-exclusion proof: {err}"
        ))
    })?;
    let (op_proof, operation, boundary) = match proof {
        CurrentExclusionProof::KeyValue(op_proof, update) => {
            let span_start = update.key.as_ref();
            let span_end = update.next_key.as_ref();
            if span_start == requested_key {
                return Err(QmdbError::ProofVerification {
                    kind: crate::ProofKind::CurrentKeyExclusion,
                });
            }
            let in_span = if span_start >= span_end {
                requested_key >= span_start || requested_key < span_end
            } else {
                requested_key >= span_start && requested_key < span_end
            };
            if !in_span {
                return Err(QmdbError::ProofVerification {
                    kind: crate::ProofKind::CurrentKeyExclusion,
                });
            }
            let boundary = ExclusionBoundary::Span {
                start: update.key.as_ref().to_vec(),
                end: update.next_key.as_ref().to_vec(),
            };
            (
                op_proof,
                QmdbOperation::<commonware_storage::mmr::Family, K, V>::Update(update),
                boundary,
            )
        }
        CurrentExclusionProof::Commit(op_proof, value) => {
            let floor = op_proof.loc;
            (
                op_proof,
                QmdbOperation::<commonware_storage::mmr::Family, K, V>::CommitFloor(value, floor),
                ExclusionBoundary::Empty,
            )
        }
    };
    let mut hasher = H::default();
    if !op_proof.verify(&mut hasher, operation, root) {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::CurrentKeyExclusion,
        });
    }
    Ok(boundary)
}

fn span_contains_key(span_start: &[u8], span_end: &[u8], key: &[u8]) -> bool {
    if span_start >= span_end {
        key >= span_start || key < span_end
    } else {
        key >= span_start && key < span_end
    }
}

fn verify_get_range_from_proto<H, K, V, const N: usize>(
    response: &GetRangeResponse,
    root: &H::Digest,
    start_key: &[u8],
    end_key: Option<&[u8]>,
    op_cfg: &(K::Cfg, V::Cfg),
) -> Result<VerifiedKeyRange<H::Digest, K, V>, QmdbError>
where
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    QmdbOperation<commonware_storage::mmr::Family, K, V>: Decode + Read<Cfg = (K::Cfg, V::Cfg)>,
{
    let mut entries = Vec::with_capacity(response.entries.len());
    for entry in &response.entries {
        let proof = entry.proof.as_option().ok_or_else(|| {
            QmdbError::CorruptData("qmdb get_range entry missing proof".to_string())
        })?;
        let verified = verify_key_value_from_proto::<H, K, V, N>(proof, root, op_cfg)?;
        let QmdbOperation::Update(update) = &verified.operation else {
            return Err(QmdbError::CorruptData(
                "qmdb get_range entry proof did not verify an update".to_string(),
            ));
        };
        if update.key.as_ref() != entry.key.as_slice() {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentKeyValue,
            });
        }
        entries.push(verified);
    }

    if let Some(first) = entries.first() {
        let QmdbOperation::Update(first_update) = &first.operation else {
            unreachable!("range entries were checked as updates");
        };
        if first_update.key.as_ref() != start_key {
            let start_proof = response.start_proof.as_option().ok_or_else(|| {
                QmdbError::CorruptData(
                    "qmdb get_range response missing start boundary proof".to_string(),
                )
            })?;
            match verify_key_exclusion_from_proto::<H, K, V, N>(
                start_proof,
                start_key,
                root,
                op_cfg,
            )? {
                ExclusionBoundary::Span { end, .. }
                    if end.as_slice() == first_update.key.as_ref() => {}
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
        let boundary =
            verify_key_exclusion_from_proto::<H, K, V, N>(start_proof, start_key, root, op_cfg)?;
        match (end_key, boundary) {
            (Some(end_key), ExclusionBoundary::Span { start, end }) => {
                if !span_contains_key(&start, &end, end_key) && end.as_slice() != end_key {
                    return Err(QmdbError::ProofVerification {
                        kind: crate::ProofKind::CurrentKeyExclusion,
                    });
                }
            }
            (None, ExclusionBoundary::Span { end, .. }) if end.as_slice() > start_key => {
                return Err(QmdbError::ProofVerification {
                    kind: crate::ProofKind::CurrentKeyExclusion,
                });
            }
            _ => {}
        }
    }

    for pair in entries.windows(2) {
        let QmdbOperation::Update(left) = &pair[0].operation else {
            unreachable!("range entries were checked as updates");
        };
        let QmdbOperation::Update(right) = &pair[1].operation else {
            unreachable!("range entries were checked as updates");
        };
        if left.next_key.as_ref() != right.key.as_ref() {
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
        let QmdbOperation::Update(last_update) = &last.operation else {
            unreachable!("range entries were checked as updates");
        };
        if response.next_start_key.as_slice() != last_update.next_key.as_ref() {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::CurrentKeyValue,
            });
        }
    } else if let Some(first) = entries.first() {
        let last = entries.last().expect("first exists");
        let QmdbOperation::Update(first_update) = &first.operation else {
            unreachable!("range entries were checked as updates");
        };
        let QmdbOperation::Update(last_update) = &last.operation else {
            unreachable!("range entries were checked as updates");
        };
        if let Some(end_key) = end_key {
            if last_update.next_key.as_ref() != end_key
                && !span_contains_key(
                    last_update.key.as_ref(),
                    last_update.next_key.as_ref(),
                    end_key,
                )
            {
                return Err(QmdbError::ProofVerification {
                    kind: crate::ProofKind::CurrentKeyValue,
                });
            }
        } else if last_update.next_key.as_ref() > first_update.key.as_ref() {
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
