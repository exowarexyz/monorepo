use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::marker::PhantomData;
use std::sync::Arc;

use bytes::Bytes;
use commonware_codec::{Decode, DecodeExt, Encode, Read};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::{
    merkle::{Family, Graftable, Location, Proof},
    qmdb::{
        any::{
            ordered::variable::Operation as QmdbOperation,
            unordered::variable::Operation as UnorderedQmdbOperation, value::VariableEncoding,
        },
        current::ordered::{db::KeyValueProof, ExclusionProof},
        current::proof::{OperationProof, OpsRootWitness, RangeProof},
        operation::Key as QmdbKey,
        verify::{verify_multi_proof, verify_proof},
    },
};
use connectrpc::client::{ClientConfig, ClientTransport, ServerStream};
use connectrpc::ConnectError;
use exoware_sdk::proto::PreferZstdHttpClient;
use exoware_sdk::qmdb::v1::{
    current_key_lookup_result, CurrentKeyExclusionProof as ProtoCurrentKeyExclusionProof,
    CurrentKeyValueProof as ProtoCurrentKeyValueProof,
    CurrentOperationRangeProof as ProtoCurrentOperationRangeProof, CurrentOperationServiceClient,
    GetCurrentOperationRangeRequest, GetManyRequest, GetOperationRangeRequest, GetRangeRequest,
    GetRangeResponse, GetRequest, HistoricalMultiProof, HistoricalOperationRangeProof,
    KeyLookupServiceClient, OperationLogServiceClient, OrderedKeyRangeServiceClient,
    SubscribeRequest, SubscribeResponseView,
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
    F: Graftable,
    H: Hasher,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
> {
    rpc: KeyLookupServiceClient<T>,
    range_rpc: OrderedKeyRangeServiceClient<T>,
    op_cfg: Arc<<QmdbOperation<F, K, V> as Read>::Cfg>,
    _marker: PhantomData<(F, H, K, V)>,
}

impl<F, H, K, V, const N: usize> OrderedConnectClient<PreferZstdHttpClient, F, H, K, V, N>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    QmdbOperation<F, K, V>: Decode + Read<Cfg = (K::Cfg, V::Cfg)>,
{
    pub fn plaintext(base: &str, op_cfg: <QmdbOperation<F, K, V> as Read>::Cfg) -> Self {
        Self::new(
            PreferZstdHttpClient::plaintext(),
            ClientConfig::new(base.parse().expect("qmdb uri")),
            op_cfg,
        )
    }
}

impl<T, F, H, K, V, const N: usize> OrderedConnectClient<T, F, H, K, V, N>
where
    T: ClientTransport + Clone,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    QmdbOperation<F, K, V>: Decode + Read<Cfg = (K::Cfg, V::Cfg)>,
{
    pub fn new(
        transport: T,
        config: ClientConfig,
        op_cfg: <QmdbOperation<F, K, V> as Read>::Cfg,
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
        op_cfg: <QmdbOperation<F, K, V> as Read>::Cfg,
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
    ) -> Result<VerifiedKeyValue<H::Digest, K, V, F>, QmdbError> {
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
        verify_key_value_from_proto::<F, H, K, V, N>(proof, expected_root, self.op_cfg.as_ref())
    }

    pub async fn get_many(
        &self,
        request: GetManyRequest,
        expected_root: &H::Digest,
    ) -> Result<Vec<VerifiedKeyLookup<H::Digest, K, V, F>>, QmdbError> {
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
                    verify_key_value_from_proto::<F, H, K, V, N>(
                        proof,
                        expected_root,
                        self.op_cfg.as_ref(),
                    )
                    .map(VerifiedKeyLookup::Hit)
                }
                Some(current_key_lookup_result::Result::Miss(proof)) => {
                    verify_key_exclusion_from_proto::<F, H, K, V, N>(
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
    ) -> Result<VerifiedKeyRange<H::Digest, K, V, F>, QmdbError> {
        let start_key = request.start_key.clone();
        let end_key = request.end_key.clone();
        let response = self
            .range_rpc
            .get_range(request)
            .await
            .map_err(connect_error_to_qmdb)?
            .into_view()
            .to_owned_message();
        verify_get_range_from_proto::<F, H, K, V, N>(
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
    F: Graftable,
    H: Hasher,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
> {
    rpc: KeyLookupServiceClient<T>,
    op_cfg: Arc<<UnorderedQmdbOperation<F, K, V> as Read>::Cfg>,
    _marker: PhantomData<(F, H, K, V)>,
}

impl<F, H, K, V, const N: usize> UnorderedConnectClient<PreferZstdHttpClient, F, H, K, V, N>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    UnorderedQmdbOperation<F, K, V>: Decode + Read<Cfg = (K::Cfg, V::Cfg)>,
{
    pub fn plaintext(base: &str, op_cfg: <UnorderedQmdbOperation<F, K, V> as Read>::Cfg) -> Self {
        Self::new(
            PreferZstdHttpClient::plaintext(),
            ClientConfig::new(base.parse().expect("qmdb uri")),
            op_cfg,
        )
    }
}

impl<T, F, H, K, V, const N: usize> UnorderedConnectClient<T, F, H, K, V, N>
where
    T: ClientTransport + Clone,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    UnorderedQmdbOperation<F, K, V>: Decode + Read<Cfg = (K::Cfg, V::Cfg)>,
{
    pub fn new(
        transport: T,
        config: ClientConfig,
        op_cfg: <UnorderedQmdbOperation<F, K, V> as Read>::Cfg,
    ) -> Self {
        Self::from_service_client(KeyLookupServiceClient::new(transport, config), op_cfg)
    }

    pub fn from_service_client(
        rpc: KeyLookupServiceClient<T>,
        op_cfg: <UnorderedQmdbOperation<F, K, V> as Read>::Cfg,
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
    ) -> Result<VerifiedUnorderedKeyValue<H::Digest, K, V, F>, QmdbError> {
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
        verify_unordered_key_value_from_proto::<F, H, K, V, N>(
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
    ) -> Result<Vec<VerifiedUnorderedKeyValue<H::Digest, K, V, F>>, QmdbError> {
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
                        verify_unordered_key_value_from_proto::<F, H, K, V, N>(
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
pub struct CurrentOperationRangeProof<D: Digest, Op, const N: usize, F: Family> {
    pub tip: Location<F>,
    pub root: D,
    pub start_location: Location<F>,
    pub operations: Vec<(Location<F>, Op)>,
    pub chunks: Vec<[u8; N]>,
}

pub struct OperationLogSubscription<B, F: Family, H: Hasher, Op: Decode + Encode + Read> {
    stream: ServerStream<B, SubscribeResponseView<'static>>,
    op_cfg: Arc<Op::Cfg>,
    _marker: PhantomData<(F, H, Op)>,
}

impl<B, F, H, Op> OperationLogSubscription<B, F, H, Op>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Display,
    F: Family,
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
pub struct OperationLogClient<T, F: Family, H: Hasher, Op: Encode + Read> {
    rpc: OperationLogServiceClient<T>,
    op_cfg: Arc<Op::Cfg>,
    _marker: PhantomData<(F, H, Op)>,
}

impl<F, H, Op> OperationLogClient<PreferZstdHttpClient, F, H, Op>
where
    F: Family,
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
    F: Family,
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

fn historical_target_root<H: Hasher>(
    ops_root: &[u8],
    ops_root_witness: &[u8],
    expected_root: &H::Digest,
) -> Result<H::Digest, QmdbError>
where
    H::Digest: DecodeExt<()>,
{
    match (ops_root.is_empty(), ops_root_witness.is_empty()) {
        (true, true) => Ok(*expected_root),
        (false, false) => {
            let ops_root = H::Digest::decode_cfg(ops_root, &()).map_err(|err| {
                QmdbError::CorruptData(format!("failed to decode historical ops root: {err}"))
            })?;
            let witness =
                OpsRootWitness::<H::Digest>::decode_cfg(ops_root_witness, &()).map_err(|err| {
                    QmdbError::CorruptData(format!(
                        "failed to decode historical ops-root witness: {err}"
                    ))
                })?;
            let mut hasher = commonware_storage::qmdb::hasher::<H>();
            if !witness.verify(&mut hasher, &ops_root, expected_root) {
                return Err(QmdbError::ProofVerification {
                    kind: crate::ProofKind::BatchMulti,
                });
            }
            Ok(ops_root)
        }
        _ => Err(QmdbError::CorruptData(
            "historical proof must include both ops_root and ops_root_witness, or neither"
                .to_string(),
        )),
    }
}

enum ExclusionBoundary {
    Span { start: Vec<u8>, end: Vec<u8> },
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
    F: Family,
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
    let target_root = historical_target_root::<H>(&proto.ops_root, &proto.ops_root_witness, root)?;
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
    F: Family,
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
    let target_root = historical_target_root::<H>(&proto.ops_root, &proto.ops_root_witness, root)?;
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
    let hasher = commonware_storage::qmdb::hasher::<H>();
    if !verify_proof(&hasher, &proof, start, &decoded_operations, &target_root) {
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
            if bytes.len() != N {
                return Err(QmdbError::CorruptData(format!(
                    "current operation range chunk {index} has invalid length {}",
                    bytes.len()
                )));
            }
            let mut chunk = [0u8; N];
            chunk.copy_from_slice(bytes);
            Ok(chunk)
        })
        .collect::<Result<Vec<_>, QmdbError>>()?;
    let mut hasher = H::default();
    if !proof.verify(&mut hasher, start, &decoded_operations, &chunks, root) {
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

fn verify_key_value_from_proto<F, H, K, V, const N: usize>(
    proto: &ProtoCurrentKeyValueProof,
    root: &H::Digest,
    op_cfg: &(K::Cfg, V::Cfg),
) -> Result<VerifiedKeyValue<H::Digest, K, V, F>, QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    QmdbOperation<F, K, V>: Decode + Read<Cfg = (K::Cfg, V::Cfg)>,
{
    let operation =
        QmdbOperation::<F, K, V>::decode_cfg(proto.encoded_operation.as_slice(), op_cfg).map_err(
            |err| {
                QmdbError::CorruptData(format!(
                    "failed to decode current key-value operation: {err}",
                ))
            },
        )?;
    let QmdbOperation::Update(update) = &operation else {
        return Err(QmdbError::CorruptData(
            "current key-value proof operation must be an update".to_string(),
        ));
    };
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof = KeyValueProof::<F, K, H::Digest, N>::decode_cfg(
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

fn verify_unordered_key_value_from_proto<F, H, K, V, const N: usize>(
    proto: &ProtoCurrentKeyValueProof,
    requested_key: &[u8],
    root: &H::Digest,
    op_cfg: &(K::Cfg, V::Cfg),
) -> Result<VerifiedUnorderedKeyValue<H::Digest, K, V, F>, QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    UnorderedQmdbOperation<F, K, V>: Decode + Read<Cfg = (K::Cfg, V::Cfg)>,
{
    let operation =
        UnorderedQmdbOperation::<F, K, V>::decode_cfg(proto.encoded_operation.as_slice(), op_cfg)
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
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof = OperationProof::<F, H::Digest, N>::decode_cfg(proto.proof.as_slice(), &max_digests)
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

fn verify_key_exclusion_from_proto<F, H, K, V, const N: usize>(
    proto: &ProtoCurrentKeyExclusionProof,
    requested_key: &[u8],
    root: &H::Digest,
    op_cfg: &(K::Cfg, V::Cfg),
) -> Result<ExclusionBoundary, QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    QmdbOperation<F, K, V>: Decode + Read<Cfg = (K::Cfg, V::Cfg)>,
{
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof = ExclusionProof::<F, K, VariableEncoding<V>, H::Digest, N>::decode_cfg(
        proto.proof.as_slice(),
        &(max_digests, op_cfg.clone(), op_cfg.1.clone()),
    )
    .map_err(|err| {
        QmdbError::CorruptData(format!(
            "failed to decode current key-exclusion proof: {err}"
        ))
    })?;
    let (op_proof, operation, boundary) = match proof {
        ExclusionProof::KeyValue(op_proof, update) => {
            let span_start = <K as AsRef<[u8]>>::as_ref(&update.key);
            let span_end = <K as AsRef<[u8]>>::as_ref(&update.next_key);
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
                start: span_start.to_vec(),
                end: span_end.to_vec(),
            };
            (op_proof, QmdbOperation::<F, K, V>::Update(update), boundary)
        }
        ExclusionProof::Commit(op_proof, value) => {
            let floor = op_proof.loc;
            (
                op_proof,
                QmdbOperation::<F, K, V>::CommitFloor(value, floor),
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

fn verify_get_range_from_proto<F, H, K, V, const N: usize>(
    response: &GetRangeResponse,
    root: &H::Digest,
    start_key: &[u8],
    end_key: Option<&[u8]>,
    op_cfg: &(K::Cfg, V::Cfg),
) -> Result<VerifiedKeyRange<H::Digest, K, V, F>, QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    QmdbOperation<F, K, V>: Decode + Read<Cfg = (K::Cfg, V::Cfg)>,
{
    let mut entries = Vec::with_capacity(response.entries.len());
    for entry in &response.entries {
        let proof = entry.proof.as_option().ok_or_else(|| {
            QmdbError::CorruptData("qmdb get_range entry missing proof".to_string())
        })?;
        let verified = verify_key_value_from_proto::<F, H, K, V, N>(proof, root, op_cfg)?;
        let QmdbOperation::Update(update) = &verified.operation else {
            return Err(QmdbError::CorruptData(
                "qmdb get_range entry proof did not verify an update".to_string(),
            ));
        };
        if <K as AsRef<[u8]>>::as_ref(&update.key) != entry.key.as_slice() {
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
        if <K as AsRef<[u8]>>::as_ref(&first_update.key) != start_key {
            let start_proof = response.start_proof.as_option().ok_or_else(|| {
                QmdbError::CorruptData(
                    "qmdb get_range response missing start boundary proof".to_string(),
                )
            })?;
            match verify_key_exclusion_from_proto::<F, H, K, V, N>(
                start_proof,
                start_key,
                root,
                op_cfg,
            )? {
                ExclusionBoundary::Span { end, .. }
                    if end.as_slice() == <K as AsRef<[u8]>>::as_ref(&first_update.key) => {}
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
            verify_key_exclusion_from_proto::<F, H, K, V, N>(start_proof, start_key, root, op_cfg)?;
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
        if <K as AsRef<[u8]>>::as_ref(&left.next_key) != <K as AsRef<[u8]>>::as_ref(&right.key) {
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
        if response.next_start_key.as_slice() != <K as AsRef<[u8]>>::as_ref(&last_update.next_key) {
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
            if <K as AsRef<[u8]>>::as_ref(&last_update.next_key) != end_key
                && !span_contains_key(
                    <K as AsRef<[u8]>>::as_ref(&last_update.key),
                    <K as AsRef<[u8]>>::as_ref(&last_update.next_key),
                    end_key,
                )
            {
                return Err(QmdbError::ProofVerification {
                    kind: crate::ProofKind::CurrentKeyValue,
                });
            }
        } else if <K as AsRef<[u8]>>::as_ref(&last_update.next_key)
            > <K as AsRef<[u8]>>::as_ref(&first_update.key)
        {
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
