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
            unordered::variable::Operation as UnorderedQmdbOperation,
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
    CurrentKeyValueProof, GetManyRequest, GetManyResponse, GetRequest, HistoricalMultiProof,
    OrderedServiceClient, RangeServiceClient, SubscribeRequest, SubscribeResponseView,
};
use exoware_sdk::ClientError;
use http_body::Body;

use crate::proof::{VerifiedKeyValue, VerifiedMultiOperations};
use crate::QmdbError;

#[derive(Clone)]
pub struct OrderedConnectClient<
    T,
    H: Hasher,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
> {
    rpc: OrderedServiceClient<T>,
    op_cfg: Arc<<QmdbOperation<commonware_storage::mmr::Family, K, V> as Read>::Cfg>,
    _marker: PhantomData<(H, K, V)>,
}

impl<H, K, V, const N: usize> OrderedConnectClient<PreferZstdHttpClient, H, K, V, N>
where
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    QmdbOperation<commonware_storage::mmr::Family, K, V>: Decode + Read,
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
    T: ClientTransport,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    QmdbOperation<commonware_storage::mmr::Family, K, V>: Decode + Read,
{
    pub fn new(
        transport: T,
        config: ClientConfig,
        op_cfg: <QmdbOperation<commonware_storage::mmr::Family, K, V> as Read>::Cfg,
    ) -> Self {
        Self::from_service_client(OrderedServiceClient::new(transport, config), op_cfg)
    }

    pub fn from_service_client(
        rpc: OrderedServiceClient<T>,
        op_cfg: <QmdbOperation<commonware_storage::mmr::Family, K, V> as Read>::Cfg,
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
    ) -> Result<VerifiedMultiOperations<H::Digest, K, V>, QmdbError> {
        let response = self
            .rpc
            .get_many(request)
            .await
            .map_err(connect_error_to_qmdb)?
            .into_view()
            .to_owned_message();
        let proof = response.proof.as_option().ok_or_else(|| {
            QmdbError::CorruptData("qmdb get_many response missing proof".to_string())
        })?;
        let ops_root = verify_get_many_current_anchor::<H, K, V, N>(
            &response,
            expected_root,
            self.op_cfg.as_ref(),
        )?;
        let (root, operations) = verify_multi_from_proto::<H, _, _>(
            proof,
            self.op_cfg.as_ref(),
            crate::ProofKind::HistoricalMultiKey,
            &ops_root,
            |bytes, cfg| {
                QmdbOperation::<commonware_storage::mmr::Family, K, V>::decode_cfg(bytes, cfg)
            },
        )?;
        Ok(VerifiedMultiOperations { root, operations })
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
    proto: &CurrentKeyValueProof,
    root: &H::Digest,
    op_cfg: &<QmdbOperation<commonware_storage::mmr::Family, K, V> as Read>::Cfg,
) -> Result<VerifiedKeyValue<H::Digest, K, V>, QmdbError>
where
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    QmdbOperation<commonware_storage::mmr::Family, K, V>: Decode + Read,
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
    let QmdbOperation::Update(_) = &operation else {
        return Err(QmdbError::CorruptData(
            "current key-value proof operation must be an update".to_string(),
        ));
    };
    let max_digests = proof_digest_cap(4)?;
    let proof = CurrentOperationProof::<commonware_storage::mmr::Family, H::Digest, N>::decode_cfg(
        proto.proof.as_slice(),
        &max_digests,
    )
    .map_err(|err| {
        QmdbError::CorruptData(format!("failed to decode current key-value proof: {err}"))
    })?;
    let mut hasher = H::default();
    if !proof.verify(&mut hasher, operation.clone(), root) {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::CurrentKeyValue,
        });
    }
    Ok(VerifiedKeyValue {
        root: *root,
        location: proof.loc,
        operation,
    })
}

fn verify_get_many_current_anchor<H, K, V, const N: usize>(
    response: &GetManyResponse,
    root: &H::Digest,
    op_cfg: &<QmdbOperation<commonware_storage::mmr::Family, K, V> as Read>::Cfg,
) -> Result<H::Digest, QmdbError>
where
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    QmdbOperation<commonware_storage::mmr::Family, K, V>: Decode + Read,
{
    if response.current_proof.is_empty() {
        return Err(QmdbError::CorruptData(
            "qmdb get_many response missing current anchor proof".to_string(),
        ));
    }
    let max_digests = proof_digest_cap(1)?;
    let proof = CurrentOperationProof::<commonware_storage::mmr::Family, H::Digest, N>::decode_cfg(
        response.current_proof.as_slice(),
        &max_digests,
    )
    .map_err(|err| {
        QmdbError::CorruptData(format!("failed to decode current anchor proof: {err}"))
    })?;
    let historical = response.proof.as_option().ok_or_else(|| {
        QmdbError::CorruptData("qmdb get_many response missing proof".to_string())
    })?;
    let operation = historical
        .operations
        .iter()
        .find(|operation| operation.location == proof.loc.as_u64())
        .ok_or_else(|| {
            QmdbError::CorruptData(format!(
                "current anchor location {} is absent from historical proof operations",
                proof.loc
            ))
        })?;
    let operation = QmdbOperation::<commonware_storage::mmr::Family, K, V>::decode_cfg(
        operation.encoded_operation.as_slice(),
        op_cfg,
    )
    .map_err(|err| {
        QmdbError::CorruptData(format!(
            "failed to decode current anchor operation at {}: {err}",
            proof.loc
        ))
    })?;
    let mut hasher = H::default();
    if !proof.verify(&mut hasher, operation, root) {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::CurrentRange,
        });
    }
    Ok(proof.range_proof.ops_root)
}
