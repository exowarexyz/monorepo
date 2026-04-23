use std::fmt::Display;
use std::marker::PhantomData;
use std::sync::Arc;

use bytes::Bytes;
use commonware_codec::{Decode, DecodeExt, Read};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::{
    mmr::{self, Location, StandardHasher},
    qmdb::{
        any::{
            ordered::variable::Operation as QmdbOperation,
            unordered::variable::Operation as UnorderedQmdbOperation,
        },
        current::proof::{
            OperationProof as CurrentOperationProof, RangeProof as CurrentRangeProof,
        },
        immutable::Operation as ImmutableOperation,
        keyless::Operation as KeylessOperation,
        operation::Key as QmdbKey,
    },
};
use connectrpc::client::{ClientConfig, ClientTransport, ServerStream};
use connectrpc::ConnectError;
use exoware_sdk_rs::proto::PreferZstdHttpClient;
use exoware_sdk_rs::store::qmdb::v1::{
    CurrentKeyValueProof, GetManyRequest, GetRequest, HistoricalMultiProof, OrderedServiceClient,
    RangeServiceClient, SubscribeRequest, SubscribeResponseView,
};
use exoware_sdk_rs::ClientError;
use http_body::Body;

use crate::proof::{RawMmrProof, VerifiedKeyValue, VerifiedMultiOperations};
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
    op_cfg: Arc<<QmdbOperation<K, V> as Read>::Cfg>,
    _marker: PhantomData<(H, K, V)>,
}

impl<H, K, V, const N: usize> OrderedConnectClient<PreferZstdHttpClient, H, K, V, N>
where
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    QmdbOperation<K, V>: Decode + Read,
{
    pub fn plaintext(base: &str, op_cfg: <QmdbOperation<K, V> as Read>::Cfg) -> Self {
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
    QmdbOperation<K, V>: Decode + Read,
{
    pub fn new(
        transport: T,
        config: ClientConfig,
        op_cfg: <QmdbOperation<K, V> as Read>::Cfg,
    ) -> Self {
        Self::from_service_client(OrderedServiceClient::new(transport, config), op_cfg)
    }

    pub fn from_service_client(
        rpc: OrderedServiceClient<T>,
        op_cfg: <QmdbOperation<K, V> as Read>::Cfg,
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
        verify_key_value_from_proto::<H, K, V, N>(proof, self.op_cfg.as_ref())
    }

    pub async fn get_many(
        &self,
        request: GetManyRequest,
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
        let (root, operations) = verify_multi_from_proto::<H, _, _>(
            proof,
            self.op_cfg.as_ref(),
            crate::ProofKind::HistoricalMultiKey,
            |bytes, cfg| QmdbOperation::<K, V>::decode_cfg(bytes, cfg),
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
            |bytes, cfg| Op::decode_cfg(bytes, cfg),
        )?;
        Ok(Some(RangeSubscribeProof {
            resume_sequence_number: frame.resume_sequence_number,
            root,
            operations,
        }))
    }
}

/// Client for `store.qmdb.v1.RangeService`, parameterized on the backend
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

pub type OrderedRangeConnectClient<T, H, K, V> = RangeConnectClient<T, H, QmdbOperation<K, V>>;
pub type UnorderedRangeConnectClient<T, H, K, V> =
    RangeConnectClient<T, H, UnorderedQmdbOperation<K, V>>;
pub type ImmutableRangeConnectClient<T, H, K, V> =
    RangeConnectClient<T, H, ImmutableOperation<K, V>>;
pub type KeylessRangeConnectClient<T, H, V> = RangeConnectClient<T, H, KeylessOperation<V>>;

fn connect_error_to_qmdb(err: ConnectError) -> QmdbError {
    QmdbError::Client(ClientError::Rpc(Box::new(err)))
}

fn decode_digest<D: Digest + DecodeExt<()>>(bytes: &[u8], label: &str) -> Result<D, QmdbError> {
    D::decode(bytes)
        .map_err(|err| QmdbError::CorruptData(format!("failed to decode {label}: {err}")))
}

fn raw_mmr_from_proto<D: Digest + Decode>(
    proto: &exoware_sdk_rs::store::qmdb::v1::MmrProof,
) -> Result<RawMmrProof<D>, QmdbError> {
    Ok(RawMmrProof {
        leaves: Location::new(proto.leaves),
        digests: proto
            .digests
            .iter()
            .map(|digest| decode_digest(digest, "mmr proof digest"))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn verify_multi_from_proto<H, Op, F>(
    proto: &HistoricalMultiProof,
    op_cfg: &Op::Cfg,
    kind: crate::ProofKind,
    decode: F,
) -> Result<(H::Digest, Vec<(Location, Op)>), QmdbError>
where
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Read,
    F: Fn(&[u8], &Op::Cfg) -> Result<Op, commonware_codec::Error>,
{
    let proof = proto.proof.as_option().ok_or_else(|| {
        QmdbError::CorruptData("historical multi proof missing mmr proof".to_string())
    })?;
    let root = decode_digest(&proto.root, "historical multi proof root")?;
    let encoded: Vec<(&[u8], Location)> = proto
        .operations
        .iter()
        .map(|op| (op.encoded_operation.as_slice(), Location::new(op.location)))
        .collect();
    let mmr_proof = raw_mmr_from_proto(proof)?;
    let mut hasher = StandardHasher::<H>::new();
    if !mmr::Proof::from(&mmr_proof).verify_multi_inclusion(&mut hasher, &encoded, &root) {
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
    Ok((root, operations))
}

fn verify_key_value_from_proto<H, K, V, const N: usize>(
    proto: &CurrentKeyValueProof,
    op_cfg: &<QmdbOperation<K, V> as Read>::Cfg,
) -> Result<VerifiedKeyValue<H::Digest, K, V>, QmdbError>
where
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    QmdbOperation<K, V>: Decode + Read,
{
    let range_proof = proto.range_proof.as_option().ok_or_else(|| {
        QmdbError::CorruptData("current key-value proof missing range proof".to_string())
    })?;
    let mmr_proof = range_proof.proof.as_option().ok_or_else(|| {
        QmdbError::CorruptData("current range proof missing mmr proof".to_string())
    })?;
    let root = decode_digest(&proto.root, "current key-value proof root")?;
    let location = Location::new(proto.location);
    let chunk: [u8; N] = proto.chunk.as_slice().try_into().map_err(|_| {
        QmdbError::CorruptData(format!(
            "invalid chunk length {}, expected {N}",
            proto.chunk.len()
        ))
    })?;
    let operation = QmdbOperation::<K, V>::decode_cfg(proto.encoded_operation.as_slice(), op_cfg)
        .map_err(|err| {
        QmdbError::CorruptData(format!(
            "failed to decode current key-value operation at {}: {err}",
            proto.location
        ))
    })?;
    let QmdbOperation::Update(_) = &operation else {
        return Err(QmdbError::CorruptData(
            "current key-value proof operation must be an update".to_string(),
        ));
    };
    let proof = CurrentOperationProof {
        loc: location,
        chunk,
        range_proof: CurrentRangeProof {
            proof: mmr::Proof::from(&raw_mmr_from_proto(mmr_proof)?),
            partial_chunk_digest: range_proof
                .partial_chunk_digest
                .as_ref()
                .map(|digest| decode_digest(digest, "current range partial chunk digest"))
                .transpose()?,
            ops_root: decode_digest(&range_proof.ops_root, "current range ops root")?,
        },
    };
    let mut hasher = H::default();
    if !proof.verify(&mut hasher, operation.clone(), &root) {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::CurrentKeyValue,
        });
    }
    Ok(VerifiedKeyValue {
        root,
        location,
        operation,
    })
}
