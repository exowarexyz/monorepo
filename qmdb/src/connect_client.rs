use std::fmt::Display;
use std::marker::PhantomData;
use std::sync::Arc;

use bytes::Bytes;
use commonware_codec::{Decode, DecodeExt, Read};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::{
    mmr::Location,
    qmdb::{
        any::{
            ordered::variable::Operation as QmdbOperation,
            unordered::variable::Operation as UnorderedQmdbOperation,
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
    CurrentKeyValueProof, GetRequest, HistoricalMultiProof, HistoricalRangeProof,
    ImmutableRangeServiceClient, KeylessRangeServiceClient, OrderedRangeServiceClient,
    OrderedServiceClient, RangeSubscribeRequest, RangeSubscribeResponseView, SubscribeRequest,
    SubscribeResponseView, UnorderedRangeServiceClient,
};
use exoware_sdk_rs::ClientError;
use http_body::Body;

use crate::proof::{
    OperationRangeCheckpoint, RawCurrentRangeProof, RawKeyValueProof, RawMmrProof, RawMultiProof,
    VerifiedKeyValue, VerifiedMultiOperations, VerifiedOperationRange,
};
use crate::QmdbError;

#[derive(Clone, Debug, PartialEq)]
pub struct OrderedSubscribeProof<
    D: Digest,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
> {
    pub resume_sequence_number: u64,
    pub proof: VerifiedMultiOperations<D, K, V>,
}

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

    pub async fn subscribe(
        &self,
        request: SubscribeRequest,
    ) -> Result<OrderedConnectSubscription<T::ResponseBody, H, K, V, N>, QmdbError> {
        let stream = self
            .rpc
            .subscribe(request)
            .await
            .map_err(connect_error_to_qmdb)?;
        Ok(OrderedConnectSubscription {
            stream,
            op_cfg: Arc::clone(&self.op_cfg),
            _marker: PhantomData,
        })
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
        let raw = raw_key_value_from_proto::<H, K, V, N>(proof, self.op_cfg.as_ref())?;
        if !raw.verify::<H>() {
            return Err(QmdbError::CorruptData(
                "key-value proof failed verification".to_string(),
            ));
        }
        Ok(VerifiedKeyValue {
            watermark: raw.watermark,
            root: raw.root,
            location: raw.location,
            operation: raw.operation,
        })
    }
}

pub struct OrderedConnectSubscription<
    B,
    H: Hasher,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
> {
    stream: ServerStream<B, SubscribeResponseView<'static>>,
    op_cfg: Arc<<QmdbOperation<K, V> as Read>::Cfg>,
    _marker: PhantomData<(H, K, V)>,
}

impl<B, H, K, V, const N: usize> OrderedConnectSubscription<B, H, K, V, N>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Display,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    QmdbOperation<K, V>: Decode + Read,
{
    pub async fn message(
        &mut self,
    ) -> Result<Option<OrderedSubscribeProof<H::Digest, K, V>>, QmdbError> {
        let Some(frame) = self.stream.message().await.map_err(connect_error_to_qmdb)? else {
            return Ok(None);
        };
        let frame = frame.to_owned_message();
        let proof = frame.proof.as_option().ok_or_else(|| {
            QmdbError::CorruptData("qmdb subscribe response missing proof".to_string())
        })?;
        let raw = raw_multi_from_proto::<H, K, V>(proof, self.op_cfg.as_ref())?;
        if !raw.verify::<H>() {
            return Err(QmdbError::CorruptData(
                "multi proof failed verification".to_string(),
            ));
        }
        Ok(Some(OrderedSubscribeProof {
            resume_sequence_number: frame.resume_sequence_number,
            proof: VerifiedMultiOperations {
                watermark: raw.watermark,
                root: raw.root,
                operations: raw.operations,
            },
        }))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RangeSubscribeProof<D: Digest, Op> {
    pub resume_sequence_number: u64,
    pub proof: VerifiedOperationRange<D, Op>,
}

pub struct RangeConnectSubscription<B, H: Hasher, Op: Decode + Read> {
    stream: ServerStream<B, RangeSubscribeResponseView<'static>>,
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
            QmdbError::CorruptData("qmdb range subscribe response missing proof".to_string())
        })?;
        let checkpoint = checkpoint_from_proto::<H>(proof)?;
        if !checkpoint.verify::<H>() {
            return Err(QmdbError::CorruptData(
                "range checkpoint proof failed verification".to_string(),
            ));
        }
        let operations = checkpoint
            .encoded_operations
            .iter()
            .enumerate()
            .map(|(offset, bytes)| {
                let location = checkpoint.start_location + offset as u64;
                Op::decode_cfg(bytes.as_slice(), self.op_cfg.as_ref()).map_err(|err| {
                    QmdbError::CorruptData(format!(
                        "failed to decode streamed operation at location {location}: {err}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(RangeSubscribeProof {
            resume_sequence_number: frame.resume_sequence_number,
            proof: VerifiedOperationRange {
                watermark: checkpoint.watermark,
                root: checkpoint.root,
                start_location: checkpoint.start_location,
                operations,
            },
        }))
    }
}

#[derive(Clone)]
pub struct OrderedRangeConnectClient<
    T,
    H: Hasher,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    const N: usize,
> {
    rpc: OrderedRangeServiceClient<T>,
    op_cfg: Arc<<QmdbOperation<K, V> as Read>::Cfg>,
    _marker: PhantomData<(H, K, V)>,
}

impl<H, K, V, const N: usize> OrderedRangeConnectClient<PreferZstdHttpClient, H, K, V, N>
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

impl<T, H, K, V, const N: usize> OrderedRangeConnectClient<T, H, K, V, N>
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
        Self::from_service_client(OrderedRangeServiceClient::new(transport, config), op_cfg)
    }

    pub fn from_service_client(
        rpc: OrderedRangeServiceClient<T>,
        op_cfg: <QmdbOperation<K, V> as Read>::Cfg,
    ) -> Self {
        Self {
            rpc,
            op_cfg: Arc::new(op_cfg),
            _marker: PhantomData,
        }
    }

    pub async fn subscribe(
        &self,
        request: RangeSubscribeRequest,
    ) -> Result<RangeConnectSubscription<T::ResponseBody, H, QmdbOperation<K, V>>, QmdbError> {
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

#[derive(Clone)]
pub struct UnorderedRangeConnectClient<
    T,
    H: Hasher,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
> {
    rpc: UnorderedRangeServiceClient<T>,
    op_cfg: Arc<<UnorderedQmdbOperation<K, V> as Read>::Cfg>,
    _marker: PhantomData<(H, K, V)>,
}

impl<H, K, V> UnorderedRangeConnectClient<PreferZstdHttpClient, H, K, V>
where
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    UnorderedQmdbOperation<K, V>: Decode + Read,
{
    pub fn plaintext(base: &str, op_cfg: <UnorderedQmdbOperation<K, V> as Read>::Cfg) -> Self {
        Self::new(
            PreferZstdHttpClient::plaintext(),
            ClientConfig::new(base.parse().expect("qmdb uri")),
            op_cfg,
        )
    }
}

impl<T, H, K, V> UnorderedRangeConnectClient<T, H, K, V>
where
    T: ClientTransport,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    UnorderedQmdbOperation<K, V>: Decode + Read,
{
    pub fn new(
        transport: T,
        config: ClientConfig,
        op_cfg: <UnorderedQmdbOperation<K, V> as Read>::Cfg,
    ) -> Self {
        Self::from_service_client(UnorderedRangeServiceClient::new(transport, config), op_cfg)
    }

    pub fn from_service_client(
        rpc: UnorderedRangeServiceClient<T>,
        op_cfg: <UnorderedQmdbOperation<K, V> as Read>::Cfg,
    ) -> Self {
        Self {
            rpc,
            op_cfg: Arc::new(op_cfg),
            _marker: PhantomData,
        }
    }

    pub async fn subscribe(
        &self,
        request: RangeSubscribeRequest,
    ) -> Result<RangeConnectSubscription<T::ResponseBody, H, UnorderedQmdbOperation<K, V>>, QmdbError>
    {
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

#[derive(Clone)]
pub struct ImmutableRangeConnectClient<
    T,
    H: Hasher,
    K: commonware_utils::Array + AsRef<[u8]> + commonware_codec::Codec,
    V: commonware_codec::Codec + Send + Sync,
> {
    rpc: ImmutableRangeServiceClient<T>,
    op_cfg: Arc<V::Cfg>,
    _marker: PhantomData<(H, K, V)>,
}

impl<H, K, V> ImmutableRangeConnectClient<PreferZstdHttpClient, H, K, V>
where
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: commonware_utils::Array + AsRef<[u8]> + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    ImmutableOperation<K, V>: Decode<Cfg = V::Cfg> + Read<Cfg = V::Cfg>,
{
    pub fn plaintext(base: &str, value_cfg: V::Cfg) -> Self {
        Self::new(
            PreferZstdHttpClient::plaintext(),
            ClientConfig::new(base.parse().expect("qmdb uri")),
            value_cfg,
        )
    }
}

impl<T, H, K, V> ImmutableRangeConnectClient<T, H, K, V>
where
    T: ClientTransport,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: commonware_utils::Array + AsRef<[u8]> + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    ImmutableOperation<K, V>: Decode<Cfg = V::Cfg> + Read<Cfg = V::Cfg>,
{
    pub fn new(transport: T, config: ClientConfig, value_cfg: V::Cfg) -> Self {
        Self::from_service_client(
            ImmutableRangeServiceClient::new(transport, config),
            value_cfg,
        )
    }

    pub fn from_service_client(rpc: ImmutableRangeServiceClient<T>, value_cfg: V::Cfg) -> Self {
        Self {
            rpc,
            op_cfg: Arc::new(value_cfg),
            _marker: PhantomData,
        }
    }

    pub async fn subscribe(
        &self,
        request: RangeSubscribeRequest,
    ) -> Result<RangeConnectSubscription<T::ResponseBody, H, ImmutableOperation<K, V>>, QmdbError>
    {
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

#[derive(Clone)]
pub struct KeylessRangeConnectClient<T, H: Hasher, V: commonware_codec::Codec + Send + Sync> {
    rpc: KeylessRangeServiceClient<T>,
    op_cfg: Arc<V::Cfg>,
    _marker: PhantomData<(H, V)>,
}

impl<H, V> KeylessRangeConnectClient<PreferZstdHttpClient, H, V>
where
    H: Hasher,
    H::Digest: DecodeExt<()>,
    V: commonware_codec::Codec + Clone + Send + Sync,
    KeylessOperation<V>: Decode<Cfg = V::Cfg> + Read<Cfg = V::Cfg>,
{
    pub fn plaintext(base: &str, value_cfg: V::Cfg) -> Self {
        Self::new(
            PreferZstdHttpClient::plaintext(),
            ClientConfig::new(base.parse().expect("qmdb uri")),
            value_cfg,
        )
    }
}

impl<T, H, V> KeylessRangeConnectClient<T, H, V>
where
    T: ClientTransport,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    V: commonware_codec::Codec + Clone + Send + Sync,
    KeylessOperation<V>: Decode<Cfg = V::Cfg> + Read<Cfg = V::Cfg>,
{
    pub fn new(transport: T, config: ClientConfig, value_cfg: V::Cfg) -> Self {
        Self::from_service_client(KeylessRangeServiceClient::new(transport, config), value_cfg)
    }

    pub fn from_service_client(rpc: KeylessRangeServiceClient<T>, value_cfg: V::Cfg) -> Self {
        Self {
            rpc,
            op_cfg: Arc::new(value_cfg),
            _marker: PhantomData,
        }
    }

    pub async fn subscribe(
        &self,
        request: RangeSubscribeRequest,
    ) -> Result<RangeConnectSubscription<T::ResponseBody, H, KeylessOperation<V>>, QmdbError> {
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

fn checkpoint_from_proto<H>(
    proto: &HistoricalRangeProof,
) -> Result<OperationRangeCheckpoint<H::Digest>, QmdbError>
where
    H: Hasher,
    H::Digest: DecodeExt<()>,
{
    let proof = proto.proof.as_option().ok_or_else(|| {
        QmdbError::CorruptData("historical range proof missing mmr proof".to_string())
    })?;
    Ok(OperationRangeCheckpoint {
        watermark: Location::new(proto.watermark),
        root: decode_digest(&proto.root, "historical range proof root")?,
        start_location: Location::new(proto.start_location),
        proof: raw_mmr_from_proto(proof)?,
        encoded_operations: proto.encoded_operations.clone(),
    })
}

fn raw_multi_from_proto<H, K, V>(
    proto: &HistoricalMultiProof,
    op_cfg: &<QmdbOperation<K, V> as Read>::Cfg,
) -> Result<RawMultiProof<H::Digest, K, V>, QmdbError>
where
    H: Hasher,
    H::Digest: DecodeExt<()>,
    K: QmdbKey + commonware_codec::Codec,
    V: commonware_codec::Codec + Clone + Send + Sync,
    QmdbOperation<K, V>: Decode + Read,
{
    let proof = proto.proof.as_option().ok_or_else(|| {
        QmdbError::CorruptData("historical multi proof missing mmr proof".to_string())
    })?;
    let operations = proto
        .operations
        .iter()
        .map(|operation| {
            Ok((
                Location::new(operation.location),
                QmdbOperation::<K, V>::decode_cfg(operation.encoded_operation.as_slice(), op_cfg)
                    .map_err(|err| {
                    QmdbError::CorruptData(format!(
                        "failed to decode multi-proof operation at {}: {err}",
                        operation.location
                    ))
                })?,
            ))
        })
        .collect::<Result<Vec<_>, QmdbError>>()?;
    Ok(RawMultiProof {
        watermark: Location::new(proto.watermark),
        root: decode_digest(&proto.root, "historical multi proof root")?,
        proof: raw_mmr_from_proto(proof)?,
        operations,
    })
}

fn raw_key_value_from_proto<H, K, V, const N: usize>(
    proto: &CurrentKeyValueProof,
    op_cfg: &<QmdbOperation<K, V> as Read>::Cfg,
) -> Result<RawKeyValueProof<H::Digest, K, V, N>, QmdbError>
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
    Ok(RawKeyValueProof {
        watermark: Location::new(proto.watermark),
        root: decode_digest(&proto.root, "current key-value proof root")?,
        location: Location::new(proto.location),
        chunk: proto.chunk.as_slice().try_into().map_err(|_| {
            QmdbError::CorruptData(format!(
                "invalid chunk length {}, expected {N}",
                proto.chunk.len()
            ))
        })?,
        range_proof: RawCurrentRangeProof {
            proof: raw_mmr_from_proto(mmr_proof)?,
            partial_chunk_digest: range_proof
                .partial_chunk_digest
                .as_ref()
                .map(|digest| decode_digest(digest, "current range partial chunk digest"))
                .transpose()?,
            ops_root: decode_digest(&range_proof.ops_root, "current range ops root")?,
        },
        operation: QmdbOperation::<K, V>::decode_cfg(proto.encoded_operation.as_slice(), op_cfg)
            .map_err(|err| {
                QmdbError::CorruptData(format!(
                    "failed to decode current key-value operation at {}: {err}",
                    proto.location
                ))
            })?,
    })
}
