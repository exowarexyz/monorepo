//! Verifying client for `qmdb.v1.OperationLogService`.

use std::fmt::Display;
use std::marker::PhantomData;
use std::num::NonZeroU64;
use std::sync::Arc;

use bytes::Bytes;
use commonware_codec::{Decode, DecodeExt, Encode, Read};
use commonware_cryptography::{Digest, Hasher};
use commonware_storage::{
    merkle::{Family, Graftable, Location, Proof},
    qmdb::{
        current::proof::OpsRootWitness,
        sync::{
            FeedbackTx, Request as SyncRequest, Response as SyncResponse, Source,
            Target as SyncTarget,
        },
        verify::{verify_multi_proof, verify_proof_and_pinned_nodes},
    },
};
use commonware_utils::range::NonEmptyRange;
use connectrpc::client::{ClientConfig, ClientTransport, ServerStream};
use exoware_sdk::proto::PreferZstdHttpClient;
use http_body::Body;

use crate::proof::{VerifiedOperationRange, VerifiedOperations};
use crate::request::{OperationLocations, OperationWindow};
use crate::service::proto::qmdb::v1::{
    GetOperationRangeRequest, GetOperationsRequest, HistoricalMultiProof,
    HistoricalOperationRangeProof, OperationLogServiceClient, SubscribeRequest,
    SubscribeResponseView,
};
use crate::{decode_digest, QmdbError};

use super::{connect_error_to_qmdb, proof_digest_cap};

#[derive(Clone, Debug, PartialEq)]
pub struct OperationLogSubscribeProof<D: Digest, Op, F: Family> {
    pub resume_sequence_number: u64,
    pub tip: Location<F>,
    /// Canonical root at `tip`; see [`crate::proof::VerifiedOperationRange::root`].
    pub root: D,
    pub operations: Vec<(Location<F>, Op)>,
}

impl<T, F, H, Op> Source for OperationLogClient<T, F, H, Op>
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

    async fn serve(
        &self,
        request: SyncRequest<Self::Family>,
    ) -> Result<
        (
            SyncResponse<Self::Family, Self::Op, Self::Digest>,
            FeedbackTx,
        ),
        Self::Error,
    > {
        let proto = self
            .operation_range_proto(request.size(), request.start(), request.max_ops())
            .await?;
        Ok((self.decode_sync_response(proto, request)?, None))
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
        let max_digests = proof_digest_cap::<H::Digest>(&proof.proof);
        let merkle_proof = Proof::<F, H::Digest>::decode_cfg(proof.proof.as_ref(), &max_digests)
            .map_err(|err| {
                QmdbError::CorruptData(format!("failed to decode historical multi proof: {err}"))
            })?;
        let tip = merkle_proof.leaves.checked_sub(1).ok_or_else(|| {
            QmdbError::CorruptData("subscription proof has no leaves".to_string())
        })?;
        let expected_root = root_for_tip(tip)?;
        let (root, operations) = verify_multi_from_proto::<F, H, Op>(
            proof,
            &merkle_proof,
            self.op_cfg.as_ref(),
            &expected_root,
        )?;
        Ok(Some(OperationLogSubscribeProof {
            resume_sequence_number: frame.resume_sequence_number,
            tip,
            root,
            operations,
        }))
    }
}

/// Client for `qmdb.v1.OperationLogService`, parameterized on the Merkle
/// family and backend operation type. Implements Commonware QMDB sync [`Source`].
/// Callers supply a target with an independently trusted operation-log root.
pub struct OperationLogClient<T, F: Graftable, H: Hasher, Op: Encode + Read> {
    rpc: OperationLogServiceClient<T>,
    op_cfg: Arc<Op::Cfg>,
    _marker: PhantomData<(F, H, Op)>,
}

impl<T, F, H, Op> Clone for OperationLogClient<T, F, H, Op>
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
    ) -> Result<VerifiedOperationRange<H::Digest, Op, F>, QmdbError> {
        let tip = Location::<F>::new(request.tip);
        let window =
            OperationWindow::new(request.tip, request.start_location, request.max_locations)?;
        let proof = fetch_operation_range_proof(
            &self.rpc,
            request,
            "qmdb get_operation_range response missing proof",
        )
        .await?;
        let (root, operations) = verify_operation_range_from_proto::<F, H, Op>(
            &proof,
            self.op_cfg.as_ref(),
            expected_root,
            window,
        )?;
        Ok(VerifiedOperationRange {
            tip,
            root,
            start_location: Location::<F>::new(proof.start_location),
            operations,
        })
    }

    /// Fetch and verify the operations at `request.locations` of `request.tip`.
    pub async fn get_operations(
        &self,
        request: GetOperationsRequest,
        expected_root: &H::Digest,
    ) -> Result<VerifiedOperations<H::Digest, Op, F>, QmdbError> {
        let tip = Location::<F>::new(request.tip);
        let requested = request.locations.clone();
        let locations = OperationLocations::new(request.tip, &requested)?;
        let response = self
            .rpc
            .get_operations(request)
            .await
            .map_err(connect_error_to_qmdb)?
            .into_view()
            .to_owned_message();
        let proof = response.proof.as_option().ok_or_else(|| {
            QmdbError::CorruptData("qmdb get_operations response missing proof".to_string())
        })?;
        let max_digests = proof_digest_cap::<H::Digest>(&proof.proof);
        let merkle_proof = Proof::<F, H::Digest>::decode_cfg(proof.proof.as_ref(), &max_digests)
            .map_err(|err| {
                QmdbError::CorruptData(format!("failed to decode operations multi proof: {err}"))
            })?;
        locations
            .validate(
                proof.operations.iter().map(|op| op.location),
                merkle_proof.leaves.as_u64(),
            )
            .map_err(QmdbError::RangeMismatch)?;
        let (root, operations) = verify_multi_from_proto::<F, H, Op>(
            proof,
            &merkle_proof,
            self.op_cfg.as_ref(),
            expected_root,
        )?;
        Ok(VerifiedOperations {
            tip,
            root,
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

    /// Derive a sync target by authenticating its operation root against a trusted current root
    pub async fn current_sync_target(
        &self,
        range: NonEmptyRange<Location<F>>,
        expected_current_root: &H::Digest,
    ) -> Result<SyncTarget<F, H::Digest>, QmdbError> {
        let proto = self
            .operation_range_proto(range.end(), range.start(), NonZeroU64::MIN)
            .await?;
        current_sync_target_from_witness::<F, H>(
            proto.ops_root.as_ref(),
            proto.ops_root_witness.as_ref(),
            expected_current_root,
            range,
        )
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
        // The upstream maximum permits a smaller transport batch
        let max_locations = u32::try_from(max_ops.get()).unwrap_or(u32::MAX);
        let proof = fetch_operation_range_proof(
            &self.rpc,
            GetOperationRangeRequest {
                tip,
                start_location: start_loc.as_u64(),
                max_locations,
                ..Default::default()
            },
            "sync operation range response missing proof",
        )
        .await?;
        Ok(proof)
    }

    fn decode_sync_response(
        &self,
        proto: HistoricalOperationRangeProof,
        request: SyncRequest<F>,
    ) -> Result<SyncResponse<F, Op, H::Digest>, QmdbError> {
        let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
        let proof = Proof::<F, H::Digest>::decode_cfg(proto.proof.as_ref(), &max_digests).map_err(
            |err| {
                QmdbError::CorruptData(format!(
                    "failed to decode sync operation range proof: {err}"
                ))
            },
        )?;
        let operations = proto
            .encoded_operations
            .iter()
            .map(|bytes| {
                Op::decode_cfg(bytes.as_ref(), self.op_cfg.as_ref()).map_err(|err| {
                    QmdbError::CorruptData(format!("failed to decode sync operation: {err}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        match request {
            SyncRequest::Operations { .. } => Ok(SyncResponse::Operations { proof, operations }),
            SyncRequest::Boundary { .. } => {
                let [op] = operations.try_into().map_err(|operations: Vec<Op>| {
                    QmdbError::CorruptData(format!(
                        "sync boundary response contained {} operations instead of one",
                        operations.len()
                    ))
                })?;
                let pinned_nodes = proto
                    .pinned_nodes
                    .iter()
                    .map(|bytes| {
                        decode_digest::<H::Digest>(bytes.as_ref(), "operation sync pinned node")
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(SyncResponse::Boundary {
                    proof,
                    op,
                    pinned_nodes,
                })
            }
        }
    }
}

async fn fetch_operation_range_proof<T>(
    rpc: &OperationLogServiceClient<T>,
    request: GetOperationRangeRequest,
    missing_proof_message: &'static str,
) -> Result<HistoricalOperationRangeProof, QmdbError>
where
    T: ClientTransport,
    T::ResponseBody: Body<Data = Bytes> + Unpin,
    <T::ResponseBody as Body>::Error: Display,
{
    let response = rpc
        .get_operation_range(request)
        .await
        .map_err(connect_error_to_qmdb)?
        .into_view()
        .to_owned_message();
    let proof = response
        .proof
        .as_option()
        .cloned()
        .ok_or_else(|| QmdbError::CorruptData(missing_proof_message.to_string()))?;
    Ok(proof)
}

/// Build the Commonware streaming-sync target for a current DB.
///
/// Current sync verifies fetched batches against the ops root, but Exoware
/// callers anchor trust in the canonical current root. The witness is the
/// bridge between those roots, so construct the sync target only after it
/// verifies.
fn current_sync_target_from_witness<F, H>(
    ops_root: &[u8],
    ops_root_witness: &[u8],
    current_root: &H::Digest,
    range: NonEmptyRange<Location<F>>,
) -> Result<SyncTarget<F, H::Digest>, QmdbError>
where
    F: Graftable,
    H::Digest: DecodeExt<()>,
    H: Hasher,
{
    let ops_root = decode_digest::<H::Digest>(ops_root, "current sync ops root")?;
    let witness = OpsRootWitness::<F, H::Digest>::decode(ops_root_witness).map_err(|err| {
        QmdbError::CorruptData(format!(
            "failed to decode current sync ops-root witness: {err}"
        ))
    })?;
    if !witness.verify::<H>(&ops_root, current_root) {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::RangeCheckpoint,
        });
    }
    Ok(SyncTarget::new(ops_root, range))
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
    if ops_root.is_empty() {
        return Err(QmdbError::CorruptData(
            "historical proof missing ops_root".to_string(),
        ));
    }
    let ops_root = decode_digest::<H::Digest>(ops_root, "historical ops root")?;
    if ops_root_witness.is_empty() {
        if ops_root != *expected_root {
            return Err(QmdbError::ProofVerification {
                kind: crate::ProofKind::BatchMulti,
            });
        }
        return Ok(ops_root);
    }
    let witness = OpsRootWitness::<F, H::Digest>::decode(ops_root_witness).map_err(|err| {
        QmdbError::CorruptData(format!(
            "failed to decode historical ops-root witness: {err}"
        ))
    })?;
    if !witness.verify::<H>(&ops_root, expected_root) {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::BatchMulti,
        });
    }
    Ok(ops_root)
}

fn verify_multi_from_proto<F, H, Op>(
    proto: &HistoricalMultiProof,
    proof: &Proof<F, H::Digest>,
    op_cfg: &Op::Cfg,
    root: &H::Digest,
) -> Result<(H::Digest, Vec<(Location<F>, Op)>), QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read,
{
    let operations = proto
        .operations
        .iter()
        .map(|op| {
            let decoded = Op::decode_cfg(op.encoded_operation.as_ref(), op_cfg).map_err(|err| {
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
    if !verify_multi_proof::<H, _, _>(proof, &operations, &target_root) {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::BatchMulti,
        });
    }
    Ok((*root, operations))
}

fn verify_operation_range_from_proto<F, H, Op>(
    proto: &HistoricalOperationRangeProof,
    op_cfg: &Op::Cfg,
    root: &H::Digest,
    window: OperationWindow,
) -> Result<(H::Digest, Vec<Op>), QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read,
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
        Proof::<F, H::Digest>::decode_cfg(proto.proof.as_ref(), &max_digests).map_err(|err| {
            QmdbError::CorruptData(format!(
                "failed to decode historical operation range proof: {err}"
            ))
        })?;
    window
        .validate(
            proto.start_location,
            proto.encoded_operations.len(),
            proof.leaves.as_u64(),
        )
        .map_err(QmdbError::RangeMismatch)?;
    let start = Location::<F>::new(proto.start_location);
    let decoded_operations = proto
        .encoded_operations
        .iter()
        .map(|bytes| {
            let decoded = Op::decode_cfg(bytes.as_ref(), op_cfg).map_err(|err| {
                QmdbError::CorruptData(format!("failed to decode operation range entry: {err}"))
            })?;
            Ok(decoded)
        })
        .collect::<Result<Vec<_>, QmdbError>>()?;
    let pinned_nodes = proto
        .pinned_nodes
        .iter()
        .map(|bytes| {
            decode_digest::<H::Digest>(bytes.as_ref(), "historical operation range pinned node")
        })
        .collect::<Result<Vec<_>, QmdbError>>()?;
    if !verify_proof_and_pinned_nodes::<H, _, _>(
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
    Ok((*root, decoded_operations))
}
