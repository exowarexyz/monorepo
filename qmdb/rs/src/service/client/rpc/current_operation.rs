//! Verifying client for `qmdb.v1.CurrentOperationService`.

use std::fmt::Display;
use std::marker::PhantomData;
use std::sync::Arc;

use bytes::Bytes;
use commonware_codec::{Copying, Decode, DecodeExt, Encode, Read};
use commonware_cryptography::Hasher;
use commonware_storage::{
    merkle::{Graftable, Location},
    qmdb::current::proof::RangeProof,
};
use connectrpc::client::{ClientConfig, ClientTransport};
use exoware_sdk::proto::PreferZstdHttpClient;
use http_body::Body;

use crate::proof::VerifiedCurrentRange;
use crate::request::OperationWindow;
use crate::service::proto::qmdb::v1::{
    CurrentOperationRangeProof as ProtoCurrentOperationRangeProof, CurrentOperationServiceClient,
    GetCurrentOperationRangeRequest,
};
use crate::QmdbError;

use super::{connect_error_to_qmdb, proof_digest_cap};

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
    ) -> Result<VerifiedCurrentRange<H::Digest, Op, N, F>, QmdbError> {
        let tip = Location::<F>::new(request.tip);
        let window =
            OperationWindow::new(request.tip, request.start_location, request.max_locations)?;
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
        let (root, operations, chunks) = verify_current_operation_range_from_proto::<F, H, Op, N>(
            proof,
            self.op_cfg.as_ref(),
            expected_root,
            window,
        )?;
        Ok(VerifiedCurrentRange {
            tip,
            root,
            start_location: Location::<F>::new(proof.start_location),
            operations,
            chunks,
        })
    }
}

fn verify_current_operation_range_from_proto<F, H, Op, const N: usize>(
    proto: &ProtoCurrentOperationRangeProof,
    op_cfg: &Op::Cfg,
    root: &H::Digest,
    window: OperationWindow,
) -> Result<(H::Digest, Vec<Op>, Vec<[u8; N]>), QmdbError>
where
    F: Graftable,
    H: Hasher,
    H::Digest: DecodeExt<()>,
    Op: Decode + Encode + Read,
{
    if proto.encoded_operations.is_empty() {
        return Err(QmdbError::CorruptData(
            "current operation range proof has no operations".to_string(),
        ));
    }
    let max_digests = proof_digest_cap::<H::Digest>(&proto.proof);
    let proof = RangeProof::<F, H::Digest>::decode_cfg(Copying(proto.proof.as_ref()), &max_digests)
        .map_err(|err| {
            QmdbError::CorruptData(format!(
                "failed to decode current operation range proof: {err}"
            ))
        })?;
    window
        .validate(
            proto.start_location,
            proto.encoded_operations.len(),
            proof.proof.leaves.as_u64(),
        )
        .map_err(QmdbError::RangeMismatch)?;
    let start = Location::<F>::new(proto.start_location);
    let decoded_operations = proto
        .encoded_operations
        .iter()
        .map(|bytes| {
            let decoded = Op::decode_cfg(Copying(bytes.as_ref()), op_cfg).map_err(|err| {
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
            <[u8; N]>::decode(Copying(bytes.as_ref())).map_err(|e| {
                QmdbError::CorruptData(format!(
                    "current operation range chunk {index} decode error: {e}"
                ))
            })
        })
        .collect::<Result<Vec<_>, QmdbError>>()?;
    if !proof.verify::<H, _, N>(start, &decoded_operations, &chunks, root) {
        return Err(QmdbError::ProofVerification {
            kind: crate::ProofKind::CurrentRange,
        });
    }
    Ok((*root, decoded_operations, chunks))
}
