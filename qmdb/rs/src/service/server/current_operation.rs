//! `qmdb.v1.CurrentOperationService`: current-state operation ranges.

use std::future::Future;
use std::sync::Arc;

use commonware_codec::Encode;
use commonware_storage::merkle::{Graftable, Location};
use connectrpc::{PreEncoded, RequestContext as Context, ServiceRequest};

use crate::proof::CurrentOperationRangeProofResult;
use crate::service::proto::qmdb::v1::{
    CurrentOperationService, GetCurrentOperationRangeRequest, GetCurrentOperationRangeResponse,
};
use crate::QmdbError;

use super::{encode, qmdb_error_to_connect};

/// Read capabilities needed by [`CurrentOperationServer`].
pub(crate) trait CurrentOperationReader<const N: usize>: Send + Sync + 'static {
    type Family: Graftable;
    type Digest: commonware_cryptography::Digest;
    type Operation: commonware_codec::Codec;

    fn current_operation_range_proof(
        &self,
        watermark: Location<Self::Family>,
        start_location: Location<Self::Family>,
        max_locations: u32,
        min_sequence_number: Option<u64>,
    ) -> impl Future<
        Output = Result<
            CurrentOperationRangeProofResult<Self::Digest, Self::Operation, N, Self::Family>,
            QmdbError,
        >,
    > + Send;
}

/// `CurrentOperationService` handler over any [`CurrentOperationReader`].
pub(crate) struct CurrentOperationServer<R: CurrentOperationReader<N>, const N: usize> {
    reader: Arc<R>,
}

impl<R: CurrentOperationReader<N>, const N: usize> Clone for CurrentOperationServer<R, N> {
    fn clone(&self) -> Self {
        Self {
            reader: self.reader.clone(),
        }
    }
}

impl<R: CurrentOperationReader<N>, const N: usize> CurrentOperationServer<R, N> {
    pub(crate) fn new(reader: Arc<R>) -> Self {
        Self { reader }
    }
}

impl<R, const N: usize> CurrentOperationService for CurrentOperationServer<R, N>
where
    R: CurrentOperationReader<N>,
    R::Operation: Encode,
{
    fn get_current_operation_range(
        &self,
        _ctx: Context,
        request: ServiceRequest<'_, GetCurrentOperationRangeRequest>,
    ) -> impl Future<Output = connectrpc::ServiceResult<PreEncoded<GetCurrentOperationRangeResponse>>>
           + Send {
        let reader = self.reader.clone();
        async move {
            let proof = reader
                .current_operation_range_proof(
                    Location::new(request.tip),
                    Location::new(request.start_location),
                    request.max_locations,
                    request.min_sequence_number,
                )
                .await
                .map_err(qmdb_error_to_connect)?;
            connectrpc::Response::ok(encode::get_current_operation_range_response(&proof))
        }
    }
}
