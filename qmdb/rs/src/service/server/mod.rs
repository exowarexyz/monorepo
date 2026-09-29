#![allow(refining_impl_trait)]

//! ConnectRPC servers.
//!
//! Each `*_stack` function mounts the services one QMDB kind supports, served
//! from that kind's [`crate::adapter`] reader. `*_operation_log_stack` mounts
//! only the operation log.

mod current_operation;
mod encode;
mod key_lookup;
mod key_range;
mod operation_log;

mod immutable;
mod keyless;
mod ordered;
mod unordered;

pub use immutable::immutable_operation_log_stack;
pub use keyless::keyless_operation_log_stack;
pub use ordered::{ordered_operation_log_stack, ordered_stack};
pub use unordered::{unordered_operation_log_stack, unordered_stack};

use current_operation::{CurrentOperationReader, CurrentOperationServer};
use key_lookup::{KeyLookupReader, KeyLookupServer};
use key_range::{KeyRangeReader, KeyRangeServer};
use operation_log::{OperationLogReader, OperationLogServer};

use connectrpc::{ConnectError, ConnectRpcService, Limits};
use exoware_sdk::ClientError;

use crate::QmdbError;

const MAX_CONNECTRPC_BODY_BYTES: usize = 256 * 1024 * 1024;

fn connect_limits() -> Limits {
    Limits::default()
        .with_max_request_body_size(MAX_CONNECTRPC_BODY_BYTES)
        .with_max_message_size(MAX_CONNECTRPC_BODY_BYTES)
}

/// Wrap mounted services with the shared body limits and compression.
fn stack<D: ::connectrpc::Dispatcher>(dispatcher: D) -> ConnectRpcService<D> {
    ConnectRpcService::new(dispatcher)
        .with_limits(connect_limits())
        .with_compression(exoware_sdk::connect_compression_registry())
}

fn qmdb_error_to_connect(err: QmdbError) -> ConnectError {
    match err {
        QmdbError::Client(ClientError::Rpc(rpc)) => {
            // Preserve RPC details without relaying the Store's transport metadata.
            let mut rpc = *rpc;
            rpc.set_response_headers(Default::default());
            rpc.set_trailers(Default::default());
            rpc
        }
        QmdbError::Client(client_err) => ConnectError::internal(client_err.to_string()),
        QmdbError::EmptyBatch
        | QmdbError::EmptyProofRequest
        | QmdbError::InvalidRangeLength
        | QmdbError::InvalidKeyRange { .. }
        | QmdbError::DuplicateRequestedKey { .. }
        | QmdbError::RangeStartOutOfBounds { .. }
        | QmdbError::EncodedValueTooLarge { .. }
        | QmdbError::SortableKeyTooLarge { .. } => ConnectError::invalid_argument(err.to_string()),
        QmdbError::WatermarkTooLow { .. } => ConnectError::out_of_range(err.to_string()),
        QmdbError::ProofKeyNotFound { .. } | QmdbError::KeyNotActive { .. } => {
            ConnectError::not_found(err.to_string())
        }
        QmdbError::CurrentProofRequiresBatchBoundary { .. }
        | QmdbError::CurrentBoundaryStateMissing { .. } => {
            ConnectError::failed_precondition(err.to_string())
        }
        QmdbError::Stream(_) => ConnectError::unavailable(err.to_string()),
        QmdbError::ProofVerification { .. }
        | QmdbError::RangeMismatch(_)
        | QmdbError::CorruptData(_)
        | QmdbError::CommonwareMerkle(_) => ConnectError::internal(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buffa::Message as _;
    use connectrpc::ErrorCode;
    use exoware_sdk::proto::google::rpc::{ErrorInfo, RetryInfo};
    use exoware_sdk::proto::query::Detail;
    use exoware_sdk::proto::{
        decode_connect_error, with_error_info_detail, with_query_detail, with_retry_info_detail,
    };

    #[test]
    fn test_client_rpc_error_preserves_code_message_and_details() {
        let raw_detail = connectrpc::error::ErrorDetail {
            type_url: "type.googleapis.com/example.RawDetail".to_string(),
            value: Some("AQID".to_string()),
            debug: None,
        };
        let mut rpc_error = with_query_detail(
            with_retry_info_detail(
                with_error_info_detail(
                    ConnectError::new(ErrorCode::Unavailable, "retry me"),
                    ErrorInfo {
                        reason: "TEST_REASON".to_string(),
                        domain: "qmdb".to_string(),
                        ..Default::default()
                    },
                ),
                RetryInfo::decode_from_slice(&[0x0a, 0x04, 0x08, 0x01, 0x10, 0x02])
                    .expect("decode retry detail fixture"),
            ),
            Detail {
                sequence_number: 42,
                ..Default::default()
            },
        )
        .with_detail(raw_detail.clone());
        rpc_error.response_headers_mut().insert(
            "set-cookie",
            "store-affinity=worker-1; Path=/".parse().unwrap(),
        );
        rpc_error
            .trailers_mut()
            .insert("x-store-trailer", "private".parse().unwrap());

        let converted =
            qmdb_error_to_connect(QmdbError::Client(ClientError::Rpc(Box::new(rpc_error))));

        assert_eq!(converted.code, ErrorCode::Unavailable);
        assert_eq!(converted.message.as_deref(), Some("retry me"));
        assert!(converted.response_headers().is_empty());
        assert!(converted.trailers().is_empty());
        assert_eq!(
            converted.details.last().unwrap().type_url,
            raw_detail.type_url
        );
        assert_eq!(converted.details.last().unwrap().value, raw_detail.value);

        let decoded = decode_connect_error(&converted).expect("decode preserved details");
        assert_eq!(decoded.error_info.unwrap().reason, "TEST_REASON");
        assert_eq!(
            decoded
                .retry_info
                .unwrap()
                .retry_delay
                .as_option()
                .unwrap()
                .seconds,
            1
        );
        assert_eq!(decoded.query_detail.unwrap().sequence_number, 42);
        assert_eq!(decoded.other_details.len(), 1);
        assert_eq!(
            decoded.other_details[0].type_url,
            "type.googleapis.com/example.RawDetail"
        );
        assert_eq!(decoded.other_details[0].value.as_ref(), &[1, 2, 3]);
    }
}
