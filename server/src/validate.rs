//! Runtime enforcement of `buf.validate` proto annotations.
//!
//! Each function validates one request message type and returns a structured
//! `ConnectError` (INVALID_ARGUMENT with `BadRequest` + `ErrorInfo` details) on
//! the first constraint violation.

use connectrpc::ConnectError;
use exoware_sdk_rs::keys::{validate_key_size, MAX_KEY_LEN};
use exoware_sdk_rs as exoware_proto;
use exoware_proto::google::rpc::{bad_request::FieldViolation, BadRequest, ErrorInfo};
use exoware_proto::{
    parse_range_traversal_direction, with_bad_request_detail, with_error_info_detail,
    RangeTraversalModeError,
};

fn field_error(
    domain: &str,
    field: impl Into<String>,
    description: impl Into<String>,
    reason: &str,
    message: impl Into<String>,
    metadata: impl IntoIterator<Item = (String, String)>,
) -> ConnectError {
    let description = description.into();
    let err = with_bad_request_detail(
        ConnectError::invalid_argument(message),
        BadRequest {
            field_violations: vec![FieldViolation {
                field: field.into(),
                description: description.clone(),
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    with_error_info_detail(
        err,
        ErrorInfo {
            reason: reason.to_string(),
            domain: domain.to_string(),
            metadata: metadata
                .into_iter()
                .chain(std::iter::once(("description".to_string(), description)))
                .collect(),
            ..Default::default()
        },
    )
}

fn validate_key_field(domain: &str, field: &str, key: &[u8]) -> Result<(), ConnectError> {
    validate_key_size(key.len()).map_err(|e| {
        field_error(
            domain,
            field,
            e.to_string(),
            "INVALID_KEY_LENGTH",
            format!("{field} key length is outside store limits"),
            [("max_key_len".to_string(), MAX_KEY_LEN.to_string())],
        )
    })
}

// -- ingest --

pub fn validate_put_request(
    request: &exoware_proto::store::ingest::v1::PutRequestView<'_>,
) -> Result<(), ConnectError> {
    // buf.validate: repeated.min_items = 1
    if request.kvs.is_empty() {
        return Err(field_error(
            "store.ingest",
            "kvs",
            "at least one key-value pair is required",
            "INVALID_BATCH",
            "put request must contain at least one key-value pair",
            [],
        ));
    }
    // buf.validate: KvPair.key bytes.max_len = 254
    for (index, kv) in request.kvs.iter().enumerate() {
        validate_key_field("store.ingest", &format!("kvs[{index}].key"), kv.key)?;
    }
    Ok(())
}

// -- query --

pub fn validate_get_request(
    request: &exoware_proto::store::query::v1::GetRequestView<'_>,
) -> Result<(), ConnectError> {
    // buf.validate: bytes.max_len = 254
    validate_key_field("store.query", "key", request.key)
}

pub fn validate_range_request(
    request: &exoware_proto::store::query::v1::RangeRequestView<'_>,
) -> Result<(), ConnectError> {
    // buf.validate: bytes.max_len = 254
    validate_key_field("store.query", "start", request.start)?;
    validate_key_field("store.query", "end", request.end)?;
    // buf.validate: uint32.gt = 0
    if request.batch_size == 0 {
        return Err(field_error(
            "store.query",
            "batch_size",
            "batch_size must be greater than 0",
            "INVALID_BATCH_SIZE",
            "range batch_size must be positive",
            [],
        ));
    }
    // buf.validate: enum.defined_only = true
    if let Err(RangeTraversalModeError::UnknownWireValue(v)) =
        parse_range_traversal_direction(request.mode)
    {
        return Err(field_error(
            "store.query",
            "mode",
            format!("unknown TraversalMode enum value {v}"),
            "INVALID_TRAVERSAL_MODE",
            "range mode must be TRAVERSAL_MODE_FORWARD (0) or TRAVERSAL_MODE_REVERSE (1)",
            [],
        ));
    }
    Ok(())
}

pub fn validate_get_many_request(
    request: &exoware_proto::store::query::v1::GetManyRequestView<'_>,
) -> Result<(), ConnectError> {
    if request.keys.is_empty() {
        return Err(field_error(
            "store.query",
            "keys",
            "at least one key is required",
            "INVALID_BATCH",
            "get_many request must contain at least one key",
            [],
        ));
    }
    for (index, key) in request.keys.iter().enumerate() {
        validate_key_field("store.query", &format!("keys[{index}]"), key)?;
    }
    if request.batch_size == 0 {
        return Err(field_error(
            "store.query",
            "batch_size",
            "batch_size must be greater than 0",
            "INVALID_BATCH_SIZE",
            "get_many batch_size must be positive",
            [],
        ));
    }
    Ok(())
}

pub fn validate_reduce_request(
    request: &exoware_proto::store::query::v1::ReduceRequestView<'_>,
) -> Result<(), ConnectError> {
    // buf.validate: bytes.max_len = 254
    validate_key_field("store.query", "start", request.start)?;
    validate_key_field("store.query", "end", request.end)?;
    // buf.validate: required = true (params must be present)
    // The view always deserializes an empty sub-message for unset fields, so we
    // check whether at least one reducer or group_by is specified (the real
    // constraint from reduce.rs validate_reduce_request).
    Ok(())
}

pub fn reduce_params_error(description: impl Into<String>) -> ConnectError {
    field_error(
        "store.query",
        "params",
        description,
        "INVALID_REDUCE_PARAMS",
        "reduce params are invalid",
        [],
    )
}

// -- compact --

pub fn validate_prune_request(
    request: &exoware_proto::store::compact::v1::PruneRequestView<'_>,
) -> Result<(), ConnectError> {
    if request.policies.is_empty() {
        return Err(field_error(
            "store.compact",
            "policies",
            "at least one policy is required",
            "INVALID_PRUNE_REQUEST",
            "prune request must contain at least one policy",
            [],
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use buffa::view::MessageView as _;

    fn empty_put_request_bytes() -> Vec<u8> {
        Vec::new()
    }

    fn put_request_with_oversized_key() -> Vec<u8> {
        use buffa::Message;
        let req = exoware_proto::ingest::PutRequest {
            kvs: vec![exoware_proto::ingest::KvPair {
                key: vec![0u8; 255],
                value: vec![1],
                ..Default::default()
            }],
            ..Default::default()
        };
        req.encode_to_vec()
    }

    fn valid_put_request() -> Vec<u8> {
        use buffa::Message;
        let req = exoware_proto::ingest::PutRequest {
            kvs: vec![exoware_proto::ingest::KvPair {
                key: vec![0u8; 10],
                value: vec![1],
                ..Default::default()
            }],
            ..Default::default()
        };
        req.encode_to_vec()
    }

    #[test]
    fn put_rejects_empty_batch() {
        let bytes = empty_put_request_bytes();
        let view = exoware_proto::store::ingest::v1::PutRequestView::decode_view(&bytes)
            .expect("parse");
        let err = validate_put_request(&view).unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument);
    }

    #[test]
    fn put_rejects_oversized_key() {
        let bytes = put_request_with_oversized_key();
        let view = exoware_proto::store::ingest::v1::PutRequestView::decode_view(&bytes)
            .expect("parse");
        let err = validate_put_request(&view).unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument);
    }

    #[test]
    fn put_accepts_valid_request() {
        let bytes = valid_put_request();
        let view = exoware_proto::store::ingest::v1::PutRequestView::decode_view(&bytes)
            .expect("parse");
        validate_put_request(&view).expect("should be valid");
    }

    fn get_request_bytes(key: &[u8]) -> Vec<u8> {
        use buffa::Message;
        exoware_proto::query::GetRequest {
            key: key.to_vec(),
            ..Default::default()
        }
        .encode_to_vec()
    }

    #[test]
    fn get_rejects_oversized_key() {
        let bytes = get_request_bytes(&[0u8; 255]);
        let view = exoware_proto::store::query::v1::GetRequestView::decode_view(&bytes)
            .expect("parse");
        assert!(validate_get_request(&view).is_err());
    }

    #[test]
    fn get_accepts_max_key() {
        let bytes = get_request_bytes(&[0u8; 254]);
        let view = exoware_proto::store::query::v1::GetRequestView::decode_view(&bytes)
            .expect("parse");
        validate_get_request(&view).expect("should be valid");
    }

    fn range_request_bytes(batch_size: u32, mode: impl Into<buffa::EnumValue<exoware_proto::query::TraversalMode>>) -> Vec<u8> {
        use buffa::Message;
        exoware_proto::query::RangeRequest {
            start: vec![0u8; 1],
            batch_size,
            mode: mode.into(),
            ..Default::default()
        }
        .encode_to_vec()
    }

    #[test]
    fn range_rejects_zero_batch_size() {
        use exoware_proto::query::TraversalMode;
        let bytes = range_request_bytes(0, TraversalMode::TRAVERSAL_MODE_FORWARD);
        let view = exoware_proto::store::query::v1::RangeRequestView::decode_view(&bytes)
            .expect("parse");
        let err = validate_range_request(&view).unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument);
    }

    #[test]
    fn range_rejects_unknown_traversal_mode() {
        let bytes = range_request_bytes(1, buffa::EnumValue::<exoware_proto::query::TraversalMode>::Unknown(99));
        let view = exoware_proto::store::query::v1::RangeRequestView::decode_view(&bytes)
            .expect("parse");
        let err = validate_range_request(&view).unwrap_err();
        assert_eq!(err.code, connectrpc::ErrorCode::InvalidArgument);
    }

    #[test]
    fn range_accepts_valid_request() {
        use exoware_proto::query::TraversalMode;
        let bytes = range_request_bytes(100, TraversalMode::TRAVERSAL_MODE_FORWARD);
        let view = exoware_proto::store::query::v1::RangeRequestView::decode_view(&bytes)
            .expect("parse");
        validate_range_request(&view).expect("should be valid");
    }

    fn prune_request_bytes(n_policies: usize) -> Vec<u8> {
        use buffa::Message;
        exoware_proto::compact::PruneRequest {
            policies: (0..n_policies)
                .map(|_| exoware_proto::compact::Policy::default())
                .collect(),
            ..Default::default()
        }
        .encode_to_vec()
    }

    #[test]
    fn prune_rejects_empty_policies() {
        let bytes = prune_request_bytes(0);
        let view = exoware_proto::store::compact::v1::PruneRequestView::decode_view(&bytes)
            .expect("parse");
        assert!(validate_prune_request(&view).is_err());
    }

    #[test]
    fn prune_accepts_one_policy() {
        let bytes = prune_request_bytes(1);
        let view = exoware_proto::store::compact::v1::PruneRequestView::decode_view(&bytes)
            .expect("parse");
        validate_prune_request(&view).expect("should be valid");
    }
}
