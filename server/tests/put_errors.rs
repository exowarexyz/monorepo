use connectrpc::{ConnectError, ErrorCode};
use exoware_sdk::decode_connect_error;
use exoware_sdk::google::rpc::{bad_request::FieldViolation, ErrorInfo};
use exoware_sdk::limits::{PutTooLarge, MAX_KEY_LEN};
use exoware_server::{
    ingest_error_to_connect, put_too_large_error, validate_put_count, validate_put_entry,
    worker_not_ready_error, IngestError, IngestLimits,
};

fn assert_validation(
    error: ConnectError,
    field: &str,
    description: &str,
    reason: &str,
    message: &str,
    metadata: &[(&str, &str)],
) {
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(error.message.as_deref(), Some(message));
    assert_eq!(error.details.len(), 2);

    let decoded = decode_connect_error(&error).unwrap();
    assert_eq!(
        decoded.bad_request.unwrap().field_violations,
        vec![FieldViolation {
            field: field.into(),
            description: description.into(),
            ..Default::default()
        }]
    );
    let info = decoded.error_info.unwrap();
    assert_eq!(info.reason, reason);
    assert_eq!(info.domain, "log.ingest");
    assert_eq!(info.metadata.len(), metadata.len() + 1);
    assert_eq!(
        info.metadata.get("description").map(String::as_str),
        Some(description)
    );
    for &(key, value) in metadata {
        assert_eq!(info.metadata.get(key).map(String::as_str), Some(value));
    }
}

fn assert_retry(error: ConnectError, message: &str, reason: &str) {
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert_eq!(error.message.as_deref(), Some(message));
    assert_eq!(error.details.len(), 2);

    let decoded = decode_connect_error(&error).unwrap();
    assert_eq!(
        decoded.error_info.unwrap(),
        ErrorInfo {
            reason: reason.into(),
            domain: "log.ingest".into(),
            ..Default::default()
        }
    );
    let retry = decoded.retry_info.unwrap();
    let delay = retry.retry_delay.as_option().unwrap();
    assert_eq!((delay.seconds, delay.nanos), (1, 0));
}

#[test]
fn readiness_error_preserves_retry_details() {
    assert_retry(
        worker_not_ready_error(),
        "ingest is not ready",
        "WORKER_NOT_READY",
    );
}

#[test]
fn backend_errors_preserve_codes_and_retry_details() {
    for (error, code, message) in [
        (
            IngestError::ResourceExhausted {
                message: "backend capacity exceeded".into(),
            },
            ErrorCode::ResourceExhausted,
            "backend capacity exceeded",
        ),
        (
            IngestError::Internal {
                message: "invariant violated".into(),
            },
            ErrorCode::Internal,
            "invariant violated",
        ),
    ] {
        let actual = ingest_error_to_connect(error);
        assert_eq!(actual.code, code);
        assert_eq!(actual.message.as_deref(), Some(message));
        assert!(actual.details.is_empty());
    }
    assert_retry(
        ingest_error_to_connect(IngestError::Unavailable {
            message: "backend bouncing".into(),
        }),
        "backend bouncing",
        "INGEST_UNAVAILABLE",
    );
}

#[test]
fn size_errors_preserve_count_details() {
    let limits = IngestLimits {
        max_entries: 2,
        max_value_len: 4,
    };
    let too_large = PutTooLarge {
        entries: 3,
        max_entries: limits.max_entries,
    };
    for error in [
        put_too_large_error(too_large),
        ingest_error_to_connect(IngestError::PutTooLarge(too_large)),
        validate_put_count(3, limits).unwrap_err(),
    ] {
        assert_validation(
            error,
            "kvs",
            "put has 3 entries, exceeding the limit of 2",
            "PUT_TOO_LARGE",
            "put request exceeds size limits",
            &[("entries", "3"), ("max_entries", "2")],
        );
    }
}

#[test]
fn validation_errors_preserve_limits_and_field_order() {
    let limits = IngestLimits {
        max_entries: 2,
        max_value_len: 4,
    };
    assert_validation(
        validate_put_count(0, limits).unwrap_err(),
        "kvs",
        "at least one key-value pair is required",
        "INVALID_BATCH",
        "put request must contain at least one key-value pair",
        &[],
    );
    assert_validation(
        validate_put_entry(1, &[0; MAX_KEY_LEN + 1], b"value", limits).unwrap_err(),
        "kvs[1].key",
        "key length 255 exceeds max 254",
        "INVALID_KEY_LENGTH",
        "kvs[1].key key length is outside store limits",
        &[("max_key_len", "254")],
    );
    assert_validation(
        validate_put_entry(0, b"key", b"value", limits).unwrap_err(),
        "kvs[0].value",
        "value length 5 exceeds maximum 4",
        "INVALID_VALUE_LENGTH",
        "kvs[0].value value length is outside store limits",
        &[("max_value_len", "4")],
    );

    validate_put_count(1, limits).unwrap();
    validate_put_count(limits.max_entries, limits).unwrap();
    validate_put_entry(0, b"", b"", limits).unwrap();
    validate_put_entry(0, &[0; MAX_KEY_LEN], b"1234", limits).unwrap();
}
