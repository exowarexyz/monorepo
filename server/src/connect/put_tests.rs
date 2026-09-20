use super::*;

use std::sync::Mutex;

use connectrpc::client::{full_body, ClientConfig, ClientTransport};
use connectrpc::{CodecFormat, Dispatcher, EncodedResponse, ErrorCode, Payload};
use exoware_sdk::decode_connect_error;
use exoware_sdk::ingest::{PutRequest, ServiceClient};
use exoware_sdk::keys::MAX_KEY_LEN;
use exoware_sdk::limits::PutTooLarge;
use exoware_sdk::transport::ServiceTransport;

use crate::{PutCodec, PutPlan};

const PUT_PATH: &str = "log.ingest.v1.Service/Put";

#[derive(Default)]
struct TestIngest {
    panic_prepare: bool,
    prepare_error: Option<IngestError>,
    plans: Mutex<Vec<PutPlan>>,
    batches: Mutex<Vec<Vec<(Bytes, Bytes)>>>,
}

impl Ingest for TestIngest {
    fn prepare(&self, plan: &PutPlan) -> Result<(), IngestError> {
        assert!(!self.panic_prepare, "prepare must not be reached");
        self.plans.lock().unwrap().push(*plan);
        match &self.prepare_error {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    async fn put_batch(&self, batch: Vec<(Bytes, Bytes)>) -> Result<u64, IngestError> {
        let mut batches = self.batches.lock().unwrap();
        batches.push(batch);
        Ok(batches.len() as u64)
    }
}

fn request(entries: usize) -> PutRequest {
    PutRequest {
        kvs: (0..entries)
            .map(|_| Entry {
                key: b"key".to_vec(),
                value: Bytes::from_static(b"value"),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

async fn dispatch(
    state: IngestState<TestIngest>,
    body: Bytes,
    format: CodecFormat,
) -> Result<EncodedResponse, ConnectError> {
    PutDispatcher::new(state)
        .call_unary(
            PUT_PATH,
            Context::default(),
            Payload::new(body, format),
            format,
        )
        .await
}

fn assert_no_writes(ingest: &TestIngest) {
    assert!(ingest.batches.lock().unwrap().is_empty());
}

fn assert_overcount(error: &ConnectError) {
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    let expected = validate::put_too_large_error(PutTooLarge {
        entries: 2,
        max_entries: 1,
    });
    assert_eq!(
        decode_connect_error(error).unwrap(),
        decode_connect_error(&expected).unwrap()
    );
}

#[tokio::test]
async fn overcount_precedes_oversized_key_and_prepare() {
    let ingest = Arc::new(TestIngest {
        panic_prepare: true,
        ..Default::default()
    });
    let state = IngestState::new(ingest.clone()).with_limits(IngestLimits {
        max_entries: 1,
        ..Default::default()
    });
    let mut request = request(2);
    request.kvs[0].key = vec![1; MAX_KEY_LEN + 1];
    let error = dispatch(state, request.encode_to_vec().into(), CodecFormat::Proto)
        .await
        .unwrap_err();

    assert_overcount(&error);
    assert_no_writes(&ingest);
}

#[tokio::test]
async fn overcount_precedes_malformed_inner_entry_and_prepare() {
    let ingest = Arc::new(TestIngest {
        panic_prepare: true,
        ..Default::default()
    });
    let state = IngestState::new(ingest.clone()).with_limits(IngestLimits {
        max_entries: 1,
        ..Default::default()
    });
    // Both entry envelopes are complete. Their key fields have truncated lengths.
    let body = Bytes::from_static(&[0x0a, 1, 0x0a, 0x0a, 1, 0x0a]);
    let error = dispatch(state, body, CodecFormat::Proto).await.unwrap_err();

    assert_overcount(&error);
    assert_no_writes(&ingest);
}

#[tokio::test]
async fn readiness_precedes_malformed_body() {
    for (format, body) in [
        (CodecFormat::Proto, Bytes::from_static(&[0x0a, 0x80])),
        (CodecFormat::Json, Bytes::from_static(b"{")),
    ] {
        let ingest = Arc::new(TestIngest {
            panic_prepare: true,
            ..Default::default()
        });
        let state = IngestState::new(ingest.clone());
        state.ready.store(false, Ordering::SeqCst);
        let error = dispatch(state, body, format).await.unwrap_err();

        assert_eq!(error.code, ErrorCode::Unavailable);
        let decoded = decode_connect_error(&error).unwrap();
        assert_eq!(decoded.error_info.unwrap().reason, REASON_WORKER_NOT_READY);
        assert!(decoded.retry_info.is_some());
        assert_no_writes(&ingest);
    }
}

#[tokio::test]
async fn empty_batch_precedes_prepare() {
    for (format, body) in [
        (CodecFormat::Proto, Bytes::new()),
        (CodecFormat::Json, Bytes::from_static(br#"{"kvs":[]}"#)),
    ] {
        let ingest = Arc::new(TestIngest {
            panic_prepare: true,
            ..Default::default()
        });
        let error = dispatch(IngestState::new(ingest.clone()), body, format)
            .await
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert_eq!(
            decode_connect_error(&error)
                .unwrap()
                .bad_request
                .unwrap()
                .field_violations[0]
                .field,
            "kvs"
        );
        assert_no_writes(&ingest);
    }
}

#[tokio::test]
async fn prepare_resource_exhausted_precedes_inner_decode() {
    let ingest = Arc::new(TestIngest {
        prepare_error: Some(IngestError::ResourceExhausted {
            message: "admission capacity exceeded".into(),
        }),
        ..Default::default()
    });
    let body = Bytes::from_static(&[0x0a, 1, 0x0a]);
    let error = dispatch(
        IngestState::new(ingest.clone()),
        body.clone(),
        CodecFormat::Proto,
    )
    .await
    .unwrap_err();

    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert!(error.details.is_empty());
    assert_eq!(
        *ingest.plans.lock().unwrap(),
        vec![PutPlan {
            entries: 1,
            message_bytes: body.len(),
            codec: PutCodec::Proto
        }]
    );
    assert_no_writes(&ingest);
}

#[tokio::test]
async fn prepare_unavailable_preserves_retry_details() {
    let ingest = Arc::new(TestIngest {
        prepare_error: Some(IngestError::Unavailable {
            message: "admission is temporarily unavailable".into(),
        }),
        ..Default::default()
    });
    let error = dispatch(
        IngestState::new(ingest.clone()),
        request(1).encode_to_vec().into(),
        CodecFormat::Proto,
    )
    .await
    .unwrap_err();

    assert_eq!(error.code, ErrorCode::Unavailable);
    let decoded = decode_connect_error(&error).unwrap();
    let info = decoded.error_info.unwrap();
    assert_eq!(info.reason, REASON_INGEST_UNAVAILABLE);
    assert_eq!(info.domain, INGEST_ERROR_DOMAIN);
    let retry = decoded.retry_info.unwrap();
    let delay = retry.retry_delay.as_option().unwrap();
    assert_eq!((delay.seconds, delay.nanos), (1, 0));
    assert_eq!(ingest.plans.lock().unwrap().len(), 1);
    assert_no_writes(&ingest);
}

#[tokio::test]
async fn interceptor_replacement_is_counted_and_written() {
    for format in [CodecFormat::Proto, CodecFormat::Json] {
        let ingest = Arc::new(TestIngest::default());
        let state = IngestState::new(ingest.clone()).with_limits(IngestLimits {
            max_entries: 1,
            ..Default::default()
        });
        let service = ingest_service(state).with_interceptor(connectrpc::unary_interceptor(
            |mut incoming, next| {
                Box::pin(async move {
                    assert_eq!(incoming.ctx.spec(), Some(SERVICE_PUT_SPEC));
                    incoming.payload.set_message(request(1));
                    next.run(incoming).await
                })
            },
        ));
        let mut config = ClientConfig::new("http://store.test".parse().unwrap());
        if format == CodecFormat::Json {
            config = config.json();
        }
        let client = ServiceClient::new(ServiceTransport::new(service), config);
        let response = client.put(request(2)).await.unwrap();
        assert_eq!(response.view().sequence_number, 1);

        let (codec, message_bytes) = match format {
            CodecFormat::Proto => (PutCodec::Proto, request(1).encode_to_vec().len()),
            CodecFormat::Json => (
                PutCodec::Json,
                connectrpc::codec::encode_json(&request(1)).unwrap().len(),
            ),
            _ => unreachable!("only protobuf and JSON are exercised"),
        };
        assert_eq!(
            *ingest.plans.lock().unwrap(),
            vec![PutPlan {
                entries: 1,
                message_bytes,
                codec
            }]
        );
        assert_eq!(
            *ingest.batches.lock().unwrap(),
            vec![vec![(
                Bytes::from_static(b"key"),
                Bytes::from_static(b"value")
            )]]
        );
    }
}

#[tokio::test]
async fn put_get_returns_method_not_allowed() {
    let ingest = Arc::new(TestIngest {
        panic_prepare: true,
        ..Default::default()
    });
    let transport = ServiceTransport::new(ingest_service(IngestState::new(ingest.clone())));
    let request = http::Request::get(format!(
        "http://store.test/{PUT_PATH}?encoding=json&message=%7B%7D"
    ))
    .body(full_body(Bytes::new()))
    .unwrap();
    let response = transport.send(request).await.unwrap();

    assert_eq!(response.status(), http::StatusCode::METHOD_NOT_ALLOWED);
    assert!(response.headers().get(http::header::ALLOW).is_none());
    assert_no_writes(&ingest);
}

#[tokio::test]
async fn put_head_returns_method_not_allowed_with_allow() {
    let ingest = Arc::new(TestIngest {
        panic_prepare: true,
        ..Default::default()
    });
    let transport = ServiceTransport::new(ingest_service(IngestState::new(ingest.clone())));
    let request = http::Request::head(format!("http://store.test/{PUT_PATH}"))
        .body(full_body(Bytes::new()))
        .unwrap();
    let response = transport.send(request).await.unwrap();

    assert_eq!(response.status(), http::StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        response.headers().get(http::header::ALLOW),
        Some(&http::HeaderValue::from_static("POST"))
    );
    assert_no_writes(&ingest);
}

#[test]
fn put_dispatcher_preserves_generated_method_metadata() {
    let dispatcher = PutDispatcher::new(IngestState::new(Arc::new(TestIngest::default())));
    let descriptor = dispatcher.lookup(PUT_PATH).unwrap();

    assert_eq!(descriptor.kind, connectrpc::MethodKind::Unary);
    assert!(!descriptor.idempotent);
    assert_eq!(descriptor.spec, Some(SERVICE_PUT_SPEC));
    assert!(descriptor.limits.is_none());
    assert!(dispatcher.lookup("log.ingest.v1.Service/Missing").is_none());
    assert!(dispatcher.lookup("other.Service/Put").is_none());
}

#[tokio::test]
async fn malformed_json_http_request_rejected_before_prepare() {
    let ingest = Arc::new(TestIngest {
        panic_prepare: true,
        ..Default::default()
    });
    let transport = ServiceTransport::new(ingest_service(IngestState::new(ingest.clone())));
    let request = http::Request::post(format!("http://store.test/{PUT_PATH}"))
        .header(http::header::CONTENT_TYPE, "application/json")
        .header("connect-protocol-version", "1")
        .body(full_body(Bytes::from_static(br#"{"kvs":["#)))
        .unwrap();
    let response = transport.send(request).await.unwrap();

    assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    assert_no_writes(&ingest);
}

#[tokio::test]
async fn json_overcount_precedes_invalid_entry_and_prepare() {
    let ingest = Arc::new(TestIngest {
        panic_prepare: true,
        ..Default::default()
    });
    let state = IngestState::new(ingest.clone()).with_limits(IngestLimits {
        max_entries: 1,
        ..Default::default()
    });
    let body = Bytes::from_static(br#"{"kvs":[{"key":"!"},{}]}"#);
    let error = dispatch(state, body, CodecFormat::Json).await.unwrap_err();

    assert_overcount(&error);
    assert_no_writes(&ingest);
}

#[tokio::test]
async fn malformed_json_never_writes() {
    for body in [
        Bytes::from_static(br#"{"kvs":["#),
        Bytes::from_static(br#"{"kvs":[{"key":"!"}]}"#),
    ] {
        let ingest = Arc::new(TestIngest::default());
        let error = dispatch(IngestState::new(ingest.clone()), body, CodecFormat::Json)
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert_no_writes(&ingest);
    }
}

#[tokio::test]
async fn json_duplicate_kvs_rejected_before_prepare() {
    let body = Bytes::from_static(br#"{"kvs":[{"key":"a2V5"}],"kvs":[]}"#);
    assert!(connectrpc::codec::decode_json::<PutRequest>(&body).is_err());

    let ingest = Arc::new(TestIngest {
        panic_prepare: true,
        ..Default::default()
    });
    let error = dispatch(IngestState::new(ingest.clone()), body, CodecFormat::Json)
        .await
        .unwrap_err();

    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_no_writes(&ingest);
}

#[tokio::test]
async fn json_malformed_unknown_field_rejected_before_prepare() {
    let body = Bytes::from_static(br#"{"kvs":[{"key":"a2V5"}],"unknown":[1,]}"#);
    assert!(connectrpc::codec::decode_json::<PutRequest>(&body).is_err());

    let ingest = Arc::new(TestIngest {
        panic_prepare: true,
        ..Default::default()
    });
    let error = dispatch(IngestState::new(ingest.clone()), body, CodecFormat::Json)
        .await
        .unwrap_err();

    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_no_writes(&ingest);
}

#[tokio::test]
async fn json_generated_client_round_trip() {
    let ingest = Arc::new(TestIngest::default());
    let client = ServiceClient::new(
        ServiceTransport::new(ingest_service(IngestState::new(ingest.clone()))),
        ClientConfig::new("http://store.test".parse().unwrap()).json(),
    );
    let response = client.put(request(1)).await.unwrap();

    assert_eq!(response.view().sequence_number, 1);
    assert_eq!(
        *ingest.batches.lock().unwrap(),
        vec![vec![(
            Bytes::from_static(b"key"),
            Bytes::from_static(b"value")
        )]]
    );
    assert_eq!(
        *ingest.plans.lock().unwrap(),
        vec![PutPlan {
            entries: 1,
            message_bytes: connectrpc::codec::encode_json(&request(1)).unwrap().len(),
            codec: PutCodec::Json,
        }]
    );
}

#[tokio::test]
async fn json_unknown_fields_match_generated_decoder() {
    let body = Bytes::from_static(
        br#"{"unknown":{"nested":[1,2]},"kvs":[{"key":"a2V5","value":"dmFsdWU=","unknown":true}]}"#,
    );
    let generated = connectrpc::codec::decode_json::<PutRequest>(&body).unwrap();
    assert_eq!(generated, request(1));

    let ingest = Arc::new(TestIngest::default());
    let response = dispatch(IngestState::new(ingest.clone()), body, CodecFormat::Json)
        .await
        .unwrap();
    let response =
        connectrpc::codec::decode_json::<ProtoPutResponse>(&response.body.into_contiguous())
            .unwrap();
    assert_eq!(response.sequence_number, 1);
    assert_eq!(ingest.batches.lock().unwrap()[0].len(), 1);
}

#[tokio::test]
async fn cancellation_while_interceptor_is_pending_never_writes() {
    let ingest = Arc::new(TestIngest {
        panic_prepare: true,
        ..Default::default()
    });
    let entered = Arc::new(AtomicBool::new(false));
    let observed = entered.clone();
    let service = ingest_service(IngestState::new(ingest.clone())).with_interceptor(
        connectrpc::unary_interceptor(move |incoming, next| {
            let entered = entered.clone();
            Box::pin(async move {
                entered.store(true, Ordering::SeqCst);
                futures::future::pending::<()>().await;
                next.run(incoming).await
            })
        }),
    );
    let client = ServiceClient::new(
        ServiceTransport::new(service),
        ClientConfig::new("http://store.test".parse().unwrap()),
    );
    let mut call = Box::pin(client.put(request(1)));
    assert!(futures::poll!(call.as_mut()).is_pending());
    assert!(observed.load(Ordering::SeqCst));
    drop(call);

    assert!(ingest.plans.lock().unwrap().is_empty());
    assert_no_writes(&ingest);
}
