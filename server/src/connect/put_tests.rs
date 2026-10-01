use super::*;

use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::sync::Mutex;
use std::task::Poll;

use crate::ingest::{DecodeBuffers, IngestBudget, PutError, PutInput, PutMiddleware};
use futures::future::BoxFuture;

use connectrpc::client::{full_body, ClientConfig, ClientTransport};
use connectrpc::{CodecFormat, ErrorCode};
use exoware_sdk::decode_connect_error;
use exoware_sdk::ingest::{PutRequest, ServiceClient};
use exoware_sdk::keys::MAX_KEY_LEN;
use exoware_sdk::limits::PutTooLarge;
use exoware_sdk::transport::ServiceTransport;
use http_body_util::BodyExt;

const PUT_PATH: &str = "log.ingest.v1.Service/Put";

#[derive(Default)]
struct TestIngest {
    put_error: Option<IngestError>,
    batches: Mutex<Vec<Vec<(Bytes, Bytes)>>>,
    expected_body_polls: Option<Arc<AtomicUsize>>,
    check_metadata: bool,
}

impl Ingest for TestIngest {
    async fn put(&self, input: &mut PutInput) -> Result<u64, PutError> {
        if let Some(polls) = &self.expected_body_polls {
            assert_eq!(polls.load(Ordering::SeqCst), 0);
        }
        if self.check_metadata {
            let parts = input.parts().expect("request metadata must reach ingest");
            assert_eq!(parts.headers["x-request-marker"], "original");
            assert_eq!(parts.headers["x-middleware-marker"], "accepted");
            assert_eq!(
                parts.extensions.get::<MetadataMarker>(),
                Some(&MetadataMarker(9))
            );
        }
        let mut batch = Vec::new();
        while let Some(chunk) = input.next_batch(DecodeBuffers::default()).await? {
            batch.extend(
                chunk.entries().map(|(key, value)| {
                    (Bytes::copy_from_slice(key), Bytes::copy_from_slice(value))
                }),
            );
        }
        input.finish().await?;

        let mut batches = self.batches.lock().unwrap();
        batches.push(batch);
        match &self.put_error {
            Some(error) => Err(error.clone().into()),
            None => Ok(batches.len() as u64),
        }
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
) -> Result<Bytes, ConnectError> {
    let content_type = match format {
        CodecFormat::Proto => "application/proto",
        CodecFormat::Json => "application/json",
        _ => panic!("unsupported test codec"),
    };
    let transport = ServiceTransport::new(ingest_service(state));
    let request = http::Request::post(format!("http://store.test/{PUT_PATH}"))
        .header(http::header::CONTENT_TYPE, content_type)
        .header("connect-protocol-version", "1")
        .body(full_body(body))
        .unwrap();
    let response = transport.send(request).await.unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    if status.is_success() {
        Ok(body)
    } else {
        Err(serde_json::from_slice(&body).unwrap())
    }
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
async fn overcount_precedes_entry_errors() {
    let mut request = request(2);
    request.kvs[0].key = vec![1; MAX_KEY_LEN + 1];

    // Both entry envelopes are complete. Their key fields have truncated lengths.
    let malformed = Bytes::from_static(&[0x0a, 1, 0x0a, 0x0a, 1, 0x0a]);
    for body in [request.encode_to_vec().into(), malformed] {
        let ingest = Arc::new(TestIngest::default());
        let state = IngestState::new(ingest.clone()).with_limits(IngestLimits {
            max_entries: 1,
            ..Default::default()
        });
        let error = dispatch(state, body, CodecFormat::Proto).await.unwrap_err();

        assert_overcount(&error);
        assert_no_writes(&ingest);
    }
}

#[tokio::test]
async fn readiness_precedes_malformed_body() {
    for (format, body) in [
        (CodecFormat::Proto, Bytes::from_static(&[0x0a, 0x80])),
        (CodecFormat::Json, Bytes::from_static(b"{")),
    ] {
        let ingest = Arc::new(TestIngest::default());
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
async fn empty_batch_is_rejected_before_publication() {
    let ingest = Arc::new(TestIngest::default());
    let error = dispatch(
        IngestState::new(ingest.clone()),
        Bytes::new(),
        CodecFormat::Proto,
    )
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

#[tokio::test]
async fn malformed_entry_is_rejected_before_publication() {
    let ingest = Arc::new(TestIngest::default());
    let error = dispatch(
        IngestState::new(ingest.clone()),
        Bytes::from_static(&[0x0a, 1, 0x0a]),
        CodecFormat::Proto,
    )
    .await
    .unwrap_err();

    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(
        error.message.as_deref(),
        Some("failed to decode proto request: unexpected end of buffer")
    );
    assert_no_writes(&ingest);
}

#[tokio::test]
async fn malformed_inner_entry_precedes_business_validation() {
    let ingest = Arc::new(TestIngest::default());
    let mut request = request(1);
    request.kvs[0].key = vec![1; MAX_KEY_LEN + 1];
    let mut body = request.encode_to_vec();
    body.extend_from_slice(&[0x0a, 1, 0x0a]);
    let error = dispatch(
        IngestState::new(ingest.clone()),
        body.into(),
        CodecFormat::Proto,
    )
    .await
    .unwrap_err();

    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(
        error.message.as_deref(),
        Some("failed to decode proto request: unexpected end of buffer")
    );
    assert_no_writes(&ingest);
}

#[tokio::test]
async fn malformed_tail_prevents_publication() {
    for tail in [
        &[0x0a, 0x80][..],
        &[0x0a, 2, 0x0a][..],
        &[0x12, 0x80][..],
        &[0][..],
    ] {
        let ingest = Arc::new(TestIngest::default());
        let mut body = request(1).encode_to_vec();
        body.extend_from_slice(tail);
        let error = dispatch(
            IngestState::new(ingest.clone()),
            body.into(),
            CodecFormat::Proto,
        )
        .await
        .unwrap_err();

        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert_no_writes(&ingest);
    }
}

#[tokio::test]
async fn backend_unavailable_preserves_retry_details() {
    let ingest = Arc::new(TestIngest {
        put_error: Some(IngestError::Unavailable {
            message: "backend is temporarily unavailable".into(),
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
    assert_eq!(ingest.batches.lock().unwrap().len(), 1);
}

#[derive(Clone, Debug, PartialEq)]
struct MetadataMarker(u64);

struct PreserveMetadata {
    polls: Arc<AtomicUsize>,
}

impl PutMiddleware for PreserveMetadata {
    fn call<'a>(
        &'a self,
        parts: &'a mut http::request::Parts,
    ) -> BoxFuture<'a, Result<(), ConnectError>> {
        Box::pin(async move {
            assert_eq!(self.polls.load(Ordering::SeqCst), 0);
            assert_eq!(parts.headers["x-request-marker"], "original");
            assert_eq!(
                parts.extensions.get::<MetadataMarker>(),
                Some(&MetadataMarker(7))
            );
            parts.headers.insert(
                "x-middleware-marker",
                http::HeaderValue::from_static("accepted"),
            );
            parts.extensions.insert(MetadataMarker(9));
            Ok(())
        })
    }
}

struct PendingMiddleware {
    entered: Arc<AtomicBool>,
}

impl PutMiddleware for PendingMiddleware {
    fn call<'a>(
        &'a self,
        _: &'a mut http::request::Parts,
    ) -> BoxFuture<'a, Result<(), ConnectError>> {
        Box::pin(async move {
            self.entered.store(true, Ordering::SeqCst);
            futures::future::pending().await
        })
    }
}

struct CountingBody {
    body: Option<Bytes>,
    polls: Arc<AtomicUsize>,
}

impl http_body::Body for CountingBody {
    type Data = Bytes;
    type Error = ConnectError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, ConnectError>>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(
            self.body
                .take()
                .map(|body| Ok(http_body::Frame::data(body))),
        )
    }
}

#[tokio::test]
async fn metadata_middleware_preserves_extensions_before_body_poll() {
    let polls = Arc::new(AtomicUsize::new(0));
    let ingest = Arc::new(TestIngest {
        expected_body_polls: Some(polls.clone()),
        check_metadata: true,
        ..Default::default()
    });
    let service =
        ingest_service(IngestState::new(ingest.clone())).with_put_middleware(PreserveMetadata {
            polls: polls.clone(),
        });
    let mut incoming = http::Request::post(format!("http://store.test/{PUT_PATH}"))
        .header(http::header::CONTENT_TYPE, "application/proto")
        .header("connect-protocol-version", "1")
        .header("x-request-marker", "original")
        .body(CountingBody {
            body: Some(request(1).encode_to_vec().into()),
            polls: polls.clone(),
        })
        .unwrap();
    incoming.extensions_mut().insert(MetadataMarker(7));
    let response = tower::ServiceExt::oneshot(service, incoming).await.unwrap();

    assert_eq!(response.status(), http::StatusCode::OK);
    assert!(polls.load(Ordering::SeqCst) > 0);
    assert_eq!(ingest.batches.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn put_get_and_head_preserve_method_rejection_headers() {
    for (method, query, allow) in [
        (http::Method::GET, "?encoding=json&message=%7B%7D", None),
        (
            http::Method::HEAD,
            "",
            Some(http::HeaderValue::from_static("POST")),
        ),
    ] {
        let ingest = Arc::new(TestIngest::default());
        let transport = ServiceTransport::new(ingest_service(IngestState::new(ingest.clone())));
        let request = http::Request::builder()
            .method(method)
            .uri(format!("http://store.test/{PUT_PATH}{query}"))
            .body(full_body(Bytes::new()))
            .unwrap();
        let response = transport.send(request).await.unwrap();

        assert_eq!(response.status(), http::StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers().get(http::header::ALLOW), allow.as_ref());
        assert_no_writes(&ingest);
    }
}

#[tokio::test]
async fn json_put_is_rejected_before_decoding() {
    for body in [
        Bytes::from_static(br#"{"kvs":[{"key":"a2V5","value":"dmFsdWU="}]}"#),
        Bytes::from_static(br#"{"kvs":[]}"#),
        Bytes::from_static(br#"{"kvs":["#),
    ] {
        let ingest = Arc::new(TestIngest::default());
        let error = dispatch(IngestState::new(ingest.clone()), body, CodecFormat::Json)
            .await
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::Unimplemented);
        assert_eq!(error.message.as_deref(), Some("Put requires protobuf"));
        assert_no_writes(&ingest);
    }
}

#[tokio::test]
async fn json_generated_client_is_rejected() {
    let ingest = Arc::new(TestIngest::default());
    let client = ServiceClient::new(
        ServiceTransport::new(ingest_service(IngestState::new(ingest.clone()))),
        ClientConfig::new("http://store.test".parse().unwrap()).json(),
    );
    let error = client.put(request(1)).await.unwrap_err();

    assert_eq!(error.code, ErrorCode::Unimplemented);
    assert_eq!(error.message.as_deref(), Some("Put requires protobuf"));
    assert_no_writes(&ingest);
}

#[tokio::test]
async fn cancellation_while_middleware_is_pending_never_polls_body_or_writes() {
    let ingest = Arc::new(TestIngest::default());
    let entered = Arc::new(AtomicBool::new(false));
    let polls = Arc::new(AtomicUsize::new(0));
    let service =
        ingest_service(IngestState::new(ingest.clone())).with_put_middleware(PendingMiddleware {
            entered: entered.clone(),
        });
    let incoming = http::Request::post(format!("http://store.test/{PUT_PATH}"))
        .header(http::header::CONTENT_TYPE, "application/proto")
        .header("connect-protocol-version", "1")
        .body(CountingBody {
            body: Some(request(1).encode_to_vec().into()),
            polls: polls.clone(),
        })
        .unwrap();
    let mut call = Box::pin(tower::ServiceExt::oneshot(service, incoming));
    assert!(futures::poll!(call.as_mut()).is_pending());
    assert!(entered.load(Ordering::SeqCst));
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    drop(call);

    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_no_writes(&ingest);
}

#[tokio::test]
async fn deadline_while_middleware_is_pending_never_polls_body_or_writes() {
    let ingest = Arc::new(TestIngest::default());
    let entered = Arc::new(AtomicBool::new(false));
    let polls = Arc::new(AtomicUsize::new(0));
    let service =
        ingest_service(IngestState::new(ingest.clone())).with_put_middleware(PendingMiddleware {
            entered: entered.clone(),
        });
    let incoming = http::Request::post(format!("http://store.test/{PUT_PATH}"))
        .header(http::header::CONTENT_TYPE, "application/proto")
        .header("connect-protocol-version", "1")
        .header("connect-timeout-ms", "10")
        .body(CountingBody {
            body: Some(request(1).encode_to_vec().into()),
            polls: polls.clone(),
        })
        .unwrap();
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        tower::ServiceExt::oneshot(service, incoming),
    )
    .await
    .expect("request deadline must include middleware")
    .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let error: ConnectError = serde_json::from_slice(&body).unwrap();

    assert_eq!(error.code, ErrorCode::DeadlineExceeded);
    assert!(entered.load(Ordering::SeqCst));
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_no_writes(&ingest);
}

#[tokio::test]
async fn exhausted_admission_never_polls_body_or_writes() {
    let polls = Arc::new(AtomicUsize::new(0));
    let ingest = Arc::new(TestIngest::default());
    let budget = IngestBudget::new(crate::ingest::BudgetConfig {
        max_requests: 0,
        max_bytes: 1024,
    });
    let state = IngestState::new(ingest.clone()).with_put_config(crate::ingest::PutConfig {
        budget: budget.clone(),
        ..Default::default()
    });
    let incoming = http::Request::post(format!("http://store.test/{PUT_PATH}"))
        .header(http::header::CONTENT_TYPE, "application/proto")
        .header("connect-protocol-version", "1")
        .body(CountingBody {
            body: Some(request(1).encode_to_vec().into()),
            polls: polls.clone(),
        })
        .unwrap();
    let response = tower::ServiceExt::oneshot(ingest_service(state), incoming)
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let error: ConnectError = serde_json::from_slice(&body).unwrap();

    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(budget.usage(), (0, 0));
    assert_no_writes(&ingest);
}

struct RejectBeforeRead;

impl Ingest for RejectBeforeRead {
    async fn put(&self, input: &mut PutInput) -> Result<u64, PutError> {
        assert_eq!(input.wire_bytes(), 0);
        Err(IngestError::ResourceExhausted {
            message: "ingest capacity exhausted".into(),
        }
        .into())
    }
}

struct RepeatedBody {
    polls: Arc<AtomicUsize>,
}

impl http_body::Body for RepeatedBody {
    type Data = Bytes;
    type Error = ConnectError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, ConnectError>>> {
        let polls = self.polls.fetch_add(1, Ordering::SeqCst);
        assert!(polls < 2, "rejection draining must stop at the wire bound");
        Poll::Ready(Some(Ok(http_body::Frame::data(Bytes::from_static(
            b"0123456789abcdef",
        )))))
    }
}

#[tokio::test]
async fn backend_rejection_drains_only_the_admitted_wire_bound() {
    let polls = Arc::new(AtomicUsize::new(0));
    let budget = IngestBudget::new(crate::ingest::BudgetConfig {
        max_requests: 1,
        max_bytes: 1024,
    });
    let state =
        IngestState::new(Arc::new(RejectBeforeRead)).with_put_config(crate::ingest::PutConfig {
            budget: budget.clone(),
            max_wire_bytes: 16,
            ..Default::default()
        });
    let incoming = http::Request::post(format!("http://store.test/{PUT_PATH}"))
        .header(http::header::CONTENT_TYPE, "application/proto")
        .header("connect-protocol-version", "1")
        .body(RepeatedBody {
            polls: polls.clone(),
        })
        .unwrap();
    let response = tower::ServiceExt::oneshot(ingest_service(state), incoming)
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let error: ConnectError = serde_json::from_slice(&body).unwrap();

    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert_eq!(
        error.message.as_deref(),
        Some("request body exceeds wire limit")
    );
    assert_eq!(polls.load(Ordering::SeqCst), 2);
    assert_eq!(budget.usage(), (0, 0));
}

#[derive(Clone)]
struct LatestDeadline(tokio::time::Instant);

struct DelayedMiddleware;

impl PutMiddleware for DelayedMiddleware {
    fn call<'a>(
        &'a self,
        parts: &'a mut http::request::Parts,
    ) -> BoxFuture<'a, Result<(), ConnectError>> {
        Box::pin(async move {
            parts.extensions.insert(LatestDeadline(
                tokio::time::Instant::now() + std::time::Duration::from_millis(100),
            ));
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            Ok(())
        })
    }
}

struct CheckDeadline {
    entered: AtomicBool,
}

impl Ingest for CheckDeadline {
    async fn put(&self, input: &mut PutInput) -> Result<u64, PutError> {
        self.entered.store(true, Ordering::SeqCst);
        let latest = input
            .parts()
            .unwrap()
            .extensions
            .get::<LatestDeadline>()
            .unwrap()
            .0;
        assert!(
            input.deadline() <= latest,
            "middleware must not restart the request timeout"
        );
        Err(IngestError::ResourceExhausted {
            message: "ingest capacity exhausted".into(),
        }
        .into())
    }
}

struct PendingBody {
    polls: Arc<AtomicUsize>,
}

impl http_body::Body for PendingBody {
    type Data = Bytes;
    type Error = ConnectError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, ConnectError>>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
}

#[tokio::test]
async fn middleware_and_rejection_drain_share_the_original_deadline() {
    let polls = Arc::new(AtomicUsize::new(0));
    let ingest = Arc::new(CheckDeadline {
        entered: AtomicBool::new(false),
    });
    let service =
        ingest_service(IngestState::new(ingest.clone())).with_put_middleware(DelayedMiddleware);
    let incoming = http::Request::post(format!("http://store.test/{PUT_PATH}"))
        .header(http::header::CONTENT_TYPE, "application/proto")
        .header("connect-protocol-version", "1")
        .header("connect-timeout-ms", "100")
        .body(PendingBody {
            polls: polls.clone(),
        })
        .unwrap();
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        tower::ServiceExt::oneshot(service, incoming),
    )
    .await
    .expect("rejection drain must stop at the request deadline")
    .unwrap();

    assert!(!response.status().is_success());
    assert!(ingest.entered.load(Ordering::SeqCst));
    assert!(polls.load(Ordering::SeqCst) > 0);
}

struct UnreachableIngest;

impl Ingest for UnreachableIngest {
    async fn put(&self, _: &mut PutInput) -> Result<u64, PutError> {
        panic!("rejected content length must never reach ingest")
    }
}

struct AdmittedDrainBody {
    body: Option<Bytes>,
    budget: Arc<IngestBudget>,
    polls: Arc<AtomicUsize>,
}

impl http_body::Body for AdmittedDrainBody {
    type Data = Bytes;
    type Error = ConnectError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, ConnectError>>> {
        assert_eq!(self.budget.usage(), (1, 0));
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(
            self.body
                .take()
                .map(|body| Ok(http_body::Frame::data(body))),
        )
    }
}

#[tokio::test]
async fn rejected_content_lengths_drain_under_admission_without_ingest() {
    let invalid = ["invalid", "-1", "+16", "184467440737095516160"].map(|declared| {
        (
            declared,
            ErrorCode::InvalidArgument,
            "invalid content length",
        )
    });
    let oversized = (
        "17",
        ErrorCode::ResourceExhausted,
        "request body exceeds wire limit",
    );
    for (declared, code, message) in std::iter::once(oversized).chain(invalid) {
        let polls = Arc::new(AtomicUsize::new(0));
        let budget = IngestBudget::new(crate::ingest::BudgetConfig {
            max_requests: 1,
            max_bytes: 0,
        });
        let state = IngestState::new(Arc::new(UnreachableIngest)).with_put_config(
            crate::ingest::PutConfig {
                budget: budget.clone(),
                max_wire_bytes: 16,
                ..Default::default()
            },
        );
        let incoming = http::Request::post(format!("http://store.test/{PUT_PATH}"))
            .header(http::header::CONTENT_TYPE, "application/proto")
            .header(http::header::CONTENT_LENGTH, declared)
            .header("connect-protocol-version", "1")
            .body(AdmittedDrainBody {
                body: Some(Bytes::from_static(b"0123456789abcdef")),
                budget: budget.clone(),
                polls: polls.clone(),
            })
            .unwrap();
        let response = tower::ServiceExt::oneshot(ingest_service(state), incoming)
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let error: ConnectError = serde_json::from_slice(&body).unwrap();

        assert_eq!(error.code, code, "declared length {declared}");
        assert_eq!(error.message.as_deref(), Some(message));
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        assert_eq!(budget.usage(), (0, 0));
    }
}

struct RecordDeadline {
    remaining: Mutex<Option<std::time::Duration>>,
}

impl Ingest for RecordDeadline {
    async fn put(&self, input: &mut PutInput) -> Result<u64, PutError> {
        *self.remaining.lock().unwrap() = Some(
            input
                .deadline()
                .saturating_duration_since(tokio::time::Instant::now()),
        );
        while input.next_batch(DecodeBuffers::default()).await?.is_some() {}
        input.finish().await?;
        Ok(1)
    }
}

#[tokio::test]
async fn review_client_timeout_longer_than_server_default_is_honored() {
    let ingest = Arc::new(RecordDeadline {
        remaining: Mutex::new(None),
    });
    let incoming = http::Request::post(format!("http://store.test/{PUT_PATH}"))
        .header(http::header::CONTENT_TYPE, "application/proto")
        .header("connect-protocol-version", "1")
        .header("connect-timeout-ms", "90000")
        .body(full_body(request(1).encode_to_vec().into()))
        .unwrap();
    let response =
        tower::ServiceExt::oneshot(ingest_service(IngestState::new(ingest.clone())), incoming)
            .await
            .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let remaining = ingest.remaining.lock().unwrap().unwrap();
    assert!(
        remaining > std::time::Duration::from_secs(60),
        "client asked for 90s but the adapter granted {remaining:?}"
    );
}

#[tokio::test]
async fn upload_can_complete_after_server_fallback_before_client_deadline() {
    let ingest = Arc::new(RecordDeadline {
        remaining: Mutex::new(None),
    });
    let service = ingest_service(IngestState::new(ingest).with_put_config(
        crate::ingest::PutConfig {
            timeout: std::time::Duration::from_millis(25),
            ..Default::default()
        },
    ));
    let body = http_body_util::StreamBody::new(futures::stream::once(async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        Ok::<_, ConnectError>(http_body::Frame::data(request(1).encode_to_vec().into()))
    }));
    let incoming = http::Request::post(format!("http://store.test/{PUT_PATH}"))
        .header(http::header::CONTENT_TYPE, "application/proto")
        .header("connect-protocol-version", "1")
        .header("connect-timeout-ms", "1000")
        .body(body)
        .unwrap();
    let response = tower::ServiceExt::oneshot(service, incoming).await.unwrap();

    assert_eq!(response.status(), http::StatusCode::OK);
}
