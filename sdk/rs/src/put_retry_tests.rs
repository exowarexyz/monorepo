use super::*;
use buffa::Message as _;
use buffa_types::google::protobuf::Duration as ProtoDuration;
use connectrpc::error::ErrorDetail;
use http_body_util::BodyExt as _;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

enum Reply {
    Error(ConnectError),
    TransportError(ConnectError),
    Success(u64),
    Pending,
}

struct RecordedPut {
    body: Bytes,
    headers: http::HeaderMap,
    at: tokio::time::Instant,
}

#[derive(Clone, Default)]
struct PutTransport {
    replies: Arc<Mutex<VecDeque<(Duration, Reply)>>>,
    requests: Arc<Mutex<Vec<RecordedPut>>>,
    dropped_pending: Arc<AtomicUsize>,
}

struct PendingGuard(Arc<AtomicUsize>);

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl PutTransport {
    fn new(replies: impl IntoIterator<Item = Reply>) -> Self {
        Self {
            replies: Arc::new(Mutex::new(
                replies
                    .into_iter()
                    .map(|reply| (Duration::ZERO, reply))
                    .collect(),
            )),
            ..Self::default()
        }
    }

    fn attempts(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

impl connectrpc::client::ClientTransport for PutTransport {
    type ResponseBody = http_body_util::Full<Bytes>;
    type Error = ConnectError;

    fn send(
        &self,
        request: http::Request<connectrpc::client::ClientBody>,
    ) -> connectrpc::client::BoxFuture<
        'static,
        Result<http::Response<Self::ResponseBody>, Self::Error>,
    > {
        let transport = self.clone();
        Box::pin(async move {
            assert_eq!(request.uri().path(), "/log.ingest.v1.Service/Put");
            let headers = request.headers().clone();
            let body = request.into_body().collect().await.unwrap().to_bytes();
            transport.requests.lock().unwrap().push(RecordedPut {
                body,
                headers,
                at: tokio::time::Instant::now(),
            });
            let (delay, reply) = transport
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected retry");
            tokio::time::sleep(delay).await;
            match reply {
                Reply::Error(error) => Ok(http::Response::builder()
                    .status(error.http_status())
                    .header("content-type", "application/json")
                    .body(http_body_util::Full::new(error.to_json()))
                    .unwrap()),
                Reply::TransportError(error) => Err(error),
                Reply::Success(sequence_number) => Ok(http::Response::builder()
                    .header("content-type", "application/proto")
                    .body(http_body_util::Full::new(
                        proto::ingest::PutResponse {
                            sequence_number,
                            ..Default::default()
                        }
                        .encode_to_bytes(),
                    ))
                    .unwrap()),
                Reply::Pending => {
                    let _guard = PendingGuard(transport.dropped_pending.clone());
                    std::future::pending().await
                }
            }
        })
    }
}

fn retry_config(attempts: usize) -> RetryConfig {
    RetryConfig::standard()
        .with_max_attempts(attempts)
        .with_initial_backoff(Duration::ZERO)
        .with_max_backoff(Duration::from_millis(100))
}

fn client(transport: PutTransport, retry: RetryConfig) -> StoreClient {
    StoreClient::builder()
        .url("http://ingest.internal")
        .client_transport(transport)
        .retry_config(retry)
        .build()
        .unwrap()
}

fn batch() -> Vec<proto::common::Entry> {
    [
        (&b"tenant/first"[..], &b"one"[..]),
        (&b"tenant/second"[..], &b"two"[..]),
    ]
    .into_iter()
    .map(|(key, value)| proto::common::Entry {
        key: key.to_vec(),
        value: Bytes::copy_from_slice(value),
        ..Default::default()
    })
    .collect()
}

fn admission_error(delay: ProtoDuration) -> ConnectError {
    proto::with_retry_info_detail(
        proto::with_error_info_detail(
            ConnectError::resource_exhausted("admission exhausted"),
            proto::google::rpc::ErrorInfo {
                domain: INGEST_ERROR_DOMAIN.to_string(),
                reason: INGEST_ADMISSION_EXHAUSTED_REASON.to_string(),
                ..Default::default()
            },
        ),
        proto::google::rpc::RetryInfo {
            retry_delay: Some(delay).into(),
            ..Default::default()
        },
    )
}

fn admission_error_ms(milliseconds: i32) -> ConnectError {
    admission_error(ProtoDuration {
        nanos: milliseconds * 1_000_000,
        ..Default::default()
    })
}

fn bare_admission_error() -> ConnectError {
    ConnectError::resource_exhausted("admission exhausted")
        .with_detail(ErrorDetail::from_message(
            "google.rpc.ErrorInfo",
            &proto::google::rpc::ErrorInfo {
                domain: INGEST_ERROR_DOMAIN.to_string(),
                reason: INGEST_ADMISSION_EXHAUSTED_REASON.to_string(),
                ..Default::default()
            },
        ))
        .with_detail(ErrorDetail::from_message(
            "google.rpc.RetryInfo",
            &proto::google::rpc::RetryInfo {
                retry_delay: Some(ProtoDuration {
                    nanos: 10_000_000,
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            },
        ))
}

#[tokio::test(start_paused = true)]
async fn put_retries_bare_connect_error_details_on_wire() {
    let transport = PutTransport::new([Reply::Error(bare_admission_error()), Reply::Success(47)]);
    assert_eq!(
        client(transport.clone(), retry_config(3))
            .send_put(batch())
            .await
            .unwrap(),
        47
    );
    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].body, requests[1].body);
    assert!(requests[1].at.duration_since(requests[0].at) >= Duration::from_millis(10));
}

#[tokio::test(start_paused = true)]
async fn put_rejects_duplicate_bare_and_prefixed_critical_details() {
    for index in 0..2 {
        for bare_first in [false, true] {
            let bare = bare_admission_error();
            let prefixed = admission_error_ms(10);
            let mut error = if bare_first {
                bare.clone()
            } else {
                prefixed.clone()
            };
            error.details.push(if bare_first {
                prefixed.details[index].clone()
            } else {
                bare.details[index].clone()
            });
            let transport = PutTransport::new([Reply::Error(error), Reply::Success(47)]);
            assert_eq!(
                client(transport.clone(), retry_config(3))
                    .send_put(batch())
                    .await
                    .unwrap_err()
                    .rpc_code(),
                Some(ErrorCode::ResourceExhausted)
            );
            assert_eq!(transport.attempts(), 1);
        }
    }
}

#[tokio::test(start_paused = true)]
async fn put_retries_admission_then_success_with_identical_atomic_payload() {
    for compression in [
        ConnectRequestCompression::None,
        ConnectRequestCompression::Zstd { level: 3 },
    ] {
        let transport =
            PutTransport::new([Reply::Error(admission_error_ms(30)), Reply::Success(47)]);
        let client = StoreClient::builder()
            .url("http://ingest.internal")
            .client_transport(transport.clone())
            .connect_request_compression(compression)
            .retry_config(retry_config(3).with_initial_backoff(Duration::from_millis(5)))
            .build()
            .unwrap();
        assert_eq!(client.send_put(batch()).await.unwrap(), 47);
        let requests = transport.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].body, requests[1].body);
        assert_eq!(
            requests[0].headers.get("content-encoding"),
            requests[1].headers.get("content-encoding")
        );
        assert!(requests[1].at.duration_since(requests[0].at) >= Duration::from_millis(30));
        assert!(requests[1].at.duration_since(requests[0].at) <= Duration::from_millis(36));
        if compression == ConnectRequestCompression::None {
            assert_eq!(
                ProtoPutRequest::decode_from_slice(&requests[0].body)
                    .unwrap()
                    .kvs,
                batch()
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn put_does_not_retry_generic_permanent_or_ambiguous_errors() {
    let mut errors = vec![ConnectError::resource_exhausted("generic exhaustion")];
    for code in [
        ErrorCode::Unavailable,
        ErrorCode::Internal,
        ErrorCode::Unknown,
        ErrorCode::Aborted,
        ErrorCode::DeadlineExceeded,
        ErrorCode::InvalidArgument,
        ErrorCode::PermissionDenied,
    ] {
        let mut error = admission_error_ms(10);
        error.code = code;
        errors.push(error);
    }
    for (domain, reason) in [
        ("other", INGEST_ADMISSION_EXHAUSTED_REASON),
        (INGEST_ERROR_DOMAIN, "WORKER_NOT_READY"),
        (INGEST_ERROR_DOMAIN, PUT_TOO_LARGE_REASON),
    ] {
        errors.push(proto::with_retry_info_detail(
            proto::with_error_info_detail(
                ConnectError::resource_exhausted("different rejection"),
                proto::google::rpc::ErrorInfo {
                    domain: domain.to_string(),
                    reason: reason.to_string(),
                    ..Default::default()
                },
            ),
            proto::google::rpc::RetryInfo {
                retry_delay: Some(ProtoDuration {
                    nanos: 10_000_000,
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            },
        ));
    }
    for error in errors {
        let code = error.code;
        let transport = PutTransport::new([Reply::Error(error), Reply::Success(47)]);
        let error = client(transport.clone(), retry_config(3))
            .send_put(batch())
            .await
            .unwrap_err();
        assert_eq!(error.rpc_code(), Some(code));
        assert_eq!(transport.attempts(), 1);
    }
    let transport = PutTransport::new([
        Reply::TransportError(ConnectError::unavailable("connection lost after upload")),
        Reply::Success(47),
    ]);
    let error = client(transport.clone(), retry_config(3))
        .send_put(batch())
        .await
        .unwrap_err();
    assert_eq!(error.rpc_code(), Some(ErrorCode::Unavailable));
    assert_eq!(transport.attempts(), 1);
}

#[tokio::test(start_paused = true)]
async fn put_requires_complete_well_formed_positive_retry_details() {
    let mut errors = Vec::new();
    for index in 0..2 {
        let mut error = admission_error_ms(10);
        error.details.remove(index);
        errors.push(error);

        let mut error = admission_error_ms(10);
        error.details.push(error.details[index].clone());
        errors.push(error);
    }
    errors.push(proto::with_error_info_detail(
        proto::with_retry_info_detail(
            ConnectError::resource_exhausted("missing delay"),
            proto::google::rpc::RetryInfo::default(),
        ),
        proto::google::rpc::ErrorInfo {
            domain: INGEST_ERROR_DOMAIN.to_string(),
            reason: INGEST_ADMISSION_EXHAUSTED_REASON.to_string(),
            ..Default::default()
        },
    ));
    for duration in [
        ProtoDuration::default(),
        ProtoDuration {
            seconds: -1,
            ..Default::default()
        },
        ProtoDuration {
            nanos: -1,
            ..Default::default()
        },
        ProtoDuration {
            nanos: 1_000_000_000,
            ..Default::default()
        },
        ProtoDuration {
            seconds: 315_576_000_001,
            ..Default::default()
        },
    ] {
        errors.push(admission_error(duration));
    }
    for type_url in [
        proto::google::rpc::ErrorInfo::TYPE_URL,
        proto::google::rpc::RetryInfo::TYPE_URL,
    ] {
        let mut malformed = admission_error_ms(10);
        malformed
            .details
            .iter_mut()
            .find(|detail| detail.type_url == type_url)
            .unwrap()
            .value = Some("!".to_string());
        errors.push(malformed);

        errors.push(admission_error_ms(10).with_detail(ErrorDetail {
            type_url: type_url.to_string(),
            value: Some("!".to_string()),
            debug: None,
        }));
    }
    for error in errors {
        let transport = PutTransport::new([Reply::Error(error), Reply::Success(47)]);
        assert_eq!(
            client(transport.clone(), retry_config(3))
                .send_put(batch())
                .await
                .unwrap_err()
                .rpc_code(),
            Some(ErrorCode::ResourceExhausted)
        );
        assert_eq!(transport.attempts(), 1);
    }
}

#[tokio::test(start_paused = true)]
async fn put_obeys_attempt_budget_and_disabled_retries() {
    for retry in [retry_config(3), RetryConfig::disabled(), retry_config(0)] {
        let attempts = retry.max_attempts;
        let transport =
            PutTransport::new((0..attempts).map(|_| Reply::Error(admission_error_ms(1))));
        let error = client(transport.clone(), retry)
            .send_put(batch())
            .await
            .unwrap_err();
        assert_eq!(error.rpc_code(), Some(ErrorCode::ResourceExhausted));
        assert_eq!(transport.attempts(), attempts);
    }
}

#[test]
fn put_jitter_respects_hint_floor_and_configured_ceiling() {
    let config = retry_config(3).with_initial_backoff(Duration::from_millis(20));
    for (hint, attempt, minimum, maximum) in [
        (30, 1, 30, 50),
        (10, 2, 40, 80),
        (90, 3, 90, 100),
        (100, 3, 100, 100),
    ] {
        for _ in 0..128 {
            let delay =
                put_retry_delay_for_error(&admission_error_ms(hint), attempt, config).unwrap();
            assert!(
                (Duration::from_millis(minimum)..=Duration::from_millis(maximum)).contains(&delay)
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn put_does_not_shorten_hint_above_maximum() {
    let transport = PutTransport::new([Reply::Error(admission_error_ms(101)), Reply::Success(47)]);
    assert_eq!(
        client(transport.clone(), retry_config(3))
            .send_put(batch())
            .await
            .unwrap_err()
            .rpc_code(),
        Some(ErrorCode::ResourceExhausted)
    );
    assert_eq!(transport.attempts(), 1);
}

#[tokio::test(start_paused = true)]
async fn put_deadline_covers_backoff_without_another_attempt() {
    let transport = PutTransport::new([Reply::Error(admission_error_ms(50)), Reply::Success(47)]);
    let client = StoreClient::builder()
        .url("http://ingest.internal")
        .client_transport(transport.clone())
        .retry_config(retry_config(3))
        .request_timeout(Duration::from_millis(25))
        .build()
        .unwrap();
    let started = tokio::time::Instant::now();
    assert_eq!(
        client.send_put(batch()).await.unwrap_err().rpc_code(),
        Some(ErrorCode::DeadlineExceeded)
    );
    assert_eq!(started.elapsed(), Duration::from_millis(25));
    assert_eq!(transport.attempts(), 1);
}

#[tokio::test]
async fn put_deadline_covers_attempts_and_sends_remaining_timeout() {
    let transport = PutTransport::new([Reply::Error(admission_error_ms(10)), Reply::Pending]);
    transport.replies.lock().unwrap()[0].0 = Duration::from_millis(10);
    let client = StoreClient::builder()
        .url("http://ingest.internal")
        .client_transport(transport.clone())
        .retry_config(retry_config(3))
        .request_timeout(Duration::from_millis(100))
        .build()
        .unwrap();
    let started = tokio::time::Instant::now();
    assert_eq!(
        client.send_put(batch()).await.unwrap_err().rpc_code(),
        Some(ErrorCode::DeadlineExceeded)
    );
    assert!(started.elapsed() >= Duration::from_millis(99));
    assert!(started.elapsed() < Duration::from_millis(200));
    assert_eq!(transport.dropped_pending.load(Ordering::SeqCst), 1);
    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    let first_timeout: u64 = requests[0]
        .headers
        .get("connect-timeout-ms")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((95..=100).contains(&first_timeout));
    let second_timeout: u64 = requests[1]
        .headers
        .get("connect-timeout-ms")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(second_timeout < first_timeout);
    let remaining = Duration::from_millis(100)
        .saturating_sub(requests[1].at.duration_since(started))
        .as_millis() as u64;
    assert!(second_timeout.abs_diff(remaining) <= 1);
}

#[tokio::test(start_paused = true)]
async fn put_without_configured_timeout_allows_upload_beyond_thirty_seconds() {
    let transport = PutTransport::new([Reply::Success(47)]);
    transport.replies.lock().unwrap()[0].0 = Duration::from_secs(31);
    assert_eq!(
        client(transport.clone(), retry_config(3))
            .send_put(batch())
            .await
            .unwrap(),
        47
    );
    assert!(!transport.requests.lock().unwrap()[0]
        .headers
        .contains_key("connect-timeout-ms"));
}

#[tokio::test(start_paused = true)]
async fn dropping_put_stops_backoff_and_inflight_requests() {
    let transport = PutTransport::new([Reply::Error(admission_error_ms(50)), Reply::Success(47)]);
    let client = client(transport.clone(), retry_config(3));
    let mut put = Box::pin(client.send_put(batch()));
    assert!(futures::poll!(&mut put).is_pending());
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(futures::poll!(&mut put).is_pending());
    assert_eq!(transport.attempts(), 1);
    drop(put);
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(transport.attempts(), 1);

    let transport = PutTransport::new([Reply::Pending]);
    let client = StoreClient::builder()
        .url("http://ingest.internal")
        .client_transport(transport.clone())
        .retry_config(retry_config(3))
        .build()
        .unwrap();
    let mut put = Box::pin(client.send_put(batch()));
    assert!(futures::poll!(&mut put).is_pending());
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(futures::poll!(&mut put).is_pending());
    drop(put);
    assert_eq!(transport.dropped_pending.load(Ordering::SeqCst), 1);
    assert_eq!(transport.attempts(), 1);
}
