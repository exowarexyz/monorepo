use super::*;
use buffa::Message as _;
use http_body_util::BodyExt as _;
use std::collections::VecDeque;
use std::sync::Mutex;

enum Reply {
    Error(ConnectError),
    Value(&'static [u8]),
}

#[derive(Clone, Default)]
struct GetTransport {
    replies: Arc<Mutex<VecDeque<(Duration, Reply)>>>,
    timeouts: Arc<Mutex<Vec<Option<String>>>>,
}

impl GetTransport {
    fn new(replies: impl IntoIterator<Item = (Duration, Reply)>) -> Self {
        Self {
            replies: Arc::new(Mutex::new(replies.into_iter().collect())),
            ..Self::default()
        }
    }

    fn timeouts(&self) -> Vec<Option<String>> {
        self.timeouts.lock().unwrap().clone()
    }
}

impl connectrpc::client::ClientTransport for GetTransport {
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
            assert_eq!(request.uri().path(), "/store.query.v1.Service/Get");
            let timeout = request
                .headers()
                .get("connect-timeout-ms")
                .map(|value| value.to_str().unwrap().to_string());
            request.into_body().collect().await.unwrap();
            transport.timeouts.lock().unwrap().push(timeout);
            let (delay, reply) = transport
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected retry");
            tokio::time::sleep(delay).await;
            Ok(match reply {
                Reply::Error(error) => http::Response::builder()
                    .status(error.http_status())
                    .header("content-type", "application/json")
                    .body(http_body_util::Full::new(error.to_json()))
                    .unwrap(),
                Reply::Value(value) => http::Response::builder()
                    .header("content-type", "application/proto")
                    .body(http_body_util::Full::new(
                        proto::query::GetResponse {
                            value: Some(Bytes::from_static(value)),
                            ..Default::default()
                        }
                        .encode_to_bytes(),
                    ))
                    .unwrap(),
            })
        })
    }
}

fn retry_config(attempts: usize) -> RetryConfig {
    RetryConfig::standard()
        .with_max_attempts(attempts)
        .with_initial_backoff(Duration::ZERO)
        .with_max_backoff(Duration::ZERO)
}

fn key() -> Key {
    Key::from(b"key".to_vec())
}

// Connect measures attempt deadlines on the real clock, so this test cannot use paused time.
#[tokio::test]
async fn read_timeout_bounds_the_whole_call_rather_than_each_attempt() {
    // Each reply alone fits the timeout, so a per-attempt timeout would let all five attempts
    // run and fail with `unavailable`.
    let delay = Duration::from_millis(100);
    let budget = Duration::from_millis(150);
    let transport =
        GetTransport::new((0..5).map(|_| (delay, Reply::Error(ConnectError::unavailable("busy")))));
    let client = StoreClient::builder()
        .url("http://query.internal")
        .client_transport(transport.clone())
        .retry_config(retry_config(5))
        .request_timeout(budget)
        .build()
        .unwrap();

    let started = tokio::time::Instant::now();
    let err = client.get(&key()).await.unwrap_err();
    let elapsed = started.elapsed();

    assert_eq!(err.rpc_code(), Some(ErrorCode::DeadlineExceeded));
    assert!(elapsed >= budget);
    assert!(elapsed < budget + Duration::from_millis(50));

    // The second attempt receives only what the first one left.
    let timeouts: Vec<u64> = transport
        .timeouts()
        .into_iter()
        .map(|timeout| timeout.unwrap().parse().unwrap())
        .collect();
    assert_eq!(timeouts.len(), 2);
    assert!((140..=150).contains(&timeouts[0]));
    assert!((1..=50).contains(&timeouts[1]));
}

#[tokio::test(start_paused = true)]
async fn attempt_timeout_never_ends_before_the_call_budget() {
    let client = StoreClient::builder()
        .url("http://query.internal")
        .request_timeout(Duration::from_millis(150))
        .build()
        .unwrap();
    let started = tokio::time::Instant::now();
    tokio::time::advance(Duration::from_micros(149_500)).await;

    // Connect truncates to whole milliseconds, so passing 0.5ms through would give the attempt
    // a zero deadline while the call still had time left.
    assert_eq!(
        client.remaining_request_timeout(started).unwrap(),
        Some(Duration::from_millis(1))
    );

    tokio::time::advance(Duration::from_micros(500)).await;
    assert_eq!(
        client.remaining_request_timeout(started).unwrap_err().code,
        ErrorCode::DeadlineExceeded
    );
}

#[tokio::test(start_paused = true)]
async fn read_retries_a_server_deadline_without_a_configured_timeout() {
    let transport = GetTransport::new([
        (
            Duration::ZERO,
            Reply::Error(ConnectError::deadline_exceeded("upstream deadline")),
        ),
        (Duration::ZERO, Reply::Value(b"value")),
    ]);
    let client = StoreClient::builder()
        .url("http://query.internal")
        .client_transport(transport.clone())
        .retry_config(retry_config(2))
        .build()
        .unwrap();

    assert_eq!(
        client.get(&key()).await.unwrap(),
        Some(Bytes::from_static(b"value"))
    );
    assert_eq!(transport.timeouts(), vec![None, None]);
}
