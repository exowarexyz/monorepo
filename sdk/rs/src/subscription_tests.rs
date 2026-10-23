use super::*;

use buffa::Message as _;
use exoware_proto::log::stream::v1::SubscribeResponse;
use futures::StreamExt as _;
use http_body_util::BodyExt as _;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::Mutex;

type TestBody = http_body_util::combinators::UnsyncBoxBody<Bytes, Infallible>;

enum Script {
    /// Frames followed by a terminal envelope.
    Ends(Vec<SubscribeResponse>, ConnectError),
    /// Frames followed by a clean end.
    Closes(Vec<SubscribeResponse>),
    /// Frames, then a body that stays open.
    Stays(Vec<SubscribeResponse>),
    /// A setup failure before any frame.
    Rejects(ConnectError),
    /// Response headers that never arrive.
    Stalls,
    /// Headers after a delay, then a body that stays open.
    Delays(Duration, Vec<SubscribeResponse>),
    /// Headers at once, frames after a delay, then a body that stays open.
    Trickles(Duration, Vec<SubscribeResponse>),
}

#[derive(Default)]
struct State {
    scripts: VecDeque<Script>,
    cursors: Vec<Option<u64>>,
}

#[derive(Clone, Default)]
struct ScriptedTransport(Arc<Mutex<State>>);

impl ScriptedTransport {
    fn new(scripts: impl IntoIterator<Item = Script>) -> Self {
        let transport = Self::default();
        transport.0.lock().unwrap().scripts.extend(scripts);
        transport
    }

    fn cursors(&self) -> Vec<Option<u64>> {
        self.0.lock().unwrap().cursors.clone()
    }
}

fn data_envelopes(frames: Vec<SubscribeResponse>) -> Vec<Bytes> {
    frames
        .into_iter()
        .map(|frame| connectrpc::envelope::Envelope::data(frame.encode_to_bytes()).encode())
        .collect()
}

fn end_envelope(error: Option<ConnectError>) -> Bytes {
    let payload = match error {
        Some(error) => {
            let error = String::from_utf8(error.to_json().to_vec()).unwrap();
            Bytes::from(format!("{{\"error\":{error}}}"))
        }
        None => Bytes::from_static(b"{}"),
    };
    connectrpc::envelope::Envelope::end_stream(payload).encode()
}

fn streaming_response(chunks: Vec<Bytes>, stays_open: bool) -> http::Response<TestBody> {
    let frames = futures::stream::iter(
        chunks
            .into_iter()
            .map(|chunk| Ok::<_, Infallible>(http_body::Frame::data(chunk))),
    );
    let body = if stays_open {
        http_body_util::StreamBody::new(frames.chain(futures::stream::pending())).boxed_unsync()
    } else {
        http_body_util::StreamBody::new(frames).boxed_unsync()
    };
    http::Response::builder()
        .header(http::header::CONTENT_TYPE, "application/connect+proto")
        .body(body)
        .unwrap()
}

impl connectrpc::client::ClientTransport for ScriptedTransport {
    type ResponseBody = TestBody;
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
            assert_eq!(request.uri().path(), "/log.stream.v1.Service/Subscribe");
            let body = request.into_body().collect().await.unwrap().to_bytes();
            let request =
                exoware_proto::log::stream::v1::SubscribeRequest::decode_from_slice(&body[5..])
                    .unwrap();
            let script = {
                let mut state = transport.0.lock().unwrap();
                state.cursors.push(request.since_sequence_number);
                state.scripts.pop_front().expect("unexpected subscription")
            };
            match script {
                Script::Ends(frames, error) => {
                    let mut chunks = data_envelopes(frames);
                    chunks.push(end_envelope(Some(error)));
                    Ok(streaming_response(chunks, false))
                }
                Script::Closes(frames) => {
                    let mut chunks = data_envelopes(frames);
                    chunks.push(end_envelope(None));
                    Ok(streaming_response(chunks, false))
                }
                Script::Stays(frames) => Ok(streaming_response(data_envelopes(frames), true)),
                Script::Rejects(error) => Ok(http::Response::builder()
                    .status(error.http_status())
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(http_body_util::Full::new(error.to_json()).boxed_unsync())
                    .unwrap()),
                Script::Stalls => futures::future::pending().await,
                Script::Delays(delay, frames) => {
                    tokio::time::sleep(delay).await;
                    Ok(streaming_response(data_envelopes(frames), true))
                }
                Script::Trickles(delay, frames) => {
                    let chunks = data_envelopes(frames);
                    let frames = futures::stream::once(tokio::time::sleep(delay))
                        .flat_map(move |()| futures::stream::iter(chunks.clone()))
                        .map(|chunk| Ok::<_, Infallible>(http_body::Frame::data(chunk)))
                        .chain(futures::stream::pending());
                    Ok(http::Response::builder()
                        .header(http::header::CONTENT_TYPE, "application/connect+proto")
                        .body(http_body_util::StreamBody::new(frames).boxed_unsync())
                        .unwrap())
                }
            }
        })
    }
}

fn checkpoint(sequence_number: u64) -> SubscribeResponse {
    SubscribeResponse {
        sequence_number,
        ..Default::default()
    }
}

fn batch(sequence_number: u64) -> SubscribeResponse {
    SubscribeResponse {
        sequence_number,
        entries: vec![exoware_proto::common::kv::v1::Entry {
            key: b"tenant/key".to_vec(),
            value: Bytes::from_static(b"value"),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn batch_evicted() -> ConnectError {
    crate::proto::with_error_info_detail(
        ConnectError::out_of_range("evicted"),
        crate::google::rpc::ErrorInfo {
            reason: "BATCH_EVICTED".to_owned(),
            domain: "log.stream".to_owned(),
            ..Default::default()
        },
    )
}

fn builder(transport: ScriptedTransport) -> StoreClientBuilder {
    StoreClient::builder()
        .url("http://store.internal")
        .retry_config(RetryConfig::disabled())
        .client_transport(transport)
}

fn client_with(
    transport: ScriptedTransport,
    config: SubscriptionRetryConfig,
) -> PrefixedStoreClient {
    builder(transport)
        .subscription_retry_config(config)
        .build()
        .unwrap()
        .prefixed(StoreKeyPrefix::new("tenant/").unwrap())
}

fn client(transport: ScriptedTransport) -> PrefixedStoreClient {
    client_with(transport, SubscriptionRetryConfig::standard())
}

fn filter() -> crate::stream_filter::StreamFilter {
    crate::stream_filter::StreamFilter {
        selectors: vec![crate::selector::Selector {
            prefix: Bytes::new(),
            payload_regex: ".*".into(),
        }],
        value_filters: Vec::new(),
    }
}

async fn next_sequence(subscription: &mut StreamSubscription) -> u64 {
    subscription.next().await.unwrap().unwrap().sequence_number
}

#[tokio::test(start_paused = true)]
async fn resumes_from_the_cursor_without_gaps_or_duplicates() {
    let transport = ScriptedTransport::new([
        Script::Closes(vec![checkpoint(10), batch(11), batch(12)]),
        Script::Ends(
            vec![checkpoint(12), batch(12), batch(13)],
            ConnectError::unavailable("restarting"),
        ),
        Script::Ends(vec![checkpoint(13)], ConnectError::internal("reset")),
        Script::Stays(vec![checkpoint(13), checkpoint(20), batch(21)]),
    ]);
    let session = ReadSession::monotonic(client(transport.clone()), None);
    let mut subscription = session.subscribe(filter(), None).await.unwrap();

    assert_eq!(next_sequence(&mut subscription).await, 11);
    assert_eq!(next_sequence(&mut subscription).await, 12);
    assert_eq!(next_sequence(&mut subscription).await, 13);
    assert_eq!(next_sequence(&mut subscription).await, 21);
    assert_eq!(session.evaluated_sequence(), Some(21));
    assert_eq!(transport.cursors(), [None, Some(13), Some(14), Some(14)]);
}

#[tokio::test(start_paused = true)]
async fn empty_checkpoints_are_cursors_but_not_read_observations() {
    let transport = ScriptedTransport::new([
        Script::Ends(
            vec![checkpoint(30)],
            ConnectError::unavailable("restarting"),
        ),
        Script::Stays(vec![checkpoint(40), batch(41)]),
    ]);
    let session = ReadSession::monotonic(client(transport.clone()), None);
    let mut subscription = session.subscribe(filter(), None).await.unwrap();

    assert_eq!(next_sequence(&mut subscription).await, 41);
    assert_eq!(session.evaluated_sequence(), Some(41));
    assert_eq!(transport.cursors(), [None, Some(31)]);

    let transport = ScriptedTransport::new([Script::Stays(vec![checkpoint(50)])]);
    let session = ReadSession::monotonic(client(transport), None);
    let mut subscription = session.subscribe(filter(), None).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), subscription.next())
            .await
            .is_err()
    );
    assert_eq!(session.evaluated_sequence(), None);
}

#[tokio::test(start_paused = true)]
async fn live_subscription_without_a_cursor_returns_its_first_failure() {
    let transport = ScriptedTransport::new([Script::Rejects(ConnectError::unavailable("down"))]);
    let err = client(transport.clone())
        .stream()
        .subscribe(filter(), None)
        .await
        .unwrap_err();
    assert_eq!(err.rpc_code(), Some(ErrorCode::Unavailable));
    assert_eq!(transport.cursors(), [None]);

    let transport = ScriptedTransport::new([Script::Closes(Vec::new())]);
    let mut subscription = client(transport.clone())
        .stream()
        .subscribe(filter(), None)
        .await
        .unwrap();
    let err = subscription.next().await.unwrap_err();
    assert_eq!(err.rpc_code(), Some(ErrorCode::Unavailable));
    assert!(err.to_string().contains("before its first frame"));
    assert!(subscription.next().await.unwrap().is_none());
    assert_eq!(transport.cursors(), [None]);

    let transport =
        ScriptedTransport::new([Script::Ends(Vec::new(), ConnectError::internal("reset"))]);
    let mut subscription = client(transport.clone())
        .stream()
        .subscribe(filter(), Some(0))
        .await
        .unwrap();
    assert_eq!(
        subscription.next().await.unwrap_err().rpc_code(),
        Some(ErrorCode::Internal)
    );
    assert_eq!(transport.cursors(), [Some(0)]);
}

#[tokio::test(start_paused = true)]
async fn explicit_cursor_retries_the_initial_open() {
    let transport = ScriptedTransport::new([
        Script::Rejects(ConnectError::unavailable("down")),
        Script::Rejects(ConnectError::internal("proxy")),
        Script::Ends(Vec::new(), ConnectError::aborted("moved")),
        Script::Stays(vec![checkpoint(4), batch(5)]),
    ]);
    let mut subscription = client(transport.clone())
        .stream()
        .subscribe(filter(), Some(5))
        .await
        .unwrap();

    assert_eq!(next_sequence(&mut subscription).await, 5);
    assert_eq!(transport.cursors(), [Some(5); 4]);
}

#[tokio::test(start_paused = true)]
async fn permanent_failures_are_returned_without_retrying() {
    for error in [
        ConnectError::unauthenticated("token"),
        ConnectError::permission_denied("scope"),
        ConnectError::invalid_argument("filter"),
        batch_evicted(),
    ] {
        let code = error.code;
        let transport = ScriptedTransport::new([Script::Rejects(error)]);
        let err = client(transport.clone())
            .stream()
            .subscribe(filter(), Some(5))
            .await
            .unwrap_err();
        assert_eq!(err.rpc_code(), Some(code));
        assert_eq!(transport.cursors(), [Some(5)]);
    }

    for error in [ConnectError::unauthenticated("token"), batch_evicted()] {
        let code = error.code;
        let transport = ScriptedTransport::new([
            Script::Ends(
                vec![checkpoint(10), batch(11)],
                ConnectError::unavailable("restart"),
            ),
            Script::Rejects(error),
        ]);
        let mut subscription = client(transport.clone())
            .stream()
            .subscribe(filter(), None)
            .await
            .unwrap();
        assert_eq!(next_sequence(&mut subscription).await, 11);
        assert_eq!(
            subscription.next().await.unwrap_err().rpc_code(),
            Some(code)
        );
        assert!(subscription.next().await.unwrap().is_none());
        assert_eq!(transport.cursors(), [None, Some(12)]);
    }
}

#[tokio::test(start_paused = true)]
async fn outage_budget_bounds_failed_attempts() {
    let transport = ScriptedTransport::new(
        std::iter::repeat_with(|| Script::Rejects(ConnectError::unavailable("down"))).take(100),
    );
    let config = SubscriptionRetryConfig::standard().with_outage_budget(Duration::from_secs(1));
    let started = tokio::time::Instant::now();
    let err = client_with(transport.clone(), config)
        .stream()
        .subscribe(filter(), Some(5))
        .await
        .unwrap_err();

    assert_eq!(err.rpc_code(), Some(ErrorCode::DeadlineExceeded));
    assert!(err.to_string().contains("down"));
    assert_eq!(started.elapsed(), Duration::from_secs(1));
    let attempts = transport.cursors().len();
    assert!((2..100).contains(&attempts), "{attempts} attempts");
}

#[tokio::test(start_paused = true)]
async fn outage_budget_bounds_stalled_opens_and_first_frames() {
    let config = SubscriptionRetryConfig::standard().with_outage_budget(Duration::from_secs(1));

    let transport = ScriptedTransport::new([Script::Stalls]);
    let started = tokio::time::Instant::now();
    let err = client_with(transport, config)
        .stream()
        .subscribe(filter(), Some(5))
        .await
        .unwrap_err();
    assert_eq!(err.rpc_code(), Some(ErrorCode::DeadlineExceeded));
    assert_eq!(started.elapsed(), Duration::from_secs(1));

    let transport = ScriptedTransport::new([Script::Stays(Vec::new())]);
    let mut subscription = client_with(transport, config)
        .stream()
        .subscribe(filter(), None)
        .await
        .unwrap();
    let started = tokio::time::Instant::now();
    let err = subscription.next().await.unwrap_err();
    assert_eq!(err.rpc_code(), Some(ErrorCode::DeadlineExceeded));
    assert!(started.elapsed() <= Duration::from_secs(1));

    let transport = ScriptedTransport::new([
        Script::Ends(
            vec![checkpoint(10), batch(11)],
            ConnectError::unavailable("restart"),
        ),
        Script::Stalls,
    ]);
    let mut subscription = client_with(transport.clone(), config)
        .stream()
        .subscribe(filter(), None)
        .await
        .unwrap();
    assert_eq!(next_sequence(&mut subscription).await, 11);
    let started = tokio::time::Instant::now();
    let err = subscription.next().await.unwrap_err();
    assert_eq!(err.rpc_code(), Some(ErrorCode::DeadlineExceeded));
    assert!(err.to_string().contains("restart"));
    assert_eq!(started.elapsed(), Duration::from_secs(1));
    assert_eq!(transport.cursors(), [None, Some(12)]);

    let transport = ScriptedTransport::new([
        Script::Ends(
            vec![checkpoint(10), batch(11)],
            ConnectError::unavailable("restart"),
        ),
        Script::Stays(Vec::new()),
    ]);
    let mut subscription = client_with(transport, config)
        .stream()
        .subscribe(filter(), None)
        .await
        .unwrap();
    assert_eq!(next_sequence(&mut subscription).await, 11);
    let started = tokio::time::Instant::now();
    let err = subscription.next().await.unwrap_err();
    assert_eq!(err.rpc_code(), Some(ErrorCode::DeadlineExceeded));
    assert_eq!(started.elapsed(), Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn any_frame_resets_the_outage_budget() {
    let config = SubscriptionRetryConfig::standard()
        .with_outage_budget(Duration::from_secs(1))
        .with_initial_backoff(Duration::from_millis(400))
        .with_max_backoff(Duration::from_millis(400));
    let mut scripts = Vec::new();
    for _ in 0..3 {
        scripts.push(Script::Ends(
            vec![checkpoint(10)],
            ConnectError::unavailable("restart"),
        ));
        scripts.push(Script::Rejects(ConnectError::unavailable("down")));
    }
    scripts.push(Script::Stays(vec![checkpoint(10), batch(11)]));
    let transport = ScriptedTransport::new(scripts);
    let started = tokio::time::Instant::now();
    let mut subscription = client_with(transport.clone(), config)
        .stream()
        .subscribe(filter(), None)
        .await
        .unwrap();

    assert_eq!(next_sequence(&mut subscription).await, 11);
    assert!(started.elapsed() > Duration::from_secs(1));
    assert_eq!(transport.cursors().len(), 7);
}

#[tokio::test(start_paused = true)]
async fn canceling_next_during_backoff_keeps_the_cursor_and_pending_delay() {
    let transport = ScriptedTransport::new([
        Script::Ends(
            vec![checkpoint(10), batch(11)],
            ConnectError::unavailable("restart"),
        ),
        Script::Stays(vec![checkpoint(11), batch(12)]),
    ]);
    let mut subscription = client(transport.clone())
        .stream()
        .subscribe(filter(), None)
        .await
        .unwrap();
    assert_eq!(next_sequence(&mut subscription).await, 11);

    // Backoff is at least 50 ms, so this cancels while sleeping.
    assert!(
        tokio::time::timeout(Duration::from_millis(1), subscription.next())
            .await
            .is_err()
    );
    assert_eq!(transport.cursors(), [None]);

    let resumed = tokio::time::Instant::now();
    assert_eq!(next_sequence(&mut subscription).await, 12);
    assert!(resumed.elapsed() >= Duration::from_millis(49));
    assert!(resumed.elapsed() < Duration::from_millis(100));
    assert_eq!(transport.cursors(), [None, Some(12)]);
}

#[tokio::test(start_paused = true)]
async fn canceling_next_during_an_open_keeps_the_cursor_and_the_open() {
    let transport = ScriptedTransport::new([
        Script::Ends(
            vec![checkpoint(10), batch(11)],
            ConnectError::unavailable("restart"),
        ),
        Script::Delays(Duration::from_secs(1), vec![checkpoint(11), batch(12)]),
    ]);
    let mut subscription = client(transport.clone())
        .stream()
        .subscribe(filter(), None)
        .await
        .unwrap();
    assert_eq!(next_sequence(&mut subscription).await, 11);

    assert!(
        tokio::time::timeout(Duration::from_millis(500), subscription.next())
            .await
            .is_err()
    );
    assert_eq!(transport.cursors(), [None, Some(12)]);

    // The open that was in flight completes on the next call instead of being reissued.
    assert_eq!(next_sequence(&mut subscription).await, 12);
    assert_eq!(transport.cursors(), [None, Some(12)]);
}

#[tokio::test(start_paused = true)]
async fn canceling_next_does_not_reset_the_outage_budget() {
    let mut scripts = vec![Script::Ends(
        vec![checkpoint(10), batch(11)],
        ConnectError::unavailable("restart"),
    )];
    scripts.extend(
        std::iter::repeat_with(|| Script::Rejects(ConnectError::unavailable("down"))).take(200),
    );
    let transport = ScriptedTransport::new(scripts);
    let config = SubscriptionRetryConfig::standard().with_outage_budget(Duration::from_secs(1));
    let mut subscription = client_with(transport, config)
        .stream()
        .subscribe(filter(), None)
        .await
        .unwrap();
    assert_eq!(next_sequence(&mut subscription).await, 11);

    let started = tokio::time::Instant::now();
    let err = loop {
        match tokio::time::timeout(Duration::from_millis(30), subscription.next()).await {
            Ok(result) => break result.unwrap_err(),
            Err(_) => assert!(started.elapsed() < Duration::from_secs(2)),
        }
    };
    assert_eq!(err.rpc_code(), Some(ErrorCode::DeadlineExceeded));
    assert_eq!(started.elapsed(), Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn unlimited_policy_keeps_retrying_past_the_standard_budget() {
    let config = SubscriptionRetryConfig::unlimited();
    let transport = ScriptedTransport::new(
        std::iter::repeat_with(|| Script::Rejects(ConnectError::unavailable("down")))
            .take(60)
            .chain([Script::Stays(vec![checkpoint(4), batch(5)])]),
    );
    let started = tokio::time::Instant::now();
    let mut subscription = client_with(transport, config)
        .stream()
        .subscribe(filter(), Some(5))
        .await
        .unwrap();

    assert_eq!(next_sequence(&mut subscription).await, 5);
    assert!(started.elapsed() > Duration::from_secs(60));
}

#[tokio::test(start_paused = true)]
async fn disabled_policy_preserves_close_and_error_behavior() {
    let config = SubscriptionRetryConfig::disabled();
    let transport = ScriptedTransport::new([Script::Closes(vec![checkpoint(10), batch(11)])]);
    let mut subscription = client_with(transport.clone(), config)
        .stream()
        .subscribe(filter(), Some(5))
        .await
        .unwrap();
    assert_eq!(next_sequence(&mut subscription).await, 11);
    assert!(subscription.next().await.unwrap().is_none());
    assert_eq!(transport.cursors(), [Some(5)]);

    // A clean close before any frame is still a clean end when nothing will resume.
    let transport = ScriptedTransport::new([Script::Closes(Vec::new())]);
    let mut subscription = client_with(transport.clone(), config)
        .stream()
        .subscribe(filter(), None)
        .await
        .unwrap();
    assert!(subscription.next().await.unwrap().is_none());
    assert_eq!(transport.cursors(), [None]);

    let transport = ScriptedTransport::new([Script::Rejects(ConnectError::unavailable("down"))]);
    let err = client_with(transport.clone(), config)
        .stream()
        .subscribe(filter(), Some(5))
        .await
        .unwrap_err();
    assert_eq!(err.rpc_code(), Some(ErrorCode::Unavailable));
    assert_eq!(transport.cursors(), [Some(5)]);
}

#[tokio::test(start_paused = true)]
async fn request_timeout_does_not_bound_subscriptions() {
    let delayed = || Script::Delays(Duration::from_millis(100), vec![checkpoint(10), batch(11)]);

    let transport = ScriptedTransport::new([delayed()]);
    let mut subscription = builder(transport)
        .request_timeout(Duration::from_millis(25))
        .build()
        .unwrap()
        .prefixed(StoreKeyPrefix::new("tenant/").unwrap())
        .stream()
        .subscribe(filter(), None)
        .await
        .unwrap();
    assert_eq!(next_sequence(&mut subscription).await, 11);

    let transport = ScriptedTransport::new([delayed()]);
    let mut subscription = builder(transport)
        .request_timeout(Duration::from_millis(25))
        .subscription_retry_config(SubscriptionRetryConfig::disabled())
        .build()
        .unwrap()
        .prefixed(StoreKeyPrefix::new("tenant/").unwrap())
        .stream()
        .subscribe(filter(), None)
        .await
        .unwrap();
    assert_eq!(next_sequence(&mut subscription).await, 11);
}

#[test]
fn backoff_is_jittered_exponential_and_capped() {
    let config = SubscriptionRetryConfig::standard();
    for _ in 0..100 {
        let first = config.backoff_delay(1);
        assert!((Duration::from_millis(50)..=Duration::from_millis(100)).contains(&first));
        let fourth = config.backoff_delay(4);
        assert!((Duration::from_millis(400)..=Duration::from_millis(800)).contains(&fourth));
        let capped = config.backoff_delay(u32::MAX);
        assert!((Duration::from_secs(1)..=Duration::from_secs(2)).contains(&capped));
    }
}

#[test]
fn max_backoff_below_initial_backoff_caps_every_delay() {
    let config = SubscriptionRetryConfig::standard()
        .with_initial_backoff(Duration::from_secs(5))
        .with_max_backoff(Duration::from_secs(1));
    let client = builder(ScriptedTransport::default())
        .subscription_retry_config(config)
        .build()
        .unwrap();
    assert_eq!(client.subscription_retry_config, config);

    for failures in [1, 2, u32::MAX] {
        let delay = client.subscription_retry_config.backoff_delay(failures);
        assert!((Duration::from_millis(500)..=Duration::from_secs(1)).contains(&delay));
    }
}

#[tokio::test(start_paused = true)]
async fn backoff_is_clamped_to_the_budget_without_another_attempt() {
    let config = SubscriptionRetryConfig::standard()
        .with_outage_budget(Duration::from_secs(1))
        .with_initial_backoff(Duration::from_secs(5));
    let transport = ScriptedTransport::new([
        Script::Rejects(ConnectError::unavailable("down")),
        Script::Stays(vec![checkpoint(4), batch(5)]),
    ]);
    let started = tokio::time::Instant::now();
    let err = client_with(transport.clone(), config)
        .stream()
        .subscribe(filter(), Some(5))
        .await
        .unwrap_err();

    assert_eq!(err.rpc_code(), Some(ErrorCode::DeadlineExceeded));
    assert!(err.to_string().contains("down"));
    assert_eq!(started.elapsed(), Duration::from_secs(1));
    assert_eq!(transport.cursors(), [Some(5)]);
}

#[tokio::test(start_paused = true)]
async fn last_sequence_number_cannot_be_resumed_past() {
    let transport = ScriptedTransport::new([Script::Ends(
        vec![checkpoint(u64::MAX - 1), batch(u64::MAX), batch(u64::MAX)],
        ConnectError::unavailable("restart"),
    )]);
    let mut subscription = client(transport.clone())
        .stream()
        .subscribe(filter(), None)
        .await
        .unwrap();

    assert_eq!(next_sequence(&mut subscription).await, u64::MAX);
    assert_eq!(
        subscription.next().await.unwrap_err().rpc_code(),
        Some(ErrorCode::Unavailable)
    );
    assert_eq!(transport.cursors(), [None]);
}

// The QMDB operation log stream polls a fresh `next()` future on every poll and drops it
// while pending, so every await inside `next()` must keep its progress in the subscription.
async fn next_with_fresh_futures(
    subscription: &mut StreamSubscription,
) -> Result<Option<StoreBatch>, ClientError> {
    std::future::poll_fn(|cx| {
        let next = subscription.next();
        tokio::pin!(next);
        std::future::Future::poll(next, cx)
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn next_makes_progress_when_each_poll_uses_a_fresh_future() {
    let transport = ScriptedTransport::new([
        Script::Closes(vec![checkpoint(10), batch(11)]),
        Script::Delays(Duration::from_millis(10), vec![checkpoint(11), batch(12)]),
    ]);
    let mut subscription = client(transport.clone())
        .stream()
        .subscribe(filter(), None)
        .await
        .unwrap();

    let first = next_with_fresh_futures(&mut subscription).await;
    assert_eq!(first.unwrap().unwrap().sequence_number, 11);
    let resumed = tokio::time::timeout(
        Duration::from_secs(5),
        next_with_fresh_futures(&mut subscription),
    )
    .await
    .expect("a reconnect must complete when the caller polls fresh futures");
    assert_eq!(resumed.unwrap().unwrap().sequence_number, 12);
    assert_eq!(transport.cursors(), [None, Some(12)]);
}

#[tokio::test(start_paused = true)]
async fn budget_expiry_wakes_a_caller_that_polls_fresh_futures() {
    let config = SubscriptionRetryConfig::standard().with_outage_budget(Duration::from_secs(1));
    for stalled in [Script::Stalls, Script::Stays(Vec::new())] {
        let transport = ScriptedTransport::new([
            Script::Ends(
                vec![checkpoint(10), batch(11)],
                ConnectError::unavailable("restart"),
            ),
            stalled,
        ]);
        let mut subscription = client_with(transport.clone(), config)
            .stream()
            .subscribe(filter(), None)
            .await
            .unwrap();
        assert_eq!(next_sequence(&mut subscription).await, 11);

        let started = tokio::time::Instant::now();
        let err = tokio::time::timeout(
            Duration::from_secs(5),
            next_with_fresh_futures(&mut subscription),
        )
        .await
        .expect("the budget must wake a caller that polls fresh futures")
        .unwrap_err();
        assert_eq!(err.rpc_code(), Some(ErrorCode::DeadlineExceeded));
        assert_eq!(started.elapsed(), Duration::from_secs(1));
        assert!(subscription.next().await.unwrap().is_none());
    }
}

#[tokio::test(start_paused = true)]
async fn a_frame_observed_after_the_budget_elapsed_does_not_revive_the_outage() {
    let config = SubscriptionRetryConfig::standard().with_outage_budget(Duration::from_secs(1));
    let transport = ScriptedTransport::new([
        Script::Ends(
            vec![checkpoint(10), batch(11)],
            ConnectError::unavailable("restart"),
        ),
        Script::Trickles(Duration::from_secs(2), vec![checkpoint(11), batch(12)]),
    ]);
    let mut subscription = client_with(transport.clone(), config)
        .stream()
        .subscribe(filter(), None)
        .await
        .unwrap();
    assert_eq!(next_sequence(&mut subscription).await, 11);

    // The caller stops polling while the reopened stream is silent, so the frames become
    // available only after the budget has already elapsed.
    assert!(
        tokio::time::timeout(Duration::from_millis(500), subscription.next())
            .await
            .is_err()
    );
    tokio::time::advance(Duration::from_secs(3)).await;

    let err = subscription.next().await.unwrap_err();
    assert_eq!(err.rpc_code(), Some(ErrorCode::DeadlineExceeded));
    assert!(subscription.next().await.unwrap().is_none());
    assert_eq!(transport.cursors(), [None, Some(12)]);
}
