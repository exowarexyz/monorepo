use super::*;
use buffa::Message as _;
use connectrpc::envelope::Envelope;
use exoware_proto::{
    common::kv::v1::Entry,
    log::stream::v1::{SubscribeRequest, SubscribeResponse},
};
use futures::channel::mpsc;
use http_body_util::BodyExt as _;
use std::{
    collections::VecDeque,
    future::Future,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
    task::{Context, Poll},
};
use tokio::time::Instant;

type TestBody = http_body_util::combinators::UnsyncBoxBody<Bytes, io::Error>;
type Chunk = Result<http_body::Frame<Bytes>, io::Error>;

enum Attempt {
    // The connection fails before response headers.
    Refuse,
    // The open never completes. The counter records when the attempt is dropped.
    Hang(Arc<AtomicUsize>),
    // Response headers arrive and the test writes the body.
    Respond(mpsc::UnboundedReceiver<Chunk>),
}

struct DropCounter(Arc<AtomicUsize>);

impl Drop for DropCounter {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct Script {
    attempts: VecDeque<Attempt>,
    cursors: Vec<Option<u64>>,
}

#[derive(Clone, Default)]
struct SubscribeTransport(Arc<Mutex<Script>>);

impl SubscribeTransport {
    fn refuse(&self) {
        self.0.lock().unwrap().attempts.push_back(Attempt::Refuse);
    }

    fn hang(&self) -> Arc<AtomicUsize> {
        let dropped = Arc::new(AtomicUsize::new(0));
        self.0
            .lock()
            .unwrap()
            .attempts
            .push_back(Attempt::Hang(dropped.clone()));
        dropped
    }

    fn respond(&self) -> Feed {
        let (sender, receiver) = mpsc::unbounded();
        self.0
            .lock()
            .unwrap()
            .attempts
            .push_back(Attempt::Respond(receiver));
        Feed(sender)
    }

    // The `since_sequence_number` of every Subscribe call, in order.
    fn cursors(&self) -> Vec<Option<u64>> {
        self.0.lock().unwrap().cursors.clone()
    }
}

impl connectrpc::client::ClientTransport for SubscribeTransport {
    type ResponseBody = TestBody;
    type Error = ConnectError;

    fn send(
        &self,
        request: http::Request<connectrpc::client::ClientBody>,
    ) -> connectrpc::client::BoxFuture<
        'static,
        Result<http::Response<Self::ResponseBody>, Self::Error>,
    > {
        let script = self.0.clone();
        Box::pin(async move {
            let body = request.into_body().collect().await.unwrap().to_bytes();
            let request = SubscribeRequest::decode_from_slice(&body[5..]).unwrap();
            let attempt = {
                let mut script = script.lock().unwrap();
                script.cursors.push(request.since_sequence_number);
                script.attempts.pop_front()
            };
            match attempt {
                Some(Attempt::Refuse) => Err(ConnectError::unavailable("connection refused")),
                Some(Attempt::Respond(chunks)) => Ok(http::Response::builder()
                    .header(http::header::CONTENT_TYPE, "application/connect+proto")
                    .body(http_body_util::StreamBody::new(chunks).boxed_unsync())
                    .unwrap()),
                Some(Attempt::Hang(dropped)) => {
                    let _guard = DropCounter(dropped);
                    std::future::pending().await
                }
                None => std::future::pending().await,
            }
        })
    }
}

// Writes one response body.
struct Feed(mpsc::UnboundedSender<Chunk>);

impl Feed {
    fn send(&self, bytes: Bytes) {
        let _ = self.0.unbounded_send(Ok(http_body::Frame::data(bytes)));
    }

    fn frame(&self, sequence_number: u64, keys: &[&'static [u8]]) {
        let frame = SubscribeResponse {
            sequence_number,
            entries: keys
                .iter()
                .map(|key| Entry {
                    key: key.to_vec(),
                    value: Bytes::from_static(b"v"),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        self.send(Envelope::data(frame.encode_to_bytes()).encode());
    }

    fn checkpoint(&self, sequence_number: u64) {
        self.frame(sequence_number, &[]);
    }

    fn end(&self) {
        self.send(Envelope::end_stream(Bytes::from_static(b"{}")).encode());
    }

    fn fail(&self, error: ConnectError) {
        let error = String::from_utf8(error.to_json().to_vec()).unwrap();
        let terminal = format!("{{\"error\":{error}}}");
        self.send(Envelope::end_stream(Bytes::from(terminal)).encode());
    }

    fn reset(&self) {
        let _ = self
            .0
            .unbounded_send(Err(io::Error::new(io::ErrorKind::ConnectionReset, "reset")));
    }
}

const fn fast_retry() -> SubscriptionRetryConfig {
    SubscriptionRetryConfig::standard()
        .with_initial_backoff(Duration::from_millis(10))
        .with_max_backoff(Duration::from_millis(40))
}

fn client(transport: &SubscribeTransport, retry: SubscriptionRetryConfig) -> PrefixedStoreClient {
    let client = StoreClient::builder()
        .url("http://store.internal")
        .retry_config(RetryConfig::disabled())
        .subscription_retry(retry)
        .client_transport(transport.clone())
        .build()
        .unwrap();
    PrefixedStoreClient::empty(client)
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

async fn subscribe(
    transport: &SubscribeTransport,
    retry: SubscriptionRetryConfig,
    since: Option<u64>,
) -> Result<StreamSubscription, ClientError> {
    client(transport, retry)
        .stream()
        .subscribe(filter(), since)
        .await
}

async fn next_sequence(subscription: &mut StreamSubscription) -> u64 {
    subscription
        .next()
        .await
        .expect("next batch")
        .expect("open subscription")
        .sequence_number
}

fn rpc_code(error: &ClientError) -> ErrorCode {
    error.rpc_error().expect("rpc error").code
}

fn stream_error(code: ErrorCode, reason: Option<&str>) -> ConnectError {
    let error = ConnectError::new(code, "rejected");
    match reason {
        Some(reason) => crate::with_error_info_detail(
            error,
            crate::google::rpc::ErrorInfo {
                reason: reason.to_string(),
                domain: "log.stream".to_string(),
                ..Default::default()
            },
        ),
        None => error,
    }
}

// Polls the way a hand-written stream does, creating a new `next()` future
// for every poll and dropping it after one poll.
struct FreshNext<'a>(&'a mut StreamSubscription);

impl Future for FreshNext<'_> {
    type Output = Result<Option<StoreBatch>, ClientError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let next = this.0.next();
        std::pin::pin!(next).poll(cx)
    }
}

#[tokio::test(start_paused = true)]
async fn resumes_after_clean_end_reset_and_transient_errors_without_gaps() {
    let transport = SubscribeTransport::default();
    let first = transport.respond();
    let second = transport.respond();
    transport.refuse();
    let fourth = transport.respond();
    let fifth = transport.respond();

    first.checkpoint(4);
    first.frame(5, &[b"a"]);
    first.frame(6, &[b"b"]);
    first.end();
    second.checkpoint(6);
    second.frame(7, &[b"c"]);
    second.reset();
    fourth.checkpoint(7);
    fourth.frame(8, &[b"d"]);
    fourth.fail(ConnectError::unavailable("server is shutting down"));
    fifth.checkpoint(8);
    fifth.frame(9, &[b"e"]);

    let mut subscription = subscribe(&transport, fast_retry(), None).await.unwrap();
    let mut delivered = Vec::new();
    for _ in 0..5 {
        delivered.push(next_sequence(&mut subscription).await);
    }

    assert_eq!(delivered, vec![5, 6, 7, 8, 9]);
    assert_eq!(
        transport.cursors(),
        vec![None, Some(7), Some(8), Some(8), Some(9)]
    );
}

#[tokio::test(start_paused = true)]
async fn every_transient_code_resumes() {
    for code in [
        ErrorCode::Internal,
        ErrorCode::Unknown,
        ErrorCode::Aborted,
        ErrorCode::ResourceExhausted,
    ] {
        let transport = SubscribeTransport::default();
        let first = transport.respond();
        let second = transport.respond();
        first.checkpoint(0);
        first.frame(1, &[b"a"]);
        first.fail(ConnectError::new(code, "transient"));
        second.checkpoint(1);
        second.frame(2, &[b"b"]);

        let mut subscription = subscribe(&transport, fast_retry(), None).await.unwrap();
        assert_eq!(next_sequence(&mut subscription).await, 1);
        assert_eq!(next_sequence(&mut subscription).await, 2);
        assert_eq!(transport.cursors(), vec![None, Some(2)]);
    }
}

#[tokio::test(start_paused = true)]
async fn empty_frames_advance_the_cursor_without_delivery() {
    let transport = SubscribeTransport::default();
    let first = transport.respond();
    let second = transport.respond();
    first.checkpoint(3);
    first.checkpoint(9);
    first.end();
    second.checkpoint(9);
    second.frame(10, &[b"a"]);

    let mut subscription = subscribe(&transport, fast_retry(), None).await.unwrap();
    assert_eq!(next_sequence(&mut subscription).await, 10);
    assert_eq!(transport.cursors(), vec![None, Some(10)]);
}

#[tokio::test(start_paused = true)]
async fn initial_checkpoint_resumes_before_writes_made_during_the_outage() {
    let transport = SubscribeTransport::default();
    let first = transport.respond();
    let second = transport.respond();
    first.checkpoint(20);
    first.end();

    // Batches 21 and 22 were published while the subscriber was disconnected.
    second.checkpoint(20);
    second.frame(21, &[b"a"]);
    second.frame(22, &[b"b"]);

    let mut subscription = subscribe(&transport, fast_retry(), None).await.unwrap();
    assert_eq!(next_sequence(&mut subscription).await, 21);
    assert_eq!(next_sequence(&mut subscription).await, 22);
    assert_eq!(transport.cursors(), vec![None, Some(21)]);
}

#[tokio::test(start_paused = true)]
async fn positive_cursor_is_kept_until_the_first_frame() {
    let transport = SubscribeTransport::default();
    transport.refuse();
    let empty = transport.respond();
    let replay = transport.respond();
    empty.end();
    replay.checkpoint(9);
    replay.frame(10, &[b"a"]);
    replay.frame(12, &[b"b"]);

    let mut subscription = subscribe(&transport, fast_retry(), Some(10)).await.unwrap();
    assert_eq!(next_sequence(&mut subscription).await, 10);
    assert_eq!(next_sequence(&mut subscription).await, 12);
    assert_eq!(transport.cursors(), vec![Some(10), Some(10), Some(10)]);
}

#[tokio::test(start_paused = true)]
async fn live_only_failure_before_the_first_frame_is_returned() {
    let refused = SubscribeTransport::default();
    refused.refuse();
    let error = subscribe(&refused, fast_retry(), None).await.unwrap_err();
    assert_eq!(rpc_code(&error), ErrorCode::Unavailable);
    assert_eq!(refused.cursors(), vec![None]);

    for since in [None, Some(0)] {
        let closed = SubscribeTransport::default();
        let feed = closed.respond();
        feed.end();
        let mut subscription = subscribe(&closed, fast_retry(), since).await.unwrap();
        let error = subscription.next().await.unwrap_err();
        assert_eq!(rpc_code(&error), ErrorCode::Unavailable);
        assert!(subscription.next().await.unwrap().is_none());
        assert_eq!(closed.cursors(), vec![since]);
    }
}

#[tokio::test(start_paused = true)]
async fn permanent_errors_are_returned_without_retrying() {
    let cases = [
        (ErrorCode::Unauthenticated, None),
        (ErrorCode::PermissionDenied, None),
        (ErrorCode::InvalidArgument, None),
        (ErrorCode::OutOfRange, Some("BATCH_EVICTED")),
    ];
    for (code, reason) in cases {
        let transport = SubscribeTransport::default();
        let feed = transport.respond();
        feed.checkpoint(4);
        feed.frame(5, &[b"a"]);
        feed.fail(stream_error(code, reason));

        let mut subscription = subscribe(&transport, fast_retry(), Some(5)).await.unwrap();
        assert_eq!(next_sequence(&mut subscription).await, 5);
        let error = subscription.next().await.unwrap_err();
        assert_eq!(rpc_code(&error), code);
        if let Some(reason) = reason {
            let decoded = error.decoded_rpc_error().unwrap().unwrap();
            assert_eq!(decoded.error_info.unwrap().reason, reason);
        }
        assert!(subscription.next().await.unwrap().is_none());
        assert_eq!(transport.cursors(), vec![Some(5)]);
    }
}

#[tokio::test(start_paused = true)]
async fn an_evicted_cursor_at_open_is_not_retried() {
    let transport = SubscribeTransport::default();
    let feed = transport.respond();
    feed.fail(stream_error(ErrorCode::OutOfRange, Some("BATCH_EVICTED")));

    let mut subscription = subscribe(&transport, fast_retry(), Some(3)).await.unwrap();
    let error = subscription.next().await.unwrap_err();
    assert_eq!(rpc_code(&error), ErrorCode::OutOfRange);
    assert_eq!(transport.cursors(), vec![Some(3)]);
}

#[tokio::test(start_paused = true)]
async fn outage_budget_bounds_repeated_failures_and_returns_the_last_one() {
    let transport = SubscribeTransport::default();
    for _ in 0..1_000 {
        transport.refuse();
    }
    let retry = fast_retry().with_outage_budget(Duration::from_secs(5));

    let started = Instant::now();
    let error = subscribe(&transport, retry, Some(1)).await.unwrap_err();
    assert_eq!(rpc_code(&error), ErrorCode::Unavailable);
    assert_eq!(started.elapsed(), Duration::from_secs(5));
    assert!(transport.cursors().len() > 10);
    assert!(transport.cursors().iter().all(|cursor| *cursor == Some(1)));
}

#[tokio::test(start_paused = true)]
async fn outage_budget_bounds_a_hanging_open() {
    let transport = SubscribeTransport::default();
    let dropped = transport.hang();
    let retry = fast_retry().with_outage_budget(Duration::from_secs(5));

    let started = Instant::now();
    let error = subscribe(&transport, retry, Some(1)).await.unwrap_err();
    assert_eq!(rpc_code(&error), ErrorCode::DeadlineExceeded);
    assert_eq!(started.elapsed(), Duration::from_secs(5));
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn outage_budget_covers_a_reopened_stream_that_sends_no_frame() {
    let transport = SubscribeTransport::default();
    let first = transport.respond();
    let _silent = transport.respond();
    first.checkpoint(0);
    first.frame(1, &[b"a"]);
    first.fail(ConnectError::unavailable("server is shutting down"));
    let retry = fast_retry().with_outage_budget(Duration::from_secs(5));

    let mut subscription = subscribe(&transport, retry, None).await.unwrap();
    assert_eq!(next_sequence(&mut subscription).await, 1);
    let started = Instant::now();
    let error = subscription.next().await.unwrap_err();
    assert_eq!(started.elapsed(), Duration::from_secs(5));
    assert_eq!(rpc_code(&error), ErrorCode::Unavailable);
    assert_eq!(transport.cursors(), vec![None, Some(2)]);
}

#[tokio::test(start_paused = true)]
async fn any_frame_resets_the_outage_budget_and_idle_streams_are_unbounded() {
    let transport = SubscribeTransport::default();
    let first = transport.respond();
    let second = transport.respond();
    let retry = fast_retry().with_outage_budget(Duration::from_secs(5));

    let consumer = tokio::spawn({
        let transport = transport.clone();
        async move {
            let mut subscription = subscribe(&transport, retry, Some(1)).await.unwrap();
            let mut delivered = Vec::new();
            for _ in 0..2 {
                delivered.push(next_sequence(&mut subscription).await);
            }
            delivered
        }
    });

    // Each frame arrives four seconds into an outage, so only a reset budget
    // lets the second one through.
    tokio::time::sleep(Duration::from_secs(4)).await;
    first.checkpoint(0);
    first.end();
    tokio::time::sleep(Duration::from_secs(4)).await;
    second.checkpoint(0);
    second.frame(1, &[b"a"]);

    // A healthy stream can then stay idle far longer than the budget.
    tokio::time::sleep(Duration::from_secs(60)).await;
    second.frame(2, &[b"b"]);

    assert_eq!(consumer.await.unwrap(), vec![1, 2]);
    assert_eq!(transport.cursors(), vec![Some(1), Some(1)]);
}

#[tokio::test(start_paused = true)]
async fn backoff_keeps_growing_while_stale_checkpoints_reset_the_budget() {
    let transport = SubscribeTransport::default();
    for _ in 0..10 {
        let attempt = transport.respond();
        attempt.checkpoint(4);
        attempt.fail(ConnectError::internal("batch 5 is unreadable"));
    }
    let healthy = transport.respond();
    healthy.checkpoint(4);
    healthy.frame(5, &[b"a"]);

    let retry = SubscriptionRetryConfig::standard()
        .with_initial_backoff(Duration::from_millis(100))
        .with_max_backoff(Duration::from_millis(400))
        .with_outage_budget(Duration::from_secs(1));
    let started = Instant::now();
    let mut subscription = subscribe(&transport, retry, Some(5)).await.unwrap();
    assert_eq!(next_sequence(&mut subscription).await, 5);

    // Ten reconnects whose backoff restarted at every checkpoint would take at
    // most one second. Doubling up to the cap takes at least 50 + 100 + 8 * 200
    // ms, which also outlasts the budget that the checkpoints keep resetting.
    assert!(started.elapsed() >= Duration::from_millis(1_750));
    assert_eq!(transport.cursors().len(), 11);
    assert!(transport.cursors().iter().all(|cursor| *cursor == Some(5)));
}

#[tokio::test(start_paused = true)]
async fn unlimited_budget_keeps_retrying() {
    let transport = SubscribeTransport::default();
    for _ in 0..100 {
        transport.refuse();
    }
    let feed = transport.respond();
    feed.checkpoint(0);
    feed.frame(1, &[b"a"]);

    let retry = SubscriptionRetryConfig::unlimited()
        .with_initial_backoff(Duration::from_secs(1))
        .with_max_backoff(Duration::from_secs(2));
    let mut subscription = subscribe(&transport, retry, Some(1)).await.unwrap();
    assert_eq!(next_sequence(&mut subscription).await, 1);
    assert_eq!(transport.cursors().len(), 101);
}

#[tokio::test(start_paused = true)]
async fn fresh_next_futures_complete_a_delayed_reconnect() {
    let transport = SubscribeTransport::default();
    let first = transport.respond();
    let second = transport.respond();
    first.checkpoint(0);
    first.frame(1, &[b"a"]);
    first.end();

    let consumer = tokio::spawn({
        let transport = transport.clone();
        async move {
            let mut subscription = subscribe(&transport, fast_retry(), None).await.unwrap();
            let mut delivered = Vec::new();
            for _ in 0..2 {
                let batch = FreshNext(&mut subscription).await.unwrap().unwrap();
                delivered.push(batch.sequence_number);
            }
            delivered
        }
    });

    tokio::time::sleep(Duration::from_secs(1)).await;
    second.checkpoint(1);
    second.frame(2, &[b"b"]);

    let delivered = tokio::time::timeout(Duration::from_secs(60), consumer)
        .await
        .expect("reconnect must make progress under fresh futures")
        .unwrap();
    assert_eq!(delivered, vec![1, 2]);
    assert_eq!(transport.cursors(), vec![None, Some(2)]);
}

#[tokio::test(start_paused = true)]
async fn fresh_next_futures_wake_when_the_outage_budget_expires() {
    let transport = SubscribeTransport::default();
    let first = transport.respond();
    first.checkpoint(0);
    first.frame(1, &[b"a"]);
    first.end();
    let dropped = transport.hang();
    let retry = fast_retry().with_outage_budget(Duration::from_secs(5));

    let mut subscription = subscribe(&transport, retry, None).await.unwrap();
    assert_eq!(
        FreshNext(&mut subscription)
            .await
            .unwrap()
            .unwrap()
            .sequence_number,
        1
    );

    // Only the budget timer can wake this poller, because the reopen never completes.
    let started = Instant::now();
    let error = tokio::time::timeout(Duration::from_secs(60), FreshNext(&mut subscription))
        .await
        .expect("budget expiry must wake the poller")
        .unwrap_err();
    assert_eq!(started.elapsed(), Duration::from_secs(5));

    // A clean end is not an error, so the outage reports its budget instead.
    assert_eq!(rpc_code(&error), ErrorCode::DeadlineExceeded);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn dropping_the_subscription_cancels_an_in_flight_reconnect() {
    let transport = SubscribeTransport::default();
    let first = transport.respond();
    first.checkpoint(0);
    first.frame(1, &[b"a"]);
    first.end();
    let dropped = transport.hang();

    let mut subscription = subscribe(&transport, fast_retry(), None).await.unwrap();
    assert_eq!(next_sequence(&mut subscription).await, 1);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), subscription.next())
            .await
            .is_err()
    );
    assert_eq!(transport.cursors(), vec![None, Some(2)]);
    assert_eq!(dropped.load(Ordering::SeqCst), 0);

    drop(subscription);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn the_last_representable_sequence_ends_the_subscription() {
    let transport = SubscribeTransport::default();
    let feed = transport.respond();
    feed.checkpoint(u64::MAX - 1);
    feed.frame(u64::MAX, &[b"a"]);
    feed.end();

    let mut subscription = subscribe(&transport, fast_retry(), Some(u64::MAX))
        .await
        .unwrap();
    assert_eq!(next_sequence(&mut subscription).await, u64::MAX);
    assert!(subscription.next().await.unwrap().is_none());
    assert_eq!(transport.cursors(), vec![Some(u64::MAX)]);

    let failed = SubscribeTransport::default();
    let feed = failed.respond();
    feed.checkpoint(u64::MAX - 1);
    feed.frame(u64::MAX, &[b"a"]);
    feed.fail(ConnectError::unavailable("server is shutting down"));
    let mut subscription = subscribe(&failed, fast_retry(), Some(u64::MAX))
        .await
        .unwrap();
    assert_eq!(next_sequence(&mut subscription).await, u64::MAX);
    let error = subscription.next().await.unwrap_err();
    assert_eq!(rpc_code(&error), ErrorCode::Unavailable);
    assert_eq!(failed.cursors(), vec![Some(u64::MAX)]);
}

#[tokio::test(start_paused = true)]
async fn disabled_resume_ends_on_close_and_returns_errors() {
    let closed = SubscribeTransport::default();
    let feed = closed.respond();
    feed.checkpoint(0);
    feed.frame(1, &[b"a"]);
    feed.end();
    let mut subscription = subscribe(&closed, SubscriptionRetryConfig::disabled(), None)
        .await
        .unwrap();
    assert_eq!(next_sequence(&mut subscription).await, 1);
    assert!(subscription.next().await.unwrap().is_none());
    assert_eq!(closed.cursors(), vec![None]);

    let failed = SubscribeTransport::default();
    let feed = failed.respond();
    feed.checkpoint(4);
    feed.fail(ConnectError::unavailable("gone"));
    let mut subscription = subscribe(&failed, SubscriptionRetryConfig::disabled(), Some(5))
        .await
        .unwrap();
    let error = subscription.next().await.unwrap_err();
    assert_eq!(rpc_code(&error), ErrorCode::Unavailable);
    assert_eq!(failed.cursors(), vec![Some(5)]);

    let refused = SubscribeTransport::default();
    refused.refuse();
    let error = subscribe(&refused, SubscriptionRetryConfig::disabled(), Some(5))
        .await
        .unwrap_err();
    assert_eq!(rpc_code(&error), ErrorCode::Unavailable);
    assert_eq!(refused.cursors(), vec![Some(5)]);
}

#[tokio::test(start_paused = true)]
async fn read_sessions_observe_delivered_batches_but_not_checkpoints() {
    let transport = SubscribeTransport::default();
    let first = transport.respond();
    let second = transport.respond();
    first.checkpoint(7);
    first.end();
    second.checkpoint(7);
    second.frame(8, &[b"a"]);

    let session = ReadSession::monotonic(client(&transport, fast_retry()), None);
    let mut subscription = session.subscribe(filter(), Some(1)).await.unwrap();
    assert_eq!(session.evaluated_sequence(), None);
    assert_eq!(next_sequence(&mut subscription).await, 8);
    assert_eq!(session.evaluated_sequence(), Some(8));
    assert_eq!(transport.cursors(), vec![Some(1), Some(8)]);
}

#[test]
fn backoff_doubles_within_jittered_bounds() {
    let retry = SubscriptionRetryConfig::standard()
        .with_initial_backoff(Duration::from_millis(100))
        .with_max_backoff(Duration::from_millis(1_000));
    for (failures, cap) in [
        (1, 100),
        (2, 200),
        (3, 400),
        (4, 800),
        (5, 1_000),
        (40, 1_000),
    ] {
        for _ in 0..100 {
            let delay = retry.backoff(failures);
            assert!(delay <= Duration::from_millis(cap));
            assert!(delay >= Duration::from_millis(cap / 2));
        }
    }

    // A tiny initial delay still climbs all the way to the maximum, and the
    // doubling never overflows.
    let tiny = SubscriptionRetryConfig::standard()
        .with_initial_backoff(Duration::from_nanos(1))
        .with_max_backoff(Duration::from_secs(60));
    assert!(tiny.backoff(40) >= Duration::from_secs(30));
    assert!(tiny.backoff(u32::MAX) >= Duration::from_secs(30));

    let none = SubscriptionRetryConfig::standard().with_initial_backoff(Duration::ZERO);
    assert_eq!(none.backoff(129), Duration::ZERO);
}
