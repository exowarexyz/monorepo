use super::*;

use buffa::Message as _;
use futures::channel::mpsc;
use http_body_util::BodyExt as _;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

type TestBody = http_body_util::combinators::UnsyncBoxBody<Bytes, Infallible>;

#[derive(Default)]
struct ScriptState {
    gets: VecDeque<Result<exoware_proto::log::stream::v1::GetResponse, ConnectError>>,
    subscriptions: VecDeque<Bytes>,
    query_sequences: VecDeque<u64>,
    get_requests: Vec<u64>,
    subscription_cursors: Vec<Option<u64>>,
    query_floors: Vec<Option<u64>>,
}

#[derive(Clone, Default)]
struct LogTransport(Arc<Mutex<ScriptState>>);

impl connectrpc::client::ClientTransport for LogTransport {
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
            let path = request.uri().path().to_owned();
            let body = request.into_body().collect().await.unwrap().to_bytes();
            let (payload, content_type) = match path.as_str() {
                "/log.stream.v1.Service/Get" => {
                    let request =
                        exoware_proto::log::stream::v1::GetRequest::decode_from_slice(&body)
                            .unwrap();
                    let result = {
                        let mut state = transport.0.lock().unwrap();
                        state.get_requests.push(request.sequence_number);
                        state.gets.pop_front().expect("unexpected log Get")
                    };
                    let result = match result {
                        Ok(result) => result,
                        Err(error) => {
                            return Ok(http::Response::builder()
                                .status(error.http_status())
                                .header(http::header::CONTENT_TYPE, "application/json")
                                .body(http_body_util::Full::new(error.to_json()).boxed_unsync())
                                .unwrap());
                        }
                    };
                    (result.encode_to_bytes(), "application/proto")
                }
                "/log.stream.v1.Service/Subscribe" => {
                    let request =
                        exoware_proto::log::stream::v1::SubscribeRequest::decode_from_slice(
                            &body[5..],
                        )
                        .unwrap();
                    let response = {
                        let mut state = transport.0.lock().unwrap();
                        state
                            .subscription_cursors
                            .push(request.since_sequence_number);
                        state
                            .subscriptions
                            .pop_front()
                            .expect("unexpected subscription")
                    };
                    (response, "application/connect+proto")
                }
                "/store.query.v1.Service/Get" => {
                    let request = proto_query::GetRequest::decode_from_slice(&body).unwrap();
                    let sequence = {
                        let mut state = transport.0.lock().unwrap();
                        state.query_floors.push(request.min_sequence_number);
                        state.query_sequences.pop_front().unwrap_or(999)
                    };
                    let response = proto_query::GetResponse {
                        detail: Some(proto_query::Detail {
                            sequence_number: sequence,
                            ..Default::default()
                        })
                        .into(),
                        ..Default::default()
                    };
                    (response.encode_to_bytes(), "application/proto")
                }
                _ => return Err(ConnectError::unimplemented(path)),
            };
            Ok(http::Response::builder()
                .header(http::header::CONTENT_TYPE, content_type)
                .body(http_body_util::Full::new(payload).boxed_unsync())
                .unwrap())
        })
    }
}

fn entry(key: &'static [u8], value: &'static [u8]) -> exoware_proto::common::kv::v1::Entry {
    exoware_proto::common::kv::v1::Entry {
        key: key.to_vec(),
        value: Bytes::from_static(value),
        ..Default::default()
    }
}

fn get_response(sequence_number: u64) -> exoware_proto::log::stream::v1::GetResponse {
    exoware_proto::log::stream::v1::GetResponse {
        sequence_number,
        entries: vec![entry(b"tenant/key", b"value")],
        ..Default::default()
    }
}

fn stream_body(
    frames: impl IntoIterator<Item = exoware_proto::log::stream::v1::SubscribeResponse>,
    terminal: &[u8],
) -> Bytes {
    let mut body = Vec::new();
    for frame in frames {
        body.extend_from_slice(
            &connectrpc::envelope::Envelope::data(frame.encode_to_bytes()).encode(),
        );
    }
    body.extend_from_slice(
        &connectrpc::envelope::Envelope::end_stream(Bytes::copy_from_slice(terminal)).encode(),
    );
    body.into()
}

fn client<T>(transport: T) -> PrefixedStoreClient
where
    T: connectrpc::client::ClientTransport<Error = ConnectError> + Clone + 'static,
    T::ResponseBody: http_body::Body<Data = Bytes> + Send + Unpin + 'static,
    <T::ResponseBody as http_body::Body>::Error: std::fmt::Display,
{
    StoreClient::builder()
        .url("http://store.internal")
        .retry_config(RetryConfig::disabled())
        .client_transport(transport)
        .build()
        .unwrap()
        .prefixed(StoreKeyPrefix::new("tenant/").unwrap())
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

#[tokio::test]
async fn client_get_preserves_batch_sequence_and_filters_namespace() {
    let transport = LogTransport::default();
    let mut response = get_response(41);
    response.entries.push(entry(b"other/key", b"excluded"));
    transport.0.lock().unwrap().gets.push_back(Ok(response));

    let batch = client(transport.clone())
        .stream()
        .get(0)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(batch.sequence_number, 41);
    assert_eq!(batch.entries.len(), 1);
    assert_eq!(batch.entries[0].key, Bytes::from_static(b"key"));
    assert_eq!(batch.entries[0].value, Bytes::from_static(b"value"));
    assert_eq!(transport.0.lock().unwrap().get_requests, vec![0]);
}

#[tokio::test]
async fn log_deliveries_observe_before_return_and_clones_apply_each_policy() {
    for monotonic in [false, true] {
        let transport = LogTransport::default();
        {
            let mut state = transport.0.lock().unwrap();
            state.gets.push_back(Ok(get_response(41)));
            state.subscriptions.push_back(stream_body(
                [exoware_proto::log::stream::v1::SubscribeResponse {
                    sequence_number: 43,
                    entries: vec![entry(b"tenant/stream", b"value")],
                    ..Default::default()
                }],
                b"{}",
            ));
            state.query_sequences.push_back(44);
        }
        let session = if monotonic {
            ReadSession::monotonic(client(transport.clone()), Some(7))
        } else {
            ReadSession::fixed(client(transport.clone()), Some(7))
        };

        let batch = session.get_batch(0).await.unwrap().unwrap();
        assert_eq!(batch.sequence_number, 41);
        assert_eq!(batch.entries[0].key, Bytes::from_static(b"key"));
        assert_eq!(session.evaluated_sequence(), Some(41));
        let mut subscription = session.clone().subscribe(filter(), None).await.unwrap();
        assert_eq!(
            subscription.next().await.unwrap().unwrap().sequence_number,
            43
        );
        assert_eq!(session.evaluated_sequence(), Some(43));
        session
            .clone()
            .get(&Bytes::from_static(b"later"))
            .await
            .unwrap();

        let state = transport.0.lock().unwrap();
        assert_eq!(state.get_requests, [0]);
        assert_eq!(state.query_floors, [Some(if monotonic { 43 } else { 7 })]);
    }
}

#[tokio::test]
async fn sequence_zero_is_an_observation_but_none_and_errors_are_not() {
    let transport = LogTransport::default();
    let missing = crate::proto::with_error_info_detail(
        ConnectError::out_of_range("missing"),
        crate::google::rpc::ErrorInfo {
            reason: "BATCH_NOT_FOUND".to_owned(),
            domain: "log.stream".to_owned(),
            ..Default::default()
        },
    );
    {
        let mut state = transport.0.lock().unwrap();
        state.gets.push_back(Err(missing));
        state.gets.push_back(Err(ConnectError::internal("broken")));
        state.gets.push_back(Ok(get_response(0)));
    }
    let session = ReadSession::monotonic(client(transport), None);

    assert!(session.get_batch(5).await.unwrap().is_none());
    assert_eq!(session.evaluated_sequence(), None);
    assert_eq!(
        session.get_batch(6).await.unwrap_err().rpc_code(),
        Some(ErrorCode::Internal)
    );
    assert_eq!(session.evaluated_sequence(), None);
    assert_eq!(
        session.get_batch(0).await.unwrap().unwrap().sequence_number,
        0
    );
    assert_eq!(session.evaluated_sequence(), Some(0));
    assert_eq!(session.min_sequence_number(), Some(0));
}

#[tokio::test]
async fn historical_subscription_ignores_empty_frames_and_preserves_the_maximum() {
    let transport = LogTransport::default();
    let first_replay = [
        exoware_proto::log::stream::v1::SubscribeResponse {
            sequence_number: 30,
            entries: vec![entry(b"tenant/a", b"a")],
            ..Default::default()
        },
        exoware_proto::log::stream::v1::SubscribeResponse {
            sequence_number: 40,
            entries: vec![entry(b"tenant/b", b"b")],
            ..Default::default()
        },
        exoware_proto::log::stream::v1::SubscribeResponse {
            sequence_number: 150,
            entries: Vec::new(),
            ..Default::default()
        },
    ];
    {
        let mut state = transport.0.lock().unwrap();
        state.gets.push_back(Ok(get_response(100)));
        state
            .subscriptions
            .push_back(stream_body(first_replay, b"{}"));
        state.subscriptions.push_back(stream_body(
            [exoware_proto::log::stream::v1::SubscribeResponse {
                sequence_number: 20,
                entries: vec![entry(b"tenant/c", b"c")],
                ..Default::default()
            }],
            b"{}",
        ));
        state.query_sequences.push_back(101);
    }
    let session = ReadSession::monotonic(client(transport.clone()), Some(80));
    session.get_batch(100).await.unwrap();
    let mut subscription = session.subscribe(filter(), Some(5)).await.unwrap();

    assert_eq!(
        subscription.next().await.unwrap().unwrap().sequence_number,
        30
    );
    assert_eq!(session.evaluated_sequence(), Some(100));
    assert_eq!(
        subscription.next().await.unwrap().unwrap().sequence_number,
        40
    );
    assert!(subscription.next().await.unwrap().is_none());
    assert_eq!(session.evaluated_sequence(), Some(100));
    let mut older_subscription = session.subscribe(filter(), Some(20)).await.unwrap();
    assert_eq!(
        older_subscription
            .next()
            .await
            .unwrap()
            .unwrap()
            .sequence_number,
        20
    );
    assert_eq!(session.evaluated_sequence(), Some(100));
    session.get(&Bytes::from_static(b"later")).await.unwrap();

    let state = transport.0.lock().unwrap();
    assert_eq!(state.subscription_cursors, [Some(5), Some(20)]);
    assert_eq!(state.query_floors, [Some(100)]);
}

#[derive(Clone, Default)]
struct GatedQueryTransport {
    query_started: Arc<AtomicBool>,
}

impl connectrpc::client::ClientTransport for GatedQueryTransport {
    type ResponseBody = TestBody;
    type Error = ConnectError;

    fn send(
        &self,
        request: http::Request<connectrpc::client::ClientBody>,
    ) -> connectrpc::client::BoxFuture<
        'static,
        Result<http::Response<Self::ResponseBody>, Self::Error>,
    > {
        let path = request.uri().path().to_owned();
        let started = self.query_started.clone();
        Box::pin(async move {
            let (payload, content_type) = match path.as_str() {
                "/store.query.v1.Service/Get" => {
                    started.store(true, Ordering::Release);
                    return futures::future::pending().await;
                }
                "/log.stream.v1.Service/Get" => {
                    (get_response(9).encode_to_bytes(), "application/proto")
                }
                "/log.stream.v1.Service/Subscribe" => {
                    (stream_body([], b"{}"), "application/connect+proto")
                }
                _ => return Err(ConnectError::unimplemented(path)),
            };
            Ok(http::Response::builder()
                .header(http::header::CONTENT_TYPE, content_type)
                .body(http_body_util::Full::new(payload).boxed_unsync())
                .unwrap())
        })
    }
}

#[tokio::test]
async fn log_calls_do_not_wait_for_the_monotonic_query_initialization_gate() {
    let transport = GatedQueryTransport::default();
    let session = ReadSession::monotonic(client(transport.clone()), None);
    let query_session = session.clone();
    let query =
        tokio::spawn(async move { query_session.get(&Bytes::from_static(b"blocked")).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while !transport.query_started.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let batch = tokio::time::timeout(Duration::from_secs(1), session.get_batch(9))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(batch.sequence_number, 9);
    let subscription =
        tokio::time::timeout(Duration::from_secs(1), session.subscribe(filter(), None))
            .await
            .unwrap()
            .unwrap();
    drop(subscription);
    assert_eq!(session.evaluated_sequence(), Some(9));
    query.abort();
}

#[derive(Clone)]
struct PendingSubscriptionTransport {
    receiver: Arc<Mutex<Option<PendingSubscriptionBody>>>,
}

type PendingSubscriptionBody = mpsc::UnboundedReceiver<Result<http_body::Frame<Bytes>, Infallible>>;

impl connectrpc::client::ClientTransport for PendingSubscriptionTransport {
    type ResponseBody = TestBody;
    type Error = ConnectError;

    fn send(
        &self,
        _request: http::Request<connectrpc::client::ClientBody>,
    ) -> connectrpc::client::BoxFuture<
        'static,
        Result<http::Response<Self::ResponseBody>, Self::Error>,
    > {
        let receiver = self.receiver.lock().unwrap().take().unwrap();
        Box::pin(async move {
            Ok(http::Response::builder()
                .header(http::header::CONTENT_TYPE, "application/connect+proto")
                .body(http_body_util::StreamBody::new(receiver).boxed_unsync())
                .unwrap())
        })
    }
}

#[tokio::test]
async fn subscription_terminal_errors_do_not_advance_and_drop_cancels_the_body() {
    let transport = LogTransport::default();
    transport
        .0
        .lock()
        .unwrap()
        .subscriptions
        .push_back(stream_body(
            [exoware_proto::log::stream::v1::SubscribeResponse {
                sequence_number: 12,
                entries: vec![entry(b"tenant/a", b"a")],
                ..Default::default()
            }],
            br#"{"error":{"code":"unavailable","message":"done"}}"#,
        ));
    let session = ReadSession::monotonic(client(transport), None);
    let mut subscription = session.subscribe(filter(), None).await.unwrap();
    assert_eq!(
        subscription.next().await.unwrap().unwrap().sequence_number,
        12
    );
    assert_eq!(session.evaluated_sequence(), Some(12));
    assert_eq!(
        subscription.next().await.unwrap_err().rpc_code(),
        Some(ErrorCode::Unavailable)
    );
    assert_eq!(session.evaluated_sequence(), Some(12));

    let (sender, receiver) = mpsc::unbounded();
    let transport = PendingSubscriptionTransport {
        receiver: Arc::new(Mutex::new(Some(receiver))),
    };
    let session = ReadSession::fixed(client(transport), Some(7));
    let subscription = session.subscribe(filter(), None).await.unwrap();
    assert!(!sender.is_closed());
    drop(subscription);
    assert!(sender.is_closed());
    assert_eq!(session.evaluated_sequence(), None);
}
