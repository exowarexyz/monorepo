use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use buffa::Message;
use bytes::Bytes;
use connectrpc::client::ClientConfig;
use exoware_sdk::{
    common::Entry,
    ingest::{PutRequest, ServiceClient},
    transport::ServiceTransport,
};
use exoware_server::{
    ingest_service, Ingest, IngestError, IngestLimits, IngestPut, IngestState, PutConfig,
    StreamHub, StreamNotifier,
};
use futures::stream;
use http_body_util::BodyExt;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::timeout;
use tower::ServiceExt;

struct State {
    sequence: AtomicU64,
    submissions: AtomicUsize,
    aborted: AtomicUsize,
    rows: Mutex<Vec<(Bytes, Bytes)>>,
    hold_commit: AtomicBool,
    hold_append: AtomicBool,
    appended: Semaphore,
    accepted: Semaphore,
    release: Semaphore,
    release_append: Semaphore,
}

impl Default for State {
    fn default() -> Self {
        Self {
            sequence: AtomicU64::new(0),
            submissions: AtomicUsize::new(0),
            aborted: AtomicUsize::new(0),
            rows: Mutex::new(Vec::new()),
            hold_commit: AtomicBool::new(false),
            hold_append: AtomicBool::new(false),
            appended: Semaphore::new(0),
            accepted: Semaphore::new(0),
            release: Semaphore::new(0),
            release_append: Semaphore::new(0),
        }
    }
}

struct Engine(Arc<State>);
struct Preparation {
    state: Arc<State>,
    rows: Vec<(Bytes, Bytes)>,
    accepted: bool,
}

impl Drop for Preparation {
    fn drop(&mut self) {
        if !self.accepted {
            self.state.aborted.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl Ingest for Engine {
    type Put = Preparation;

    fn begin_put(&self) -> Result<Preparation, IngestError> {
        Ok(Preparation {
            state: self.0.clone(),
            rows: Vec::new(),
            accepted: false,
        })
    }
}

impl IngestPut for Preparation {
    async fn append(&mut self, rows: Vec<(Bytes, Bytes)>) -> Result<(), IngestError> {
        self.rows.extend(rows);
        self.state.appended.add_permits(1);
        if self.state.hold_append.load(Ordering::SeqCst) {
            self.state.release_append.acquire().await.unwrap().forget();
        }
        Ok(())
    }

    fn submit(
        mut self,
    ) -> Result<
        impl std::future::Future<Output = Result<u64, IngestError>> + Send + 'static,
        IngestError,
    > {
        self.accepted = true;
        self.state.submissions.fetch_add(1, Ordering::SeqCst);
        self.state.accepted.add_permits(1);
        let state = self.state.clone();
        let rows = std::mem::take(&mut self.rows);
        Ok(async move {
            if state.hold_commit.load(Ordering::SeqCst) {
                state.release.acquire().await.unwrap().forget();
            }
            *state.rows.lock().unwrap() = rows;
            Ok(state.sequence.fetch_add(1, Ordering::SeqCst) + 1)
        })
    }
}

fn request(value: &'static [u8]) -> PutRequest {
    PutRequest {
        kvs: vec![Entry {
            key: b"key".to_vec(),
            value: Bytes::from_static(value),
            ..Default::default()
        }],
        ..Default::default()
    }
}

async fn wait(signal: &Semaphore) {
    timeout(Duration::from_secs(5), signal.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
}

#[tokio::test]
async fn chunks_are_prepared_before_eof_and_published_once() {
    let state = Arc::new(State::default());
    let service = ingest_service(IngestState::new(Arc::new(Engine(state.clone()))));
    let client = ServiceClient::new(
        ServiceTransport::new(service),
        ClientConfig::new("http://store.test".parse().unwrap()),
    );
    let (send, receive) = mpsc::channel(1);
    let requests = stream::unfold(receive, |mut receive| async move {
        receive.recv().await.map(|item| (item, receive))
    });
    let call = tokio::spawn(async move { client.put(requests).await });
    send.send(request(b"first")).await.unwrap();
    wait(&state.appended).await;
    assert_eq!(state.submissions.load(Ordering::SeqCst), 0);
    assert_eq!(state.sequence.load(Ordering::SeqCst), 0);
    send.send(request(b"second")).await.unwrap();
    wait(&state.appended).await;
    assert_eq!(state.submissions.load(Ordering::SeqCst), 0);
    drop(send);
    let result = timeout(Duration::from_secs(5), call)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(result.view().sequence_number, 1);
    assert_eq!(state.submissions.load(Ordering::SeqCst), 1);
    assert_eq!(
        state.rows.lock().unwrap().as_slice(),
        &[
            (Bytes::from_static(b"key"), Bytes::from_static(b"first")),
            (Bytes::from_static(b"key"), Bytes::from_static(b"second"))
        ]
    );
}

#[tokio::test]
async fn cancelled_upload_drops_preparation_without_publication() {
    let state = Arc::new(State::default());
    let service = ingest_service(IngestState::new(Arc::new(Engine(state.clone()))));
    let client = ServiceClient::new(
        ServiceTransport::new(service),
        ClientConfig::new("http://store.test".parse().unwrap()),
    );
    let (send, receive) = mpsc::channel(1);
    let requests = stream::unfold(receive, |mut receive| async move {
        receive.recv().await.map(|item| (item, receive))
    });
    let call = tokio::spawn(async move { client.put(requests).await });
    send.send(request(b"first")).await.unwrap();
    wait(&state.appended).await;
    call.abort();
    assert!(call.await.unwrap_err().is_cancelled());
    drop(send);
    timeout(Duration::from_secs(5), async {
        while state.aborted.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(state.aborted.load(Ordering::SeqCst), 1);
    assert_eq!(state.submissions.load(Ordering::SeqCst), 0);
    assert_eq!(state.sequence.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn accepted_write_notifies_after_request_cancellation() {
    let state = Arc::new(State::default());
    state.hold_commit.store(true, Ordering::SeqCst);
    let hub = Arc::new(StreamHub::new(0));
    let service = ingest_service(IngestState::with_notifier(
        Arc::new(Engine(state.clone())),
        hub.clone(),
    ));
    let client = ServiceClient::new(
        ServiceTransport::new(service),
        ClientConfig::new("http://store.test".parse().unwrap()),
    );
    let call = tokio::spawn(async move { client.put(stream::iter([request(b"committed")])).await });
    wait(&state.accepted).await;
    call.abort();
    assert!(call.await.unwrap_err().is_cancelled());
    assert_eq!(hub.current_sequence(), 0);
    state.release.add_permits(1);
    timeout(Duration::from_secs(5), async {
        while hub.current_sequence() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(state.sequence.load(Ordering::SeqCst), 1);
    assert_eq!(
        state.rows.lock().unwrap()[0].1,
        Bytes::from_static(b"committed")
    );
}

fn envelope(request: PutRequest) -> Vec<u8> {
    let payload = request.encode_to_vec();
    let mut bytes = vec![0];
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&payload);
    bytes
}

#[tokio::test]
async fn corrupt_or_failed_streams_never_submit_prepared_entries() {
    let valid = envelope(request(b"first"));
    let mut terminal = vec![2, 0, 0, 0, 0];
    terminal.extend_from_slice(b"junk");
    for tail in [
        Ok(Bytes::from_static(b"\0\0")),
        Ok(Bytes::from_static(b"\0\0\0\0\x02\x0a")),
        Ok(Bytes::from(terminal)),
        Err(connectrpc::ConnectError::internal("broken upload")),
    ] {
        let state = Arc::new(State::default());
        let body = http_body_util::StreamBody::new(stream::iter([
            Ok(http_body::Frame::data(Bytes::from(valid.clone()))),
            tail.map(http_body::Frame::data),
        ]));
        let response = ingest_service(IngestState::new(Arc::new(Engine(state.clone()))))
            .oneshot(
                http::Request::post("/log.ingest.v1.Service/Put")
                    .header("content-type", "application/connect+proto")
                    .header("connect-protocol-version", "1")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();
        let response = response.into_body().collect().await.unwrap().to_bytes();
        assert!(response
            .windows(b"\"error\"".len())
            .any(|bytes| bytes == b"\"error\""));
        assert_eq!(state.submissions.load(Ordering::SeqCst), 0);
        assert_eq!(state.sequence.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn entry_limit_applies_to_the_whole_stream() {
    let state = Arc::new(State::default());
    let service = ingest_service(
        IngestState::new(Arc::new(Engine(state.clone()))).with_limits(IngestLimits {
            max_entries: 1,
            ..Default::default()
        }),
    );
    let client = ServiceClient::new(
        ServiceTransport::new(service),
        ClientConfig::new("http://store.test".parse().unwrap()),
    );
    let error = client
        .put(stream::iter([request(b"first"), request(b"second")]))
        .await
        .unwrap_err();
    assert_eq!(error.code, connectrpc::ErrorCode::InvalidArgument);
    assert_eq!(state.submissions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancellation_keeps_admission_until_preparation_quiesces() {
    let state = Arc::new(State::default());
    state.hold_append.store(true, Ordering::SeqCst);
    let service =
        ingest_service(IngestState::new(Arc::new(Engine(state.clone())))).with_config(PutConfig {
            max_requests: 1,
            timeout: Duration::from_secs(5),
        });
    let client = ServiceClient::new(
        ServiceTransport::new(service),
        ClientConfig::new("http://store.test".parse().unwrap()),
    );
    let first = client.clone();
    let call = tokio::spawn(async move { first.put(stream::iter([request(b"cancelled")])).await });
    wait(&state.appended).await;
    call.abort();
    assert!(call.await.unwrap_err().is_cancelled());
    let error = client
        .put(stream::iter([request(b"blocked")]))
        .await
        .unwrap_err();
    assert_eq!(error.code, connectrpc::ErrorCode::ResourceExhausted);
    assert_eq!(state.aborted.load(Ordering::SeqCst), 0);
    state.hold_append.store(false, Ordering::SeqCst);
    state.release_append.add_permits(1);
    timeout(Duration::from_secs(5), async {
        while state.aborted.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let sequence = timeout(Duration::from_secs(5), async {
        loop {
            match client.put(stream::iter([request(b"next")])).await {
                Ok(response) => break response.view().sequence_number,
                Err(error) => {
                    assert_eq!(error.code, connectrpc::ErrorCode::ResourceExhausted);
                    tokio::task::yield_now().await;
                }
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(sequence, 1);
    assert_eq!(state.submissions.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn deadline_during_preparation_never_submits() {
    let state = Arc::new(State::default());
    state.hold_append.store(true, Ordering::SeqCst);
    let service =
        ingest_service(IngestState::new(Arc::new(Engine(state.clone())))).with_config(PutConfig {
            max_requests: 1,
            timeout: Duration::from_millis(50),
        });
    let client = ServiceClient::new(
        ServiceTransport::new(service),
        ClientConfig::new("http://store.test".parse().unwrap()),
    );
    let first = client.clone();
    let call = tokio::spawn(async move { first.put(stream::iter([request(b"expired")])).await });
    wait(&state.appended).await;
    let error = timeout(Duration::from_secs(5), call)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code, connectrpc::ErrorCode::DeadlineExceeded);
    let error = client
        .put(stream::iter([request(b"blocked")]))
        .await
        .unwrap_err();
    assert_eq!(error.code, connectrpc::ErrorCode::ResourceExhausted);
    state.hold_append.store(false, Ordering::SeqCst);
    state.release_append.add_permits(1);
    timeout(Duration::from_secs(5), async {
        while state.aborted.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(state.submissions.load(Ordering::SeqCst), 0);
    assert_eq!(state.sequence.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn accepted_publication_keeps_admission_after_rpc_cancellation() {
    let state = Arc::new(State::default());
    state.hold_commit.store(true, Ordering::SeqCst);
    let service =
        ingest_service(IngestState::new(Arc::new(Engine(state.clone())))).with_config(PutConfig {
            max_requests: 1,
            timeout: Duration::from_secs(5),
        });
    let client = ServiceClient::new(
        ServiceTransport::new(service),
        ClientConfig::new("http://store.test".parse().unwrap()),
    );
    let first = client.clone();
    let call = tokio::spawn(async move { first.put(stream::iter([request(b"accepted")])).await });
    wait(&state.accepted).await;
    call.abort();
    assert!(call.await.unwrap_err().is_cancelled());
    let error = client
        .put(stream::iter([request(b"blocked")]))
        .await
        .unwrap_err();
    assert_eq!(error.code, connectrpc::ErrorCode::ResourceExhausted);
    state.release.add_permits(1);
    timeout(Duration::from_secs(5), async {
        while state.sequence.load(Ordering::SeqCst) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(state.submissions.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn malformed_suffix_discards_already_prepared_entries() {
    let state = Arc::new(State::default());
    let service = ingest_service(IngestState::new(Arc::new(Engine(state.clone()))));
    let (send, receive) = mpsc::channel(1);
    let frames = stream::unfold(receive, |mut receive| async move {
        receive.recv().await.map(|frame| (frame, receive))
    });
    let call = tokio::spawn(
        service.oneshot(
            http::Request::post("/log.ingest.v1.Service/Put")
                .header("content-type", "application/connect+proto")
                .header("connect-protocol-version", "1")
                .body(http_body_util::StreamBody::new(frames))
                .unwrap(),
        ),
    );
    send.send(Ok::<_, connectrpc::ConnectError>(http_body::Frame::data(
        Bytes::from(envelope(request(b"prepared"))),
    )))
    .await
    .unwrap();
    wait(&state.appended).await;
    assert_eq!(state.submissions.load(Ordering::SeqCst), 0);
    send.send(Ok(http_body::Frame::data(Bytes::from_static(b"\0\0"))))
        .await
        .unwrap();
    drop(send);
    let response = timeout(Duration::from_secs(5), call)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let response = response.into_body().collect().await.unwrap().to_bytes();
    assert!(response
        .windows(b"\"error\"".len())
        .any(|bytes| bytes == b"\"error\""));
    assert_eq!(state.aborted.load(Ordering::SeqCst), 1);
    assert_eq!(state.submissions.load(Ordering::SeqCst), 0);
    assert_eq!(state.sequence.load(Ordering::SeqCst), 0);
}
