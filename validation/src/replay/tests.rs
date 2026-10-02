use std::{
    collections::BTreeMap,
    ops::Deref,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use axum::Router;
use bytes::Bytes;
use connectrpc::client::{BoxFuture, ClientBody, ClientTransport};
use connectrpc::{ConnectError, ConnectRpcService, InboundStream, RequestContext};
use exoware_sdk::ingest::{PutRequest, PutResponse, Service, ServiceServer};
use exoware_sdk::{PreferZstdHttpClient, RetryConfig, StoreClient};
use futures::StreamExt;
use tokio::{sync::Semaphore, task::JoinHandle, time::timeout};

use super::*;
use crate::capture::{
    Bundle, Domain, Endian, Family, Generator, Offset, Patch, Profile, Row, Target,
};

type Rows = Vec<(Vec<u8>, Bytes)>;

#[derive(Default)]
struct Rpc {
    compression: Option<String>,
    messages: Vec<Rows>,
}

#[derive(Clone, Copy, Default)]
struct Behavior {
    hold_upload: bool,
    hold_response: bool,
    hold_response_key: Option<[u8; 3]>,
    reject_second: bool,
}

struct State {
    behavior: Behavior,
    rpcs: Mutex<Vec<Rpc>>,
    first_message: Semaphore,
    uploaded: Semaphore,
    release_upload: Semaphore,
    release_response: Semaphore,
    responses: AtomicUsize,
}

impl State {
    fn new(behavior: Behavior) -> Self {
        Self {
            behavior,
            rpcs: Mutex::new(Vec::new()),
            first_message: Semaphore::new(0),
            uploaded: Semaphore::new(0),
            release_upload: Semaphore::new(0),
            release_response: Semaphore::new(0),
            responses: AtomicUsize::new(0),
        }
    }
}

#[derive(Clone)]
struct Harness(Arc<State>);

struct UploadGate {
    started: Semaphore,
    release: Semaphore,
}

#[derive(Clone)]
struct GatedTransport {
    native: PreferZstdHttpClient,
    gate: Arc<UploadGate>,
}

#[derive(Clone, Default)]
struct ImmediateTransport {
    calls: Arc<AtomicUsize>,
    uploaded_bytes: Arc<AtomicUsize>,
}

impl ClientTransport for ImmediateTransport {
    type ResponseBody = axum::body::Body;
    type Error = ConnectError;

    fn send(
        &self,
        request: http::Request<ClientBody>,
    ) -> BoxFuture<'static, Result<http::Response<Self::ResponseBody>, Self::Error>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let uploaded_bytes = self.uploaded_bytes.clone();
        Box::pin(async move {
            let body = axum::body::to_bytes(axum::body::Body::new(request.into_body()), usize::MAX)
                .await
                .unwrap();
            uploaded_bytes.store(body.len(), Ordering::SeqCst);

            // An immediate framed response isolates synchronous SDK encoding from network delay.
            let response = [0, 0, 0, 0, 2, 8, 91, 2, 0, 0, 0, 2, b'{', b'}'];
            Ok(http::Response::builder()
                .header("content-type", "application/connect+proto")
                .body(axum::body::Body::from(response.to_vec()))
                .unwrap())
        })
    }
}

impl ClientTransport for GatedTransport {
    type ResponseBody = <PreferZstdHttpClient as ClientTransport>::ResponseBody;
    type Error = ConnectError;

    fn send(
        &self,
        request: http::Request<ClientBody>,
    ) -> BoxFuture<'static, Result<http::Response<Self::ResponseBody>, Self::Error>> {
        let native = self.native.clone();
        let gate = self.gate.clone();
        Box::pin(async move {
            gate.started.add_permits(1);
            gate.release.acquire().await.unwrap().forget();
            native.send(request).await
        })
    }
}

#[allow(refining_impl_trait)]
impl Service for Harness {
    async fn put(
        &self,
        ctx: RequestContext,
        mut requests: InboundStream<PutRequest>,
    ) -> connectrpc::ServiceResult<PutResponse> {
        let rpc = {
            let mut rpcs = self.0.rpcs.lock().unwrap();
            let index = rpcs.len();
            rpcs.push(Rpc {
                compression: ctx
                    .headers()
                    .get("connect-content-encoding")
                    .map(|value| value.to_str().unwrap().to_owned()),
                ..Default::default()
            });
            index
        };

        let mut messages = 0;
        while let Some(request) = requests.next().await {
            let rows = request?
                .to_owned_message()
                .kvs
                .into_iter()
                .map(|row| (row.key, row.value))
                .collect();
            self.0.rpcs.lock().unwrap()[rpc].messages.push(rows);
            messages += 1;
            if messages == 1 {
                self.0.first_message.add_permits(1);
                if self.0.behavior.hold_upload {
                    self.0.release_upload.acquire().await.unwrap().forget();
                }
            }
            if messages == 2 && self.0.behavior.reject_second {
                return Err(ConnectError::resource_exhausted("later message rejected"));
            }
        }

        self.0.uploaded.add_permits(1);
        let hold_response = self.0.behavior.hold_response
            || self
                .0
                .behavior
                .hold_response_key
                .is_some_and(|key| self.0.rpcs.lock().unwrap()[rpc].messages[0][0].0 == key);
        if hold_response {
            self.0.release_response.acquire().await.unwrap().forget();
        }
        self.0.responses.fetch_add(1, Ordering::SeqCst);
        connectrpc::Response::ok(PutResponse {
            sequence_number: 91 + rpc as u64,
            ..Default::default()
        })
    }
}

struct Server {
    client: PrefixedStoreClient,
    state: Arc<State>,
    url: String,
    task: JoinHandle<()>,
}

impl Server {
    async fn start(compression: RequestCompression, behavior: Behavior) -> Self {
        let state = Arc::new(State::new(behavior));
        let service = ConnectRpcService::new(ServiceServer::new(Harness(state.clone())));
        let app = Router::new().fallback_service(service);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = build_client(
            &ClientConfig::new(&url, 3)
                .unwrap()
                .with_request_compression(compression),
        )
        .unwrap();
        Self {
            client,
            state,
            url,
            task,
        }
    }

    fn schedule(&self, generator: Generator, args: Args) -> JoinHandle<TestReport> {
        let client = self.client.clone();
        tokio::spawn(async move {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("capture");
            generator.bundle().write(&path).unwrap();
            let generator = FileGenerator::open(path, args.seed).unwrap();
            generator
                .validate_passes(args.start_pass, args.passes)
                .unwrap();
            let schedule = schedule::Schedule {
                repeat_period_ns: generator.repeat_period_ns(),
                last_offset_ns: generator.last_offset_ns(),
                event_count: generator.event_count(),
            };
            let (input, preparation) = prepare(generator, &args).await.unwrap();
            let (sender, mut receiver) = tokio::sync::mpsc::channel(args.concurrency);
            let collector = tokio::spawn(async move {
                let mut requests = Vec::new();
                while let Some(request) = receiver.recv().await {
                    requests.push(request);
                }
                requests
            });
            let summary = schedule::run(
                &args,
                schedule,
                input,
                move |batch| {
                    let client = client.clone();
                    async move { issue(&client, batch).await }
                },
                Some(sender),
            )
            .await
            .unwrap();
            preparation.await.unwrap();
            let requests = collector.await.unwrap();
            drop(directory);
            TestReport { summary, requests }
        })
    }
}

struct TestReport {
    summary: schedule::Report,
    requests: Vec<schedule::Request>,
}

impl Deref for TestReport {
    type Target = schedule::Report;

    fn deref(&self) -> &Self::Target {
        &self.summary
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn wait(signal: &Semaphore) {
    timeout(Duration::from_secs(5), signal.acquire())
        .await
        .expect("service did not reach the expected phase")
        .unwrap()
        .forget();
}

async fn finish<T>(task: JoinHandle<T>) -> T {
    timeout(Duration::from_secs(10), task)
        .await
        .expect("replay did not finish")
        .unwrap()
}

fn fixture(batches: usize) -> Generator {
    Generator::new(
        Bundle {
            profile: Profile {
                version: 1,
                domains: BTreeMap::from([("location".into(), Domain::Numeric { width: 2 })]),
                families: vec![Family {
                    id: 1,
                    name: "rows".into(),
                    key_prefix_hex: "aa".into(),
                    fresh_key: 0,
                    patches: vec![Patch {
                        target: Target::Key,
                        offset: Offset::Start(1),
                        domain: "location".into(),
                        endian: Endian::Big,
                    }],
                }],
            },
            source: BTreeMap::new(),
            repeat_period_ns: 1_000_000_000,
            batches: (0..batches)
                .map(|batch| Batch {
                    offset_ns: 0,
                    rows: [3, 1, 4, 2]
                        .into_iter()
                        .map(|index| {
                            let id = (batch * 4 + index) as u8;
                            Row {
                                family: 1,
                                key: Bytes::from(vec![0xaa, 0, id]),
                                value: if index == 1 {
                                    Bytes::new()
                                } else {
                                    Bytes::from(vec![id; 700_000])
                                },
                            }
                        })
                        .collect(),
                })
                .collect(),
        },
        0,
    )
    .unwrap()
}

fn args() -> Args {
    Args {
        capture: "unused".into(),
        url: "unused".into(),
        seed: 0,
        start_pass: 0,
        passes: 1,
        speed: 1.0,
        concurrency: 1,
        buffer_batches: 2,
        max_lag_ms: 5000,
        request_timeout_ms: 5000,
        duration_secs: None,
        request_compression: RequestCompression::None,
        output: None,
    }
}

fn assert_failed_once(report: &TestReport, state: &State, error: &str) {
    assert_eq!(report.stop_reason, "request_failed");
    assert_eq!(report.requests.len(), 1);
    assert_eq!(report.requests[0].event, 0);
    assert_eq!(report.requests[0].rows, 4);
    assert_eq!(report.requests[0].sequence_number, None);
    assert_eq!(report.issued, 1);
    assert_eq!(report.succeeded, 0);
    assert_eq!(report.failed, 1);
    assert!(report.requests[0].error.as_ref().unwrap().contains(error));
    assert!(report.error.as_ref().unwrap().contains(error));
    assert_eq!(state.rpcs.lock().unwrap().len(), 1);
    assert_eq!(state.responses.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn captured_batch_streams_once_and_reports_only_after_final_response() {
    for compression in [RequestCompression::None, RequestCompression::Zstd] {
        let server = Server::start(
            compression,
            Behavior {
                hold_response: true,
                ..Default::default()
            },
        )
        .await;
        let generator = fixture(1);
        let expected = generator
            .batch(0, 0)
            .unwrap()
            .rows
            .into_iter()
            .map(|row| (row.key.to_vec(), row.value))
            .collect::<Rows>();
        let directory = tempfile::tempdir().unwrap();
        let capture = directory.path().join("capture");
        generator.bundle().write(&capture).unwrap();
        let output = directory.path().join("report.json");
        let mut args = args();
        args.capture = capture;
        args.url = server.url.clone();
        args.request_compression = compression;
        args.output = Some(output.clone());
        let replay = tokio::spawn(run(args));
        wait(&server.state.uploaded).await;

        assert!(!replay.is_finished());
        assert!(output.exists());
        assert!(
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(&output).unwrap()).is_err()
        );
        assert_eq!(server.state.responses.load(Ordering::SeqCst), 0);
        {
            let rpcs = server.state.rpcs.lock().unwrap();
            assert_eq!(rpcs.len(), 1);
            assert!(rpcs[0].messages.len() > 1);
            assert_eq!(
                rpcs[0].messages.iter().flatten().cloned().collect::<Rows>(),
                expected
            );
            assert_eq!(
                rpcs[0].compression.as_deref(),
                match compression {
                    RequestCompression::None => None,
                    RequestCompression::Zstd => Some("zstd"),
                    RequestCompression::Gzip => unreachable!(),
                }
            );
        }

        server.state.release_response.add_permits(1);
        finish(replay).await.unwrap();
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
        let requests = report["run"]["requests"].as_array().unwrap();
        assert_eq!(report["format_version"], 2);
        assert_eq!(report["run"]["issued"], 1);
        assert_eq!(report["run"]["succeeded"], 1);
        assert_eq!(report["run"]["failed"], 0);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["rows"], 4);
        assert_eq!(requests[0]["logical_bytes"], 2_100_012u64);
        assert_eq!(requests[0]["sequence_number"], 91);
        assert!(requests[0]["error"].is_null());
        assert_eq!(report["run"]["stop_reason"], "complete");
        assert_eq!(server.state.responses.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn later_message_rejection_fails_whole_batch_without_retry_or_split() {
    let server = Server::start(
        RequestCompression::None,
        Behavior {
            reject_second: true,
            ..Default::default()
        },
    )
    .await;
    let report = finish(server.schedule(fixture(2), args())).await;
    assert_failed_once(&report, &server.state, "later message rejected");
    assert_eq!(server.state.rpcs.lock().unwrap()[0].messages.len(), 2);
}

#[tokio::test]
async fn stalled_upload_times_out_as_one_failed_batch_without_retry() {
    let server = Server::start(
        RequestCompression::None,
        Behavior {
            hold_upload: true,
            ..Default::default()
        },
    )
    .await;
    let mut args = args();
    args.request_timeout_ms = 250;
    let replay = server.schedule(fixture(2), args);
    wait(&server.state.first_message).await;
    let report = finish(replay).await;
    assert_failed_once(&report, &server.state, "request timed out");
    assert_eq!(server.state.rpcs.lock().unwrap()[0].messages.len(), 1);
    assert_eq!(server.state.uploaded.available_permits(), 0);
}

#[tokio::test]
async fn stalled_final_response_times_out_as_one_failed_batch_without_retry() {
    let server = Server::start(
        RequestCompression::Zstd,
        Behavior {
            hold_response: true,
            ..Default::default()
        },
    )
    .await;
    let mut args = args();
    args.request_timeout_ms = 250;
    let replay = server.schedule(fixture(2), args);
    wait(&server.state.uploaded).await;
    let report = finish(replay).await;
    assert_failed_once(&report, &server.state, "request timed out");
    assert!(server.state.rpcs.lock().unwrap()[0].messages.len() > 1);
}

#[tokio::test]
async fn one_timeout_budget_covers_upload_and_final_response() {
    let mut server = Server::start(
        RequestCompression::None,
        Behavior {
            hold_response: true,
            ..Default::default()
        },
    )
    .await;
    let gate = Arc::new(UploadGate {
        started: Semaphore::new(0),
        release: Semaphore::new(0),
    });
    server.client = PrefixedStoreClient::empty(
        StoreClient::builder()
            .url(&server.url)
            .retry_config(RetryConfig::standard().with_max_attempts(3))
            .client_transport(GatedTransport {
                native: PreferZstdHttpClient::plaintext(),
                gate: gate.clone(),
            })
            .build()
            .unwrap(),
    );
    let mut args = args();
    args.request_timeout_ms = 1000;
    let replay = server.schedule(fixture(2), args);
    wait(&gate.started).await;
    assert!(server.state.rpcs.lock().unwrap().is_empty());

    // Spend most of the deadline before the native transport can poll the upload.
    tokio::time::sleep(Duration::from_millis(600)).await;
    gate.release.add_permits(1);
    wait(&server.state.uploaded).await;
    let report = timeout(Duration::from_millis(800), replay)
        .await
        .expect("request timeout was restarted after upload")
        .unwrap();
    assert_failed_once(&report, &server.state, "request timed out");
    assert!(server.state.rpcs.lock().unwrap()[0].messages.len() > 1);
}

#[tokio::test]
async fn concurrency_slot_is_held_until_final_response() {
    let server = Server::start(
        RequestCompression::None,
        Behavior {
            hold_response: true,
            ..Default::default()
        },
    )
    .await;
    let mut args = args();
    args.concurrency = 2;
    let replay = server.schedule(fixture(3), args);
    wait(&server.state.uploaded).await;
    wait(&server.state.uploaded).await;
    assert_eq!(server.state.rpcs.lock().unwrap().len(), 2);
    assert!(!replay.is_finished());

    server.state.release_response.add_permits(2);
    wait(&server.state.uploaded).await;
    server.state.release_response.add_permits(1);
    let report = finish(replay).await;
    assert!(report.error.is_none());
    assert_eq!(report.requests.len(), 3);
    assert!(report
        .requests
        .iter()
        .all(|request| request.sequence_number.is_some()));
    let first_completed = report
        .requests
        .iter()
        .filter(|request| request.event < 2)
        .map(|request| request.completed_ns)
        .min()
        .unwrap();
    let third = report
        .requests
        .iter()
        .find(|request| request.event == 2)
        .unwrap();
    assert!(third.dispatched_ns >= first_completed);
    assert_eq!(server.state.rpcs.lock().unwrap().len(), 3);
    assert_eq!(server.state.responses.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn duration_stops_admission_and_drains_issued_streaming_rpc() {
    let server = Server::start(
        RequestCompression::Zstd,
        Behavior {
            hold_response: true,
            ..Default::default()
        },
    )
    .await;
    let mut args = args();
    args.duration_secs = Some(1);
    let replay = server.schedule(fixture(2), args);
    wait(&server.state.uploaded).await;

    // Keep the issued RPC alive through the admission cutoff.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(!replay.is_finished());
    assert_eq!(server.state.rpcs.lock().unwrap().len(), 1);
    server.state.release_response.add_permits(1);
    let report = finish(replay).await;
    assert_eq!(report.stop_reason, "duration");
    assert!(report.error.is_none());
    assert_eq!(report.requests.len(), 1);
    assert_eq!(report.requests[0].sequence_number, Some(91));
    assert!(report.requests[0].completed_ns >= 1_000_000_000);
    assert_eq!(server.state.rpcs.lock().unwrap().len(), 1);
    assert_eq!(server.state.responses.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn synchronous_streaming_preparation_cannot_succeed_after_its_deadline() {
    let mut server = Server::start(RequestCompression::None, Behavior::default()).await;
    let transport = ImmediateTransport::default();
    server.client = PrefixedStoreClient::empty(
        StoreClient::builder()
            .url(&server.url)
            .retry_config(RetryConfig::standard().with_max_attempts(3))
            .client_transport(transport.clone())
            .build()
            .unwrap(),
    );
    let mut bundle = fixture(1).bundle().clone();
    let value = Bytes::from(vec![42; 1024 * 1024]);
    bundle.batches[0].rows = (1..=32)
        .map(|id| Row {
            family: 1,
            key: Bytes::from(vec![0xaa, 0, id]),
            value: value.clone(),
        })
        .collect();
    let mut args = args();
    args.request_timeout_ms = 1;
    let report = finish(server.schedule(Generator::new(bundle, 0).unwrap(), args)).await;
    assert_eq!(report.issued, 1);
    assert_eq!(report.requests.len(), 1);
    assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
    assert!(transport.uploaded_bytes.load(Ordering::SeqCst) >= 32 * 1024 * 1024);
    let request = &report.requests[0];
    if request.sequence_number.is_some() {
        assert!(
            request.completed_ns - request.dispatched_ns <= 1_000_000,
            "streaming success consumed {} ns of a 1000000 ns timeout",
            request.completed_ns - request.dispatched_ns,
        );
        assert_eq!(report.succeeded, 1);
        assert_eq!(report.failed, 0);
    } else {
        assert_eq!(request.error.as_deref(), Some("request timed out"));
        assert_eq!(report.succeeded, 0);
        assert_eq!(report.failed, 1);
    }
}

#[tokio::test]
async fn report_preserves_completion_order_when_first_event_finishes_last() {
    let fixture = fixture(2);
    let first_key = fixture.batch(0, 0).unwrap().rows[0]
        .key
        .as_ref()
        .try_into()
        .unwrap();
    let server = Server::start(
        RequestCompression::None,
        Behavior {
            hold_response_key: Some(first_key),
            ..Default::default()
        },
    )
    .await;
    let directory = tempfile::tempdir().unwrap();
    let capture = directory.path().join("capture");
    let output = directory.path().join("report.json");
    fixture.bundle().write(&capture).unwrap();
    let generator = FileGenerator::open(&capture, 0).unwrap();
    let schedule = schedule::Schedule {
        repeat_period_ns: generator.repeat_period_ns(),
        last_offset_ns: generator.last_offset_ns(),
        event_count: generator.event_count(),
    };
    let mut args = args();
    args.concurrency = 2;
    args.capture = capture;
    args.output = Some(output.clone());
    let mut writer = output::Writer::create(
        &output,
        output::Header {
            capture_sha256: generator.capture_sha256().to_owned(),
            source: generator.source().clone(),
            settings: args.clone(),
        },
    )
    .unwrap();
    let (input, preparation) = prepare(generator, &args).await.unwrap();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    let client = server.client.clone();
    let replay = tokio::spawn(async move {
        schedule::run(
            &args,
            schedule,
            input,
            move |batch| {
                let client = client.clone();
                async move { issue(&client, batch).await }
            },
            Some(sender),
        )
        .await
        .unwrap()
    });
    let first = timeout(Duration::from_secs(5), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.event, 1);
    assert!(first.sequence_number.is_some());
    assert_eq!(server.state.responses.load(Ordering::SeqCst), 1);
    assert!(!replay.is_finished());
    writer.record(&first).unwrap();
    server.state.release_response.add_permits(1);
    let second = timeout(Duration::from_secs(5), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second.event, 0);
    assert!(second.sequence_number.is_some());
    assert_ne!(first.sequence_number, second.sequence_number);
    assert!(first.completed_ns < second.completed_ns);
    writer.record(&second).unwrap();
    let summary = finish(replay).await;
    preparation.await.unwrap();
    assert!(receiver.recv().await.is_none());
    assert_eq!(summary.succeeded, 2);
    writer.finish(&summary).unwrap();
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
    let records = report["run"]["requests"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[0]["sequence_number"],
        first.sequence_number.unwrap()
    );
    assert_eq!(
        records[1]["sequence_number"],
        second.sequence_number.unwrap()
    );
    assert_eq!(records[0]["event"], first.event);
    assert_eq!(records[1]["event"], second.event);
}

#[tokio::test]
async fn incremental_streaming_replay_preserves_duplicates_and_complete_reports() {
    for compression in [RequestCompression::None, RequestCompression::Zstd] {
        let server = Server::start(compression, Behavior::default()).await;
        let directory = tempfile::tempdir().unwrap();
        let capture = directory.path().join("capture");
        let output = directory.path().join("report.json");
        let mut bundle = fixture(1).bundle().clone();
        bundle.repeat_period_ns = 1_000_000;
        bundle
            .source
            .insert("producer".into(), "duplicate-test".into());
        let row = bundle.batches[0].rows[0].clone();
        bundle.batches[0].rows = vec![row.clone(), row];
        let generator = Generator::new(bundle.clone(), 7).unwrap();
        let mut expected = (0..20)
            .map(|pass| generator.batch(0, pass).unwrap().rows[0].key.to_vec())
            .collect::<Vec<_>>();
        expected.sort();
        bundle.write(&capture).unwrap();
        let mut args = args();
        args.capture = capture;
        args.url = server.url.clone();
        args.seed = 7;
        args.passes = 20;
        args.concurrency = 2;
        args.buffer_batches = 3;
        args.request_compression = compression;
        args.output = Some(output.clone());
        run(args.clone()).await.unwrap();
        for occupied in [&output, &args.capture.join("rows.bin")] {
            let original = std::fs::read(occupied).unwrap();
            let mut rejected = args.clone();
            rejected.output = Some(occupied.clone());
            let error = run(rejected).await.unwrap_err();
            assert!(error.to_string().contains("creating report"));
            assert_eq!(std::fs::read(occupied).unwrap(), original);
            assert_eq!(server.state.rpcs.lock().unwrap().len(), 20);
        }
        let rpcs = server.state.rpcs.lock().unwrap();
        assert_eq!(rpcs.len(), 20);
        let mut keys = Vec::new();
        for rpc in rpcs.iter() {
            let rows = rpc.messages.iter().flatten().collect::<Vec<_>>();
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[0], rows[1]);
            assert_eq!(rows[0].1, Bytes::from(vec![3; 700_000]));
            keys.push(rows[0].0.clone());
        }
        keys.sort();
        assert_eq!(keys, expected);
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
        assert_eq!(report["format_version"], 2);
        assert_eq!(report["run"]["issued"], 20);
        assert_eq!(report["run"]["succeeded"], 20);
        assert_eq!(report["run"]["failed"], 0);
        assert_eq!(report["run"]["requests"].as_array().unwrap().len(), 20);
        assert_eq!(report["source"]["producer"], "duplicate-test");
    }
}
