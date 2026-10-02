use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use buffa::Message;
use bytes::Bytes;
use exoware_sdk::common::Entry;
use exoware_sdk::ingest::{PutRequest, PutResponse};
use exoware_server::{
    ingest_service, transport, Ingest, IngestError, IngestPut, IngestState, PutConfig,
};
use futures::stream::{self, BoxStream};
use futures::StreamExt;
use http::{header, Request, Response, Version};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant};

const PUT_PATH: &str = "/log.ingest.v1.Service/Put";
const CONTENT_TYPE: &str = "application/connect+proto";
const FALLBACK: Duration = Duration::from_millis(400);
const PAUSE: Duration = Duration::from_millis(500);
const TEST_BOUND: Duration = Duration::from_secs(5);

type UploadBody = StreamBody<BoxStream<'static, Result<Frame<Bytes>, Infallible>>>;

struct State {
    sequence: AtomicU64,
    begins: AtomicUsize,
    submissions: AtomicUsize,
    appended: mpsc::UnboundedSender<Bytes>,
    aborted: Semaphore,
}

struct Backend(Arc<State>);

struct Preparation {
    state: Arc<State>,
    rows: Vec<(Bytes, Bytes)>,
    accepted: bool,
}

impl Drop for Preparation {
    fn drop(&mut self) {
        if !self.accepted {
            self.state.aborted.add_permits(1);
        }
    }
}

impl Ingest for Backend {
    type Put = Preparation;

    fn begin_put(&self) -> Result<Self::Put, IngestError> {
        self.0.begins.fetch_add(1, Ordering::SeqCst);
        Ok(Preparation {
            state: self.0.clone(),
            rows: Vec::new(),
            accepted: false,
        })
    }
}

impl IngestPut for Preparation {
    async fn append(&mut self, rows: Vec<(Bytes, Bytes)>) -> Result<(), IngestError> {
        for (_, value) in &rows {
            self.state.appended.send(value.clone()).unwrap();
        }
        self.rows.extend(rows);
        Ok(())
    }

    fn submit(
        mut self,
    ) -> Result<impl Future<Output = Result<u64, IngestError>> + Send + 'static, IngestError> {
        self.accepted = true;
        self.state.submissions.fetch_add(1, Ordering::SeqCst);
        Ok(async move {
            let sequence = self.state.sequence.fetch_add(1, Ordering::SeqCst) + 1;
            drop(self);
            Ok(sequence)
        })
    }
}

struct Server {
    address: SocketAddr,
    state: Arc<State>,
    appended: mpsc::UnboundedReceiver<Bytes>,
    task: JoinHandle<std::io::Result<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    timeout(TEST_BOUND, future)
        .await
        .expect("transport test stalled")
}

async fn server() -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (appended, receive) = mpsc::unbounded_channel();
    let state = Arc::new(State {
        sequence: AtomicU64::new(0),
        begins: AtomicUsize::new(0),
        submissions: AtomicUsize::new(0),
        appended,
        aborted: Semaphore::new(0),
    });
    let service =
        ingest_service(IngestState::new(Arc::new(Backend(state.clone())))).with_config(PutConfig {
            timeout: FALLBACK,
            ..Default::default()
        });
    let task = tokio::spawn(transport::serve(listener, service, std::future::pending()));
    Server {
        address,
        state,
        appended: receive,
        task,
    }
}

async fn appended(server: &mut Server, expected: &[u8]) {
    bounded(async {
        loop {
            let value = server.appended.recv().await.unwrap();
            if value.as_ref() == expected {
                return;
            }
        }
    })
    .await;
}

async fn aborted(server: &Server) {
    bounded(server.state.aborted.acquire())
        .await
        .unwrap()
        .forget();
}

fn envelope(value: &'static [u8]) -> Bytes {
    let payload = PutRequest {
        kvs: vec![Entry {
            key: b"key".to_vec(),
            value: Bytes::from_static(value),
            ..Default::default()
        }],
        ..Default::default()
    }
    .encode_to_vec();
    let mut bytes = vec![0];
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&payload);
    bytes.into()
}

async fn send_http1(
    socket: &mut TcpStream,
    prefix: &[u8],
    total_len: usize,
    content_type: &str,
    client_timeout_ms: Option<u64>,
) {
    let timeout_header = client_timeout_ms
        .map(|ms| format!("connect-timeout-ms: {ms}\r\n"))
        .unwrap_or_default();
    let headers = format!("POST {PUT_PATH} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {content_type}\r\nConnect-Protocol-Version: 1\r\nContent-Length: {total_len}\r\n{timeout_header}\r\n");
    bounded(socket.write_all(headers.as_bytes())).await.unwrap();
    bounded(socket.write_all(prefix)).await.unwrap();
}

async fn read_http1(socket: &mut TcpStream) -> Response<Bytes> {
    bounded(async {
        let mut reader = BufReader::new(socket);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let status = line
            .split_ascii_whitespace()
            .nth(1)
            .expect("missing response status")
            .parse::<u16>()
            .unwrap();
        let mut response = Response::builder().status(status);
        loop {
            line.clear();
            assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
            if line == "\r\n" {
                break;
            }
            let (name, value) = line.trim_end().split_once(':').unwrap();
            response = response.header(name, value.trim());
        }

        let headers = response.headers_ref().unwrap();
        let mut body = Vec::new();
        if let Some(length) = headers.get(header::CONTENT_LENGTH) {
            body.resize(length.to_str().unwrap().parse().unwrap(), 0);
            reader.read_exact(&mut body).await.unwrap();
        } else {
            assert_eq!(headers[header::TRANSFER_ENCODING], "chunked");
            loop {
                line.clear();
                assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
                let length =
                    usize::from_str_radix(line.trim().split(';').next().unwrap(), 16).unwrap();
                if length == 0 {
                    loop {
                        line.clear();
                        assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
                        if line == "\r\n" {
                            break;
                        }
                    }
                    break;
                }
                let start = body.len();
                body.resize(start + length, 0);
                reader.read_exact(&mut body[start..]).await.unwrap();
                let mut ending = [0; 2];
                reader.read_exact(&mut ending).await.unwrap();
                assert_eq!(&ending, b"\r\n");
            }
        }
        response.body(body.into()).unwrap()
    })
    .await
}

fn successful(response: &Response<Bytes>, expected: u64) {
    assert_eq!(response.status(), http::StatusCode::OK);
    let body = response.body();
    assert_eq!(body[0], 0);
    let length = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
    let response = PutResponse::decode_from_slice(&body[5..5 + length]).unwrap();
    assert_eq!(response.sequence_number, expected);
    assert!(!body
        .windows(b"\"error\"".len())
        .any(|window| window == b"\"error\""));
}

async fn healthy_http1(socket: &mut TcpStream, value: &'static [u8], sequence: u64) {
    let body = envelope(value);
    send_http1(socket, &body, body.len(), CONTENT_TYPE, None).await;
    let response = read_http1(socket).await;
    successful(&response, sequence);
    assert_ne!(
        response
            .headers()
            .get(header::CONNECTION)
            .map(|value| value.as_bytes()),
        Some(b"close".as_slice())
    );
}

#[tokio::test]
async fn http1_stalled_partial_upload_closes_at_the_fallback_deadline() {
    let mut server = server().await;
    let mut socket = TcpStream::connect(server.address).await.unwrap();
    let prefix = envelope(b"stalled");
    let started = Instant::now();
    send_http1(&mut socket, &prefix, prefix.len() + 1, CONTENT_TYPE, None).await;
    appended(&mut server, b"stalled").await;
    assert_eq!(server.state.submissions.load(Ordering::SeqCst), 0);

    let mut response = Vec::new();
    bounded(socket.read_to_end(&mut response)).await.unwrap();
    assert!(started.elapsed() >= FALLBACK);
    aborted(&server).await;
    assert_eq!(server.state.submissions.load(Ordering::SeqCst), 0);
    assert_eq!(server.state.sequence.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn http1_client_deadline_allows_upload_paused_past_the_fallback() {
    let mut server = server().await;
    let mut socket = TcpStream::connect(server.address).await.unwrap();
    let first = envelope(b"first");
    let last = envelope(b"last");
    send_http1(
        &mut socket,
        &first,
        first.len() + last.len(),
        CONTENT_TYPE,
        Some(5000),
    )
    .await;
    let (release, gate) = oneshot::channel();
    let upload = tokio::spawn(async move {
        gate.await.unwrap();
        socket.write_all(&last).await.unwrap();
        read_http1(&mut socket).await
    });
    appended(&mut server, b"first").await;
    tokio::time::sleep(PAUSE).await;
    assert_eq!(server.state.sequence.load(Ordering::SeqCst), 0);
    assert_eq!(server.state.aborted.available_permits(), 0);
    release.send(()).unwrap();

    let response = bounded(upload).await.unwrap();
    successful(&response, 1);
    assert_eq!(server.state.submissions.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn http1_clean_put_disarms_its_deadline_before_keep_alive_reuse() {
    let server = server().await;
    let mut socket = TcpStream::connect(server.address).await.unwrap();
    healthy_http1(&mut socket, b"first", 1).await;
    tokio::time::sleep(PAUSE).await;
    healthy_http1(&mut socket, b"second", 2).await;
    assert_eq!(server.state.submissions.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn http1_malformed_and_prehandler_rejections_close_the_connection() {
    let server = server().await;
    for content_type in [CONTENT_TYPE, "application/octet-stream"] {
        let begins = server.state.begins.load(Ordering::SeqCst);
        let mut socket = TcpStream::connect(server.address).await.unwrap();
        let mut body = envelope(b"invalid").to_vec();
        body.push(0);
        send_http1(&mut socket, &body, body.len(), content_type, None).await;
        let response = read_http1(&mut socket).await;
        assert_eq!(response.headers()[header::CONNECTION], "close");
        if content_type == CONTENT_TYPE {
            assert!(response
                .body()
                .windows(b"invalid_argument".len())
                .any(|window| window == b"invalid_argument"));
        } else {
            assert_eq!(response.status(), http::StatusCode::UNSUPPORTED_MEDIA_TYPE);
            assert_eq!(server.state.begins.load(Ordering::SeqCst), begins);
        }
        let mut byte = [0];
        assert_eq!(bounded(socket.read(&mut byte)).await.unwrap(), 0);
    }
    assert_eq!(server.state.submissions.load(Ordering::SeqCst), 0);
    tokio::time::sleep(PAUSE).await;
    let mut replacement = TcpStream::connect(server.address).await.unwrap();
    healthy_http1(&mut replacement, b"replacement", 1).await;
}

struct H2Client {
    sender: SendRequest<UploadBody>,
    driver: JoinHandle<()>,
    address: SocketAddr,
}

impl Drop for H2Client {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

async fn h2_client(address: SocketAddr) -> H2Client {
    let socket = TcpStream::connect(address).await.unwrap();
    let (sender, connection) = bounded(hyper::client::conn::http2::handshake(
        TokioExecutor::new(),
        TokioIo::new(socket),
    ))
    .await
    .unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    H2Client {
        sender,
        driver,
        address,
    }
}

fn h2_request(address: SocketAddr, body: UploadBody) -> Request<UploadBody> {
    Request::post(format!("http://{address}{PUT_PATH}"))
        .version(Version::HTTP_2)
        .header(header::CONTENT_TYPE, CONTENT_TYPE)
        .header("connect-protocol-version", "1")
        .body(body)
        .unwrap()
}

fn paused_body() -> (mpsc::Sender<Bytes>, UploadBody) {
    let (sender, receiver) = mpsc::channel(1);
    let stream = stream::unfold(receiver, |mut receiver| async {
        receiver
            .recv()
            .await
            .map(|bytes| (Ok(Frame::data(bytes)), receiver))
    });
    (sender, StreamBody::new(stream.boxed()))
}

async fn h2_response(response: hyper::Response<hyper::body::Incoming>) -> Response<Bytes> {
    let (parts, body) = response.into_parts();
    Response::from_parts(parts, bounded(body.collect()).await.unwrap().to_bytes())
}

async fn healthy_h2(client: &mut H2Client, value: &'static [u8], sequence: u64) {
    let body = StreamBody::new(stream::iter([Ok(Frame::data(envelope(value)))]).boxed());
    let response = bounded(client.sender.send_request(h2_request(client.address, body)))
        .await
        .unwrap();
    let response = h2_response(response).await;
    successful(&response, sequence);
    assert!(!response.headers().contains_key(header::CONNECTION));
}

#[tokio::test]
async fn http2_stalled_put_deadline_preserves_neighbor_streams() {
    let mut server = server().await;
    let mut client = h2_client(server.address).await;
    let (upload, body) = paused_body();
    let response = client.sender.send_request(h2_request(client.address, body));
    let stalled = tokio::spawn(response);
    upload.send(envelope(b"stalled")).await.unwrap();
    appended(&mut server, b"stalled").await;
    healthy_h2(&mut client, b"neighbor", 1).await;

    let response = h2_response(bounded(stalled).await.unwrap().unwrap()).await;
    assert!(response
        .body()
        .windows(b"deadline_exceeded".len())
        .any(|window| window == b"deadline_exceeded"));
    aborted(&server).await;
    assert_eq!(server.state.submissions.load(Ordering::SeqCst), 1);
    healthy_h2(&mut client, b"after-deadline", 2).await;
    drop(upload);
}

#[tokio::test]
async fn http2_cancelled_put_preserves_a_healthy_neighbor() {
    let mut server = server().await;
    let mut client = h2_client(server.address).await;
    let (upload, body) = paused_body();
    let response = client.sender.send_request(h2_request(client.address, body));
    let cancelled = tokio::spawn(response);
    upload.send(envelope(b"cancelled")).await.unwrap();
    appended(&mut server, b"cancelled").await;
    cancelled.abort();
    assert!(cancelled.await.unwrap_err().is_cancelled());

    healthy_h2(&mut client, b"neighbor", 1).await;
    aborted(&server).await;
    assert_eq!(server.state.submissions.load(Ordering::SeqCst), 1);
    assert_eq!(server.state.sequence.load(Ordering::SeqCst), 1);
    healthy_h2(&mut client, b"after-cancel", 2).await;
    drop(upload);
}
