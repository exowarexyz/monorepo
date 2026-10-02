use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use connectrpc::http_body::{Body, Frame, SizeHint};
use connectrpc::{ConnectError, Protocol};
use exoware_sdk::limits::{MAX_PUT_CHUNK_BYTES, MAX_PUT_ENTRIES, MAX_REQUEST_MESSAGE_BYTES};
use http::{header, Request, Response, Version};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, Sleep};
use tower::Service;

use crate::transport::ConnectionControl;

const PUT_PATH: &str = "/log.ingest.v1.Service/Put";
const HEADER_BYTES: usize = 5;
const MAX_PUT_WIRE_BYTES: usize = MAX_REQUEST_MESSAGE_BYTES + HEADER_BYTES * MAX_PUT_ENTRIES;
const DEFAULT_MAX_PUT_REQUESTS: usize = 16;
const DEFAULT_PUT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadStatus {
    Pending,
    Clean,
    Failed,
}

/// Records physical EOF independently of decoded stream exhaustion.
#[derive(Clone, Debug)]
pub struct UploadCompletion(Arc<UploadState>);

#[derive(Debug)]
struct UploadState {
    outcome: Mutex<UploadOutcome>,
    admission: Option<Arc<OwnedSemaphorePermit>>,
    deadline: Instant,
    connection: Option<(ConnectionControl, u64)>,
}

#[derive(Debug)]
struct UploadOutcome {
    status: UploadStatus,
    error: Option<ConnectError>,
    handler_finished: bool,
}

impl UploadCompletion {
    fn new(
        deadline: Instant,
        admission: Option<OwnedSemaphorePermit>,
        connection: Option<(ConnectionControl, u64)>,
    ) -> Self {
        Self(Arc::new(UploadState {
            outcome: Mutex::new(UploadOutcome {
                status: UploadStatus::Pending,
                error: None,
                handler_finished: false,
            }),
            admission: admission.map(Arc::new),
            deadline,
            connection,
        }))
    }

    pub fn status(&self) -> UploadStatus {
        self.0.outcome.lock().unwrap().status
    }

    pub fn clean(&self) -> bool {
        self.status() == UploadStatus::Clean
    }

    pub fn failure(&self) -> Option<ConnectError> {
        self.0.outcome.lock().unwrap().error.clone()
    }

    pub fn check(&self) -> Result<(), ConnectError> {
        let outcome = self.0.outcome.lock().unwrap();
        match outcome.status {
            UploadStatus::Clean => Ok(()),
            UploadStatus::Pending => Err(ConnectError::invalid_argument(
                "Put request body did not reach clean EOF",
            )),
            UploadStatus::Failed => Err(outcome.error.clone().unwrap()),
        }
    }

    pub fn deadline(&self) -> Instant {
        self.0.deadline
    }

    #[cfg(test)]
    pub fn admission(&self) -> Option<Arc<OwnedSemaphorePermit>> {
        self.0.admission.clone()
    }

    pub fn handler_finished(&self) {
        let mut outcome = self.0.outcome.lock().unwrap();
        outcome.handler_finished = true;
        self.disarm_if_finished(&outcome);
    }

    fn disarm_if_finished(&self, outcome: &UploadOutcome) {
        if outcome.handler_finished && outcome.status == UploadStatus::Clean {
            if let Some((control, generation)) = &self.0.connection {
                control.disarm(*generation);
            }
        }
    }

    fn finish(&self, error: Option<ConnectError>) {
        let mut outcome = self.0.outcome.lock().unwrap();
        if outcome.status == UploadStatus::Pending {
            outcome.status = if error.is_some() {
                UploadStatus::Failed
            } else {
                UploadStatus::Clean
            };
            outcome.error = error;
            self.disarm_if_finished(&outcome);
        }
    }

    #[cfg(test)]
    pub(crate) fn test_clean() -> Self {
        let completion = Self::new(Instant::now() + DEFAULT_PUT_TIMEOUT, None, None);
        completion.finish(None);
        completion
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PutConfig {
    /// Slots remain held until reception and backend work release their resources.
    pub max_requests: usize,
    /// Fallback when the client omits a protocol timeout header.
    pub timeout: Duration,
}

impl Default for PutConfig {
    fn default() -> Self {
        Self {
            max_requests: DEFAULT_MAX_PUT_REQUESTS,
            timeout: DEFAULT_PUT_TIMEOUT,
        }
    }
}

/// Checks Put framing before the generated service decodes messages.
#[derive(Clone)]
pub struct PutService<S> {
    inner: S,
    admission: Arc<Semaphore>,
    timeout: Duration,
}

impl<S> PutService<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            admission: Arc::new(Semaphore::new(DEFAULT_MAX_PUT_REQUESTS)),
            timeout: DEFAULT_PUT_TIMEOUT,
        }
    }

    pub fn with_config(mut self, config: PutConfig) -> Self {
        self.admission = Arc::new(Semaphore::new(config.max_requests));
        self.timeout = config.timeout;
        self
    }
}

impl<S, B, R> Service<Request<B>> for PutService<S>
where
    S: Service<Request<PutBody<B>>, Response = Response<R>>,
    S::Future: Send + 'static,
    S::Error: 'static,
    R: 'static,
    B: Body<Data = Bytes>,
    B::Error: Error + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = futures::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let (mut parts, body) = req.into_parts();
        let version = parts.version;
        let completion = if parts.uri.path() == PUT_PATH {
            let deadline = Instant::now() + client_timeout(&parts.headers).unwrap_or(self.timeout);
            let admission = self.admission.clone().try_acquire_owned();
            let connection = parts
                .extensions
                .get::<ConnectionControl>()
                .and_then(|control| {
                    control
                        .arm_http1(parts.version, deadline)
                        .map(|generation| (control.clone(), generation))
                });
            let completion = UploadCompletion::new(deadline, admission.ok(), connection);
            if completion.0.admission.is_none() {
                completion.finish(Some(ConnectError::resource_exhausted(
                    "Put admission exhausted",
                )));
            }
            parts.extensions.insert(completion.clone());
            Some(completion)
        } else {
            None
        };
        let future = self.inner.call(Request::from_parts(
            parts,
            PutBody::new(body, completion.clone()),
        ));
        Box::pin(async move {
            let mut response = future.await?;
            if matches!(version, Version::HTTP_10 | Version::HTTP_11) {
                if let Some(completion) = completion {
                    if !completion.clean() || Instant::now() >= completion.deadline() {
                        response
                            .headers_mut()
                            .insert(header::CONNECTION, http::HeaderValue::from_static("close"));
                    }
                }
            }
            Ok(response)
        })
    }
}

fn client_timeout(headers: &http::HeaderMap) -> Option<Duration> {
    let protocol = Protocol::detect(headers)?.protocol;
    let value = headers.get(protocol.timeout_header())?.to_str().ok()?;
    match protocol {
        Protocol::Connect => {
            if value.is_empty() || value.len() > 10 {
                return None;
            }
            value.parse::<u64>().ok().map(Duration::from_millis)
        }
        Protocol::Grpc | Protocol::GrpcWeb => {
            if !value.is_ascii() || value.len() < 2 || value.len() > 9 {
                return None;
            }
            let (digits, unit) = value.split_at(value.len() - 1);
            let value = digits.parse::<u64>().ok()?;
            match unit {
                "H" => value.checked_mul(3600).map(Duration::from_secs),
                "M" => value.checked_mul(60).map(Duration::from_secs),
                "S" => Some(Duration::from_secs(value)),
                "m" => Some(Duration::from_millis(value)),
                "u" => Some(Duration::from_micros(value)),
                "n" => Some(Duration::from_nanos(value)),
                _ => None,
            }
        }
        _ => None,
    }
}

#[derive(Default)]
struct EnvelopeScan {
    header: [u8; HEADER_BYTES],
    header_len: usize,
    remaining: usize,
    wire_bytes: usize,
}

impl EnvelopeScan {
    fn at_boundary(&self) -> bool {
        self.header_len == 0 && self.remaining == 0
    }

    fn data(&mut self, mut data: &[u8]) -> Result<(), ConnectError> {
        self.wire_bytes = self
            .wire_bytes
            .checked_add(data.len())
            .filter(|total| *total <= MAX_PUT_WIRE_BYTES)
            .ok_or_else(|| {
                ConnectError::resource_exhausted("Put request exceeds the total wire limit")
            })?;

        while !data.is_empty() {
            if self.remaining != 0 {
                let consumed = self.remaining.min(data.len());
                self.remaining -= consumed;
                data = &data[consumed..];
                continue;
            }

            let consumed = (HEADER_BYTES - self.header_len).min(data.len());
            self.header[self.header_len..self.header_len + consumed]
                .copy_from_slice(&data[..consumed]);
            self.header_len += consumed;
            data = &data[consumed..];
            if self.header_len != HEADER_BYTES {
                continue;
            }

            // Request END_STREAM would let the generated reader discard trailing failures.
            if self.header[0] > 1 {
                return Err(ConnectError::invalid_argument(
                    "Put request envelope has unsupported flags",
                ));
            }

            self.remaining = u32::from_be_bytes(self.header[1..].try_into().unwrap()) as usize;
            if self.remaining > MAX_PUT_CHUNK_BYTES {
                return Err(ConnectError::resource_exhausted(
                    "Put request envelope exceeds the wire chunk limit",
                ));
            }
            self.header_len = 0;
        }
        Ok(())
    }
}

pub struct PutBody<B> {
    inner: Pin<Box<B>>,
    completion: Option<UploadCompletion>,
    scan: EnvelopeScan,
    stopped: bool,
    timer: Option<Pin<Box<Sleep>>>,
}

impl<B> PutBody<B> {
    fn new(inner: B, completion: Option<UploadCompletion>) -> Self {
        let timer = completion
            .as_ref()
            .map(|completion| Box::pin(tokio::time::sleep_until(completion.deadline())));
        Self {
            inner: Box::pin(inner),
            completion,
            scan: EnvelopeScan::default(),
            stopped: false,
            timer,
        }
    }

    fn fail(&mut self, error: ConnectError) {
        self.stopped = true;
        if let Some(completion) = &self.completion {
            completion.finish(Some(error));
        }
    }
}

impl<B> Drop for PutBody<B> {
    fn drop(&mut self) {
        if let Some(completion) = &self.completion {
            completion.finish(Some(ConnectError::canceled(
                "Put request body was not exhausted",
            )));
        }
    }
}

impl<B> Body for PutBody<B>
where
    B: Body<Data = Bytes>,
    B::Error: Error + Send + Sync + 'static,
{
    type Data = Bytes;
    type Error = ConnectError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.stopped {
            return Poll::Ready(None);
        }

        if let Some(error) = this.completion.as_ref().and_then(UploadCompletion::failure) {
            this.stopped = true;
            return Poll::Ready(Some(Err(error)));
        }

        if let Some(timer) = &mut this.timer {
            if timer.as_mut().poll(cx).is_ready() {
                let error = ConnectError::deadline_exceeded("Put request timeout");
                this.fail(error.clone());
                return Poll::Ready(Some(Err(error)));
            }
        }

        match this.inner.as_mut().poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(frame))) => {
                if this.completion.is_some() {
                    if let Some(data) = frame.data_ref() {
                        if let Err(error) = this.scan.data(data) {
                            this.fail(error.clone());
                            return Poll::Ready(Some(Err(error)));
                        }
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                let error = ConnectError::internal(error.to_string());
                this.fail(error.clone());
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.stopped = true;
                if let Some(completion) = &this.completion {
                    if !this.scan.at_boundary() {
                        let error =
                            ConnectError::invalid_argument("Put request ended inside an envelope");
                        completion.finish(Some(error.clone()));
                        return Poll::Ready(Some(Err(error)));
                    }
                    completion.finish(None);
                }
                Poll::Ready(None)
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        if self.completion.is_some() {
            self.stopped
        } else {
            self.inner.is_end_stream()
        }
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use connectrpc::ErrorCode;
    use futures::future::{ready, Ready};

    use super::*;

    #[derive(Default)]
    struct ScriptedBody {
        frames: VecDeque<Result<Frame<Bytes>, std::io::Error>>,
        pending_at_end: bool,
        polls: Arc<AtomicUsize>,
    }

    impl Body for ScriptedBody {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            let this = self.get_mut();
            this.polls.fetch_add(1, Ordering::Relaxed);
            if let Some(frame) = this.frames.pop_front() {
                Poll::Ready(Some(frame))
            } else if this.pending_at_end {
                Poll::Pending
            } else {
                Poll::Ready(None)
            }
        }

        fn is_end_stream(&self) -> bool {
            true
        }
    }

    #[derive(Clone)]
    struct EchoService;

    impl Service<Request<PutBody<ScriptedBody>>> for EchoService {
        type Response = Response<Request<PutBody<ScriptedBody>>>;
        type Error = Infallible;
        type Future = Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: Request<PutBody<ScriptedBody>>) -> Self::Future {
            ready(Ok(Response::new(request)))
        }
    }

    fn envelope(flags: u8, payload: &[u8]) -> Bytes {
        let mut bytes = Vec::with_capacity(HEADER_BYTES + payload.len());
        bytes.push(flags);
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes.into()
    }

    fn scripted(data: impl IntoIterator<Item = Bytes>) -> ScriptedBody {
        ScriptedBody {
            frames: data.into_iter().map(|data| Ok(Frame::data(data))).collect(),
            ..Default::default()
        }
    }

    fn checked(body: ScriptedBody) -> (PutBody<ScriptedBody>, UploadCompletion) {
        let completion = UploadCompletion::new(Instant::now() + DEFAULT_PUT_TIMEOUT, None, None);
        (PutBody::new(body, Some(completion.clone())), completion)
    }

    fn poll(body: &mut PutBody<ScriptedBody>) -> Poll<Option<Result<Frame<Bytes>, ConnectError>>> {
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        Pin::new(body).poll_frame(&mut cx)
    }

    fn forwarded(body: &mut PutBody<ScriptedBody>) -> Frame<Bytes> {
        match poll(body) {
            Poll::Ready(Some(Ok(frame))) => frame,
            result => panic!("expected a forwarded frame, got {result:?}"),
        }
    }

    fn rejected(body: &mut PutBody<ScriptedBody>, completion: &UploadCompletion, code: ErrorCode) {
        match poll(body) {
            Poll::Ready(Some(Err(error))) => assert_eq!(error.code, code),
            result => panic!("expected a rejected frame, got {result:?}"),
        }
        assert_eq!(completion.status(), UploadStatus::Failed);
        assert_eq!(completion.failure().unwrap().code, code);
        assert_eq!(completion.check().unwrap_err().code, code);
        assert!(matches!(poll(body), Poll::Ready(None)));
    }

    #[tokio::test]
    async fn fragmented_header_preserves_frames_until_raw_eof() {
        let message = envelope(0, b"payload");
        for split in 1..HEADER_BYTES {
            let frames = [
                message.slice(..split),
                message.slice(split..split + 1),
                message.slice(split + 1..),
            ];
            let (mut body, completion) = checked(scripted(frames.clone()));
            assert!(!body.is_end_stream());
            for expected in frames {
                assert_eq!(forwarded(&mut body).into_data().unwrap(), expected);
                assert_eq!(completion.status(), UploadStatus::Pending);
                assert!(completion.check().is_err());
            }
            assert!(matches!(poll(&mut body), Poll::Ready(None)));
            assert!(completion.clean());
            assert!(completion.check().is_ok());
            assert!(body.is_end_stream());
            drop(body);
            assert!(completion.clean());
        }
    }

    #[tokio::test]
    async fn multiple_envelopes_and_fragmented_payload_are_clean() {
        let messages = [
            envelope(0, b"first"),
            envelope(1, b"compressed"),
            envelope(0, b""),
        ]
        .concat();
        let (mut body, completion) =
            checked(scripted(messages.chunks(2).map(Bytes::copy_from_slice)));
        while let Poll::Ready(Some(Ok(_))) = poll(&mut body) {
            assert!(!completion.clean());
        }
        assert!(completion.clean());
    }

    #[tokio::test]
    async fn empty_body_requires_a_raw_eof_poll() {
        let (mut body, completion) = checked(ScriptedBody::default());
        assert_eq!(completion.status(), UploadStatus::Pending);
        assert!(!body.is_end_stream());
        assert!(matches!(poll(&mut body), Poll::Ready(None)));
        assert!(completion.clean());
    }

    #[tokio::test]
    async fn eof_inside_header_or_payload_fails() {
        let message = envelope(0, b"payload");
        for len in 1..message.len() {
            let (mut body, completion) = checked(scripted([message.slice(..len)]));
            forwarded(&mut body);
            rejected(&mut body, &completion, ErrorCode::InvalidArgument);
            drop(body);
            assert_eq!(completion.status(), UploadStatus::Failed);
        }
    }

    #[tokio::test]
    async fn end_stream_and_reserved_flags_are_rejected_before_forwarding() {
        for flags in [2, 3, 4, 0x80, 0xff] {
            let invalid = envelope(flags, b"{}");
            for split in 0..HEADER_BYTES {
                let (mut body, completion) =
                    checked(scripted([invalid.slice(..split), invalid.slice(split..)]));
                forwarded(&mut body);
                rejected(&mut body, &completion, ErrorCode::InvalidArgument);
            }
        }
    }

    #[tokio::test]
    async fn end_stream_with_same_or_later_junk_fails() {
        let valid = envelope(0, b"valid");
        let invalid = envelope(2, b"{}");
        let junk = Bytes::from_static(b"junk");
        let (mut same, completion) = checked(scripted([Bytes::from(
            [valid.as_ref(), invalid.as_ref(), junk.as_ref()].concat(),
        )]));
        rejected(&mut same, &completion, ErrorCode::InvalidArgument);

        let (mut later, completion) = checked(scripted([valid.clone(), invalid, junk]));
        assert_eq!(forwarded(&mut later).into_data().unwrap(), valid);
        rejected(&mut later, &completion, ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn body_error_after_a_complete_envelope_fails() {
        let mut raw = scripted([envelope(0, b"valid")]);
        raw.frames
            .push_back(Err(std::io::Error::other("late body error")));
        let (mut body, completion) = checked(raw);
        forwarded(&mut body);
        rejected(&mut body, &completion, ErrorCode::Internal);
        assert_eq!(
            completion.failure().unwrap().message.as_deref(),
            Some("late body error")
        );
    }

    #[tokio::test]
    async fn drop_before_eof_fails_even_at_an_envelope_boundary() {
        let (mut body, completion) = checked(scripted([envelope(0, b"valid")]));
        forwarded(&mut body);
        drop(body);
        assert_eq!(completion.status(), UploadStatus::Failed);
        assert_eq!(completion.failure().unwrap().code, ErrorCode::Canceled);

        let (body, completion) = checked(ScriptedBody::default());
        drop(body);
        assert_eq!(completion.status(), UploadStatus::Failed);
    }

    #[tokio::test]
    async fn trailers_do_not_prove_eof_or_repair_a_partial_header() {
        for partial in [false, true] {
            let mut raw = if partial {
                scripted([Bytes::from_static(&[0])])
            } else {
                ScriptedBody::default()
            };
            raw.frames
                .push_back(Ok(Frame::trailers(http::HeaderMap::new())));
            let (mut body, completion) = checked(raw);
            if partial {
                forwarded(&mut body);
            }
            assert!(forwarded(&mut body).is_trailers());
            assert_eq!(completion.status(), UploadStatus::Pending);
            assert!(!body.is_end_stream());
            if partial {
                rejected(&mut body, &completion, ErrorCode::InvalidArgument);
            } else {
                assert!(matches!(poll(&mut body), Poll::Ready(None)));
                assert!(completion.clean());
            }
        }
    }

    #[tokio::test]
    async fn oversized_declared_chunk_fails_before_payload_arrives() {
        let mut header = vec![0];
        header.extend_from_slice(&((MAX_PUT_CHUNK_BYTES + 1) as u32).to_be_bytes());
        let (mut body, completion) = checked(scripted([header.into()]));
        rejected(&mut body, &completion, ErrorCode::ResourceExhausted);
    }

    #[tokio::test]
    async fn total_wire_limit_rejects_a_frame_before_forwarding() {
        let (mut body, completion) = checked(scripted([envelope(0, b"")]));
        body.scan.wire_bytes = MAX_PUT_WIRE_BYTES - HEADER_BYTES + 1;
        rejected(&mut body, &completion, ErrorCode::ResourceExhausted);
    }

    #[tokio::test]
    async fn pending_raw_body_is_woken_by_the_original_deadline() {
        let raw = ScriptedBody {
            pending_at_end: true,
            ..Default::default()
        };
        let completion =
            UploadCompletion::new(Instant::now() + Duration::from_millis(10), None, None);
        let mut body = PutBody::new(raw, Some(completion.clone()));
        assert!(matches!(poll(&mut body), Poll::Pending));
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)),
        )
        .await
        .unwrap();
        assert_eq!(
            result.unwrap().unwrap_err().code,
            ErrorCode::DeadlineExceeded
        );
        assert_eq!(
            completion.failure().unwrap().code,
            ErrorCode::DeadlineExceeded
        );
    }

    fn request(path: &str, body: ScriptedBody) -> Request<ScriptedBody> {
        Request::builder()
            .uri(path)
            .header(header::CONTENT_TYPE, "application/connect+proto")
            .body(body)
            .unwrap()
    }

    #[tokio::test]
    async fn non_put_requests_bypass_framing_and_admission() {
        let mut service = PutService::new(EchoService).with_config(PutConfig {
            max_requests: 0,
            timeout: Duration::ZERO,
        });
        let invalid = Bytes::from_static(b"not an envelope");
        let mut req = service
            .call(request(
                "/log.query.v1.Service/Get",
                scripted([invalid.clone()]),
            ))
            .await
            .unwrap()
            .into_body();
        assert!(req.extensions().get::<UploadCompletion>().is_none());
        assert_eq!(forwarded(req.body_mut()).into_data().unwrap(), invalid);
    }

    #[tokio::test]
    async fn admission_is_shared_and_survives_clean_eof_until_accepted_guard_drops() {
        let mut service = PutService::new(EchoService).with_config(PutConfig {
            max_requests: 1,
            ..Default::default()
        });
        let mut clone = service.clone();
        let mut first = service
            .call(request(PUT_PATH, ScriptedBody::default()))
            .await
            .unwrap()
            .into_body();
        let witness = first
            .extensions()
            .get::<UploadCompletion>()
            .unwrap()
            .clone();
        let accepted = witness.admission().unwrap();
        assert!(matches!(poll(first.body_mut()), Poll::Ready(None)));
        assert!(witness.clean());
        drop(witness);
        drop(first);

        let raw = ScriptedBody::default();
        let raw_polls = raw.polls.clone();
        let mut rejected_request = clone
            .call(request(PUT_PATH, raw))
            .await
            .unwrap()
            .into_body();
        let witness = rejected_request
            .extensions()
            .get::<UploadCompletion>()
            .unwrap()
            .clone();
        rejected(
            rejected_request.body_mut(),
            &witness,
            ErrorCode::ResourceExhausted,
        );
        assert_eq!(raw_polls.load(Ordering::Relaxed), 0);
        drop(accepted);

        let admitted = service
            .call(request(PUT_PATH, ScriptedBody::default()))
            .await
            .unwrap()
            .into_body();
        assert_eq!(
            admitted
                .extensions()
                .get::<UploadCompletion>()
                .unwrap()
                .status(),
            UploadStatus::Pending
        );
    }

    #[tokio::test]
    async fn client_timeout_overrides_fallback_without_a_server_cap() {
        let mut service = PutService::new(EchoService).with_config(PutConfig {
            timeout: Duration::from_millis(10),
            ..Default::default()
        });
        let before = Instant::now();
        let mut req = request(PUT_PATH, ScriptedBody::default());
        req.headers_mut()
            .insert("connect-timeout-ms", "60000".parse().unwrap());
        let req = service.call(req).await.unwrap().into_body();
        let deadline = req
            .extensions()
            .get::<UploadCompletion>()
            .unwrap()
            .deadline();
        assert!(deadline >= before + Duration::from_secs(60));

        let before = Instant::now();
        let mut req = request(PUT_PATH, ScriptedBody::default());
        req.headers_mut()
            .insert("connect-timeout-ms", "invalid".parse().unwrap());
        let req = service.call(req).await.unwrap().into_body();
        let deadline = req
            .extensions()
            .get::<UploadCompletion>()
            .unwrap()
            .deadline();
        assert!(deadline >= before + Duration::from_millis(10));
        assert!(deadline <= Instant::now() + Duration::from_millis(10));
    }

    #[tokio::test]
    async fn grpc_timeout_uses_its_protocol_header() {
        let mut service = PutService::new(EchoService);
        let mut req = request(PUT_PATH, ScriptedBody::default());
        req.headers_mut()
            .insert(header::CONTENT_TYPE, "application/grpc".parse().unwrap());
        req.headers_mut()
            .insert("grpc-timeout", "90S".parse().unwrap());
        req.headers_mut()
            .insert("connect-timeout-ms", "1".parse().unwrap());
        let before = Instant::now();
        let req = service.call(req).await.unwrap().into_body();
        assert!(
            req.extensions()
                .get::<UploadCompletion>()
                .unwrap()
                .deadline()
                >= before + Duration::from_secs(90)
        );
    }

    #[tokio::test]
    async fn pending_put_body_response_requests_connection_close() {
        let mut service = PutService::new(EchoService);
        let response = service
            .call(request(PUT_PATH, ScriptedBody::default()))
            .await
            .unwrap();
        assert_eq!(response.headers()[header::CONNECTION], "close");
        assert_eq!(
            response
                .body()
                .extensions()
                .get::<UploadCompletion>()
                .unwrap()
                .status(),
            UploadStatus::Pending
        );
    }

    #[tokio::test]
    async fn prehandler_failure_closes_http1_but_preserves_other_response_headers() {
        let inner = tower::service_fn(|request: Request<PutBody<ScriptedBody>>| async move {
            drop(request);
            Ok::<_, Infallible>(
                Response::builder()
                    .status(http::StatusCode::UNSUPPORTED_MEDIA_TYPE)
                    .header(header::CONNECTION, "keep-alive")
                    .header("custom-header", "retained")
                    .body(())
                    .unwrap(),
            )
        });
        let mut service = PutService::new(inner);
        for (path, version, expected) in [
            (PUT_PATH, Version::HTTP_11, "close"),
            (PUT_PATH, Version::HTTP_10, "close"),
            (PUT_PATH, Version::HTTP_2, "keep-alive"),
            ("/unknown/route", Version::HTTP_11, "keep-alive"),
        ] {
            let mut request = request(path, ScriptedBody::default());
            *request.version_mut() = version;
            let response = service.call(request).await.unwrap();
            assert_eq!(response.headers()[header::CONNECTION], expected);
            assert_eq!(response.headers()["custom-header"], "retained");
            assert_eq!(response.status(), http::StatusCode::UNSUPPORTED_MEDIA_TYPE);
        }
    }

    #[tokio::test]
    async fn clean_put_response_preserves_keep_alive_until_its_original_deadline() {
        for expired in [false, true] {
            let inner = tower::service_fn(
                move |mut request: Request<PutBody<ScriptedBody>>| async move {
                    assert!(matches!(poll(request.body_mut()), Poll::Ready(None)));
                    let completion = request
                        .extensions()
                        .get::<UploadCompletion>()
                        .unwrap()
                        .clone();
                    completion.handler_finished();
                    if expired {
                        tokio::time::sleep_until(completion.deadline()).await;
                    }
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header(header::CONNECTION, "keep-alive")
                            .body(())
                            .unwrap(),
                    )
                },
            );
            let mut service = PutService::new(inner).with_config(PutConfig {
                timeout: Duration::from_millis(10),
                ..Default::default()
            });
            let response = service
                .call(request(PUT_PATH, ScriptedBody::default()))
                .await
                .unwrap();
            let expected = if expired { "close" } else { "keep-alive" };
            assert_eq!(response.headers()[header::CONNECTION], expected);
        }
    }
}
