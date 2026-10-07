use std::{fmt::Display, pin::Pin, sync::Arc, task::Poll, time::Duration};

use bytes::Bytes;
use connectrpc::ConnectError;
use futures::FutureExt;
use http_body::Body;
use http_body_util::BodyExt;
use tokio::time::{timeout_at, Instant};

use super::decode::{DecodeOutput, DecodeState, DecodeStep, WireBatch};
use super::{
    Admission, ByteLease, DecodeBuffers, IngestEvent, IngestObserver, PutChunk, PutError,
    RequestLease,
};
use crate::validate::IngestLimits;

pub(super) const FRAME_WORK_BUDGET: usize = 64;
const DRAIN_BYTE_BUDGET: usize = 64 * 1024;

pub type PutBody = Pin<Box<dyn Body<Data = Bytes, Error = ConnectError> + Send>>;

struct TransportCopy {
    data: Vec<u8>,
    _bytes: ByteLease,
    _request: Arc<RequestLease>,
}

struct IdleTimeout {
    timeout: Duration,
    remaining: Duration,
    expired: bool,
}

struct IdleWait<'a> {
    idle: &'a mut IdleTimeout,
    started: Instant,
}

impl IdleWait<'_> {
    fn deadline(&self) -> Instant {
        self.started + self.idle.remaining
    }

    fn progress(&mut self) {
        self.idle.remaining = self.idle.timeout;
        self.started = Instant::now();
    }
}

impl Drop for IdleWait<'_> {
    fn drop(&mut self) {
        // Cancelled lookahead reads retain elapsed waiting time without charging CPU work.
        self.idle.remaining = self.idle.remaining.saturating_sub(self.started.elapsed());
        self.idle.expired |= self.idle.remaining.is_zero();
    }
}

impl AsRef<[u8]> for TransportCopy {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

pub fn box_body<B>(body: B) -> PutBody
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Display,
{
    Box::pin(
        body.map_err(|error| {
            ConnectError::invalid_argument(format!("request body error: {error}"))
        }),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PutEncoding {
    Identity,
    Zstd,
}

#[derive(Clone, Copy, Debug)]
pub struct PutMetadata {
    pub encoding: PutEncoding,
    pub content_length: Option<usize>,
}

impl Default for PutMetadata {
    fn default() -> Self {
        Self {
            encoding: PutEncoding::Identity,
            content_length: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PutLimits {
    pub wire_bytes: usize,
    pub message_bytes: usize,
    pub ingest: IngestLimits,
}

impl Default for PutLimits {
    fn default() -> Self {
        Self {
            wire_bytes: exoware_sdk::limits::MAX_REQUEST_MESSAGE_BYTES,
            message_bytes: exoware_sdk::limits::MAX_REQUEST_MESSAGE_BYTES,
            ingest: IngestLimits::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainOutcome {
    Complete,
    WireLimit,
    Deadline,
    BodyError,
}

pub trait DecodeExecutor: Send + Sync + 'static {
    fn execute(
        &self,
        state: DecodeState,
        buffers: DecodeBuffers,
    ) -> futures::future::BoxFuture<'static, Result<DecodeOutput, PutError>>;
}

pub struct BlockingDecodeExecutor;

impl DecodeExecutor for BlockingDecodeExecutor {
    fn execute(
        &self,
        state: DecodeState,
        buffers: DecodeBuffers,
    ) -> futures::future::BoxFuture<'static, Result<DecodeOutput, PutError>> {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || state.run(buffers))
                .await
                .map_err(|error| {
                    ConnectError::internal(format!("ingest CPU worker failed: {error}")).into()
                })
        })
    }
}

// The body remains with the adapter while CPU work owns only the detached state.
pub struct PutInput {
    body: PutBody,
    state: Option<DecodeState>,
    parts: Option<http::request::Parts>,
    admission: Admission,
    metadata: PutMetadata,
    limits: PutLimits,
    deadline: Instant,
    idle: Option<IdleTimeout>,
    observer: Arc<dyn IngestObserver>,
    notifier: Option<Arc<dyn crate::stream::StreamNotifier>>,
    executor: Arc<dyn DecodeExecutor>,
    wire_bytes: usize,
    eof: bool,
    stopped: bool,
    validated: bool,
    rejection_observed: bool,
    body_error: Option<ConnectError>,
    copy_error: Option<ConnectError>,
    decode_eof: bool,
}

impl PutInput {
    pub fn new(
        body: PutBody,
        metadata: PutMetadata,
        mut limits: PutLimits,
        deadline: Instant,
        admission: Admission,
    ) -> Self {
        limits.wire_bytes = limits.wire_bytes.min(admission.wire_bound());
        let state = DecodeState::new(
            metadata.encoding,
            limits,
            admission.transport.clone(),
            admission.request.clone(),
        );
        Self {
            body,
            state: Some(state),
            parts: None,
            admission,
            metadata,
            limits,
            deadline,
            idle: None,
            observer: Arc::new(()),
            notifier: None,
            executor: Arc::new(BlockingDecodeExecutor),
            wire_bytes: 0,
            eof: false,
            stopped: false,
            validated: false,
            rejection_observed: false,
            body_error: None,
            copy_error: None,
            decode_eof: false,
        }
    }

    pub fn with_parts(mut self, parts: http::request::Parts) -> Self {
        self.parts = Some(parts);
        self
    }

    pub fn with_idle_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.idle = timeout.map(|timeout| IdleTimeout {
            timeout,
            remaining: timeout,
            expired: false,
        });
        self
    }

    pub(super) fn idle_timed_out(&self) -> bool {
        self.idle.as_ref().is_some_and(|idle| idle.expired)
    }
    pub fn parts(&self) -> Option<&http::request::Parts> {
        self.parts.as_ref()
    }
    pub fn with_observer(mut self, observer: Arc<dyn IngestObserver>) -> Self {
        self.observer = observer;
        self
    }
    pub fn set_executor(&mut self, executor: Arc<dyn DecodeExecutor>) {
        self.executor = executor;
    }

    pub fn with_notifier(
        mut self,
        notifier: Option<Arc<dyn crate::stream::StreamNotifier>>,
    ) -> Self {
        self.notifier = notifier;
        self
    }
    pub fn notifier(&self) -> Option<Arc<dyn crate::stream::StreamNotifier>> {
        self.notifier.clone()
    }
    pub fn metadata(&self) -> &PutMetadata {
        &self.metadata
    }
    pub fn limits(&self) -> PutLimits {
        self.limits
    }

    /// Inspect the sizing bound before reserving preparation memory.
    /// This does not validate the payload or authorize publication.
    pub async fn message_bound(&mut self) -> Result<usize, PutError> {
        self.check_deadline()?;
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| ConnectError::internal("ingest decode state detached"))?;
        let cached = state.message_bound()?;
        if self.metadata.encoding == PutEncoding::Identity {
            return Ok(self
                .metadata
                .content_length
                .unwrap_or(self.limits.wire_bytes)
                .min(self.limits.wire_bytes)
                .min(self.limits.message_bytes));
        }
        if let Some(bound) = cached {
            return Ok(bound);
        }
        loop {
            match self.process(DecodeBuffers::header()).await? {
                DecodeStep::Bound(bound) => return Ok(bound),
                DecodeStep::Wire => {
                    self.read_wire(false).await?;
                }
                _ => {
                    return Err(ConnectError::internal("ingest inspection returned payload").into())
                }
            }
        }
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn wire_bytes(&self) -> usize {
        self.wire_bytes
    }
    pub fn is_finished(&self) -> bool {
        self.validated
    }
    pub(super) fn is_end_stream(&self) -> bool {
        self.eof || self.body.is_end_stream()
    }

    pub fn request_lease(&self) -> Arc<RequestLease> {
        self.admission.request_lease()
    }
    pub fn reserve_bytes(&self, bytes: usize) -> Result<ByteLease, ConnectError> {
        self.admission.reserve_bytes(bytes)
    }

    fn reserve_input_bytes(&mut self, bytes: usize) -> Result<ByteLease, PutError> {
        self.reserve_bytes(bytes).map_err(|error| {
            self.copy_error = Some(error.clone());
            error.into()
        })
    }

    pub fn reject(&mut self, error: PutError) {
        if let Some(state) = &mut self.state {
            state.reject(error);
        }
        self.validated = false;
        self.observe_rejection();
    }

    fn observe_rejection(&mut self) {
        if !self.rejection_observed {
            self.rejection_observed = true;
            self.observer.observe(IngestEvent::Rejected);
        }
    }

    pub fn check_deadline(&self) -> Result<(), PutError> {
        if self.idle_timed_out() {
            return Err(
                ConnectError::deadline_exceeded("ingest body idle timeout exceeded").into(),
            );
        }
        if Instant::now() >= self.deadline {
            return Err(ConnectError::deadline_exceeded("ingest deadline exceeded").into());
        }
        Ok(())
    }

    async fn raw_next(&mut self, copy: bool) -> Result<Option<Bytes>, PutError> {
        if copy {
            if let Some(error) = &self.copy_error {
                return Err(error.clone().into());
            }
        }
        if let Some(error) = &self.body_error {
            return Err(error.clone().into());
        }
        if self.eof {
            return Ok(None);
        }
        if self.stopped {
            return Err(ConnectError::resource_exhausted("request body exceeds wire limit").into());
        }
        self.check_deadline()?;
        let mut idle_wait = self.idle.as_mut().map(|idle| IdleWait {
            idle,
            started: Instant::now(),
        });
        let idle_deadline = idle_wait.as_ref().map(IdleWait::deadline);
        let deadline = idle_deadline.map_or(self.deadline, |idle| idle.min(self.deadline));
        let timeout_message = if idle_deadline.is_some_and(|idle| idle <= self.deadline) {
            "ingest body idle timeout exceeded"
        } else {
            "ingest deadline exceeded"
        };
        let mut frames = 0;
        loop {
            if frames == FRAME_WORK_BUDGET {
                tokio::task::yield_now().await;
                frames = 0;
            }
            frames += 1;
            let body = &mut self.body;
            let frame = timeout_at(
                deadline,
                futures::future::poll_fn(|cx| {
                    if Instant::now() >= deadline {
                        return Poll::Ready(Err(ConnectError::deadline_exceeded(timeout_message)));
                    }
                    body.as_mut().poll_frame(cx).map(Ok)
                }),
            )
            .await
            .map_err(|_| ConnectError::deadline_exceeded(timeout_message))??;
            match frame {
                Some(Ok(frame)) => {
                    let Ok(bytes) = frame.into_data() else {
                        continue;
                    };
                    if bytes.len() > self.limits.wire_bytes.saturating_sub(self.wire_bytes) {
                        self.stopped = true;
                        return Err(ConnectError::resource_exhausted(
                            "request body exceeds wire limit",
                        )
                        .into());
                    }
                    self.wire_bytes += bytes.len();
                    self.observer.observe(IngestEvent::WireBytes(bytes.len()));
                    if bytes.is_empty() {
                        continue;
                    }
                    if let Some(idle) = &mut idle_wait {
                        idle.progress();
                    }
                    drop(idle_wait);

                    // Copying prevents a transport slice from pinning an unbounded owner in a CPU job.
                    return Ok(Some(if copy {
                        let lease = self.reserve_input_bytes(bytes.len())?;
                        Bytes::from_owner(TransportCopy {
                            data: bytes.to_vec(),
                            _bytes: lease,
                            _request: self.request_lease(),
                        })
                    } else {
                        Bytes::new()
                    }));
                }
                Some(Err(error)) => {
                    self.stopped = true;
                    self.body_error = Some(error.clone());
                    return Err(error.into());
                }
                None => {
                    self.eof = true;
                    self.observer.observe(IngestEvent::HttpEof);
                    if self
                        .metadata
                        .content_length
                        .is_some_and(|length| length != self.wire_bytes)
                    {
                        let error = ConnectError::invalid_argument(
                            "request body differs from content length",
                        );
                        self.body_error = Some(error.clone());
                        return Err(error.into());
                    }
                    return Ok(None);
                }
            }
        }
    }

    async fn process(&mut self, buffers: DecodeBuffers) -> Result<DecodeStep, PutError> {
        self.check_deadline()?;
        let state = self
            .state
            .take()
            .ok_or_else(|| ConnectError::internal("ingest decode state detached"))?;
        let started = Instant::now();
        let previous = state.total();
        let job = self.executor.execute(state, buffers);
        let output = timeout_at(self.deadline, job)
            .await
            .map_err(|_| ConnectError::deadline_exceeded("ingest deadline exceeded"))??;
        let DecodeOutput { result, state } = output;
        if !state.belongs_to(&self.admission.request) {
            return Err(
                ConnectError::internal("ingest decode state belongs to another request").into(),
            );
        }
        let decoded = state.total().saturating_sub(previous);
        self.state = Some(state);
        self.decode_eof = matches!(result, Ok(DecodeStep::Eof));
        let result = self.check_deadline().and(result);
        self.observer.observe(IngestEvent::DecodedBytes(decoded));
        self.observer
            .observe(IngestEvent::DecodeElapsed(started.elapsed()));
        if let Ok(DecodeStep::Batch(batch)) = &result {
            self.observer.observe(IngestEvent::Batch {
                entries: batch.ranges.len(),
                bytes: batch.data.len(),
            });
        }
        result
    }

    async fn read_wire(&mut self, batch: bool) -> Result<(), PutError> {
        let started = Instant::now();
        let bytes = self.raw_next(true).await?;
        let received = bytes.is_some();
        let mut wire_bytes = bytes.as_ref().map_or(0, Bytes::len);
        let frame_capacity = self
            .limits
            .wire_bytes
            .saturating_sub(self.wire_bytes)
            .min(FRAME_WORK_BUDGET - 1);
        self.state
            .as_mut()
            .unwrap()
            .feed(bytes.unwrap_or_default(), !received);
        self.decode_eof = false;
        let mut queued = false;

        // A scheduler turn lets the connection supply buffered fragments before CPU handoff.
        if received && batch {
            for _ in 0..frame_capacity {
                if wire_bytes >= DRAIN_BYTE_BUDGET {
                    break;
                }
                let next = match self.raw_next(true).now_or_never() {
                    Some(next) => next,
                    None => {
                        tokio::task::yield_now().await;
                        let Some(next) = self.raw_next(true).now_or_never() else {
                            break;
                        };
                        next
                    }
                };
                let Some(next) = next? else {
                    self.state.as_mut().unwrap().finish_wire();
                    break;
                };
                let batch = if queued {
                    None
                } else {
                    let lease =
                        self.reserve_input_bytes(frame_capacity * std::mem::size_of::<Bytes>())?;
                    queued = true;
                    Some(WireBatch {
                        frames: std::collections::VecDeque::with_capacity(frame_capacity),
                        _bytes: lease,
                    })
                };
                wire_bytes += next.len();
                self.state.as_mut().unwrap().queue_wire(next, batch);
            }
        }
        self.observer
            .observe(IngestEvent::ReceiveElapsed(started.elapsed()));
        Ok(())
    }

    pub async fn next_batch(
        &mut self,
        buffers: DecodeBuffers,
    ) -> Result<Option<PutChunk>, PutError> {
        self.check_deadline()?;
        if self.decode_eof {
            return Ok(None);
        }
        loop {
            if self.state.as_ref().is_some_and(DecodeState::needs_wire) {
                self.read_wire(true).await?;
            }
            match self.process(buffers).await? {
                DecodeStep::Batch(batch) => return Ok(Some(batch)),
                DecodeStep::Eof => return Ok(None),
                DecodeStep::Bound(_) => {
                    return Err(
                        ConnectError::internal("ingest decoding returned a sizing bound").into(),
                    )
                }
                DecodeStep::Wire => {
                    self.read_wire(true).await?;
                }
            }
        }
    }

    pub async fn finish(&mut self) -> Result<(), PutError> {
        let started = Instant::now();
        self.check_deadline()?;
        if self.validated {
            return Ok(());
        }
        while !self.decode_eof {
            let Some(chunk) = self.next_batch(DecodeBuffers::default()).await? else {
                break;
            };
            if !chunk.ranges.is_empty() {
                self.reject(
                    ConnectError::internal("Put entries remain unconsumed at finalization").into(),
                );
            }
        }
        if !self.eof {
            return Err(ConnectError::internal("ingest finalization before HTTP EOF").into());
        }
        self.state
            .as_mut()
            .ok_or_else(|| ConnectError::internal("ingest decode state detached"))?
            .finish()?;
        self.validated = true;
        self.observer.observe(IngestEvent::Validated);
        self.observer
            .observe(IngestEvent::ValidationElapsed(started.elapsed()));
        Ok(())
    }

    pub async fn drain_rejected(&mut self) -> DrainOutcome {
        let started = Instant::now();
        let outcome = self.drain_raw().await;
        self.observer
            .observe(IngestEvent::CleanupElapsed(started.elapsed()));
        outcome
    }

    async fn drain_raw(&mut self) -> DrainOutcome {
        // Cancelled worker output has no restoration path after cleanup discards the state.
        self.state = None;
        self.validated = false;
        self.observe_rejection();
        let mut frames = 0;
        let mut bytes = self.wire_bytes;
        loop {
            if frames == FRAME_WORK_BUDGET
                || self.wire_bytes.saturating_sub(bytes) >= DRAIN_BYTE_BUDGET
            {
                tokio::task::yield_now().await;
                frames = 0;
                bytes = self.wire_bytes;
            }
            frames += 1;
            match self.raw_next(false).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    self.observer.observe(IngestEvent::Drained {
                        bytes: self.wire_bytes,
                    });
                    return DrainOutcome::Complete;
                }
                Err(PutError::Connect(error))
                    if error.code == connectrpc::ErrorCode::DeadlineExceeded =>
                {
                    return DrainOutcome::Deadline
                }
                Err(PutError::Connect(error))
                    if error.code == connectrpc::ErrorCode::ResourceExhausted =>
                {
                    return DrainOutcome::WireLimit
                }
                Err(_) => return DrainOutcome::BodyError,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        num::NonZeroUsize,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Mutex,
        },
        time::Duration,
    };

    use commonware_parallel::{Rayon, Strategy};
    use futures::StreamExt;
    use http_body::Frame;
    use http_body_util::{Full, StreamBody};

    use super::super::{BudgetConfig, IngestBudget};
    use super::*;

    fn entry(key: &[u8], value: &[u8]) -> Vec<u8> {
        fn field(tag: u8, bytes: &[u8]) -> Vec<u8> {
            let mut output = vec![tag];
            buffa::encoding::encode_varint(bytes.len() as u64, &mut output);
            output.extend_from_slice(bytes);
            output
        }
        field(10, &[field(10, key), field(18, value)].concat())
    }

    fn input(
        wire: &[u8],
        split: usize,
        encoding: PutEncoding,
        limits: PutLimits,
    ) -> (PutInput, Arc<IngestBudget>) {
        let frames = wire
            .chunks(split.max(1))
            .map(|bytes| Ok::<_, Infallible>(Frame::data(Bytes::copy_from_slice(bytes))))
            .collect::<Vec<_>>();
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: 64 * 1024 * 1024,
        });
        let admission = budget.try_admit(wire.len()).unwrap();
        let body = box_body(StreamBody::new(futures::stream::iter(frames)));
        (
            PutInput::new(
                body,
                PutMetadata {
                    encoding,
                    content_length: Some(wire.len()),
                },
                limits,
                Instant::now() + Duration::from_secs(5),
                admission,
            ),
            budget,
        )
    }

    fn channel_input(
        wire_len: usize,
        max_bytes: usize,
    ) -> (
        PutInput,
        Arc<IngestBudget>,
        tokio::sync::mpsc::Sender<Bytes>,
    ) {
        let (sender, receiver) = tokio::sync::mpsc::channel::<Bytes>(2);
        let body = StreamBody::new(futures::stream::unfold(receiver, |mut receiver| async {
            receiver
                .recv()
                .await
                .map(|bytes| (Ok::<_, Infallible>(Frame::data(bytes)), receiver))
        }));
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes,
        });
        let input = PutInput::new(
            box_body(body),
            PutMetadata {
                content_length: Some(wire_len),
                ..PutMetadata::default()
            },
            PutLimits::default(),
            Instant::now() + Duration::from_secs(5),
            budget.try_admit(wire_len).unwrap(),
        );
        (input, budget, sender)
    }

    struct CountingExecutor(Arc<AtomicUsize>);
    impl DecodeExecutor for CountingExecutor {
        fn execute(
            &self,
            state: DecodeState,
            buffers: DecodeBuffers,
        ) -> futures::future::BoxFuture<'static, Result<DecodeOutput, PutError>> {
            self.0.fetch_add(1, Ordering::Relaxed);
            BlockingDecodeExecutor.execute(state, buffers)
        }
    }

    struct InlineExecutor;
    impl DecodeExecutor for InlineExecutor {
        fn execute(
            &self,
            state: DecodeState,
            buffers: DecodeBuffers,
        ) -> futures::future::BoxFuture<'static, Result<DecodeOutput, PutError>> {
            Box::pin(async move { Ok(state.run(buffers)) })
        }
    }

    async fn collect(input: &mut PutInput) -> Result<Vec<(Vec<u8>, Vec<u8>)>, PutError> {
        let mut output = Vec::new();
        while let Some(chunk) = input.next_batch(DecodeBuffers::new(8, 2)).await? {
            output.extend(
                chunk
                    .entries()
                    .map(|(key, value)| (key.to_vec(), value.to_vec())),
            );
        }
        input.finish().await?;
        Ok(output)
    }

    #[tokio::test(start_paused = true)]
    async fn idle_timeout_bounds_first_bytes_and_eof_without_restarting_cleanup() {
        for receive_data in [false, true] {
            let (input, budget, sender) = channel_input(1, 1024);
            let mut input = input.with_idle_timeout(Some(Duration::from_secs(1)));
            if receive_data {
                sender.send(Bytes::from_static(b"a")).await.unwrap();
                assert_eq!(input.raw_next(true).await.unwrap().unwrap(), b"a"[..]);
            }
            let started = Instant::now();
            let error = input.raw_next(true).await.unwrap_err().into_connect();
            assert_eq!(error.code, connectrpc::ErrorCode::DeadlineExceeded);
            assert!(input.idle_timed_out());
            assert_eq!(started.elapsed(), Duration::from_secs(1));
            assert_eq!(input.drain_rejected().await, DrainOutcome::Deadline);
            assert_eq!(started.elapsed(), Duration::from_secs(1));
            assert!(input.finish().await.is_err());
            drop(input);
            assert_eq!(budget.usage(), (0, 0));
            drop(sender);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_timeout_does_not_extend_the_absolute_deadline() {
        let (input, _, _sender) = channel_input(1, 1024);
        let mut input = input.with_idle_timeout(Some(Duration::from_secs(1)));
        let started = Instant::now();
        input.deadline = started + Duration::from_millis(100);
        assert!(input.raw_next(true).await.is_err());
        assert_eq!(started.elapsed(), Duration::from_millis(100));
        assert!(!input.idle_timed_out());
        assert_eq!(input.drain_rejected().await, DrainOutcome::Deadline);
        assert_eq!(started.elapsed(), Duration::from_millis(100));
    }

    #[tokio::test(start_paused = true)]
    async fn idle_wait_survives_cancellation_and_pauses_between_reads() {
        let (input, _, sender) = channel_input(2, 1024);
        let mut input = input.with_idle_timeout(Some(Duration::from_secs(1)));
        input.deadline = Instant::now() + Duration::from_secs(60);
        let mut reading = Box::pin(input.raw_next(true));
        assert!(futures::poll!(&mut reading).is_pending());
        tokio::time::advance(Duration::from_millis(400)).await;
        drop(reading);

        // Time spent preparing a previous batch must not consume the peer's remaining wait.
        tokio::time::advance(Duration::from_secs(10)).await;
        let mut reading = Box::pin(input.raw_next(true));
        assert!(futures::poll!(&mut reading).is_pending());
        tokio::time::advance(Duration::from_millis(500)).await;
        sender.send(Bytes::from_static(b"a")).await.unwrap();
        assert_eq!(reading.await.unwrap().unwrap(), b"a"[..]);

        let mut reading = Box::pin(input.raw_next(true));
        assert!(futures::poll!(&mut reading).is_pending());
        tokio::time::advance(Duration::from_millis(900)).await;
        sender.send(Bytes::from_static(b"b")).await.unwrap();
        assert_eq!(reading.await.unwrap().unwrap(), b"b"[..]);

        let mut reading = Box::pin(input.raw_next(true));
        assert!(futures::poll!(&mut reading).is_pending());
        tokio::time::advance(Duration::from_millis(600)).await;
        drop(reading);
        let started = Instant::now();
        assert!(input.raw_next(true).await.is_err());
        assert_eq!(started.elapsed(), Duration::from_millis(400));
        assert!(input.idle_timed_out());
    }

    #[tokio::test(start_paused = true)]
    async fn idle_timeout_ignores_empty_frames_and_trailers() {
        for trailers in [false, true] {
            let frames = futures::stream::unfold((), move |()| async move {
                tokio::time::sleep(Duration::from_millis(600)).await;
                let frame = if trailers {
                    Frame::trailers(http::HeaderMap::new())
                } else {
                    Frame::data(Bytes::new())
                };
                Some((Ok::<_, Infallible>(frame), ()))
            });
            let (mut input, _) = input(&[], 1, PutEncoding::Identity, PutLimits::default());
            input.body = box_body(StreamBody::new(frames));
            let mut input = input.with_idle_timeout(Some(Duration::from_secs(1)));
            let started = Instant::now();
            assert_eq!(input.drain_rejected().await, DrainOutcome::Deadline);
            assert_eq!(started.elapsed(), Duration::from_secs(1));
            assert!(input.idle_timed_out());
            assert_eq!(input.wire_bytes(), 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn idle_timeout_excludes_decode_execution() {
        struct SlowExecutor;

        impl DecodeExecutor for SlowExecutor {
            fn execute(
                &self,
                state: DecodeState,
                buffers: DecodeBuffers,
            ) -> futures::future::BoxFuture<'static, Result<DecodeOutput, PutError>> {
                Box::pin(async move {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    Ok(state.run(buffers))
                })
            }
        }

        let wire = entry(b"key", b"value");
        let (mut input, _) = input(&wire, 1, PutEncoding::Identity, PutLimits::default());
        input.deadline = Instant::now() + Duration::from_secs(60);
        input.set_executor(Arc::new(SlowExecutor));
        let mut input = input.with_idle_timeout(Some(Duration::from_secs(1)));
        let started = Instant::now();
        assert_eq!(
            collect(&mut input).await.unwrap(),
            vec![(b"key".to_vec(), b"value".to_vec())]
        );
        assert!(started.elapsed() > Duration::from_secs(1));
        assert!(!input.idle_timed_out());
    }

    #[tokio::test]
    async fn identity_message_bound_uses_enforced_limits_without_polling() {
        for (length, wire_bound, message_limit, expected) in [
            (Some(30), 100, 60, 30),
            (Some(80), 100, 60, 60),
            (None, 50, 60, 50),
            (Some(80), 50, 60, 50),
        ] {
            let body = StreamBody::new(futures::stream::poll_fn(
                |_| -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
                    panic!("identity sizing must not poll the body")
                },
            ));
            let budget = IngestBudget::new(BudgetConfig {
                max_requests: 1,
                max_bytes: wire_bound,
            });
            let mut input = PutInput::new(
                box_body(body),
                PutMetadata {
                    content_length: length,
                    ..PutMetadata::default()
                },
                PutLimits {
                    message_bytes: message_limit,
                    ..PutLimits::default()
                },
                Instant::now() + Duration::from_secs(1),
                budget.try_admit(wire_bound).unwrap(),
            );
            assert_eq!(input.message_bound().await.unwrap(), expected);
            assert_eq!(input.message_bound().await.unwrap(), expected);
            assert_eq!(input.wire_bytes(), 0);
            assert_eq!(budget.usage(), (1, wire_bound));
            drop(input);
            assert_eq!(budget.usage(), (0, 0));
        }
    }

    #[tokio::test]
    async fn zstd_message_bound_preserves_fragments_suffix_and_cached_result() {
        let payload = [entry(b"a", &[7; 1024]), entry(b"b", b"value")].concat();
        let wire = zstd::bulk::compress(&payload, 1).unwrap();
        let header = (1..=wire.len())
            .find(|&size| {
                zstd::zstd_safe::get_frame_content_size(&wire[..size])
                    .ok()
                    .flatten()
                    .is_some()
            })
            .unwrap();
        for split in (1..=header + 1).chain([wire.len()]) {
            let (mut input, budget) = input(&wire, split, PutEncoding::Zstd, PutLimits::default());
            let jobs = Arc::new(AtomicUsize::new(0));
            input.set_executor(Arc::new(CountingExecutor(jobs.clone())));
            assert_eq!(input.message_bound().await.unwrap(), payload.len());
            assert_eq!(
                input.wire_bytes(),
                header.div_ceil(split).saturating_mul(split).min(wire.len())
            );
            assert_eq!(input.state.as_ref().unwrap().total(), 0);
            assert!(!input.is_finished());
            let snapshot = (
                input.wire_bytes(),
                jobs.load(Ordering::Relaxed),
                budget.usage(),
            );
            assert_eq!(input.message_bound().await.unwrap(), payload.len());
            assert_eq!(
                snapshot,
                (
                    input.wire_bytes(),
                    jobs.load(Ordering::Relaxed),
                    budget.usage()
                )
            );
            let chunk = input
                .next_batch(DecodeBuffers::new(64, 1))
                .await
                .unwrap()
                .unwrap();
            let mut rows = chunk
                .entries()
                .map(|(key, value)| (key.to_vec(), value.to_vec()))
                .collect::<Vec<_>>();
            drop(chunk);
            let snapshot = (
                input.wire_bytes(),
                jobs.load(Ordering::Relaxed),
                budget.usage(),
                input.state.as_ref().unwrap().total(),
            );
            assert_eq!(input.message_bound().await.unwrap(), payload.len());
            assert_eq!(
                snapshot,
                (
                    input.wire_bytes(),
                    jobs.load(Ordering::Relaxed),
                    budget.usage(),
                    input.state.as_ref().unwrap().total()
                )
            );
            rows.extend(collect(&mut input).await.unwrap());
            assert_eq!(
                rows,
                vec![
                    (b"a".to_vec(), vec![7; 1024]),
                    (b"b".to_vec(), b"value".to_vec())
                ]
            );
            drop(input);
            assert_eq!(budget.usage(), (0, 0));
        }
    }

    #[tokio::test]
    async fn zstd_message_bound_stops_at_header_under_transport_only_admission() {
        for value_len in [1024, 15_400_000, 12 * 1024 * 1024] {
            let payload = entry(b"key", &vec![7; value_len]);
            let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
            encoder
                .set_pledged_src_size(Some(payload.len() as u64))
                .unwrap();
            std::io::Write::write_all(&mut encoder, &payload).unwrap();
            let wire = encoder.finish().unwrap();
            let header = (1..=wire.len())
                .find(|&size| {
                    zstd::zstd_safe::get_frame_content_size(&wire[..size])
                        .ok()
                        .flatten()
                        .is_some()
                })
                .unwrap();
            for first in [wire[..header].to_vec(), wire.clone()] {
                let polls = Arc::new(AtomicUsize::new(0));
                let count = polls.clone();
                let mut first = Some(first);
                let body = StreamBody::new(futures::stream::poll_fn(move |_| {
                    count.fetch_add(1, Ordering::Relaxed);
                    Poll::Ready(Some(Ok::<_, Infallible>(Frame::data(Bytes::from(
                        first
                            .take()
                            .expect("inspection must not poll after the header"),
                    )))))
                }));
                let budget = IngestBudget::new(BudgetConfig {
                    max_requests: 1,
                    max_bytes: 2 * wire.len(),
                });
                let mut input = PutInput::new(
                    box_body(body),
                    PutMetadata {
                        encoding: PutEncoding::Zstd,
                        content_length: Some(wire.len()),
                    },
                    PutLimits::default(),
                    Instant::now() + Duration::from_secs(1),
                    budget.try_admit(wire.len()).unwrap(),
                );
                assert_eq!(input.message_bound().await.unwrap(), payload.len());
                assert_eq!(input.message_bound().await.unwrap(), payload.len());
                assert_eq!(polls.load(Ordering::Relaxed), 1);
                assert_eq!(input.state.as_ref().unwrap().total(), 0);
                assert!(!input.eof);
                assert_eq!(budget.usage().1, wire.len() + input.wire_bytes());
                drop(input);
                assert_eq!(budget.usage(), (0, 0));
            }
        }
    }

    #[tokio::test]
    async fn invalid_message_bound_is_sticky_and_uses_shared_header_policy() {
        let payload = entry(b"a", b"b");
        let valid = zstd::bulk::compress(&payload, 1).unwrap();
        let mut reserved_bit = valid.clone();
        reserved_bit[4] |= 8;
        let mut unpledged = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
        std::io::Write::write_all(&mut unpledged, &payload).unwrap();
        for (wire, limit, code, message) in [
            (
                b"invalid".to_vec(),
                1024,
                connectrpc::ErrorCode::InvalidArgument,
                "expected a standard frame",
            ),
            (
                reserved_bit,
                1024,
                connectrpc::ErrorCode::InvalidArgument,
                "reserved frame header bit",
            ),
            (
                unpledged.finish().unwrap(),
                1024,
                connectrpc::ErrorCode::InvalidArgument,
                "frame content size is required",
            ),
            (
                valid[..3].to_vec(),
                1024,
                connectrpc::ErrorCode::InvalidArgument,
                "incomplete frame",
            ),
            (
                vec![0x28, 0xb5, 0x2f, 0xfd, 0x21, 1, 1],
                1024,
                connectrpc::ErrorCode::InvalidArgument,
                "dictionaries are not supported",
            ),
            (
                super::super::zstd::OVERSIZED_WINDOW_FRAME.to_vec(),
                1,
                connectrpc::ErrorCode::InvalidArgument,
                "Frame requires too much memory",
            ),
            (
                valid,
                1,
                connectrpc::ErrorCode::ResourceExhausted,
                "decoded request exceeds message limit",
            ),
        ] {
            let (mut input, budget) = input(
                &wire,
                1,
                PutEncoding::Zstd,
                PutLimits {
                    message_bytes: limit,
                    ..PutLimits::default()
                },
            );
            for _ in 0..2 {
                let error = input.message_bound().await.unwrap_err().into_connect();
                assert_eq!(error.code, code);
                assert!(
                    error
                        .message
                        .as_deref()
                        .is_some_and(|text| text.contains(message)),
                    "{:?}",
                    error.message
                );
            }
            assert!(!input.is_finished());
            assert_eq!(input.drain_rejected().await, DrainOutcome::Complete);
            assert!(input.message_bound().await.is_err());
            drop(input);
            assert_eq!(budget.usage(), (0, 0));
        }
    }

    #[tokio::test]
    async fn inspected_bound_does_not_validate_compression_or_protobuf_tail() {
        let payload = entry(b"a", b"b");
        let valid = zstd::bulk::compress(&payload, 1).unwrap();
        let mut truncated = valid.clone();
        truncated.pop();
        let mut concatenated = valid.clone();
        concatenated.extend_from_slice(&valid);
        for wire in [
            truncated,
            concatenated,
            zstd::bulk::compress(&[0], 1).unwrap(),
        ] {
            let expected = zstd::zstd_safe::get_frame_content_size(&wire)
                .unwrap()
                .unwrap() as usize;
            let (mut input, budget) =
                input(&wire, wire.len(), PutEncoding::Zstd, PutLimits::default());
            assert_eq!(input.message_bound().await.unwrap(), expected);
            assert!(!input.is_finished());
            assert!(collect(&mut input).await.is_err());
            assert!(input.finish().await.is_err());
            drop(input);
            assert_eq!(budget.usage(), (0, 0));
        }
    }

    #[tokio::test]
    async fn cancelled_header_reception_resumes_with_the_original_deadline() {
        let payload = entry(b"key", b"value");
        let wire = zstd::bulk::compress(&payload, 1).unwrap();
        let (original, budget, sender) = channel_input(wire.len(), 64 * 1024 * 1024);
        let PutInput {
            body,
            admission,
            deadline,
            state,
            ..
        } = original;
        drop(state);
        let mut input = PutInput::new(
            body,
            PutMetadata {
                encoding: PutEncoding::Zstd,
                content_length: Some(wire.len()),
            },
            PutLimits::default(),
            deadline,
            admission,
        );
        input.set_executor(Arc::new(InlineExecutor));
        sender
            .send(Bytes::copy_from_slice(&wire[..2]))
            .await
            .unwrap();
        assert!(input.message_bound().now_or_never().is_none());
        assert_eq!(input.wire_bytes(), 2);
        assert_eq!(input.deadline(), deadline);
        sender
            .send(Bytes::copy_from_slice(&wire[2..]))
            .await
            .unwrap();
        drop(sender);
        assert_eq!(input.message_bound().await.unwrap(), payload.len());
        assert_eq!(
            collect(&mut input).await.unwrap(),
            vec![(b"key".to_vec(), b"value".to_vec())]
        );
        drop(input);
        assert_eq!(budget.usage(), (0, 0));

        let (mut input, budget, _sender) = channel_input(64, 128);
        input.deadline = Instant::now();
        assert_eq!(
            input.message_bound().await.unwrap_err().into_connect().code,
            connectrpc::ErrorCode::DeadlineExceeded
        );
        assert_eq!(input.wire_bytes(), 0);
        assert_eq!(input.drain_rejected().await, DrainOutcome::Deadline);
        drop(input);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[tokio::test]
    async fn cancelled_or_expired_header_cpu_job_retains_charges_through_cleanup() {
        let wire = zstd::bulk::compress(&entry(b"key", b"value"), 1).unwrap();
        for expire in [false, true] {
            let (mut input, budget) =
                input(&wire, wire.len(), PutEncoding::Zstd, PutLimits::default());
            if expire {
                input.deadline = Instant::now() + Duration::from_secs(1);
            }
            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let dropped = Arc::new(tokio::sync::Notify::new());
            input.set_executor(Arc::new(PoolExecutor {
                pool: Rayon::new(NonZeroUsize::new(2).unwrap()).unwrap(),
                calls: AtomicUsize::new(0),
                started: Mutex::new(Some(started_tx)),
                release: Mutex::new(Some(release_rx)),
                dropped: dropped.clone(),
            }));
            let mut inspection = Box::pin(input.message_bound());
            tokio::select! {
                result = &mut inspection => panic!("gated job returned {result:?}"),
                result = tokio::task::spawn_blocking(move || started_rx.recv_timeout(Duration::from_secs(5)).unwrap()) => { result.unwrap(); }
            }
            if expire {
                assert_eq!(
                    inspection.as_mut().await.unwrap_err().into_connect().code,
                    connectrpc::ErrorCode::DeadlineExceeded
                );
            }
            drop(inspection);
            assert!(input.state.is_none());
            assert!(input.message_bound().await.is_err());
            assert_eq!(
                input.drain_rejected().await,
                if expire {
                    DrainOutcome::Deadline
                } else {
                    DrainOutcome::Complete
                }
            );
            drop(input);
            assert_eq!(budget.usage(), (1, 2 * wire.len()));
            release_tx.send(()).unwrap();
            timeout_at(Instant::now() + Duration::from_secs(5), dropped.notified())
                .await
                .unwrap();
            assert_eq!(budget.usage(), (0, 0));
        }
    }

    #[tokio::test]
    async fn executor_cpu_handoffs_emit_common_observations_once() {
        struct Events(Arc<Mutex<Vec<IngestEvent>>>);

        impl IngestObserver for Events {
            fn observe(&self, event: IngestEvent) {
                self.0.lock().unwrap().push(event);
            }
        }

        let payload = [entry(b"a", &[7; 47]), entry(b"b", b"value")].concat();
        for encoding in [PutEncoding::Identity, PutEncoding::Zstd] {
            let wire = match encoding {
                PutEncoding::Identity => payload.clone(),
                PutEncoding::Zstd => zstd::bulk::compress(&payload, 1).unwrap(),
            };
            let (mut input, budget) = input(&wire, 1, encoding, PutLimits::default());
            let events = Arc::new(Mutex::new(Vec::new()));
            input = input.with_observer(Arc::new(Events(events.clone())));
            let jobs = Arc::new(AtomicUsize::new(0));
            input.set_executor(Arc::new(CountingExecutor(jobs.clone())));
            let mut batches = 0;
            let mut entries = 0;
            while let Some(chunk) = input.next_batch(DecodeBuffers::new(8, 2)).await.unwrap() {
                batches += 1;
                entries += chunk.entries().len();
            }
            input.finish().await.unwrap();
            assert_eq!(entries, 2);
            let recorded = events.lock().unwrap();
            let decoded = recorded
                .iter()
                .filter_map(|event| match event {
                    IngestEvent::DecodedBytes(bytes) => Some(bytes),
                    _ => None,
                })
                .sum::<usize>();
            assert_eq!(decoded, payload.len());
            let decode_events = recorded
                .iter()
                .filter(|event| matches!(event, IngestEvent::DecodeElapsed(_)))
                .count();
            assert!(decode_events > 0);
            assert_eq!(
                decode_events,
                recorded
                    .iter()
                    .filter(|event| matches!(event, IngestEvent::DecodedBytes(_)))
                    .count()
            );
            assert_eq!(
                recorded
                    .iter()
                    .filter_map(|event| match event {
                        IngestEvent::Batch { entries, .. } => Some(entries),
                        _ => None,
                    })
                    .sum::<usize>(),
                2
            );
            assert_eq!(
                recorded
                    .iter()
                    .filter(|event| matches!(event, IngestEvent::Batch { .. }))
                    .count(),
                batches
            );
            assert_eq!(decode_events, jobs.load(Ordering::Relaxed));
            drop(recorded);
            drop(input);
            assert_eq!(budget.usage(), (0, 0));
        }
    }

    #[tokio::test]
    async fn rejection_is_observed_once_across_backend_and_cleanup() {
        struct Rejections(Arc<AtomicUsize>);

        impl IngestObserver for Rejections {
            fn observe(&self, event: IngestEvent) {
                if event == IngestEvent::Rejected {
                    self.0.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        let wire = entry(b"key", b"value");
        for backend_rejection in [false, true] {
            let (mut input, budget) = input(
                &wire,
                wire.len(),
                PutEncoding::Identity,
                PutLimits::default(),
            );
            let rejections = Arc::new(AtomicUsize::new(0));
            input = input.with_observer(Arc::new(Rejections(rejections.clone())));
            if backend_rejection {
                for _ in 0..2 {
                    input.reject(ConnectError::resource_exhausted("backend full").into());
                    assert_eq!(rejections.load(Ordering::Relaxed), 1);
                }
            }
            assert_eq!(input.drain_rejected().await, DrainOutcome::Complete);
            assert_eq!(rejections.load(Ordering::Relaxed), 1);
            drop(input);
            assert_eq!(budget.usage(), (0, 0));
        }
    }

    #[tokio::test]
    async fn single_frame_identity_skips_empty_decode_jobs() {
        let wire = entry(b"key", b"value");
        let (mut input, budget) = input(
            &wire,
            wire.len(),
            PutEncoding::Identity,
            PutLimits::default(),
        );
        let jobs = Arc::new(AtomicUsize::new(0));
        input.set_executor(Arc::new(CountingExecutor(jobs.clone())));
        while input
            .next_batch(DecodeBuffers::default())
            .await
            .unwrap()
            .is_some()
        {}
        input.finish().await.unwrap();
        assert_eq!(jobs.load(Ordering::Relaxed), 2);
        drop(input);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[tokio::test]
    async fn ready_fragments_share_bounded_cpu_jobs() {
        let wire = entry(b"key", &[42; 1024]);
        let (mut input, budget) = input(&wire, 1, PutEncoding::Identity, PutLimits::default());
        let jobs = Arc::new(AtomicUsize::new(0));
        input.set_executor(Arc::new(CountingExecutor(jobs.clone())));
        assert_eq!(
            collect(&mut input).await.unwrap(),
            vec![(b"key".to_vec(), vec![42; 1024])]
        );
        assert!(jobs.load(Ordering::Relaxed) <= wire.len().div_ceil(FRAME_WORK_BUDGET) + 4);
        drop(input);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[tokio::test]
    async fn late_cpu_output_is_rejected_before_batch_observation() {
        struct Late {
            deadline: Instant,
            calls: AtomicUsize,
        }
        impl DecodeExecutor for Late {
            fn execute(
                &self,
                state: DecodeState,
                buffers: DecodeBuffers,
            ) -> futures::future::BoxFuture<'static, Result<DecodeOutput, PutError>> {
                let output = state.run(buffers);
                self.calls.fetch_add(1, Ordering::Relaxed);
                if matches!(output.result, Ok(DecodeStep::Batch(_))) {
                    std::thread::sleep(
                        self.deadline.saturating_duration_since(Instant::now())
                            + Duration::from_millis(1),
                    );
                }
                Box::pin(async move { Ok(output) })
            }
        }
        struct Events(Arc<Mutex<Vec<IngestEvent>>>);
        impl IngestObserver for Events {
            fn observe(&self, event: IngestEvent) {
                self.0.lock().unwrap().push(event);
            }
        }
        let wire = entry(b"key", b"value");
        let (mut input, budget) = input(
            &wire,
            wire.len(),
            PutEncoding::Identity,
            PutLimits::default(),
        );
        input.deadline = Instant::now() + Duration::from_millis(200);
        let executor = Arc::new(Late {
            deadline: input.deadline(),
            calls: AtomicUsize::new(0),
        });
        input.set_executor(executor.clone());
        let events = Arc::new(Mutex::new(Vec::new()));
        input = input.with_observer(Arc::new(Events(events.clone())));
        assert_eq!(
            input
                .next_batch(DecodeBuffers::new(64, 2))
                .await
                .err()
                .unwrap()
                .into_connect()
                .code,
            connectrpc::ErrorCode::DeadlineExceeded
        );
        assert_eq!(executor.calls.load(Ordering::Relaxed), 1);
        assert!(input.state.is_some());
        assert!(!input.is_finished());
        assert!(input.finish().await.is_err());
        let recorded = events.lock().unwrap();
        assert_eq!(
            recorded
                .iter()
                .filter(|event| matches!(event, IngestEvent::DecodeElapsed(_)))
                .count(),
            1
        );
        assert_eq!(
            recorded
                .iter()
                .filter_map(|event| match event {
                    IngestEvent::DecodedBytes(bytes) => Some(bytes),
                    _ => None,
                })
                .sum::<usize>(),
            wire.len()
        );
        assert!(!recorded
            .iter()
            .any(|event| matches!(event, IngestEvent::Batch { .. })));
        drop(input);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[tokio::test]
    async fn cancelled_cpu_output_cannot_finalize_a_raw_drained_prefix() {
        let first = entry(b"a", b"b");
        let (mut input, budget, sender) = channel_input(first.len() + 1, 1024 * 1024);
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let dropped = Arc::new(tokio::sync::Notify::new());
        input.set_executor(Arc::new(PoolExecutor {
            pool: Rayon::new(NonZeroUsize::new(2).unwrap()).unwrap(),
            calls: AtomicUsize::new(0),
            started: Mutex::new(Some(started_tx)),
            release: Mutex::new(Some(release_rx)),
            dropped: dropped.clone(),
        }));
        sender.send(Bytes::from(first)).await.unwrap();
        let mut next = Box::pin(input.next_batch(DecodeBuffers::new(8, 1)));
        tokio::select! {
            result = &mut next => panic!("gated job returned {}", result.is_ok()),
            result = tokio::task::spawn_blocking(move || started_rx.recv_timeout(Duration::from_secs(5)).unwrap()) => { result.unwrap(); }
        }
        drop(next);
        assert!(input.state.is_none());
        sender.send(Bytes::from_static(&[0x80])).await.unwrap();
        drop(sender);
        assert_eq!(input.drain_rejected().await, DrainOutcome::Complete);
        assert!(input.finish().await.is_err());
        assert!(!input.is_finished());
        release_tx.send(()).unwrap();
        timeout_at(Instant::now() + Duration::from_secs(5), dropped.notified())
            .await
            .unwrap();
        assert!(input.next_batch(DecodeBuffers::new(8, 1)).await.is_err());
        assert!(input.finish().await.is_err());
        drop(input);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[tokio::test]
    async fn cancelled_receive_lookahead_keeps_every_consumed_frame() {
        let first = entry(b"a", b"b");
        let second = entry(b"c", b"d");
        let (mut input, budget, sender) =
            channel_input(first.len() + second.len(), 64 * 1024 * 1024);
        input.set_executor(Arc::new(InlineExecutor));
        sender.send(Bytes::from(first)).await.unwrap();
        assert!(input
            .next_batch(DecodeBuffers::new(8, 2))
            .now_or_never()
            .is_none());
        sender.send(Bytes::from(second)).await.unwrap();
        drop(sender);
        assert_eq!(
            collect(&mut input).await.unwrap(),
            vec![
                (b"a".to_vec(), b"b".to_vec()),
                (b"c".to_vec(), b"d".to_vec())
            ]
        );
        drop(input);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[tokio::test]
    async fn failed_ready_batch_admission_cannot_finalize_a_received_prefix() {
        let first = entry(b"a", b"b");
        let second = entry(b"c", b"d");
        let wire_len = first.len() + second.len();
        let max_bytes = 1024 * 1024;
        let (mut input, budget, sender) = channel_input(wire_len, max_bytes);
        input.set_executor(Arc::new(InlineExecutor));
        sender.send(Bytes::from(first)).await.unwrap();
        let chunk = input
            .next_batch(DecodeBuffers::new(8, 2))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(chunk.entries().count(), 1);
        drop(chunk);
        assert!(input
            .next_batch(DecodeBuffers::new(8, 2))
            .now_or_never()
            .is_none());
        sender
            .send(Bytes::copy_from_slice(&second[..4]))
            .await
            .unwrap();
        sender
            .send(Bytes::copy_from_slice(&second[4..]))
            .await
            .unwrap();
        drop(sender);
        let pressure = input
            .reserve_bytes(max_bytes - budget.usage().1 - second.len())
            .unwrap();
        let error = input
            .next_batch(DecodeBuffers::new(8, 2))
            .await
            .err()
            .unwrap()
            .into_connect();
        assert_eq!(error.code, connectrpc::ErrorCode::ResourceExhausted);
        drop(pressure);
        assert!(input.finish().await.is_err());
        assert!(!input.is_finished());
        assert_eq!(input.drain_rejected().await, DrainOutcome::Complete);
        drop(input);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[tokio::test]
    async fn decoded_limit_has_consistent_errors_across_encoding_and_fragmentation() {
        let payload = entry(b"k", &[42; 20]);
        let limits = PutLimits {
            message_bytes: 16,
            ..PutLimits::default()
        };
        for encoding in [PutEncoding::Identity, PutEncoding::Zstd] {
            let wire = match encoding {
                PutEncoding::Identity => payload.clone(),
                PutEncoding::Zstd => zstd::bulk::compress(&payload, 1).unwrap(),
            };
            for split in [1, wire.len()] {
                let (mut input, budget) = input(&wire, split, encoding, limits);
                let error = collect(&mut input).await.unwrap_err().into_connect();
                assert_eq!(error.code, connectrpc::ErrorCode::ResourceExhausted);
                assert!(!input.is_finished());
                assert_eq!(input.drain_rejected().await, DrainOutcome::Complete);
                drop(input);
                assert_eq!(budget.usage(), (0, 0));
            }
        }
        let (mut input, _) = input(&payload[..16], 1, PutEncoding::Identity, limits);
        let error = collect(&mut input).await.unwrap_err().into_connect();
        assert_eq!(error.code, connectrpc::ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn every_fragment_boundary_preserves_ranges_and_spills() {
        let payload = [
            entry(b"first", &[7; 47]),
            vec![0x1b, 0x20, 0, 0x1c],
            entry(b"second", b"value"),
        ]
        .concat();
        for encoding in [PutEncoding::Identity, PutEncoding::Zstd] {
            let wire = match encoding {
                PutEncoding::Identity => payload.clone(),
                PutEncoding::Zstd => zstd::bulk::compress(&payload, 1).unwrap(),
            };
            for split in 1..=wire.len() {
                let (mut input, budget) = input(&wire, split, encoding, PutLimits::default());
                assert_eq!(
                    collect(&mut input)
                        .await
                        .unwrap_or_else(|error| panic!("{encoding:?} split {split}: {error}")),
                    vec![
                        (b"first".to_vec(), vec![7; 47]),
                        (b"second".to_vec(), b"value".to_vec())
                    ]
                );
                assert!(input.is_finished());
                drop(input);
                assert_eq!(budget.usage(), (0, 0));
            }
        }
    }

    #[tokio::test]
    async fn outer_structure_then_count_then_inner_then_business_precedence() {
        let limits = PutLimits {
            ingest: IngestLimits {
                max_entries: 1,
                max_value_len: 1,
            },
            ..PutLimits::default()
        };
        let cases = [
            (
                [entry(b"a", b"too long"), vec![0x80]].concat(),
                "unexpected end of buffer",
            ),
            (
                vec![10, 1, 10, 10, 1, 10],
                "put request exceeds size limits",
            ),
            (
                [entry(b"a", b"too long"), vec![10, 1, 10]].concat(),
                "put request exceeds size limits",
            ),
            (
                [entry(b"a", b"too long"), vec![10, 1, 10]].concat(),
                "failed to decode proto request",
            ),
        ];
        for (index, (wire, message)) in cases.into_iter().enumerate() {
            let limits = if index == 3 {
                PutLimits {
                    ingest: IngestLimits {
                        max_entries: 2,
                        max_value_len: 1,
                    },
                    ..limits
                }
            } else {
                limits
            };
            let (mut input, budget) = input(&wire, 1, PutEncoding::Identity, limits);
            input.reject(
                crate::engine::IngestError::ResourceExhausted {
                    message: "backend full".into(),
                }
                .into(),
            );
            let error = collect(&mut input).await.unwrap_err().into_connect();
            assert!(
                error.message.as_deref().unwrap().contains(message),
                "{error:?}"
            );
            assert_eq!(input.drain_rejected().await, DrainOutcome::Complete);
            drop(input);
            assert_eq!(budget.usage(), (0, 0));
        }
    }

    #[tokio::test]
    async fn finalization_requires_consumption_and_remains_rejected() {
        let wire = entry(b"a", b"b");
        let (mut input, _) = input(
            &wire,
            wire.len(),
            PutEncoding::Identity,
            PutLimits::default(),
        );
        assert!(input.finish().await.is_err());
        assert!(input.finish().await.is_err());
        assert!(!input.is_finished());
    }

    #[tokio::test]
    async fn zstd_requires_one_pledged_complete_frame_and_http_eof() {
        let payload = entry(b"a", b"b");
        let valid = zstd::bulk::compress(&payload, 1).unwrap();
        let mut truncated = valid.clone();
        truncated.pop();
        let mut concatenated = valid.clone();
        concatenated.extend_from_slice(&zstd::bulk::compress(&[], 1).unwrap());
        let mut unpledged = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
        std::io::Write::write_all(&mut unpledged, &payload).unwrap();
        for wire in [
            truncated,
            concatenated,
            unpledged.finish().unwrap(),
            b"invalid".to_vec(),
        ] {
            let (mut input, budget) = input(&wire, 1, PutEncoding::Zstd, PutLimits::default());
            assert!(collect(&mut input).await.is_err());
            input.drain_rejected().await;
            drop(input);
            assert_eq!(budget.usage(), (0, 0));
        }
    }

    #[tokio::test]
    async fn construction_and_rejection_drain_never_initialize_decoder() {
        let polls = Arc::new(AtomicUsize::new(0));
        let observed = polls.clone();
        let frames = futures::stream::iter([Bytes::from_static(b"not zstd")]).map(move |bytes| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok::<_, Infallible>(Frame::data(bytes))
        });
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: 8,
        });
        let admission = budget.try_admit(8).unwrap();
        let mut input = PutInput::new(
            box_body(StreamBody::new(frames)),
            PutMetadata {
                encoding: PutEncoding::Zstd,
                content_length: None,
            },
            PutLimits::default(),
            Instant::now() + Duration::from_secs(1),
            admission,
        );
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(budget.usage(), (1, 8));
        assert_eq!(input.drain_rejected().await, DrainOutcome::Complete);
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(budget.usage(), (1, 8));
        drop(input);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[tokio::test]
    async fn raw_drain_stops_at_wire_bound_and_original_deadline() {
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: 16,
        });
        let mut input = PutInput::new(
            box_body(Full::new(Bytes::from_static(b"too big"))),
            PutMetadata::default(),
            PutLimits::default(),
            Instant::now() + Duration::from_secs(1),
            budget.try_admit(4).unwrap(),
        );
        assert_eq!(input.drain_rejected().await, DrainOutcome::WireLimit);
        assert_eq!(input.wire_bytes(), 0);
        drop(input);
        let mut input = PutInput::new(
            box_body(Full::new(Bytes::new())),
            PutMetadata::default(),
            PutLimits::default(),
            Instant::now(),
            budget.try_admit(4).unwrap(),
        );
        assert_eq!(input.drain_rejected().await, DrainOutcome::Deadline);
        drop(input);
        assert_eq!(budget.usage(), (0, 0));
    }

    struct PoolExecutor {
        pool: Rayon,
        calls: AtomicUsize,
        started: Mutex<Option<std::sync::mpsc::Sender<()>>>,
        release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
        dropped: Arc<tokio::sync::Notify>,
    }

    impl DecodeExecutor for PoolExecutor {
        fn execute(
            &self,
            state: DecodeState,
            buffers: DecodeBuffers,
        ) -> futures::future::BoxFuture<'static, Result<DecodeOutput, PutError>> {
            let gated =
                self.calls.fetch_add(1, Ordering::SeqCst) == usize::from(buffers.inspect_header);
            let started = if gated {
                self.started.lock().unwrap().take()
            } else {
                None
            };
            let release = if gated {
                self.release.lock().unwrap().take()
            } else {
                None
            };
            let dropped = self.dropped.clone();
            let future = self.pool.manual().spawn(1, move |_| {
                let output = state.run(buffers);
                if let Some(started) = started {
                    started.send(()).unwrap();
                }
                if let Some(release) = release {
                    release.recv_timeout(Duration::from_secs(5)).unwrap();
                }
                struct Wake(Arc<tokio::sync::Notify>);
                impl Drop for Wake {
                    fn drop(&mut self) {
                        self.0.notify_one();
                    }
                }
                (output, gated.then(|| Wake(dropped)))
            });
            Box::pin(async move {
                let (output, _wake) = future.await;
                Ok(output)
            })
        }
    }

    #[tokio::test]
    async fn cancelled_commonware_cpu_work_retains_output_bytes_and_request() {
        let wire = entry(b"key", b"value");
        let (mut input, budget) = input(
            &wire,
            wire.len(),
            PutEncoding::Identity,
            PutLimits::default(),
        );
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let dropped = Arc::new(tokio::sync::Notify::new());
        input.set_executor(Arc::new(PoolExecutor {
            pool: Rayon::new(NonZeroUsize::new(2).unwrap()).unwrap(),
            calls: AtomicUsize::new(0),
            started: Mutex::new(Some(started_tx)),
            release: Mutex::new(Some(release_rx)),
            dropped: dropped.clone(),
        }));
        let job = tokio::spawn(async move {
            input
                .next_batch(DecodeBuffers::new(64, 2))
                .await
                .map(|_| ())
        });
        tokio::task::spawn_blocking(move || {
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap()
        })
        .await
        .unwrap();
        job.abort();
        assert!(job.await.unwrap_err().is_cancelled());
        assert_eq!(budget.usage().0, 1);
        assert!(budget.usage().1 > wire.len());
        release_tx.send(()).unwrap();
        timeout_at(Instant::now() + Duration::from_secs(5), dropped.notified())
            .await
            .unwrap();
        assert_eq!(budget.usage(), (0, 0));
    }

    #[tokio::test]
    async fn executor_cpu_handoff_restores_sticky_decode_errors() {
        let wire = entry(b"key", b"value");
        let (mut input, budget, sender) = channel_input(wire.len() + 1, 64 * 1024 * 1024);
        input.set_executor(Arc::new(InlineExecutor));
        sender.send(Bytes::from(wire)).await.unwrap();
        let chunk = input
            .next_batch(DecodeBuffers::new(64, 2))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(chunk.entries().count(), 1);
        drop(chunk);
        sender.send(Bytes::from_static(&[0])).await.unwrap();
        drop(sender);
        for _ in 0..2 {
            assert_eq!(
                input
                    .next_batch(DecodeBuffers::new(64, 2))
                    .await
                    .err()
                    .unwrap()
                    .into_connect()
                    .code,
                connectrpc::ErrorCode::InvalidArgument
            );
            assert!(input.state.is_some());
        }
        assert!(input.finish().await.is_err());
        assert_eq!(input.drain_rejected().await, DrainOutcome::Complete);
        drop(input);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[tokio::test]
    async fn content_length_failure_cannot_be_retried_into_success() {
        let wire = entry(b"a", b"b");
        let (mut input, _) = input(
            &wire,
            wire.len(),
            PutEncoding::Identity,
            PutLimits::default(),
        );
        input.metadata.content_length = Some(wire.len() + 1);
        assert!(collect(&mut input).await.is_err());
        assert!(input.finish().await.is_err());
        assert!(!input.is_finished());
    }

    #[tokio::test]
    async fn deferred_capacity_rejection_needs_no_entry_allocation() {
        let wire = [entry(b"a", b"b"), vec![0]].concat();
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: wire.len() * 2 + 8,
        });
        let admission = budget.try_admit(wire.len()).unwrap();
        let mut input = PutInput::new(
            box_body(Full::new(Bytes::from(wire))),
            PutMetadata::default(),
            PutLimits::default(),
            Instant::now() + Duration::from_secs(1),
            admission,
        );
        input.reject(
            crate::engine::IngestError::ResourceExhausted {
                message: "backend full".into(),
            }
            .into(),
        );
        let error = input
            .next_batch(DecodeBuffers::new(8, 4096))
            .await
            .err()
            .unwrap()
            .into_connect();
        assert_eq!(error.code, connectrpc::ErrorCode::InvalidArgument);
        assert_eq!(input.drain_rejected().await, DrainOutcome::Complete);
        drop(input);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[tokio::test]
    async fn cloned_chunk_backing_retains_admission_without_chunk_container() {
        let wire = entry(b"key", b"value");
        let (mut input, budget) = input(
            &wire,
            wire.len(),
            PutEncoding::Identity,
            PutLimits::default(),
        );
        let chunk = input
            .next_batch(DecodeBuffers::new(64, 2))
            .await
            .unwrap()
            .unwrap();
        let kept = chunk.data.slice(chunk.ranges()[0].value.clone());
        drop(chunk);
        assert!(input
            .next_batch(DecodeBuffers::default())
            .await
            .unwrap()
            .is_none());
        input.finish().await.unwrap();
        drop(input);
        assert_eq!(kept.as_ref(), b"value");
        assert_eq!(budget.usage().0, 1);
        assert!(budget.usage().1 >= 64);
        drop(kept);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[tokio::test]
    async fn range_allocation_rejection_still_checks_malformed_outer_wire() {
        let wire = [entry(b"a", b"b"), vec![0]].concat();
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: wire.len() * 2 + 8,
        });
        let mut input = PutInput::new(
            box_body(Full::new(Bytes::from(wire.clone()))),
            PutMetadata::default(),
            PutLimits::default(),
            Instant::now() + Duration::from_secs(1),
            budget.try_admit(wire.len()).unwrap(),
        );
        let error = input
            .next_batch(DecodeBuffers::new(8, 4096))
            .await
            .err()
            .unwrap()
            .into_connect();
        assert_eq!(error.code, connectrpc::ErrorCode::InvalidArgument);
        assert_eq!(input.drain_rejected().await, DrainOutcome::Complete);
        drop(input);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[tokio::test]
    async fn batch_retention_rejection_still_checks_malformed_outer_wire() {
        let wire = [entry(b"a", b"b"), vec![0]].concat();
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: wire.len() * 2 + 8 + 2 * std::mem::size_of::<super::super::EntryRanges>(),
        });
        let mut input = PutInput::new(
            box_body(Full::new(Bytes::from(wire.clone()))),
            PutMetadata::default(),
            PutLimits::default(),
            Instant::now() + Duration::from_secs(1),
            budget.try_admit(wire.len()).unwrap(),
        );
        let error = input
            .next_batch(DecodeBuffers::new(8, 2))
            .await
            .err()
            .unwrap()
            .into_connect();
        assert_eq!(error.code, connectrpc::ErrorCode::InvalidArgument);
        assert_eq!(input.drain_rejected().await, DrainOutcome::Complete);
        drop(input);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[tokio::test]
    async fn copy_admission_failure_does_not_block_raw_cleanup() {
        let wire = [entry(b"a", b"b"), entry(b"c", b"d")].concat();
        let frames = wire
            .chunks(6)
            .map(|bytes| Ok::<_, Infallible>(Frame::data(Bytes::copy_from_slice(bytes))))
            .collect::<Vec<_>>();
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: wire.len() + 8,
        });
        let mut input = PutInput::new(
            box_body(StreamBody::new(futures::stream::iter(frames))),
            PutMetadata::default(),
            PutLimits::default(),
            Instant::now() + Duration::from_secs(1),
            budget.try_admit(wire.len()).unwrap(),
        );
        input.reject(
            crate::engine::IngestError::ResourceExhausted {
                message: "backend full".into(),
            }
            .into(),
        );
        let error = input
            .next_batch(DecodeBuffers::new(8, 2))
            .await
            .err()
            .unwrap()
            .into_connect();
        assert_eq!(error.code, connectrpc::ErrorCode::ResourceExhausted);
        assert_eq!(input.drain_rejected().await, DrainOutcome::Complete);
        assert_eq!(input.wire_bytes(), wire.len());
        drop(input);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[tokio::test]
    async fn failed_batch_retention_reuses_compacted_arena_without_growth() {
        let wire = [vec![10, 0], entry(b"a", b"123456789"), vec![0]].concat();
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: wire.len() * 2 + 16 + 4 * std::mem::size_of::<super::super::EntryRanges>(),
        });
        let mut input = PutInput::new(
            box_body(Full::new(Bytes::from(wire.clone()))),
            PutMetadata::default(),
            PutLimits::default(),
            Instant::now() + Duration::from_secs(1),
            budget.try_admit(wire.len()).unwrap(),
        );
        let error = input
            .next_batch(DecodeBuffers::new(16, 4))
            .await
            .err()
            .unwrap()
            .into_connect();
        assert_eq!(error.code, connectrpc::ErrorCode::InvalidArgument);
        assert_eq!(input.drain_rejected().await, DrainOutcome::Complete);
        drop(input);
        assert_eq!(budget.usage(), (0, 0));
    }

    #[tokio::test]
    async fn ready_empty_frames_and_trailers_yield_before_original_deadline() {
        for trailers in [false, true] {
            let frames = futures::stream::repeat_with(move || {
                Ok::<_, Infallible>(if trailers {
                    Frame::trailers(http::HeaderMap::new())
                } else {
                    Frame::data(Bytes::new())
                })
            });
            let budget = IngestBudget::new(BudgetConfig {
                max_requests: 1,
                max_bytes: 16,
            });
            let deadline = Instant::now() + Duration::from_millis(20);
            let mut input = PutInput::new(
                box_body(StreamBody::new(frames)),
                PutMetadata::default(),
                PutLimits::default(),
                deadline,
                budget.try_admit(16).unwrap(),
            );
            let progressed = Arc::new(AtomicUsize::new(0));
            let neighbor = progressed.clone();
            let other = tokio::spawn(async move {
                neighbor.store(1, Ordering::SeqCst);
            });
            assert_eq!(input.drain_rejected().await, DrainOutcome::Deadline);
            assert_eq!(progressed.load(Ordering::SeqCst), 1);
            other.await.unwrap();
            assert!(Instant::now() >= deadline);
            drop(input);
            assert_eq!(budget.usage(), (0, 0));
        }
    }

    #[tokio::test]
    async fn ready_data_drain_yields_after_bounded_frame_work() {
        let frames = futures::stream::repeat_with(|| {
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"a")))
        });
        let budget = IngestBudget::new(BudgetConfig {
            max_requests: 1,
            max_bytes: 4096,
        });
        let mut input = PutInput::new(
            box_body(StreamBody::new(frames)),
            PutMetadata::default(),
            PutLimits::default(),
            Instant::now() + Duration::from_secs(1),
            budget.try_admit(4096).unwrap(),
        );
        let progressed = Arc::new(AtomicUsize::new(0));
        let neighbor = progressed.clone();
        let other = tokio::spawn(async move {
            neighbor.store(1, Ordering::SeqCst);
        });
        assert_eq!(input.drain_rejected().await, DrainOutcome::WireLimit);
        assert_eq!(progressed.load(Ordering::SeqCst), 1);
        other.await.unwrap();
        assert_eq!(input.wire_bytes(), 4096);
        drop(input);
        assert_eq!(budget.usage(), (0, 0));
    }
}
