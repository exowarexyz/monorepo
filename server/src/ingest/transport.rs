use std::{
    convert::Infallible,
    future::Future,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use axum::{body::Body, serve::Listener};
use bytes::Buf as _;
use http::{Request, Response, Version};
use http_body::Body as _;
use hyper::service::service_fn;
use hyper_util::{rt::TokioIo, server::conn::auto::Builder};
use tokio::{sync::watch, task::JoinSet, time::Instant};
use tower::{Service, ServiceExt};

tokio::task_local! {
    static STREAM_DEADLINE: watch::Sender<Option<Instant>>;
    static CURRENT_REQUEST: StreamWatchdog;
}

/// How long a stalled response may outlive the bound that ended its subscription.
///
/// A responsive peer receives the terminal error well inside this window. A
/// peer that withholds flow-control credit or stops reading is cut off when it
/// elapses, so termination is bounded by the bound plus this grace period and
/// not by the bound alone.
pub(crate) const STALLED_RESPONSE_GRACE: Duration = Duration::from_secs(2);

#[derive(Clone, Copy)]
struct StreamExecutor;

/// Cuts off the response of one request when its peer stops draining it.
///
/// Hyper stops polling a response body while the peer withholds output
/// capacity, so termination for a streaming response cannot rely on the body
/// being polled. The watchdog instead shortens the deadline owned by the
/// per-stream executor task for HTTP/2, which drops only that response, and arms
/// the connection deadline for HTTP/1, which has no other streams to protect.
#[derive(Clone, Debug)]
pub(crate) struct StreamWatchdog {
    control: ConnectionControl,
    stream_deadline: Option<watch::Sender<Option<Instant>>>,
    version: Version,
    request: u64,
    supervised: Arc<AtomicBool>,
    terminating: Arc<AtomicBool>,
}

impl StreamWatchdog {
    pub(crate) fn current() -> Option<Self> {
        CURRENT_REQUEST.try_with(Clone::clone).ok()
    }

    pub(crate) fn mark_supervised(&self) {
        self.supervised.store(true, Ordering::Release);
        self.control.mark_supervised();
    }

    /// Cuts the response off after the grace period unless it completes first.
    ///
    /// Both the stream and its supervisor call this when a bound fires, and the
    /// earliest deadline wins. The stream cannot rely on the supervisor alone
    /// because it may finish and drop it first. Termination also makes the
    /// response body hold its final byte back. Hyper queues a whole chunk once
    /// one byte of credit exists and may then finish the response, so holding
    /// the last byte back keeps the stream task alive until every earlier byte
    /// fits in the peer window and the deadline still covers the terminal
    /// envelope.
    pub(crate) fn cancel_after_grace(&self) {
        self.terminating.store(true, Ordering::Release);
        let deadline = Instant::now() + STALLED_RESPONSE_GRACE;
        match &self.stream_deadline {
            Some(sender) => {
                sender.send_if_modified(|current| {
                    if current.is_some_and(|current| current <= deadline) {
                        return false;
                    }
                    *current = Some(deadline);
                    true
                });
            }
            None => self
                .control
                .arm_watchdog(self.version, deadline, self.request),
        }
    }
}

pin_project_lite::pin_project! {
    // Streaming responses that opted in keep their final byte back once
    // terminating. Every other response passes through untouched.
    struct ResponseBody<B> {
        #[pin]
        inner: B,
        _request: RequestGuard,
        supervised: bool,
        terminating: Arc<AtomicBool>,
        tail: Option<bytes::Bytes>,
    }
}

impl<B> http_body::Body for ResponseBody<B>
where
    B: http_body::Body,
{
    type Data = bytes::Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        if let Some(tail) = this.tail.take() {
            return Poll::Ready(Some(Ok(http_body::Frame::data(tail))));
        }
        let frame = match std::task::ready!(this.inner.poll_frame(cx)) {
            Some(Ok(frame)) => frame,
            Some(Err(error)) => return Poll::Ready(Some(Err(error))),
            None => return Poll::Ready(None),
        };
        let split = *this.supervised && this.terminating.load(Ordering::Acquire);
        let frame = frame.map_data(|mut data| {
            let length = data.remaining();
            if split && length > 1 {
                let prefix = data.copy_to_bytes(length - 1);
                *this.tail = Some(data.copy_to_bytes(1));
                prefix
            } else {
                data.copy_to_bytes(length)
            }
        });
        Poll::Ready(Some(Ok(frame)))
    }

    fn is_end_stream(&self) -> bool {
        self.tail.is_none() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// Reports that the server has begun shutting down.
///
/// `serve` inserts one into the extensions of every request. Streaming handlers
/// pass [Self::closed] to `bound_subscription` so open subscriptions end with
/// `UNAVAILABLE` instead of holding the graceful connection drain open.
#[derive(Clone, Debug)]
pub struct ShutdownSignal {
    started: watch::Receiver<bool>,
}

impl ShutdownSignal {
    /// Completes once shutdown has started, immediately if it already has.
    ///
    /// A dropped server also counts as shutdown, so a handler can never wait on a
    /// transport that no longer exists.
    pub fn closed(self) -> impl Future<Output = ()> + Send + 'static {
        let mut started = self.started;
        async move {
            let _ = started.wait_for(|started| *started).await;
        }
    }
}

// Release the upload timer before backend work can reach the same deadline.
struct UploadBody {
    inner: Body,
    control: ConnectionControl,
    generation: u64,
}

impl http_body::Body for UploadBody {
    type Data = bytes::Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let frame = std::task::ready!(Pin::new(&mut self.inner).poll_frame(cx));
        if frame.is_none() || self.inner.is_end_stream() {
            self.control.disarm(self.generation);
        }

        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

struct AdmissionBody {
    inner: Body,
    tail: Option<bytes::Bytes>,
}

impl http_body::Body for AdmissionBody {
    type Data = bytes::Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        if let Some(tail) = self.tail.take() {
            return Poll::Ready(Some(Ok(http_body::Frame::data(tail))));
        }
        match std::task::ready!(Pin::new(&mut self.inner).poll_frame(cx)) {
            Some(Ok(frame)) => match frame.into_data() {
                Ok(mut data) if data.len() > 1 => {
                    let prefix = data.split_to(data.len() - 1);
                    self.tail = Some(data);
                    Poll::Ready(Some(Ok(http_body::Frame::data(prefix))))
                }
                Ok(data) => Poll::Ready(Some(Ok(http_body::Frame::data(data)))),
                Err(frame) => Poll::Ready(Some(Ok(frame))),
            },
            frame => Poll::Ready(frame),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.tail.is_none() && self.inner.is_end_stream()
    }
}

impl<F> hyper::rt::Executor<F> for StreamExecutor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        let (deadline, mut changes) = watch::channel(None);
        tokio::spawn(STREAM_DEADLINE.scope(deadline, async move {
            tokio::pin!(future);
            loop {
                let deadline = *changes.borrow_and_update();
                tokio::select! {
                    biased;
                    _ = async {
                        match deadline {
                            Some(deadline) => tokio::time::sleep_until(deadline).await,
                            None => std::future::pending().await,
                        }
                    } => return,
                    _ = &mut future => return,
                    _ = changes.changed() => {}
                }
            }
        }));
    }
}

// Rejected uploads keep their writer only briefly, even when the request
// deadline is much longer.
fn rejection_deadline(deadline: Instant) -> Instant {
    deadline.min(Instant::now() + std::time::Duration::from_secs(1))
}

// Hyper does not poll response bodies while DATA capacity is unavailable. The
// executor owns cancellation so a rejected stream cannot retain its writer.
pub(super) fn admission_rejection_response(
    version: Version,
    response: Response<Body>,
    deadline: Instant,
    control: Option<&ConnectionControl>,
    generation: Option<u64>,
) -> Response<Body> {
    let deadline = rejection_deadline(deadline);
    if version == Version::HTTP_2
        && STREAM_DEADLINE
            .try_with(|sender| sender.send_replace(Some(deadline)))
            .is_ok()
    {
        // Hyper can queue a whole DATA frame after obtaining one byte of
        // capacity. Keeping the final byte separate preserves the stream
        // task until the peer grants capacity for the complete error.
        return response.map(|inner| Body::new(AdmissionBody { inner, tail: None }));
    }

    terminate_rejected_response(version, response, deadline, control, generation)
}

// Rejections that cannot drain their upload close HTTP/1 connections after a
// short bound instead of the full request deadline. HTTP/2 resets the stream
// on the first body poll, so it needs no executor deadline.
pub(super) fn terminate_rejected_response(
    version: Version,
    response: Response<Body>,
    deadline: Instant,
    control: Option<&ConnectionControl>,
    generation: Option<u64>,
) -> Response<Body> {
    if let (Some(control), Some(generation)) = (control, generation) {
        control.shorten(generation, rejection_deadline(deadline));
    }

    terminate_unfinished_response(version, response)
}

struct CancelBody;

impl http_body::Body for CancelBody {
    type Data = bytes::Bytes;
    type Error = h2::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(Some(Err(h2::Error::from(h2::Reason::CANCEL))))
    }
}

/// Terminates an unfinished upload after cleanup fails.
///
/// HTTP/1 callers must keep the connection deadline armed. HTTP/2 discards the response body.
pub fn terminate_unfinished_response(
    version: Version,
    mut response: Response<Body>,
) -> Response<Body> {
    if version == Version::HTTP_2 {
        // An error on the first poll resets the stream even without response DATA capacity.
        *response.body_mut() = Body::new(CancelBody);
    } else if matches!(version, Version::HTTP_10 | Version::HTTP_11) {
        response.headers_mut().insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("close"),
        );
    }
    response
}

#[derive(Clone, Copy, Debug)]
struct Arm {
    id: u64,
    deadline: Instant,
}

#[derive(Clone, Copy, Debug, Default)]
struct State {
    next: u64,
    request: u64,
    active: Option<Arm>,
    watchdog: Option<u64>,
}

/// Controls termination of the connection that carried a request.
#[derive(Clone, Debug)]
pub struct ConnectionControl {
    state: watch::Sender<State>,
    activity: watch::Sender<Activity>,
}

#[derive(Clone, Copy, Debug, Default)]
struct Activity {
    in_flight: usize,
    supervised: bool,
}

// Counts requests until their response body is dropped, which Hyper does once
// the body has been handed to the connection. A nonzero count means a stream
// task still owns its response.
struct RequestGuard(watch::Sender<Activity>);

impl Drop for RequestGuard {
    fn drop(&mut self) {
        self.0.send_modify(|activity| activity.in_flight -= 1);
    }
}

impl ConnectionControl {
    fn new() -> Self {
        let (state, _) = watch::channel(State::default());
        let (activity, _) = watch::channel(Activity::default());
        Self { state, activity }
    }

    fn begin_request(&self) -> RequestGuard {
        self.activity
            .send_modify(|activity| activity.in_flight += 1);
        RequestGuard(self.activity.clone())
    }

    fn mark_supervised(&self) {
        self.activity
            .send_if_modified(|activity| !std::mem::replace(&mut activity.supervised, true));
    }

    // After a bounded subscription's stream task has finished, queued response
    // bytes can still wait on a peer that stopped reading, with no deadline left
    // to cancel them. This completes once such a connection has had no request
    // in flight for the grace period. Connections that never carried a bounded
    // subscription are left to drain as long as their requests need.
    async fn flush_stalled(&self, grace: Duration) {
        let mut activity = self.activity.subscribe();
        let idle = |activity: &Activity| activity.supervised && activity.in_flight == 0;
        loop {
            let now_idle = idle(&activity.borrow_and_update());
            if now_idle {
                tokio::select! {
                    _ = tokio::time::sleep(grace) => {
                        if idle(&activity.borrow()) {
                            return;
                        }
                    }
                    changed = activity.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                }
            } else if activity.changed().await.is_err() {
                return;
            }
        }
    }

    /// Arms an HTTP/1 connection with an absolute request deadline.
    pub fn arm_http1(&self, version: Version, deadline: Instant) -> Option<u64> {
        if !matches!(version, Version::HTTP_10 | Version::HTTP_11) {
            return None;
        }

        let mut id = 0;
        self.state.send_modify(|state| {
            state.next = state
                .next
                .checked_add(1)
                .expect("connection generation exhausted");
            id = state.next;
            state.active = Some(Arm { id, deadline });
        });
        Some(id)
    }

    pub(super) fn disarm_on_eof(&self, body: Body, generation: u64) -> Body {
        if body.is_end_stream() {
            self.disarm(generation);
            return body;
        }

        Body::new(UploadBody {
            inner: body,
            control: self.clone(),
            generation,
        })
    }

    /// Disarms only the matching request generation after body reception or cleanup.
    pub fn disarm(&self, id: u64) -> bool {
        self.state.send_if_modified(|state| {
            if state.active.is_some_and(|arm| arm.id == id) {
                state.active = None;
                true
            } else {
                false
            }
        })
    }

    /// Expires only the matching unfinished HTTP/1 request.
    pub fn expire(&self, id: u64) -> bool {
        self.shorten(id, Instant::now())
    }

    // An HTTP/1 connection carries one response at a time, so closing it cuts
    // off only the stalled subscription. An armed upload deadline already
    // bounds the connection, so it is left alone.
    //
    // The request number keeps a late arm from a finished response off its
    // successor, because the next request on the connection advances it.
    fn arm_watchdog(&self, version: Version, deadline: Instant, request: u64) {
        if !matches!(version, Version::HTTP_10 | Version::HTTP_11) {
            return;
        }

        self.state.send_if_modified(|state| {
            if state.request != request || state.active.is_some() {
                return false;
            }
            state.next = state
                .next
                .checked_add(1)
                .expect("connection generation exhausted");
            state.watchdog = Some(state.next);
            state.active = Some(Arm {
                id: state.next,
                deadline,
            });
            true
        });
    }

    // Hyper reads the next HTTP/1 request only after the previous response is
    // written, so a new request proves the watched response completed and
    // retires its watchdog arm.
    fn start_request(&self) -> u64 {
        let mut request = 0;
        self.state.send_modify(|state| {
            state.request += 1;
            request = state.request;
            if let Some(id) = state.watchdog.take() {
                if state.active.is_some_and(|arm| arm.id == id) {
                    state.active = None;
                }
            }
        });
        request
    }

    fn shorten(&self, id: u64, deadline: Instant) -> bool {
        self.state.send_if_modified(|state| {
            if let Some(arm) = &mut state.active {
                if arm.id == id && deadline < arm.deadline {
                    arm.deadline = deadline;
                    return true;
                }
            }
            false
        })
    }

    async fn cancelled(&self) {
        let mut receiver = self.state.subscribe();
        loop {
            let active = receiver.borrow_and_update().active;
            if let Some(arm) = active {
                tokio::select! {
                    _ = tokio::time::sleep_until(arm.deadline) => {
                        if receiver.borrow().active.is_some_and(|current| {
                            current.id == arm.id && current.deadline <= Instant::now()
                        }) {
                            return;
                        }
                    }
                    _ = receiver.changed() => {}
                }
            } else {
                let _ = receiver.changed().await;
            }
        }
    }
}

/// Serves requests with connection control in their extensions and drains connections on shutdown.
///
/// Shutdown first signals every in-flight request through [ShutdownSignal] and
/// then lets connections finish gracefully, however long their requests take.
///
/// Hyper stops polling a response body while the peer withholds output
/// capacity, so a bounded subscription also arms a watchdog. A subscription
/// whose bound fires, or that ends early, is reset after a fixed two second
/// grace period if its peer has not drained the terminal error. Only the
/// stalled response is dropped on HTTP/2, while HTTP/1 closes its single
/// connection. A connection that carried a bounded subscription is also closed
/// once shutdown has begun and it has had no request in flight for that grace
/// period, which bounds output blocked in TCP. Connections without bounded
/// subscriptions drain as long as their requests need.
pub async fn serve<L, S, B, F>(mut listener: L, service: S, shutdown: F) -> io::Result<()>
where
    L: Listener,
    L::Io: Send + Unpin + 'static,
    S: Service<Request<Body>, Response = Response<B>, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send,
    B: http_body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    F: Future<Output = ()> + Send,
{
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            _ = connections.join_next(), if !connections.is_empty() => {}
            (io, _) = listener.accept() => {
                let control = ConnectionControl::new();
                let requests = control.clone();
                let service = service.clone();
                let signal = ShutdownSignal { started: shutdown_rx.clone() };
                let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                    let service = service.clone();
                    let control = requests.clone();
                    let signal = signal.clone();

                    // Counting happens when Hyper invokes this closure. The closure
                    // is handed to Hyper directly, because the Tower adapter only
                    // calls the inner service on the first poll, which would leave
                    // a queued stream task uncounted by the shutdown drain fallback.
                    let version = request.version();
                    let request_number = control.start_request();
                    let request_guard = control.begin_request();
                    async move {
                        let mut request = request.map(Body::new);
                        request.extensions_mut().insert(control.clone());
                        request.extensions_mut().insert(signal);
                        let watchdog = StreamWatchdog {
                            control,
                            stream_deadline: STREAM_DEADLINE
                                .try_with(Clone::clone)
                                .ok()
                                .filter(|_| version == Version::HTTP_2),
                            version,
                            request: request_number,
                            supervised: Arc::new(AtomicBool::new(false)),
                            terminating: Arc::new(AtomicBool::new(false)),
                        };
                        let result = CURRENT_REQUEST
                            .scope(watchdog.clone(), service.oneshot(request))
                            .await;
                        result.map(|response| {
                            response.map(|inner| ResponseBody {
                                inner,
                                _request: request_guard,
                                supervised: watchdog.supervised.load(Ordering::Acquire),
                                terminating: watchdog.terminating.clone(),
                                tail: None,
                            })
                        })
                    }
                });
                let mut shutdown = shutdown_rx.clone();

                // Cancellation stays outside Hyper so stalled output cannot hold the socket.
                connections.spawn(async move {
                    let mut builder = Builder::new(StreamExecutor);
                    builder.http2().enable_connect_protocol();
                    let connection =
                        builder.serve_connection_with_upgrades(TokioIo::new(io), service);
                    tokio::pin!(connection);
                    tokio::select! {
                        _ = control.cancelled() => {}
                        _ = &mut connection => {}
                        _ = shutdown.changed() => {
                            connection.as_mut().graceful_shutdown();
                            tokio::select! {
                                _ = control.cancelled() => {}
                                _ = &mut connection => {}
                                _ = control.flush_stalled(STALLED_RESPONSE_GRACE) => {}
                            }
                        }
                    }
                });
            }
        }
    }

    drop(listener);
    shutdown_tx.send_replace(true);
    while connections.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use futures::{stream, StreamExt};
    use http_body::Frame;
    use http_body_util::{BodyExt, StreamBody};
    use std::time::Duration;

    #[tokio::test(start_paused = true)]
    async fn completed_upload_disarms_without_another_body_poll() {
        let frames = stream::iter([Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"x")))]);
        let bodies = [
            (Body::empty(), 0),
            (Body::from("x"), 1),
            (Body::new(StreamBody::new(frames)), 2),
        ];
        for (body, polls) in bodies {
            let control = ConnectionControl::new();
            let generation = control
                .arm_http1(Version::HTTP_11, Instant::now() + Duration::from_secs(1))
                .unwrap();
            let mut body = control.disarm_on_eof(body, generation);
            for _ in 0..polls {
                if let Some(frame) = body.frame().await {
                    assert_eq!(frame.unwrap().into_data().unwrap(), "x");
                }
            }

            tokio::time::advance(Duration::from_secs(1)).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(1), control.cancelled())
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_unfinished_upload_keeps_connection_deadline() {
        let frames = stream::iter([Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"x")))])
            .chain(stream::pending());
        let control = ConnectionControl::new();
        let generation = control
            .arm_http1(Version::HTTP_11, Instant::now() + Duration::from_secs(1))
            .unwrap();
        let mut body = control.disarm_on_eof(Body::new(StreamBody::new(frames)), generation);
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            "x"
        );
        drop(body);

        tokio::time::timeout(Duration::from_secs(2), control.cancelled())
            .await
            .expect("unfinished upload must retain its connection deadline");
    }

    #[tokio::test(start_paused = true)]
    async fn stale_watchdog_arm_cannot_target_a_successor_request() {
        let control = ConnectionControl::new();
        let first = control.start_request();
        let second = control.start_request();
        let deadline = Instant::now() + Duration::from_secs(1);

        control.arm_watchdog(Version::HTTP_11, deadline, first);
        assert!(control.state.borrow().active.is_none());

        control.arm_watchdog(Version::HTTP_11, deadline, second);
        assert!(control.state.borrow().active.is_some());
        control.start_request();
        assert!(control.state.borrow().active.is_none());
    }
}
