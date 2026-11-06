use axum::{body::Body, serve::Listener};
use http::{Request, Response, Version};
use http_body::Body as _;
use hyper_util::{rt::TokioIo, server::conn::auto::Builder};
use std::{
    convert::Infallible,
    future::Future,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{sync::watch, time::Instant};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tower::{Service, ServiceExt};

tokio::task_local! {
    static STREAM_DEADLINE: watch::Sender<Option<Instant>>;
    static REQUEST: Arc<RequestCutoff>;
}

// A responsive peer drains a subscription's terminal frame well within this
// window after its lifetime. A peer that withholds flow-control credit or
// stops reading is cut off once it ends.
const STALLED_RESPONSE_GRACE: Duration = Duration::from_secs(2);

/// Default for [ServeConfig::shutdown_timeout].
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Options for [serve_with_config].
#[derive(Clone, Copy, Debug)]
pub struct ServeConfig {
    /// How long shutdown lets open connections finish before closing them.
    ///
    /// The timeout starts when shutdown begins, and progress on a connection
    /// does not extend it. Defaults to [DEFAULT_SHUTDOWN_TIMEOUT].
    pub shutdown_timeout: Duration,
}

impl Default for ServeConfig {
    fn default() -> Self {
        Self {
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
        }
    }
}

// Hyper runs each HTTP/2 stream on a task from this executor, outside the
// connection future. Dropping the connection errors every stream, which ends
// its task even when its handler never returns or its peer never grants
// credit. Tracking the tasks lets serve wait for that to finish.
#[derive(Clone)]
struct StreamExecutor {
    tasks: TaskTracker,
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
        let stream = async move {
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
        };
        self.tasks.spawn(STREAM_DEADLINE.scope(deadline, stream));
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
    active: Option<Arm>,
}

// Lets a subscription handler arm a cutoff for its response. The handler
// scope and the response body each hold a reference, so an HTTP/1 cutoff
// stays armed until Hyper has finished with both.
struct RequestCutoff {
    connection: ConnectionControl,
    version: Version,
    // Generation of the armed cutoff, or zero. Generations start at one.
    generation: AtomicU64,
}

impl Drop for RequestCutoff {
    fn drop(&mut self) {
        // The response is complete, so a later request on this HTTP/1
        // connection must not inherit the subscription's cutoff.
        let generation = *self.generation.get_mut();
        if generation != 0 {
            self.connection.disarm(generation);
        }
    }
}

pin_project_lite::pin_project! {
    struct CutoffBody<B> {
        #[pin]
        inner: B,
        cutoff: Arc<RequestCutoff>,
    }
}

impl<B> http_body::Body for CutoffBody<B>
where
    B: http_body::Body,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        self.project().inner.poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// Cuts off the current request's response a short grace period after `lifetime_end`.
///
/// Outside [serve], or off the handler's task, this does nothing.
pub(crate) fn arm_subscription_cutoff(lifetime_end: Instant) {
    let Some(cutoff) = lifetime_end.checked_add(STALLED_RESPONSE_GRACE) else {
        return;
    };
    let _ = REQUEST.try_with(|request| {
        if request.version == Version::HTTP_2 {
            // The per-stream executor task owns this deadline, so it fires
            // even while Hyper is not polling the response body.
            let _ = STREAM_DEADLINE.try_with(|sender| {
                sender.send_if_modified(|current| {
                    if current.is_some_and(|current| current <= cutoff) {
                        return false;
                    }
                    *current = Some(cutoff);
                    true
                })
            });
        } else if let Some(generation) = request.connection.arm_http1(request.version, cutoff) {
            request.generation.store(generation, Ordering::Release);
        }
    });
}

/// Reports that [serve] has begun shutting down.
///
/// [serve] inserts one into the extensions of every request. Long-lived
/// handlers wait on [Self::closed] so they end promptly instead of being cut
/// off at the shutdown timeout.
#[derive(Clone, Debug)]
pub struct ShutdownSignal(watch::Receiver<bool>);

impl ShutdownSignal {
    /// Whether shutdown has started.
    pub fn is_shutting_down(&self) -> bool {
        *self.0.borrow()
    }

    /// Completes once shutdown has started, or immediately if it already has.
    ///
    /// A server that no longer exists counts as shut down.
    pub async fn closed(mut self) {
        let _ = self.0.wait_for(|started| *started).await;
    }
}

/// Controls termination of the connection that carried a request.
#[derive(Clone, Debug)]
pub struct ConnectionControl {
    state: watch::Sender<State>,
}

impl ConnectionControl {
    fn new() -> Self {
        let (state, _) = watch::channel(State::default());
        Self { state }
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

/// Serves requests with connection control and a [ShutdownSignal] in their extensions.
///
/// This is [serve_with_config] with the default [ServeConfig], so shutdown
/// closes connections that are still open after [DEFAULT_SHUTDOWN_TIMEOUT].
pub async fn serve<L, S, B, F>(listener: L, service: S, shutdown: F) -> io::Result<()>
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
    serve_with_config(listener, service, shutdown, ServeConfig::default()).await
}

/// Serves requests like [serve], with explicit options.
///
/// Once `shutdown` completes, this stops accepting connections, fires every
/// request's [ShutdownSignal], and lets open connections finish their
/// requests. It returns as soon as they have all closed. Connections still
/// open when [ServeConfig::shutdown_timeout] has elapsed are closed and their
/// requests cancelled, however much progress their peers are making, so no
/// client can hold the process open. Responses still being sent are cut off
/// at that point.
///
/// The tasks that serve connections and HTTP/2 streams have all been dropped,
/// with the requests and sockets they own, by the time this returns. A task
/// is only dropped once it yields, so a request that blocks its thread delays
/// this. Work that a handler moved to blocking threads or to tasks of its own
/// is not cancelled and can outlive this. Dropping the returned future stops
/// every connection and stream task without waiting for them.
pub async fn serve_with_config<L, S, B, F>(
    mut listener: L,
    service: S,
    shutdown: F,
    config: ServeConfig,
) -> io::Result<()>
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
    let tasks = TaskTracker::new();
    let stop = CancellationToken::new();

    // Every connection and stream task stops with this future, including
    // when it is dropped before shutdown completes.
    let _stop = stop.clone().drop_guard();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            (io, _) = listener.accept() => {
                let control = ConnectionControl::new();
                let requests = control.clone();
                let service = service.clone();
                let signal = ShutdownSignal(shutdown_rx.clone());
                let service = hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
                    let service = service.clone();
                    let control = requests.clone();
                    let signal = signal.clone();
                    async move {
                        let cutoff = Arc::new(RequestCutoff {
                            connection: control.clone(),
                            version: request.version(),
                            generation: AtomicU64::new(0),
                        });
                        let mut request = request.map(Body::new);
                        request.extensions_mut().insert(control);
                        request.extensions_mut().insert(signal);
                        let Ok(response) = REQUEST.scope(cutoff.clone(), service.oneshot(request)).await;
                        Ok::<_, Infallible>(response.map(|inner| CutoffBody { inner, cutoff }))
                    }
                });
                let mut shutdown = shutdown_rx.clone();
                let executor = StreamExecutor {
                    tasks: tasks.clone(),
                };
                let stop = stop.clone();

                // Cancellation stays outside Hyper so stalled output cannot hold the socket.
                tasks.spawn(async move {
                    let mut builder = Builder::new(executor);
                    builder.http2().enable_connect_protocol();
                    let connection = builder.serve_connection_with_upgrades(TokioIo::new(io), service);
                    tokio::pin!(connection);
                    tokio::select! {
                        biased;
                        _ = stop.cancelled() => {}
                        _ = control.cancelled() => {}
                        _ = &mut connection => {}
                        _ = shutdown.changed() => {
                            connection.as_mut().graceful_shutdown();
                            tokio::select! {
                                biased;
                                _ = stop.cancelled() => {}
                                _ = control.cancelled() => {}
                                _ = &mut connection => {}
                            }
                        }
                    }
                });
            }
        }
    }

    // One deadline, set as shutdown begins, bounds the whole drain. Requests
    // that need longer are cancelled rather than allowed to hold the process.
    drop(listener);
    shutdown_tx.send_replace(true);
    tasks.close();
    let _ = tokio::time::timeout(config.shutdown_timeout, tasks.wait()).await;

    // Stopped tasks are dropped when the runtime next polls them, so wait
    // until they are gone before reporting that serving is over.
    stop.cancel();
    tasks.wait().await;
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
}
