use std::{
    convert::Infallible,
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use axum::{body::Body, serve::Listener};
use http::{Request, Response, Version};
use hyper_util::{rt::TokioIo, server::conn::auto::Builder, service::TowerToHyperService};
use tokio::{sync::watch, task::JoinSet, time::Instant};
use tower::{service_fn, Service, ServiceExt};

tokio::task_local! {
    static STREAM_DEADLINE: watch::Sender<Option<Instant>>;
}

#[derive(Clone, Copy)]
struct StreamExecutor;

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

// Hyper does not poll response bodies while DATA capacity is unavailable. The
// executor owns cancellation so a rejected stream cannot retain its writer.
pub(super) fn admission_rejection_response(
    version: Version,
    response: Response<Body>,
    deadline: Instant,
    control: Option<&ConnectionControl>,
    generation: Option<u64>,
) -> Response<Body> {
    let deadline = deadline.min(Instant::now() + std::time::Duration::from_secs(1));
    if version == Version::HTTP_2 {
        if STREAM_DEADLINE
            .try_with(|sender| sender.send_replace(Some(deadline)))
            .is_ok()
        {
            // Hyper can queue a whole DATA frame after obtaining one byte of
            // capacity. Keeping the final byte separate preserves the stream
            // task until the peer grants capacity for the complete error.
            return response.map(|inner| Body::new(AdmissionBody { inner, tail: None }));
        }
    } else if let (Some(control), Some(generation)) = (control, generation) {
        control.shorten(generation, deadline);
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

    /// Disarms only the matching request generation after cleanup succeeds.
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

/// Serves requests with connection control in their extensions and drains connections on shutdown.
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
                let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                    let service = service.clone();
                    let control = requests.clone();
                    async move {
                        let mut request = request.map(Body::new);
                        request.extensions_mut().insert(control);
                        service.oneshot(request).await
                    }
                });
                let mut shutdown = shutdown_rx.clone();

                // Cancellation stays outside Hyper so stalled output cannot hold the socket.
                connections.spawn(async move {
                    let mut builder = Builder::new(StreamExecutor);
                    builder.http2().enable_connect_protocol();
                    let connection = builder.serve_connection_with_upgrades(
                        TokioIo::new(io),
                        TowerToHyperService::new(service),
                    );
                    tokio::pin!(connection);
                    tokio::select! {
                        _ = control.cancelled() => {}
                        _ = &mut connection => {}
                        _ = shutdown.changed() => {
                            connection.as_mut().graceful_shutdown();
                            tokio::select! {
                                _ = control.cancelled() => {}
                                _ = &mut connection => {}
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
