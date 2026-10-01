use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use connectrpc::{ConnectError, ConnectRpcService, Dispatcher};
use futures::future::BoxFuture;
use http::{request::Parts, Request, Response};
use tower::Service;

use super::transport::{terminate_unfinished_response, ConnectionControl};
use super::{box_body, DrainOutcome, PutEncoding, PutInput, PutLimits, PutMetadata};
use crate::{Ingest, IngestState};

const PUT_PATH: &str = exoware_sdk::ingest::SERVICE_PUT_SPEC.procedure;

#[derive(Clone)]
pub struct PutConfig {
    pub budget: Arc<super::IngestBudget>,
    /// Unknown-length bodies reserve this maximum before reception. Known lengths
    /// reserve a smaller bound that is enforced during reception and cleanup.
    pub max_wire_bytes: usize,
    pub timeout: std::time::Duration,
    pub observer: Option<Arc<dyn super::IngestObserver>>,
}

impl Default for PutConfig {
    fn default() -> Self {
        Self {
            budget: super::IngestBudget::new(super::BudgetConfig::default()),
            max_wire_bytes: crate::MAX_CONNECTRPC_BODY_BYTES,
            timeout: std::time::Duration::from_secs(30),
            observer: None,
        }
    }
}

fn validate_protocol(parts: &Parts) -> Result<(), ConnectError> {
    if parts.method != http::Method::POST {
        return Err(ConnectError::method_not_allowed("Put requires POST"));
    }
    let protocol = connectrpc::Protocol::detect(&parts.headers).ok_or_else(|| {
        ConnectError::unsupported_media_type("Put requires Connect unary protobuf")
    })?;
    if protocol.codec_format == connectrpc::CodecFormat::Json {
        return Err(ConnectError::unimplemented("Put requires protobuf"));
    }
    if protocol.protocol != connectrpc::Protocol::Connect || protocol.is_streaming {
        return Err(ConnectError::unsupported_media_type(
            "Put requires Connect unary protobuf",
        ));
    }
    if parts.headers.contains_key("connect-content-encoding")
        || parts.headers.contains_key("grpc-encoding")
    {
        return Err(ConnectError::unsupported_media_type(
            "Put encoding must use content-encoding",
        ));
    }
    if parts
        .headers
        .get("connect-protocol-version")
        .is_some_and(|value| value != "1")
    {
        return Err(ConnectError::invalid_argument(
            "unsupported protocol version",
        ));
    }
    Ok(())
}

fn compressed(parts: &Parts) -> Result<bool, ConnectError> {
    let unsupported = |message| {
        let mut error = ConnectError::unsupported_media_type(message);
        error.response_headers_mut().insert(
            http::header::ACCEPT_ENCODING,
            http::HeaderValue::from_static("zstd"),
        );
        error
    };
    let mut values = parts.headers.get_all(http::header::CONTENT_ENCODING).iter();
    let encoding = values.next();
    if values.next().is_some() {
        return Err(unsupported(
            "Put requires at most one content-encoding value",
        ));
    }
    match encoding {
        None => Ok(false),
        Some(value) if value == "identity" => Ok(false),
        Some(value) if value == "zstd" => Ok(true),
        Some(_) => Err(unsupported("unsupported Put request encoding")),
    }
}

fn deadline(
    parts: &Parts,
    default: std::time::Duration,
) -> Result<tokio::time::Instant, ConnectError> {
    let timeout = match parts.headers.get("connect-timeout-ms") {
        None => default,
        Some(value) => {
            let value = value
                .to_str()
                .map_err(|_| ConnectError::invalid_argument("invalid request timeout"))?;
            if value.is_empty()
                || value.len() > 10
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(ConnectError::invalid_argument("invalid request timeout"));
            }
            std::time::Duration::from_millis(
                value
                    .parse()
                    .map_err(|_| ConnectError::invalid_argument("invalid request timeout"))?,
            )
            .min(default)
        }
    };
    Ok(tokio::time::Instant::now() + timeout)
}

/// Put middleware runs on metadata while the body remains unread.
pub trait PutMiddleware: Send + Sync + 'static {
    fn call<'a>(&'a self, parts: &'a mut Parts) -> BoxFuture<'a, Result<(), ConnectError>>;
}

impl<F> PutMiddleware for F
where
    F: for<'a> Fn(&'a mut Parts) -> BoxFuture<'a, Result<(), ConnectError>> + Send + Sync + 'static,
{
    fn call<'a>(&'a self, parts: &'a mut Parts) -> BoxFuture<'a, Result<(), ConnectError>> {
        self(parts)
    }
}

/// Routes Put before the ordinary RPC dispatcher can collect its body.
pub struct PutService<I, D> {
    state: IngestState<I>,
    other: ConnectRpcService<D>,
    middleware: Vec<Arc<dyn PutMiddleware>>,
}

impl<I, D> Clone for PutService<I, D> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            other: self.other.clone(),
            middleware: self.middleware.clone(),
        }
    }
}

impl<I: Ingest, D: Dispatcher> PutService<I, D> {
    pub fn new(state: IngestState<I>, other: ConnectRpcService<D>) -> Self {
        Self {
            state,
            other,
            middleware: Vec::new(),
        }
    }

    pub fn with_put_middleware(mut self, middleware: impl PutMiddleware) -> Self {
        self.middleware.push(Arc::new(middleware));
        self
    }
}

impl<I, D, B> Service<Request<B>> for PutService<I, D>
where
    I: Ingest,
    D: Dispatcher,
    B: http_body::Body<Data = bytes::Bytes> + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        if request.uri().path() != PUT_PATH {
            let call = self.other.call(request);
            return Box::pin(async move { Ok(call.await?.map(Body::new)) });
        }
        let state = self.state.clone();
        let middleware = self.middleware.clone();
        Box::pin(async move {
            let started = tokio::time::Instant::now();
            let observer = state.put_config.observer.clone();
            let response = put(state, middleware, request.map(Body::new)).await;
            if let Some(observer) = observer {
                observer.observe(super::IngestEvent::ResponseElapsed(started.elapsed()));
            }
            Ok(response)
        })
    }
}

async fn put<I: Ingest>(
    state: IngestState<I>,
    middleware: Vec<Arc<dyn PutMiddleware>>,
    request: Request<Body>,
) -> Response<Body> {
    use buffa::Message;
    use http_body::Body as _;
    use std::sync::atomic::Ordering;

    let (mut parts, body) = request.into_parts();
    let headers = parts.headers.clone();
    let parsed_deadline = deadline(&parts, state.put_config.timeout);
    let request_deadline = parsed_deadline
        .as_ref()
        .copied()
        .unwrap_or_else(|_| tokio::time::Instant::now());
    let control = parts.extensions.get::<ConnectionControl>().cloned();
    let generation = control
        .as_ref()
        .and_then(|control| control.arm_http1(parts.version, request_deadline));
    let version = parts.version;
    let method = parts.method.clone();
    let mut lengths = parts.headers.get_all(http::header::CONTENT_LENGTH).iter();
    let declared_length = match (lengths.next(), lengths.next()) {
        (None, _) => Ok(None),
        (Some(value), None) => value
            .to_str()
            .ok()
            .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|value| value.parse::<usize>().ok())
            .map(Some)
            .ok_or_else(|| ConnectError::invalid_argument("invalid content length")),
        (Some(_), Some(_)) => Err(ConnectError::invalid_argument("invalid content length")),
    };
    let exact_length = body
        .size_hint()
        .exact()
        .and_then(|length| usize::try_from(length).ok());
    let known_bound = match (
        declared_length.as_ref().ok().copied().flatten(),
        exact_length,
    ) {
        (Some(declared), Some(exact)) => Some(declared.min(exact)),
        (declared, exact) => declared.or(exact),
    };
    let metadata = PutMetadata {
        encoding: if compressed(&parts).unwrap_or(false) {
            PutEncoding::Zstd
        } else {
            PutEncoding::Identity
        },
        content_length: declared_length
            .as_ref()
            .ok()
            .copied()
            .flatten()
            .or(exact_length),
    };
    let mut rejection = if let Err(error) = parsed_deadline {
        Some(error)
    } else if !state.ready.load(Ordering::SeqCst) {
        Some(crate::connect::worker_not_ready_error())
    } else {
        validate_protocol(&parts)
            .and_then(|()| compressed(&parts).map(|_| ()))
            .and_then(|()| declared_length.map(|_| ()))
            .and_then(|()| {
                if metadata
                    .content_length
                    .is_some_and(|length| length > state.put_config.max_wire_bytes)
                {
                    Err(ConnectError::resource_exhausted(
                        "request body exceeds wire limit",
                    ))
                } else {
                    Ok(())
                }
            })
            .err()
    };
    if rejection.is_none()
        && exact_length.is_some_and(|length| length > state.put_config.max_wire_bytes)
    {
        rejection = Some(ConnectError::resource_exhausted(
            "request body exceeds wire limit",
        ));
    }

    // Unknown bodies reserve the maximum before polling. Known bounds are also
    // enforced during reception and raw cleanup, including dishonest lengths.
    let wire_bound = known_bound
        .unwrap_or(state.put_config.max_wire_bytes)
        .min(state.put_config.max_wire_bytes);
    let admission = if rejection.is_some() {
        state.put_config.budget.try_admit_cleanup(wire_bound)
    } else {
        state.put_config.budget.try_admit(wire_bound)
    };
    let admission = match admission {
        Ok(admission) => admission,
        Err(error) => {
            let error = rejection.unwrap_or(error);
            let response =
                method_response(&method, error.into_http_response(&headers).map(Body::new));
            return if body.is_end_stream() {
                if let (Some(control), Some(generation)) = (&control, generation) {
                    control.disarm(generation);
                }
                response
            } else {
                terminate_unfinished_response(version, response)
            };
        }
    };
    if rejection.is_none() {
        for middleware in &middleware {
            let result =
                tokio::time::timeout_at(request_deadline, middleware.call(&mut parts)).await;
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    rejection = Some(error);
                    break;
                }
                Err(_) => {
                    rejection = Some(ConnectError::deadline_exceeded("ingest deadline exceeded"));
                    break;
                }
            }
        }
    }
    let mut input = PutInput::new(
        box_body(body),
        metadata,
        PutLimits {
            wire_bytes: state.put_config.max_wire_bytes,
            ingest: state.limits,
            ..Default::default()
        },
        request_deadline,
        admission,
    )
    .with_parts(parts)
    .with_notifier(state.notifier.clone());
    if let Some(observer) = &state.put_config.observer {
        input = input.with_observer(observer.clone());
    }
    let mut result = match rejection {
        Some(error) => Err(error),
        None => match tokio::time::timeout_at(request_deadline, state.ingest.put(&mut input)).await
        {
            Ok(Ok(sequence)) if input.is_finished() => Ok(sequence),
            Ok(Ok(_)) => Err(ConnectError::internal(
                "backend published without checked Put finalization",
            )),
            Ok(Err(error)) => Err(error.into_connect()),
            Err(_) => Err(ConnectError::deadline_exceeded("ingest deadline exceeded")),
        },
    };
    let cleanup = if input.is_finished() {
        DrainOutcome::Complete
    } else {
        input.drain_rejected().await
    };
    let complete = cleanup == DrainOutcome::Complete || input.is_end_stream();
    if cleanup == DrainOutcome::WireLimit {
        result = Err(ConnectError::resource_exhausted(
            "request body exceeds wire limit",
        ));
    }
    if complete {
        if let (Some(control), Some(generation)) = (&control, generation) {
            control.disarm(generation);
        }
    }
    let response = match result {
        Ok(sequence_number) => {
            let response = exoware_sdk::ingest::PutResponse {
                sequence_number,
                ..Default::default()
            };
            Response::builder()
                .header(http::header::CONTENT_TYPE, "application/proto")
                .header(http::header::ACCEPT_ENCODING, "zstd")
                .body(Body::from(response.encode_to_vec()))
                .expect("static Put response headers are valid")
        }
        Err(error) => error.into_http_response(&headers).map(Body::new),
    };
    let response = method_response(&method, response);
    if complete {
        response
    } else {
        terminate_unfinished_response(version, response)
    }
}

fn method_response(method: &http::Method, response: Response<Body>) -> Response<Body> {
    if method != http::Method::POST && method != http::Method::GET {
        Response::builder()
            .status(http::StatusCode::METHOD_NOT_ALLOWED)
            .header(http::header::ALLOW, "POST")
            .body(Body::empty())
            .expect("static method rejection headers are valid")
    } else {
        response
    }
}
