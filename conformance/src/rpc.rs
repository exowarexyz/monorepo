//! Connect requests held in memory and sent to [`exoware_server::connect_stack`] as a tower
//! service, with the decoding of their responses.

use buffa::Message;
use bytes::{Buf as _, Bytes, BytesMut};
use exoware_sdk::{decode_connect_error, google::rpc::ErrorInfo, ConnectError};
use http_body_util::{BodyExt as _, Full};
use std::{fmt::Debug, pin::Pin};
use tower::{Service, ServiceExt as _};

/// Path of the Put RPC.
pub const PUT: &str = "/log.ingest.v1.Service/Put";

/// Path of the Range RPC.
pub const RANGE: &str = "/store.query.v1.Service/Range";

/// Path of the Reduce RPC.
pub const REDUCE: &str = "/store.query.v1.Service/Reduce";

/// Path of the sequence log Get RPC.
pub const LOG_GET: &str = "/log.stream.v1.Service/Get";

/// Path of the Subscribe RPC.
pub const SUBSCRIBE: &str = "/log.stream.v1.Service/Subscribe";

/// Content type of a unary protobuf request.
pub const UNARY_PROTO: &str = "application/proto";

/// Content type of a streaming protobuf request.
const STREAMING_PROTO: &str = "application/connect+proto";

/// Envelope flag that marks the end of a Connect stream.
const END_STREAM: u8 = 0x02;

/// Length of an envelope header, one flag byte and a 4-byte big-endian length.
const ENVELOPE_HEADER: usize = 5;

/// A POST request to `path` with the given body.
pub fn request<T>(path: &str, content_type: &str, body: T) -> http::Request<T> {
    http::Request::builder()
        .method(http::Method::POST)
        .uri(path)
        .header(http::header::CONTENT_TYPE, content_type)
        .body(body)
        .expect("the request parts must be valid")
}

/// A unary request carrying `message`.
pub fn unary(path: &str, message: &impl Message) -> http::Request<Full<Bytes>> {
    request(
        path,
        UNARY_PROTO,
        Full::new(Bytes::from(message.encode_to_vec())),
    )
}

/// A server streaming request carrying `message` in one envelope.
pub fn streaming(path: &str, message: &impl Message) -> http::Request<Full<Bytes>> {
    let message = message.encode_to_vec();
    let length = u32::try_from(message.len()).expect("a message must fit a 32-bit length");
    let mut body = Vec::with_capacity(ENVELOPE_HEADER + message.len());
    body.push(0);
    body.extend_from_slice(&length.to_be_bytes());
    body.extend_from_slice(&message);
    request(path, STREAMING_PROTO, Full::new(Bytes::from(body)))
}

/// Sends one request and returns the response with its body still unread.
pub async fn call<S, T, B>(service: &mut S, request: http::Request<T>) -> http::Response<B>
where
    S: Service<http::Request<T>, Response = http::Response<B>>,
    S::Error: Debug,
{
    service
        .ready()
        .await
        .expect("the service must become ready")
        .call(request)
        .await
        .expect("the service must answer")
}

/// Sends a unary request and decodes its answer, either the response message or the error.
pub async fn unary_call<S, T, B, M>(
    service: &mut S,
    request: http::Request<T>,
) -> Result<M, ConnectError>
where
    S: Service<http::Request<T>, Response = http::Response<B>>,
    S::Error: Debug,
    B: http_body::Body<Data = Bytes>,
    B::Error: Debug,
    M: Message,
{
    let response = call(service, request).await;
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("the response body must be readable")
        .to_bytes();
    if status.is_success() {
        Ok(M::decode_from_slice(&body).expect("a success response must decode"))
    } else {
        Err(buffa::serde_json::from_slice(&body).expect("an error response must decode"))
    }
}

/// The `google.rpc.ErrorInfo` detail of an error.
pub fn error_info(error: &ConnectError) -> ErrorInfo {
    decode_connect_error(error)
        .expect("the error details must decode")
        .error_info
        .expect("the error must carry an ErrorInfo detail")
}

/// Sends a server streaming request and returns a reader of its envelopes.
pub async fn open_stream<S, B>(service: &mut S, path: &str, message: &impl Message) -> Envelopes<B>
where
    S: Service<http::Request<Full<Bytes>>, Response = http::Response<B>>,
    S::Error: Debug,
    B: http_body::Body<Data = Bytes>,
    B::Error: Debug,
{
    let response = call(service, streaming(path, message)).await;
    assert!(
        response.status().is_success(),
        "a stream must open with a success status, got {}",
        response.status()
    );
    Envelopes::new(response.into_body())
}

/// One envelope of a Connect stream.
pub enum Envelope {
    /// A message payload.
    Message(Bytes),
    /// The end of the stream, with the error it carries.
    End(Option<ConnectError>),
}

/// Reads the envelopes of a streaming response as they arrive.
pub struct Envelopes<B> {
    body: Pin<Box<B>>,
    buffered: BytesMut,
}

impl<B> Envelopes<B>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: Debug,
{
    /// A reader of the envelopes in `body`.
    pub fn new(body: B) -> Self {
        Self {
            body: Box::pin(body),
            buffered: BytesMut::new(),
        }
    }

    /// The next envelope, or `None` when the body ends.
    pub async fn next(&mut self) -> Option<Envelope> {
        loop {
            if let Some(header) = self.buffered.get(..ENVELOPE_HEADER) {
                let length = u32::from_be_bytes(
                    header[1..]
                        .try_into()
                        .expect("an envelope length must be 4 bytes"),
                );
                let length = ENVELOPE_HEADER
                    + usize::try_from(length).expect("an envelope length must fit usize");
                if self.buffered.len() >= length {
                    let mut envelope = self.buffered.split_to(length);
                    let flags = envelope[0];
                    envelope.advance(ENVELOPE_HEADER);
                    let payload = envelope.freeze();
                    if flags & END_STREAM == 0 {
                        return Some(Envelope::Message(payload));
                    }
                    return Some(Envelope::End(end_error(&payload)));
                }
            }
            let Some(frame) = self.body.frame().await else {
                assert!(
                    self.buffered.is_empty(),
                    "a stream must not end inside an envelope"
                );
                return None;
            };
            if let Ok(data) = frame
                .expect("the response body must be readable")
                .into_data()
            {
                self.buffered.extend_from_slice(&data);
            }
        }
    }
}

/// The error of an end of stream message, `{"error": {...}}` or `{}`.
fn end_error(payload: &[u8]) -> Option<ConnectError> {
    let mut end: buffa::serde_json::Value =
        buffa::serde_json::from_slice(payload).expect("an end of stream message must be JSON");
    let error = end.get_mut("error")?.take();
    Some(buffa::serde_json::from_value(error).expect("an end of stream error must decode"))
}
