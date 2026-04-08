//! Transport metadata for `store.query.v1.Detail` on successful query RPCs (same name and base64
//! protobuf encoding everywhere). Success responses **do not** embed `Detail` in protobuf bodies;
//! it is only carried here (and still attached to `google.rpc` errors as a packed `Detail`).
//!
//! - **Unary** `Get` / `Reduce`: set on `connectrpc::handler::Context::response_headers`.
//! - **Server-streaming** `Range`: set on `Context::trailers` so Connect emits it in the
//!   terminal END_STREAM envelope after all frames (full accrued read stats for the scan).

use base64::Engine;
use buffa::Message;
use connectrpc::Context;
use http::header::HeaderValue;

use crate::query::Detail;

/// Lowercase HTTP header name (ASCII; safe for HTTP/2).
pub const QUERY_DETAIL_RESPONSE_HEADER: &str = "x-store-query-detail-bin";

/// Encode [`Detail`] for [`QUERY_DETAIL_RESPONSE_HEADER`] (standard base64, no padding).
pub fn encode_query_detail_header_value(detail: &Detail) -> String {
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(detail.encode_to_vec())
}

/// Decode a value from [`QUERY_DETAIL_RESPONSE_HEADER`].
pub fn decode_query_detail_header_value(s: &str) -> Result<Detail, String> {
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
        .map_err(|e| e.to_string())?;
    Detail::decode_from_slice(&bytes).map_err(|e| e.to_string())
}

/// Attach encoded [`Detail`] to unary success [`Context::response_headers`] (used by mocks/tests).
pub fn with_query_detail_response_header(mut ctx: Context, detail: &Detail) -> Context {
    if let Ok(v) = HeaderValue::from_str(&encode_query_detail_header_value(detail)) {
        if let Ok(name) = http::HeaderName::from_bytes(QUERY_DETAIL_RESPONSE_HEADER.as_bytes()) {
            ctx.response_headers.insert(name, v);
        }
    }
    ctx
}

/// Attach encoded [`Detail`] to [`Context::trailers`] for server-streaming `Range`.
pub fn with_query_detail_trailer(mut ctx: Context, detail: &Detail) -> Context {
    if let Ok(v) = HeaderValue::from_str(&encode_query_detail_header_value(detail)) {
        if let Ok(name) = http::HeaderName::from_bytes(QUERY_DETAIL_RESPONSE_HEADER.as_bytes()) {
            ctx.set_trailer(name, v);
        }
    }
    ctx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_detail_header() {
        let detail = Detail {
            sequence_number: 42,
            read_stats: [("read_bytes".to_string(), 3)].into_iter().collect(),
            ..Default::default()
        };
        let s = encode_query_detail_header_value(&detail);
        let back = decode_query_detail_header_value(&s).unwrap();
        assert_eq!(back.sequence_number, detail.sequence_number);
        assert_eq!(back.read_stats.get("read_bytes"), Some(&3u64));
    }
}
