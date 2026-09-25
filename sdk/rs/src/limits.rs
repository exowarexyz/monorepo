//! Put validation limits and shared transport budgets.

use buffa::{encoding::varint_len, types::bytes_encoded_len};

pub use crate::keys::MAX_KEY_LEN;

pub const MAX_PUT_ENTRIES: usize = 2_000_000;
pub const MAX_REQUEST_MESSAGE_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_VALUE_LEN: usize = 32 * 1024 * 1024;

// A stored batch adds sequence metadata to a full-size request. JSON reads also add
// base64 expansion, so responses get double the request budget.
pub const MAX_RESPONSE_MESSAGE_BYTES: usize = 2 * MAX_REQUEST_MESSAGE_BYTES;
pub const MAX_RESPONSE_ELEMENT_MEMORY_BYTES: usize = 256 * 1024 * 1024;

pub const INGEST_ERROR_DOMAIN: &str = "log.ingest";
pub const PUT_TOO_LARGE_REASON: &str = "PUT_TOO_LARGE";

/// Encoded contribution of one physical key/value pair to a protobuf `PutRequest`.
/// Includes the repeated entry framing and omits empty byte fields.
pub fn put_entry_encoded_len(key: &[u8], value: &[u8]) -> usize {
    // Proto3 omits empty byte fields. All three field tags occupy one byte.
    let key_len = if key.is_empty() {
        0
    } else {
        1 + bytes_encoded_len(key)
    };
    let value_len = if value.is_empty() {
        0
    } else {
        1 + bytes_encoded_len(value)
    };
    let entry_len = key_len + value_len;
    1 + varint_len(entry_len as u64) + entry_len
}

/// Exact encoded size of a protobuf `PutRequest` carrying `kvs`.
pub fn put_encoded_len<'a>(kvs: impl IntoIterator<Item = (&'a [u8], &'a [u8])>) -> usize {
    kvs.into_iter()
        .map(|(key, value)| put_entry_encoded_len(key, value))
        .sum()
}

/// The entry count and limit reported by an ingest size rejection.
#[derive(Debug, Clone, Copy, Eq, PartialEq, thiserror::Error)]
#[error("put has {entries} entries, exceeding the limit of {max_entries}")]
pub struct PutTooLarge {
    pub entries: usize,
    pub max_entries: usize,
}
