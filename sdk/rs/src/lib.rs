//! Store Rust SDK Client.
//!
//! Provides typed access to the store put/get/query APIs plus
//! HTTP health/readiness probes.
//!
//! ## Errors
//!
//! RPC failures surface as [`ClientError::Rpc`] carrying a native [`ConnectError`]. Use
//! [`ClientError::decoded_rpc_error`] or [`StoreClient::decode_error_details`] to unpack
//! protobuf `google.rpc` details (and `store.query.v1.Detail` on query RPC errors), not string parsing.
//! Idempotent reads honor `google.rpc.RetryInfo` when deciding backoff (see `retry_delay_for_error`).

#[cfg(not(target_arch = "wasm32"))]
mod client;
#[cfg(not(target_arch = "wasm32"))]
mod credential;
pub mod keys;
pub mod kv_codec;
pub mod limits;
pub mod proto;
pub mod prune_policy;
pub mod retention;
pub mod selector;
pub mod stream_filter;
#[cfg(not(target_arch = "wasm32"))]
pub use client::*;
pub use connectrpc::{ConnectError, ErrorCode};
#[cfg(not(target_arch = "wasm32"))]
pub use credential::API_KEY_ENV;
pub use keys::{Key, KeyMut, KeyValidationError, Prefix, PrefixError, Value, MAX_KEY_LEN};
pub use proto::*;
#[cfg(not(target_arch = "wasm32"))]
extern crate self as exoware_proto;
