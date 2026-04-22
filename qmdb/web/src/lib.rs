extern crate self as connectrpc;
extern crate self as exoware_qmdb_core;
extern crate self as exoware_sdk_rs;

use std::collections::HashMap;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::Bytes;
use commonware_codec::{Encode, Read};
use commonware_cryptography::{Digest, Sha256};
use commonware_storage::mmr::{verification, Location, Position};
use commonware_storage::qmdb::{
    any::{
        ordered::variable::Operation as OrderedOperation,
        unordered::variable::Operation as UnorderedOperation,
    },
    keyless::Operation as KeylessOperation,
};
use futures::{FutureExt, Stream, StreamExt};
use js_sys::{Array, BigInt, Function, Object, Promise, Reflect, Uint8Array};
use send_wrapper::SendWrapper;
use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

#[path = "../../../sdk-rs/src/keys.rs"]
pub mod keys;

pub mod kv_codec {
    #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct Utf8(pub String);

    impl std::ops::Deref for Utf8 {
        type Target = str;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl From<String> for Utf8 {
        fn from(value: String) -> Self {
            Self(value)
        }
    }

    impl From<&str> for Utf8 {
        fn from(value: &str) -> Self {
            Self(value.to_string())
        }
    }
}

pub mod match_key {
    use super::kv_codec::Utf8;

    #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct MatchKey {
        pub reserved_bits: u8,
        pub prefix: u16,
        pub payload_regex: Utf8,
    }
}

pub mod stream_filter {
    use super::match_key::MatchKey;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct StreamFilter {
        pub match_keys: Vec<MatchKey>,
    }
}

mod connectrpc_types {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ErrorCode {
        Aborted,
        ResourceExhausted,
        Unavailable,
        Unknown,
    }
}

pub use connectrpc_types::ErrorCode;

#[derive(Debug, Clone)]
pub struct RpcError {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ClientError {
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("RPC error ({0:?}): {1}")]
    Rpc(ErrorCode, String),
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    #[error("wire format error: {0}")]
    WireFormat(String),
}

impl ClientError {
    pub fn rpc_code(&self) -> Option<connectrpc::ErrorCode> {
        match self {
            Self::Rpc(code, _) => Some(*code),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RangeMode {
    Forward,
    Reverse,
}

#[derive(Clone, Debug, Default)]
pub struct StoreClient;

impl StoreClient {
    pub fn new(_url: &str) -> Self {
        Self
    }
}

#[path = "../../core/src/error.rs"]
pub mod error;
#[path = "../../core/src/read_store.rs"]
pub mod read_store;
#[path = "../../core/src/codec.rs"]
pub mod codec;
#[path = "../../core/src/proof.rs"]
pub mod proof;
#[path = "../../core/src/stream.rs"]
pub mod core_stream;

#[path = "../../src/auth.rs"]
mod auth;
#[path = "../../src/core.rs"]
mod core;
#[path = "../../src/keyless.rs"]
mod keyless;
#[path = "../../src/ordered.rs"]
mod ordered;
#[path = "../../src/storage.rs"]
mod storage;
#[path = "../../src/stream/driver.rs"]
pub mod stream_driver;
#[path = "../../src/unordered.rs"]
mod unordered;

pub mod stream {
    pub use crate::core_stream::{Accumulator, ClosedBatch, Family};
    pub use crate::stream_driver as driver;
}

pub use error::QmdbError;
pub use proof::{
    OperationRangeCheckpoint, RawMmrProof, VariantRoot, VerifiedCurrentRange, VerifiedKeyValue,
    VerifiedMultiOperations, VerifiedOperationRange, VerifiedVariantRange,
};
pub use read_store::{ReadSession, ReadStore, ReadSubscription, SubscriptionEntry, SubscriptionFrame};

pub const MAX_OPERATION_SIZE: usize = u16::MAX as usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QmdbVariant {
    Any,
    Current,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionedValue<K, V> {
    pub key: K,
    pub location: Location,
    pub value: Option<V>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentBoundaryState<D: Digest, const N: usize> {
    pub root: D,
    pub chunks: Vec<(u64, [u8; N])>,
    pub grafted_nodes: Vec<(Position, D)>,
}

#[derive(Clone, Debug, Default)]
pub struct SdkReadStore;

impl SdkReadStore {
    pub fn new(_client: StoreClient) -> Self {
        Self
    }
}

#[async_trait]
impl ReadStore for SdkReadStore {
    fn create_session(&self) -> Box<dyn ReadSession> {
        panic!("StoreClient-backed constructors are unavailable in wasm; use JS read-store adapters")
    }

    fn create_session_with_sequence(&self, _sequence: u64) -> Box<dyn ReadSession> {
        panic!("StoreClient-backed constructors are unavailable in wasm; use JS read-store adapters")
    }

    async fn subscribe(
        &self,
        _filter: stream_filter::StreamFilter,
        _since: Option<u64>,
    ) -> Result<Box<dyn ReadSubscription>, ClientError> {
        panic!("StoreClient-backed constructors are unavailable in wasm; use JS read-store adapters")
    }
}

#[derive(Clone)]
struct JsReadStore {
    adapter: SendWrapper<JsValue>,
}

impl JsReadStore {
    fn new(adapter: JsValue) -> Self {
        Self {
            adapter: SendWrapper::new(adapter),
        }
    }
}

struct JsReadSession {
    adapter: SendWrapper<JsValue>,
    min_sequence: Option<u64>,
}

struct JsReadSubscription {
    iterator: SendWrapper<JsValue>,
}

struct SendJsFuture {
    inner: SendWrapper<JsFuture>,
}

impl SendJsFuture {
    fn new(value: JsValue) -> Self {
        Self {
            inner: SendWrapper::new(JsFuture::from(Promise::resolve(&value))),
        }
    }
}

impl Future for SendJsFuture {
    type Output = Result<JsValue, JsValue>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut *self.inner).poll(cx)
    }
}

fn js_error(message: impl Into<String>) -> ClientError {
    ClientError::Http(message.into())
}

fn js_key(name: &str) -> JsValue {
    JsValue::from_str(name)
}

fn value_to_u64(value: &JsValue, label: &str) -> Result<u64, ClientError> {
    if let Some(num) = value.as_f64() {
        if num >= 0.0 && num.fract() == 0.0 && num <= u64::MAX as f64 {
            return Ok(num as u64);
        }
    }
    if value.is_bigint() {
        let bigint = value
            .clone()
            .dyn_into::<BigInt>()
            .map_err(|_| js_error(format!("{label} is not a bigint")))?;
        let s = bigint
            .to_string(10)
            .map_err(|_| js_error(format!("cannot stringify bigint {label}")))?;
        return s
            .as_string()
            .ok_or_else(|| js_error(format!("cannot read bigint {label} as string")))?
            .parse::<u64>()
            .map_err(|e| js_error(format!("cannot parse bigint {label}: {e}")));
    }
    Err(js_error(format!("{label} is not a u64-compatible value")))
}

fn optional_u64_to_js(value: Option<u64>) -> JsValue {
    value
        .map(BigInt::from)
        .map(JsValue::from)
        .unwrap_or(JsValue::UNDEFINED)
}

fn bytes_to_js(bytes: &[u8]) -> JsValue {
    Uint8Array::from(bytes).into()
}

fn bytes_from_js(value: &JsValue, label: &str) -> Result<Vec<u8>, ClientError> {
    if value.is_null() || value.is_undefined() {
        return Err(js_error(format!("{label} is missing")));
    }
    Ok(Uint8Array::new(value).to_vec())
}

fn get_property(target: &JsValue, key: &str) -> Result<JsValue, ClientError> {
    Reflect::get(target, &js_key(key)).map_err(|err| {
        js_error(format!(
            "failed to read property {key}: {}",
            js_error_to_string(&err)
        ))
    })
}

fn get_method(target: &JsValue, name: &str) -> Result<Function, ClientError> {
    get_property(target, name)?
        .dyn_into::<Function>()
        .map_err(|_| js_error(format!("property {name} is not a function")))
}

async fn await_js(value: JsValue) -> Result<JsValue, ClientError> {
    SendJsFuture::new(value)
        .await
        .map_err(|err| js_error(js_error_to_string(&err)))
}

fn js_error_to_string(value: &JsValue) -> String {
    value
        .as_string()
        .or_else(|| {
            value
                .dyn_ref::<js_sys::Error>()
                .map(|err| err.to_string().as_string().unwrap_or_else(|| "Error".to_string()))
        })
        .unwrap_or_else(|| format!("{value:?}"))
}

async fn call_method1(target: &JsValue, name: &str, a0: &JsValue) -> Result<JsValue, ClientError> {
    let method = get_method(target, name)?;
    let result = method
        .call1(target, a0)
        .map_err(|err| js_error(format!("calling {name} failed: {}", js_error_to_string(&err))))?;
    await_js(result).await
}

async fn call_method2(
    target: &JsValue,
    name: &str,
    a0: &JsValue,
    a1: &JsValue,
) -> Result<JsValue, ClientError> {
    let method = get_method(target, name)?;
    let result = method
        .call2(target, a0, a1)
        .map_err(|err| js_error(format!("calling {name} failed: {}", js_error_to_string(&err))))?;
    await_js(result).await
}

async fn call_method3(
    target: &JsValue,
    name: &str,
    a0: &JsValue,
    a1: &JsValue,
    a2: &JsValue,
) -> Result<JsValue, ClientError> {
    let method = get_method(target, name)?;
    let result = method
        .call3(target, a0, a1, a2)
        .map_err(|err| js_error(format!("calling {name} failed: {}", js_error_to_string(&err))))?;
    await_js(result).await
}

async fn call_method5(
    target: &JsValue,
    name: &str,
    a0: &JsValue,
    a1: &JsValue,
    a2: &JsValue,
    a3: &JsValue,
    a4: &JsValue,
) -> Result<JsValue, ClientError> {
    let method = get_method(target, name)?;
    let result = Reflect::apply(
        method.as_ref(),
        target,
        &Array::of5(a0, a1, a2, a3, a4),
    )
    .map_err(|err| js_error(format!("calling {name} failed: {}", js_error_to_string(&err))))?;
    await_js(result).await
}

fn entry_from_js(value: &JsValue) -> Result<(Bytes, Bytes), ClientError> {
    let key = bytes_from_js(&get_property(value, "key")?, "entry.key")?;
    let val = bytes_from_js(&get_property(value, "value")?, "entry.value")?;
    Ok((Bytes::from(key), Bytes::from(val)))
}

fn entries_from_js(value: &JsValue) -> Result<Vec<(Bytes, Bytes)>, ClientError> {
    let arr = Array::from(value);
    let mut entries = Vec::with_capacity(arr.length() as usize);
    for item in arr.iter() {
        entries.push(entry_from_js(&item)?);
    }
    Ok(entries)
}

fn frame_from_js(value: &JsValue) -> Result<SubscriptionFrame, ClientError> {
    let sequence_number = value_to_u64(&get_property(value, "sequenceNumber")?, "frame.sequenceNumber")?;
    let entries_value = get_property(value, "entries")?;
    let entries = entries_from_js(&entries_value)?
        .into_iter()
        .map(|(key, value)| SubscriptionEntry { key, value })
        .collect();
    Ok(SubscriptionFrame {
        sequence_number,
        entries,
    })
}

fn filter_to_js(filter: &stream_filter::StreamFilter) -> JsValue {
    let out = Array::new();
    for mk in &filter.match_keys {
        let obj = Object::new();
        let _ = Reflect::set(
            &obj,
            &js_key("reservedBits"),
            &JsValue::from_f64(f64::from(mk.reserved_bits)),
        );
        let _ = Reflect::set(
            &obj,
            &js_key("prefix"),
            &JsValue::from_f64(f64::from(mk.prefix)),
        );
        let _ = Reflect::set(
            &obj,
            &js_key("payloadRegex"),
            &JsValue::from_str(&mk.payload_regex.0),
        );
        out.push(&obj);
    }
    out.into()
}

#[async_trait]
impl ReadSession for JsReadSession {
    async fn get(&self, key: &keys::Key) -> Result<Option<Bytes>, ClientError> {
        let value = call_method2(
            &self.adapter,
            "get",
            &bytes_to_js(key.as_ref()),
            &optional_u64_to_js(self.min_sequence),
        )
        .await?;
        if value.is_null() || value.is_undefined() {
            return Ok(None);
        }
        Ok(Some(Bytes::from(bytes_from_js(&value, "get result")?)))
    }

    async fn get_many(
        &self,
        keys: &[&keys::Key],
        batch_size: u32,
    ) -> Result<HashMap<keys::Key, Bytes>, ClientError> {
        let js_keys = Array::new();
        for key in keys {
            js_keys.push(&bytes_to_js(key.as_ref()));
        }
        let result = call_method3(
            &self.adapter,
            "getMany",
            &js_keys.into(),
            &JsValue::from_f64(f64::from(batch_size)),
            &optional_u64_to_js(self.min_sequence),
        )
        .await?;
        Ok(entries_from_js(&result)?
            .into_iter()
            .collect::<HashMap<_, _>>())
    }

    async fn range(
        &self,
        start: &keys::Key,
        end: &keys::Key,
        limit: usize,
    ) -> Result<Vec<(keys::Key, Bytes)>, ClientError> {
        self.range_with_mode(start, end, limit, RangeMode::Forward)
            .await
    }

    async fn range_with_mode(
        &self,
        start: &keys::Key,
        end: &keys::Key,
        limit: usize,
        mode: RangeMode,
    ) -> Result<Vec<(keys::Key, Bytes)>, ClientError> {
        let mode = match mode {
            RangeMode::Forward => JsValue::from_str("forward"),
            RangeMode::Reverse => JsValue::from_str("reverse"),
        };
        let result = call_method5(
            &self.adapter,
            "range",
            &bytes_to_js(start.as_ref()),
            &bytes_to_js(end.as_ref()),
            &JsValue::from_f64(limit as f64),
            &mode,
            &optional_u64_to_js(self.min_sequence),
        )
        .await?;
        entries_from_js(&result)
    }
}

#[async_trait]
impl ReadSubscription for JsReadSubscription {
    async fn next(&mut self) -> Result<Option<SubscriptionFrame>, ClientError> {
        let result = call_method1(&self.iterator, "next", &JsValue::UNDEFINED).await?;
        let done = get_property(&result, "done")?.as_bool().unwrap_or(false);
        if done {
            return Ok(None);
        }
        let value = get_property(&result, "value")?;
        Ok(Some(frame_from_js(&value)?))
    }
}

#[async_trait]
impl ReadStore for JsReadStore {
    fn create_session(&self) -> Box<dyn ReadSession> {
        Box::new(JsReadSession {
            adapter: self.adapter.clone(),
            min_sequence: None,
        })
    }

    fn create_session_with_sequence(&self, sequence: u64) -> Box<dyn ReadSession> {
        Box::new(JsReadSession {
            adapter: self.adapter.clone(),
            min_sequence: Some(sequence),
        })
    }

    async fn subscribe(
        &self,
        filter: stream_filter::StreamFilter,
        since: Option<u64>,
    ) -> Result<Box<dyn ReadSubscription>, ClientError> {
        let iterator = call_method2(
            &self.adapter,
            "subscribe",
            &filter_to_js(&filter),
            &optional_u64_to_js(since),
        )
        .await?;
        Ok(Box::new(JsReadSubscription {
            iterator: SendWrapper::new(iterator),
        }))
    }
}

fn serializer() -> Serializer {
    Serializer::new().serialize_large_number_types_as_bigints(true)
}

fn to_js<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    value
        .serialize(&serializer())
        .map_err(|err| JsValue::from_str(&err.to_string()))
}

fn to_js_error(err: impl std::fmt::Display) -> JsValue {
    js_sys::Error::new(&err.to_string()).into()
}

fn value_range_cfg() -> <Vec<u8> as Read>::Cfg {
    ((0..=MAX_OPERATION_SIZE).into(), ())
}

fn ordered_update_row_cfg() -> (<Vec<u8> as Read>::Cfg, <Vec<u8> as Read>::Cfg) {
    (value_range_cfg(), value_range_cfg())
}

fn ordered_op_cfg() -> <OrderedOperation<Vec<u8>, Vec<u8>> as Read>::Cfg {
    (value_range_cfg(), value_range_cfg())
}

fn unordered_op_cfg() -> <UnorderedOperation<Vec<u8>, Vec<u8>> as Read>::Cfg {
    (value_range_cfg(), value_range_cfg())
}

fn keyless_value_cfg() -> <Vec<u8> as Read>::Cfg {
    value_range_cfg()
}

const ORDERED_CURRENT_CHUNK_BYTES: usize = 32;

type OrderedBytesClient =
    ordered::OrderedClient<Sha256, Vec<u8>, Vec<u8>, ORDERED_CURRENT_CHUNK_BYTES>;
type UnorderedBytesClient = unordered::UnorderedClient<Sha256, Vec<u8>, Vec<u8>>;
type KeylessBytesClient = keyless::KeylessClient<Sha256, Vec<u8>>;

#[derive(Clone, Debug, PartialEq, Eq)]
enum ImmutableBytesOperation {
    Set { key: Vec<u8>, value: Vec<u8> },
    Commit { metadata: Option<Vec<u8>> },
}

#[derive(Clone)]
struct ImmutableBytesClient {
    store: Arc<dyn ReadStore>,
    value_cfg: <Vec<u8> as Read>::Cfg,
    key_size_bytes: usize,
}

impl ImmutableBytesClient {
    fn from_read_store(
        store: Arc<dyn ReadStore>,
        value_cfg: <Vec<u8> as Read>::Cfg,
        key_size_bytes: usize,
    ) -> Result<Self, QmdbError> {
        if key_size_bytes == 0 {
            return Err(QmdbError::CorruptData(
                "immutable key size must be greater than zero".to_string(),
            ));
        }
        Ok(Self {
            store,
            value_cfg,
            key_size_bytes,
        })
    }

    async fn writer_location_watermark(&self) -> Result<Option<Location>, QmdbError> {
        core::retry_transient_post_ingest_query(|| {
            let session = self.store.create_session();
            async move {
                auth::read_latest_auth_watermark(
                    session.as_ref(),
                    auth::AuthenticatedBackendNamespace::Immutable,
                )
                .await
            }
        })
        .await
    }

    async fn root_at(&self, watermark: Location) -> Result<commonware_cryptography::sha256::Digest, QmdbError> {
        let namespace = auth::AuthenticatedBackendNamespace::Immutable;
        let session = self.store.create_session();
        auth::require_published_auth_watermark(session.as_ref(), namespace, watermark).await?;
        auth::compute_auth_root::<Sha256>(session.as_ref(), namespace, watermark).await
    }

    async fn operation_range_checkpoint(
        &self,
        watermark: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<OperationRangeCheckpoint<commonware_cryptography::sha256::Digest>, QmdbError> {
        let session = self.store.create_session();
        self.operation_range_checkpoint_in_session(
            session.as_ref(),
            watermark,
            start_location,
            max_locations,
        )
        .await
    }

    async fn operation_range_checkpoint_in_session(
        &self,
        session: &dyn ReadSession,
        watermark: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<OperationRangeCheckpoint<commonware_cryptography::sha256::Digest>, QmdbError> {
        if max_locations == 0 {
            return Err(QmdbError::InvalidRangeLength);
        }
        let namespace = auth::AuthenticatedBackendNamespace::Immutable;
        auth::require_published_auth_watermark(session, namespace, watermark).await?;
        let count = watermark
            .checked_add(1)
            .ok_or_else(|| QmdbError::CorruptData("watermark overflow".to_string()))?;
        if start_location >= count {
            return Err(QmdbError::RangeStartOutOfBounds {
                start: start_location,
                count,
            });
        }
        let end = start_location
            .saturating_add(max_locations as u64)
            .min(count);
        let storage = storage::AuthKvMmrStorage {
            session,
            namespace,
            mmr_size: codec::mmr_size_for_watermark(watermark)?,
            _marker: PhantomData::<commonware_cryptography::sha256::Digest>,
        };
        let proof = verification::range_proof(&storage, start_location..end)
            .await
            .map_err(|e| QmdbError::CommonwareMmr(e.to_string()))?;
        let checkpoint = OperationRangeCheckpoint {
            watermark,
            root: auth::compute_auth_root::<Sha256>(session, namespace, watermark).await?,
            start_location,
            proof: proof.into(),
            encoded_operations: auth::load_auth_operation_bytes_range(
                session,
                namespace,
                start_location,
                end,
            )
            .await?,
        };
        if !checkpoint.verify::<Sha256>() {
            return Err(QmdbError::CorruptData(
                "immutable checkpoint proof failed verification".to_string(),
            ));
        }
        Ok(checkpoint)
    }

    async fn operation_range_proof_with_read_floor(
        &self,
        read_floor_sequence: u64,
        watermark: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<VerifiedOperationRange<commonware_cryptography::sha256::Digest, ImmutableBytesOperation>, QmdbError> {
        let session = self.store.create_session_with_sequence(read_floor_sequence);
        let checkpoint = self
            .operation_range_checkpoint_in_session(
                session.as_ref(),
                watermark,
                start_location,
                max_locations,
            )
            .await?;
        let operations = checkpoint
            .encoded_operations
            .iter()
            .enumerate()
            .map(|(offset, bytes)| {
                let location = checkpoint.start_location + offset as u64;
                decode_immutable_operation(bytes, self.key_size_bytes, &self.value_cfg).map_err(
                    |err| {
                        QmdbError::CorruptData(format!(
                            "failed to decode immutable operation at location {location}: {err}"
                        ))
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(VerifiedOperationRange {
            resume_sequence_number: Some(read_floor_sequence),
            watermark: checkpoint.watermark,
            root: checkpoint.root,
            start_location: checkpoint.start_location,
            operations,
        })
    }

    async fn operation_range_proof(
        &self,
        watermark: Location,
        start_location: Location,
        max_locations: u32,
    ) -> Result<VerifiedOperationRange<commonware_cryptography::sha256::Digest, ImmutableBytesOperation>, QmdbError> {
        let checkpoint = self
            .operation_range_checkpoint(watermark, start_location, max_locations)
            .await?;
        let operations = checkpoint
            .encoded_operations
            .iter()
            .enumerate()
            .map(|(offset, bytes)| {
                let location = checkpoint.start_location + offset as u64;
                decode_immutable_operation(bytes, self.key_size_bytes, &self.value_cfg).map_err(
                    |err| {
                        QmdbError::CorruptData(format!(
                            "failed to decode immutable operation at location {location}: {err}"
                        ))
                    },
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(VerifiedOperationRange {
            resume_sequence_number: None,
            watermark: checkpoint.watermark,
            root: checkpoint.root,
            start_location: checkpoint.start_location,
            operations,
        })
    }

    async fn get_at(
        &self,
        key: &[u8],
        watermark: Location,
    ) -> Result<Option<VersionedValue<Vec<u8>, Vec<u8>>>, QmdbError> {
        if key.len() != self.key_size_bytes {
            return Err(QmdbError::CorruptData(format!(
                "immutable key length mismatch: expected {}, got {}",
                self.key_size_bytes,
                key.len()
            )));
        }
        let namespace = auth::AuthenticatedBackendNamespace::Immutable;
        let session = self.store.create_session();
        auth::require_published_auth_watermark(session.as_ref(), namespace, watermark).await?;
        let Some((row_key, row_value)) =
            auth::load_latest_auth_immutable_update_row(session.as_ref(), watermark, key).await?
        else {
            return Ok(None);
        };
        let location = auth::decode_auth_immutable_update_location(&row_key)?;
        let decoded_row =
            decode_immutable_update_row(&row_value, self.key_size_bytes, &self.value_cfg)?;
        if decoded_row.key != key {
            return Err(QmdbError::CorruptData(format!(
                "authenticated immutable update row key mismatch at location {location}"
            )));
        }
        let verified = self.operation_range_proof(watermark, location, 1).await?;
        let Some(operation) = verified.operations.into_iter().next() else {
            return Err(QmdbError::CorruptData(format!(
                "immutable proof for location {location} returned no operations"
            )));
        };
        match operation {
            ImmutableBytesOperation::Set {
                key: op_key,
                value,
            } if op_key == key => {
                if decoded_row.value.as_ref() != Some(&value) {
                    return Err(QmdbError::CorruptData(format!(
                        "immutable update row value mismatch at location {location}"
                    )));
                }
                Ok(Some(VersionedValue {
                    key: op_key,
                    location,
                    value: Some(value),
                }))
            }
            ImmutableBytesOperation::Set { .. } => Err(QmdbError::CorruptData(format!(
                "immutable proof key mismatch at location {location}"
            ))),
            ImmutableBytesOperation::Commit { .. } => Err(QmdbError::CorruptData(format!(
                "immutable update row points at commit location {location}"
            ))),
        }
    }

    async fn stream_batches(
        self: Arc<Self>,
        since: Option<u64>,
    ) -> Result<stream_driver::BatchProofStream<VerifiedOperationRange<commonware_cryptography::sha256::Digest, ImmutableBytesOperation>>, QmdbError>
    where
        Self: 'static,
    {
        let (classify, filter) =
            stream_driver::authenticated_classify_and_filter(auth::AuthenticatedBackendNamespace::Immutable);
        let sub = self.store.subscribe(filter, since).await?;

        let build_proof: stream_driver::BuildProof<
            VerifiedOperationRange<commonware_cryptography::sha256::Digest, ImmutableBytesOperation>,
        > = Arc::new(
            move |read_floor_sequence: u64, watermark: Location, start: Location, count: u32| {
                let me = self.clone();
                async move {
                    me.operation_range_proof_with_read_floor(
                        read_floor_sequence,
                        watermark,
                        start,
                        count,
                    )
                    .await
                }
                .boxed()
            },
        );

        Ok(stream_driver::BatchProofStream::new(sub, classify, build_proof))
    }
}

struct DecodedImmutableUpdateRow {
    key: Vec<u8>,
    value: Option<Vec<u8>>,
}

fn decode_immutable_update_row(
    bytes: &[u8],
    key_size_bytes: usize,
    value_cfg: &<Vec<u8> as Read>::Cfg,
) -> Result<DecodedImmutableUpdateRow, QmdbError> {
    if bytes.len() < key_size_bytes {
        return Err(QmdbError::CorruptData(format!(
            "immutable update row shorter than key size {key_size_bytes}"
        )));
    }
    let key = bytes[..key_size_bytes].to_vec();
    let mut tail = &bytes[key_size_bytes..];
    let value = Option::<Vec<u8>>::read_cfg(&mut tail, value_cfg)
        .map_err(|e| QmdbError::CorruptData(format!("immutable update row decode: {e}")))?;
    if !tail.is_empty() {
        return Err(QmdbError::CorruptData(format!(
            "immutable update row has {} trailing bytes",
            tail.len()
        )));
    }
    Ok(DecodedImmutableUpdateRow { key, value })
}

fn decode_immutable_operation(
    bytes: &[u8],
    key_size_bytes: usize,
    value_cfg: &<Vec<u8> as Read>::Cfg,
) -> Result<ImmutableBytesOperation, String> {
    let Some((&tag, rest)) = bytes.split_first() else {
        return Err("empty immutable operation".to_string());
    };
    match tag {
        0 => {
            if rest.len() < key_size_bytes {
                return Err(format!(
                    "immutable set shorter than key size {key_size_bytes}"
                ));
            }
            let key = rest[..key_size_bytes].to_vec();
            let mut value_bytes = &rest[key_size_bytes..];
            let value = Vec::<u8>::read_cfg(&mut value_bytes, value_cfg)
                .map_err(|e| format!("immutable set value decode: {e}"))?;
            if !value_bytes.is_empty() {
                return Err(format!(
                    "immutable set has {} trailing bytes",
                    value_bytes.len()
                ));
            }
            Ok(ImmutableBytesOperation::Set { key, value })
        }
        1 => {
            let mut metadata_bytes = rest;
            let metadata = Option::<Vec<u8>>::read_cfg(&mut metadata_bytes, value_cfg)
                .map_err(|e| format!("immutable commit metadata decode: {e}"))?;
            if !metadata_bytes.is_empty() {
                return Err(format!(
                    "immutable commit has {} trailing bytes",
                    metadata_bytes.len()
                ));
            }
            Ok(ImmutableBytesOperation::Commit { metadata })
        }
        other => Err(format!("invalid immutable operation tag {other}")),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VersionedValueJs {
    key: Vec<u8>,
    location: u64,
    value: Option<Vec<u8>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
enum OrderedOperationJs {
    Delete { key: Vec<u8> },
    Update { key: Vec<u8>, value: Vec<u8>, next_key: Vec<u8> },
    CommitFloor { metadata: Option<Vec<u8>>, inactivity_floor: u64 },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
enum UnorderedOperationJs {
    Delete { key: Vec<u8> },
    Update { key: Vec<u8>, value: Vec<u8> },
    CommitFloor { metadata: Option<Vec<u8>>, inactivity_floor: u64 },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
enum ImmutableOperationJs {
    Set { key: Vec<u8>, value: Vec<u8> },
    Commit { metadata: Option<Vec<u8>> },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
enum KeylessOperationJs {
    Append { value: Vec<u8> },
    Commit { metadata: Option<Vec<u8>> },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationRangeJs<Op> {
    resume_sequence_number: Option<u64>,
    watermark: u64,
    root: Vec<u8>,
    start_location: u64,
    operations: Vec<Op>,
}

fn versioned_value_to_js(value: VersionedValue<Vec<u8>, Vec<u8>>) -> VersionedValueJs {
    VersionedValueJs {
        key: value.key,
        location: value.location.as_u64(),
        value: value.value,
    }
}

fn ordered_operation_to_js(value: OrderedOperation<Vec<u8>, Vec<u8>>) -> OrderedOperationJs {
    match value {
        OrderedOperation::Delete(key) => OrderedOperationJs::Delete { key },
        OrderedOperation::Update(update) => OrderedOperationJs::Update {
            key: update.key,
            value: update.value,
            next_key: update.next_key,
        },
        OrderedOperation::CommitFloor(metadata, inactivity_floor) => OrderedOperationJs::CommitFloor {
            metadata,
            inactivity_floor: inactivity_floor.as_u64(),
        },
    }
}

fn unordered_operation_to_js(value: UnorderedOperation<Vec<u8>, Vec<u8>>) -> UnorderedOperationJs {
    match value {
        UnorderedOperation::Delete(key) => UnorderedOperationJs::Delete { key },
        UnorderedOperation::Update(update) => UnorderedOperationJs::Update {
            key: update.0,
            value: update.1,
        },
        UnorderedOperation::CommitFloor(metadata, inactivity_floor) => UnorderedOperationJs::CommitFloor {
            metadata,
            inactivity_floor: inactivity_floor.as_u64(),
        },
    }
}

fn immutable_operation_to_js(value: ImmutableBytesOperation) -> ImmutableOperationJs {
    match value {
        ImmutableBytesOperation::Set { key, value } => ImmutableOperationJs::Set { key, value },
        ImmutableBytesOperation::Commit { metadata } => ImmutableOperationJs::Commit { metadata },
    }
}

fn keyless_operation_to_js(value: KeylessOperation<Vec<u8>>) -> KeylessOperationJs {
    match value {
        KeylessOperation::Append(value) => KeylessOperationJs::Append { value },
        KeylessOperation::Commit(metadata) => KeylessOperationJs::Commit { metadata },
    }
}

fn ordered_range_to_js(
    value: VerifiedOperationRange<commonware_cryptography::sha256::Digest, OrderedOperation<Vec<u8>, Vec<u8>>>,
) -> Result<JsValue, JsValue> {
    to_js(&OperationRangeJs {
        resume_sequence_number: value.resume_sequence_number,
        watermark: value.watermark.as_u64(),
        root: value.root.encode().to_vec(),
        start_location: value.start_location.as_u64(),
        operations: value.operations.into_iter().map(ordered_operation_to_js).collect(),
    })
}

fn unordered_range_to_js(
    value: VerifiedOperationRange<commonware_cryptography::sha256::Digest, UnorderedOperation<Vec<u8>, Vec<u8>>>,
) -> Result<JsValue, JsValue> {
    to_js(&OperationRangeJs {
        resume_sequence_number: value.resume_sequence_number,
        watermark: value.watermark.as_u64(),
        root: value.root.encode().to_vec(),
        start_location: value.start_location.as_u64(),
        operations: value.operations.into_iter().map(unordered_operation_to_js).collect(),
    })
}

fn immutable_range_to_js(
    value: VerifiedOperationRange<commonware_cryptography::sha256::Digest, ImmutableBytesOperation>,
) -> Result<JsValue, JsValue> {
    to_js(&OperationRangeJs {
        resume_sequence_number: value.resume_sequence_number,
        watermark: value.watermark.as_u64(),
        root: value.root.encode().to_vec(),
        start_location: value.start_location.as_u64(),
        operations: value.operations.into_iter().map(immutable_operation_to_js).collect(),
    })
}

fn keyless_range_to_js(
    value: VerifiedOperationRange<commonware_cryptography::sha256::Digest, KeylessOperation<Vec<u8>>>,
) -> Result<JsValue, JsValue> {
    to_js(&OperationRangeJs {
        resume_sequence_number: value.resume_sequence_number,
        watermark: value.watermark.as_u64(),
        root: value.root.encode().to_vec(),
        start_location: value.start_location.as_u64(),
        operations: value.operations.into_iter().map(keyless_operation_to_js).collect(),
    })
}

#[wasm_bindgen]
pub struct QmdbBatchStream {
    inner: Pin<Box<dyn Stream<Item = Result<JsValue, JsValue>>>>,
}

#[wasm_bindgen]
impl QmdbBatchStream {
    #[wasm_bindgen(js_name = next)]
    pub async fn next_js(&mut self) -> Result<JsValue, JsValue> {
        match self.inner.next().await {
            Some(result) => result,
            None => Ok(JsValue::UNDEFINED),
        }
    }
}

fn map_stream<S, T, F>(stream: S, mapper: F) -> QmdbBatchStream
where
    S: Stream<Item = Result<T, QmdbError>> + 'static,
    F: Fn(T) -> Result<JsValue, JsValue> + 'static,
{
    QmdbBatchStream {
        inner: Box::pin(stream.map(move |item| match item {
            Ok(value) => mapper(value),
            Err(err) => Err(to_js_error(err)),
        })),
    }
}

#[wasm_bindgen]
pub struct OrderedQmdbClient {
    inner: Arc<OrderedBytesClient>,
}

#[wasm_bindgen]
impl OrderedQmdbClient {
    #[wasm_bindgen(constructor)]
    pub fn new(adapter: JsValue) -> Self {
        let store = Arc::new(JsReadStore::new(adapter));
        Self {
            inner: Arc::new(OrderedBytesClient::from_read_store(
                store,
                ordered_op_cfg(),
                ordered_update_row_cfg(),
            )),
        }
    }

    #[wasm_bindgen(js_name = rootAt)]
    pub async fn root_at(&self, watermark: u64) -> Result<JsValue, JsValue> {
        let root = self
            .inner
            .root_at(Location::new(watermark))
            .await
            .map_err(to_js_error)?;
        to_js(&root.encode().to_vec())
    }

    #[wasm_bindgen(js_name = operationRangeProof)]
    pub async fn operation_range_proof(
        &self,
        watermark: u64,
        start_location: u64,
        max_locations: u32,
    ) -> Result<JsValue, JsValue> {
        ordered_range_to_js(
            self.inner
                .operation_range_proof(Location::new(watermark), Location::new(start_location), max_locations)
                .await
                .map_err(to_js_error)?,
        )
    }

    #[wasm_bindgen(js_name = streamBatches)]
    pub async fn stream_batches(&self, since: Option<u64>) -> Result<QmdbBatchStream, JsValue> {
        let stream = self
            .inner
            .clone()
            .stream_batches(since)
            .await
            .map_err(to_js_error)?;
        Ok(map_stream(stream, ordered_range_to_js))
    }
}

#[wasm_bindgen]
pub struct UnorderedQmdbClient {
    inner: Arc<UnorderedBytesClient>,
}

#[wasm_bindgen]
impl UnorderedQmdbClient {
    #[wasm_bindgen(constructor)]
    pub fn new(adapter: JsValue) -> Self {
        let store = Arc::new(JsReadStore::new(adapter));
        Self {
            inner: Arc::new(UnorderedBytesClient::from_read_store(
                store,
                unordered_op_cfg(),
                ordered_update_row_cfg(),
            )),
        }
    }

    #[wasm_bindgen(js_name = rootAt)]
    pub async fn root_at(&self, watermark: u64) -> Result<JsValue, JsValue> {
        let root = self
            .inner
            .root_at(Location::new(watermark))
            .await
            .map_err(to_js_error)?;
        to_js(&root.encode().to_vec())
    }

    #[wasm_bindgen(js_name = operationRangeProof)]
    pub async fn operation_range_proof(
        &self,
        watermark: u64,
        start_location: u64,
        max_locations: u32,
    ) -> Result<JsValue, JsValue> {
        unordered_range_to_js(
            self.inner
                .operation_range_proof(Location::new(watermark), Location::new(start_location), max_locations)
                .await
                .map_err(to_js_error)?,
        )
    }

    #[wasm_bindgen(js_name = streamBatches)]
    pub async fn stream_batches(&self, since: Option<u64>) -> Result<QmdbBatchStream, JsValue> {
        let stream = self
            .inner
            .clone()
            .stream_batches(since)
            .await
            .map_err(to_js_error)?;
        Ok(map_stream(stream, unordered_range_to_js))
    }
}

#[wasm_bindgen]
pub struct ImmutableQmdbClient {
    inner: Arc<ImmutableBytesClient>,
}

#[wasm_bindgen]
impl ImmutableQmdbClient {
    #[wasm_bindgen(constructor)]
    pub fn new(adapter: JsValue, key_size_bytes: u32) -> Result<Self, JsValue> {
        let store = Arc::new(JsReadStore::new(adapter));
        let inner = ImmutableBytesClient::from_read_store(
            store,
            value_range_cfg(),
            key_size_bytes as usize,
        )
        .map_err(to_js_error)?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    #[wasm_bindgen(js_name = writerLocationWatermark)]
    pub async fn writer_location_watermark(&self) -> Result<JsValue, JsValue> {
        to_js(
            &self
                .inner
                .writer_location_watermark()
                .await
                .map(|value| value.map(|location| location.as_u64()))
                .map_err(to_js_error)?,
        )
    }

    #[wasm_bindgen(js_name = rootAt)]
    pub async fn root_at(&self, watermark: u64) -> Result<JsValue, JsValue> {
        let root = self
            .inner
            .root_at(Location::new(watermark))
            .await
            .map_err(to_js_error)?;
        to_js(&root.encode().to_vec())
    }

    #[wasm_bindgen(js_name = getAt)]
    pub async fn get_at(&self, key: Vec<u8>, watermark: u64) -> Result<JsValue, JsValue> {
        let value = self
            .inner
            .get_at(&key, Location::new(watermark))
            .await
            .map_err(to_js_error)?
            .map(versioned_value_to_js);
        to_js(&value)
    }

    #[wasm_bindgen(js_name = operationRangeProof)]
    pub async fn operation_range_proof(
        &self,
        watermark: u64,
        start_location: u64,
        max_locations: u32,
    ) -> Result<JsValue, JsValue> {
        immutable_range_to_js(
            self.inner
                .operation_range_proof(Location::new(watermark), Location::new(start_location), max_locations)
                .await
                .map_err(to_js_error)?,
        )
    }

    #[wasm_bindgen(js_name = streamBatches)]
    pub async fn stream_batches(&self, since: Option<u64>) -> Result<QmdbBatchStream, JsValue> {
        let stream = self
            .inner
            .clone()
            .stream_batches(since)
            .await
            .map_err(to_js_error)?;
        Ok(map_stream(stream, immutable_range_to_js))
    }
}

#[wasm_bindgen]
pub struct KeylessQmdbClient {
    inner: Arc<KeylessBytesClient>,
}

#[wasm_bindgen]
impl KeylessQmdbClient {
    #[wasm_bindgen(constructor)]
    pub fn new(adapter: JsValue) -> Self {
        let store = Arc::new(JsReadStore::new(adapter));
        Self {
            inner: Arc::new(KeylessBytesClient::from_read_store(store, keyless_value_cfg())),
        }
    }

    #[wasm_bindgen(js_name = rootAt)]
    pub async fn root_at(&self, watermark: u64) -> Result<JsValue, JsValue> {
        let root = self
            .inner
            .root_at(Location::new(watermark))
            .await
            .map_err(to_js_error)?;
        to_js(&root.encode().to_vec())
    }

    #[wasm_bindgen(js_name = operationRangeProof)]
    pub async fn operation_range_proof(
        &self,
        watermark: u64,
        start_location: u64,
        max_locations: u32,
    ) -> Result<JsValue, JsValue> {
        keyless_range_to_js(
            self.inner
                .operation_range_proof(Location::new(watermark), Location::new(start_location), max_locations)
                .await
                .map_err(to_js_error)?,
        )
    }

    #[wasm_bindgen(js_name = streamBatches)]
    pub async fn stream_batches(&self, since: Option<u64>) -> Result<QmdbBatchStream, JsValue> {
        let stream = self
            .inner
            .clone()
            .stream_batches(since)
            .await
            .map_err(to_js_error)?;
        Ok(map_stream(stream, keyless_range_to_js))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use commonware_codec::FixedSize;
    use commonware_cryptography::Sha256;
    use commonware_storage::qmdb::immutable::Operation as ImmutableOperation;
    use commonware_utils::sequence::FixedBytes;
    use exoware_sdk_rs_real as real_sdk;
    use futures::StreamExt;
    use store_qmdb_native::ImmutableWriter;

    #[derive(Clone, Debug)]
    struct RealReadStore {
        client: real_sdk::StoreClient,
    }

    impl RealReadStore {
        fn new(client: real_sdk::StoreClient) -> Self {
            Self { client }
        }
    }

    struct RealReadSession {
        session: real_sdk::SerializableReadSession,
    }

    struct RealReadSubscription {
        subscription: real_sdk::StreamSubscription,
    }

    fn map_client_error(err: real_sdk::ClientError) -> ClientError {
        match err {
            real_sdk::ClientError::Http(err) => ClientError::Http(err.to_string()),
            real_sdk::ClientError::Rpc(err) => ClientError::Rpc(ErrorCode::Unknown, err.to_string()),
            real_sdk::ClientError::InvalidKeyLength { expected, got } => {
                ClientError::InvalidKeyLength { expected, got }
            }
            real_sdk::ClientError::WireFormat(message) => ClientError::WireFormat(message),
        }
    }

    fn to_real_mode(mode: RangeMode) -> real_sdk::RangeMode {
        match mode {
            RangeMode::Forward => real_sdk::RangeMode::Forward,
            RangeMode::Reverse => real_sdk::RangeMode::Reverse,
        }
    }

    fn to_real_filter(filter: stream_filter::StreamFilter) -> real_sdk::stream_filter::StreamFilter {
        real_sdk::stream_filter::StreamFilter {
            match_keys: filter
                .match_keys
                .into_iter()
                .map(|key| real_sdk::match_key::MatchKey {
                    reserved_bits: key.reserved_bits,
                    prefix: key.prefix,
                    payload_regex: real_sdk::kv_codec::Utf8::from(key.payload_regex.0),
                })
                .collect(),
        }
    }

    #[async_trait]
    impl ReadSession for RealReadSession {
        async fn get(&self, key: &keys::Key) -> Result<Option<Bytes>, ClientError> {
            self.session.get(key).await.map_err(map_client_error)
        }

        async fn get_many(
            &self,
            keys: &[&keys::Key],
            batch_size: u32,
        ) -> Result<HashMap<keys::Key, Bytes>, ClientError> {
            self.session
                .get_many(keys, batch_size)
                .await
                .map_err(map_client_error)?
                .collect()
                .await
                .map_err(map_client_error)
        }

        async fn range(
            &self,
            start: &keys::Key,
            end: &keys::Key,
            limit: usize,
        ) -> Result<Vec<(keys::Key, Bytes)>, ClientError> {
            self.session.range(start, end, limit).await.map_err(map_client_error)
        }

        async fn range_with_mode(
            &self,
            start: &keys::Key,
            end: &keys::Key,
            limit: usize,
            mode: RangeMode,
        ) -> Result<Vec<(keys::Key, Bytes)>, ClientError> {
            self.session
                .range_with_mode(start, end, limit, to_real_mode(mode))
                .await
                .map_err(map_client_error)
        }
    }

    #[async_trait]
    impl ReadSubscription for RealReadSubscription {
        async fn next(&mut self) -> Result<Option<SubscriptionFrame>, ClientError> {
            self.subscription
                .next()
                .await
                .map_err(map_client_error)
                .map(|frame| {
                    frame.map(|frame| SubscriptionFrame {
                        sequence_number: frame.sequence_number,
                        entries: frame
                            .entries
                            .into_iter()
                            .map(|entry| SubscriptionEntry {
                                key: entry.key,
                                value: entry.value,
                            })
                            .collect(),
                    })
                })
        }
    }

    #[async_trait]
    impl ReadStore for RealReadStore {
        fn create_session(&self) -> Box<dyn ReadSession> {
            Box::new(RealReadSession {
                session: self.client.create_session(),
            })
        }

        fn create_session_with_sequence(&self, sequence: u64) -> Box<dyn ReadSession> {
            Box::new(RealReadSession {
                session: self.client.create_session_with_sequence(sequence),
            })
        }

        async fn subscribe(
            &self,
            filter: stream_filter::StreamFilter,
            since: Option<u64>,
        ) -> Result<Box<dyn ReadSubscription>, ClientError> {
            Ok(Box::new(RealReadSubscription {
                subscription: self
                    .client
                    .stream()
                    .subscribe(to_real_filter(filter), since)
                    .await
                    .map_err(map_client_error)?,
            }))
        }
    }

    async fn local_store_client(
    ) -> (
        tempfile::TempDir,
        tokio::task::JoinHandle<()>,
        real_sdk::StoreClient,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let (jh, url) = exoware_simulator::spawn_for_test(dir.path())
            .await
            .expect("spawn simulator");
        let client = real_sdk::StoreClient::with_split_urls(&url, &url, &url, &url);
        (dir, jh, client)
    }

    #[tokio::test]
    async fn immutable_reader_supports_non_32_byte_keys_and_verified_streams() {
        let (_dir, _server, client) = local_store_client().await;
        let store = Arc::new(RealReadStore::new(client.clone()));
        let reader =
            ImmutableBytesClient::from_read_store(store, value_range_cfg(), 20).expect("reader");
        let writer: ImmutableWriter<Sha256, FixedBytes<20>, Vec<u8>> =
            ImmutableWriter::empty(client.clone());

        let key_a = FixedBytes::new([0x11; 20]);
        let key_b = FixedBytes::new([0x22; 20]);
        let ops = vec![
            ImmutableOperation::Set(key_a.clone(), b"alpha".to_vec()),
            ImmutableOperation::Set(key_b.clone(), b"beta".to_vec()),
        ];
        writer.upload_and_publish(&ops).await.expect("upload_and_publish");

        let watermark = reader
            .writer_location_watermark()
            .await
            .expect("writer watermark")
            .expect("published watermark");
        assert_eq!(watermark.as_u64(), 1);

        let got = reader
            .get_at(key_a.as_ref(), watermark)
            .await
            .expect("get_at")
            .expect("value");
        assert_eq!(got.key, key_a.as_ref());
        assert_eq!(got.value.as_deref(), Some(b"alpha".as_slice()));

        let verified = reader
            .operation_range_proof(watermark, Location::new(0), 2)
            .await
            .expect("range proof");
        assert_eq!(verified.operations.len(), 2);
        assert!(matches!(
            &verified.operations[0],
            ImmutableBytesOperation::Set { key, value }
                if key.as_slice() == key_a.as_ref() && value.as_slice() == b"alpha"
        ));
        assert!(matches!(
            &verified.operations[1],
            ImmutableBytesOperation::Set { key, value }
                if key.as_slice() == key_b.as_ref() && value.as_slice() == b"beta"
        ));

        let mut stream = Arc::new(reader)
            .stream_batches(Some(1))
            .await
            .expect("stream_batches");
        let streamed = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
            .await
            .expect("timeout")
            .expect("stream not closed")
            .expect("verified batch");
        assert_eq!(streamed.watermark, watermark);
        assert_eq!(streamed.operations, verified.operations);
    }

    #[tokio::test]
    async fn immutable_stream_rejects_tampered_proofs() {
        let (_dir, _server, client) = local_store_client().await;
        let store = Arc::new(RealReadStore::new(client.clone()));
        let reader =
            ImmutableBytesClient::from_read_store(store, value_range_cfg(), 20).expect("reader");
        let writer: ImmutableWriter<Sha256, FixedBytes<20>, Vec<u8>> =
            ImmutableWriter::empty(client.clone());

        let key_a = FixedBytes::new([0x11; 20]);
        let key_b = FixedBytes::new([0x22; 20]);
        let ops = vec![
            ImmutableOperation::Set(key_a.clone(), b"alpha".to_vec()),
            ImmutableOperation::Set(key_b.clone(), b"beta".to_vec()),
        ];
        writer.upload_and_publish(&ops).await.expect("upload_and_publish");

        let watermark = reader
            .writer_location_watermark()
            .await
            .expect("writer watermark")
            .expect("published watermark");
        let checkpoint = reader
            .operation_range_checkpoint(watermark, Location::new(0), 2)
            .await
            .expect("checkpoint");
        let (peak_pos, _, _) = checkpoint
            .reconstruct_peaks::<Sha256>()
            .expect("reconstruct peaks")
            .into_iter()
            .next()
            .expect("peak");
        let key = auth::encode_auth_node_key(auth::AuthenticatedBackendNamespace::Immutable, peak_pos);
        let bad_value = vec![0xAA; commonware_cryptography::sha256::Digest::SIZE];
        client
            .ingest()
            .put(&[(&key, bad_value.as_slice())])
            .await
            .expect("tamper put");

        let mut stream = Arc::new(reader)
            .stream_batches(Some(1))
            .await
            .expect("stream_batches");
        let err = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
            .await
            .expect("timeout")
            .expect("stream not closed")
            .expect_err("tampered proof must fail");
        assert!(matches!(err, QmdbError::CorruptData(_)));
    }
}
