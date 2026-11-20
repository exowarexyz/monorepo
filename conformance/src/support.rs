//! Helpers the cases share for rows, store calls, prune policies and Put requests.

use crate::{rpc, Backend};
use buffa::Message as _;
use bytes::Bytes;
use commonware_codec::Encode as _;
use exoware_sdk::{
    common::kv::v1::Entry,
    keys::Prefix,
    kv_codec::{StoredRow, StoredValue, Utf8},
    log::ingest::v1::{PutRequest, PutResponse},
    prune_policy::{
        GroupBy, KeysScope, OrderBy, OrderEncoding, PrunePolicy, PrunePolicyDocument, RetainPolicy,
        PRUNE_POLICY_DOCUMENT_VERSION,
    },
    retention::RetentionPolicy,
    selector::Selector,
};
use exoware_server::{
    connect_stack,
    ingest::{box_body, BudgetConfig, IngestBudget, PutLimits, PutMetadata},
    AppState, Ingest, Log, Prune, PutInput, Query, RangeScan, Retention, Sequence, StoreEngine,
    StreamHub, StreamNotifier,
};
use http_body_util::Full;
use std::{fmt::Display, sync::Arc, time::Duration};

/// Prefix byte of the key family that prune cases select.
pub(crate) const FAMILY_PREFIX: u8 = 1;

/// Matches the payload of a versioned key: a logical name with each NUL escaped as `00 FF`, the
/// separator `00 00`, and an 8-byte version.
pub(crate) const VERSION_REGEX: &str =
    "(?s-u)^(?P<logical>(?:\\x00\\xFF|[^\\x00])*)\\x00\\x00(?P<version>.{8})$";

/// How often [`settle`] pauses before it gives up.
const SETTLE_PAUSES: usize = 200;

/// Time a Put built by the cases has before its deadline, far beyond any case's duration.
const PUT_TIMEOUT: Duration = Duration::from_secs(60);

/// A row with copies of `key` and `value`.
pub fn row(key: &[u8], value: &[u8]) -> (Bytes, Bytes) {
    (Bytes::copy_from_slice(key), Bytes::copy_from_slice(value))
}

pub(crate) fn keys(rows: &[(Bytes, Bytes)]) -> Vec<&[u8]> {
    rows.iter().map(|(key, _)| key.as_ref()).collect()
}

/// Opens a store at a new location. The location must outlive the store.
pub(crate) async fn fresh<B: Backend>(backend: &B) -> (B::Location, B::Store) {
    let location = backend.location();
    let store = backend.open(&location).await;
    (location, store)
}

/// Closes the store and opens its location again.
pub(crate) async fn reopen<B: Backend>(
    backend: &B,
    store: B::Store,
    location: &B::Location,
) -> B::Store {
    backend.close(store).await;
    backend.open(location).await
}

/// Commits rows through [`Backend::put_batch`] and returns the sequence number.
pub(crate) async fn commit<B: Backend>(
    backend: &B,
    store: &B::Store,
    rows: Vec<(Bytes, Bytes)>,
) -> u64 {
    backend
        .put_batch(store, rows)
        .await
        .expect("put_batch must succeed")
}

/// Commits one row through [`Backend::put_batch`].
pub(crate) async fn commit_one<B: Backend>(
    backend: &B,
    store: &B::Store,
    key: &[u8],
    value: &[u8],
) -> u64 {
    commit(backend, store, vec![row(key, value)]).await
}

/// Commits rows through [`Ingest::put`] and returns the sequence number.
pub(crate) async fn ingest_put(store: &(impl Ingest + Sequence), rows: &[(Bytes, Bytes)]) -> u64 {
    let hub = Arc::new(StreamHub::new(store.current_sequence()));
    let (_budget, mut input) = admitted_put(rows, &hub);
    store.put(&mut input).await.expect("put must succeed")
}

/// Commits rows through the Put RPC and returns the sequence number of its response.
pub(crate) async fn rpc_put<S: StoreEngine + Clone>(store: &S, rows: &[(Bytes, Bytes)]) -> u64 {
    let mut stack = connect_stack(AppState::new(Arc::new(store.clone())));
    let response: PutResponse =
        rpc::unary_call(&mut stack, rpc::unary(rpc::PUT, &put_request(rows)))
            .await
            .expect("the Put RPC must succeed");
    response.sequence_number
}

/// Commits the rows `a=1`, `b=2` and `c=3` as one batch.
pub(crate) async fn seed_abc<B: Backend>(backend: &B, store: &B::Store) -> u64 {
    commit(
        backend,
        store,
        vec![row(b"a", b"1"), row(b"b", b"2"), row(b"c", b"3")],
    )
    .await
}

/// Pauses through [`Backend::pause`] until `done` holds, at most 200 times, and reports
/// whether it held.
pub async fn settle<B: Backend>(backend: &B, mut done: impl FnMut() -> bool) -> bool {
    for _ in 0..SETTLE_PAUSES {
        if done() {
            return true;
        }
        backend.pause().await;
    }
    done()
}

/// Pulls every remaining row of a cursor up to its first empty batch, at most `max_items` per
/// pull, and asserts that no pull returns more.
pub async fn drain(cursor: &mut impl RangeScan, max_items: usize) -> Vec<(Bytes, Bytes)> {
    let mut rows = Vec::new();
    loop {
        let batch = cursor
            .next_batch(max_items)
            .await
            .expect("next_batch must succeed");
        if batch.rows.is_empty() {
            return rows;
        }
        assert!(
            batch.rows.len() <= max_items,
            "a pull must return at most {max_items} rows, but it returned {}",
            batch.rows.len()
        );
        rows.extend(batch.rows);
    }
}

/// Returns every row that one cursor of [`Query::range_scan`] yields for the range and limit.
pub async fn scan(
    store: &impl Query,
    start: &[u8],
    end: &[u8],
    limit: usize,
    forward: bool,
) -> Vec<(Bytes, Bytes)> {
    let mut cursor = store
        .range_scan(
            Bytes::copy_from_slice(start),
            Bytes::copy_from_slice(end),
            limit,
            forward,
        )
        .await
        .expect("range_scan must succeed")
        .scan;
    drain(&mut cursor, usize::MAX).await
}

pub(crate) async fn get_value(store: &impl Query, key: &[u8]) -> Option<Bytes> {
    store
        .get(Bytes::copy_from_slice(key))
        .await
        .expect("get must succeed")
        .value
}

pub(crate) async fn get_many_values(
    store: &impl Query,
    keys: &[&[u8]],
) -> Vec<(Bytes, Option<Bytes>)> {
    let keys = keys.iter().map(|key| Bytes::copy_from_slice(key)).collect();
    store
        .get_many(keys)
        .await
        .expect("get_many must succeed")
        .value
}

/// The entries of the log batch at `sequence`, or `None` when the log does not hold it.
pub(crate) async fn log_entries(store: &impl Log, sequence: u64) -> Option<Vec<(Bytes, Bytes)>> {
    let batch = store
        .get_batch(sequence)
        .await
        .expect("get_batch must succeed")?;
    assert_eq!(batch.sequence_number(), sequence);
    let response = batch.decode_response().expect("a log batch must decode");
    assert_eq!(response.sequence_number, sequence);
    Some(
        response
            .entries
            .into_iter()
            .map(|entry| (Bytes::from(entry.key), entry.value))
            .collect(),
    )
}

/// True when the log still serves a batch at `sequence`.
pub(crate) async fn has_batch(store: &impl Log, sequence: u64) -> bool {
    store
        .get_batch(sequence)
        .await
        .expect("get_batch must succeed")
        .is_some()
}

pub(crate) async fn oldest_retained(store: &impl Log) -> Option<u64> {
    store
        .oldest_retained_batch()
        .await
        .expect("oldest_retained_batch must succeed")
}

pub(crate) async fn set_retention(
    store: &impl Retention,
    policy: Option<RetentionPolicy>,
) -> Option<u64> {
    store
        .set_retention(policy)
        .await
        .expect("set_retention must succeed")
}

/// A key of the prune family with the given payload.
pub(crate) fn family_key(payload: &[u8]) -> Bytes {
    prefixed_key(FAMILY_PREFIX, payload)
}

fn prefixed_key(prefix: u8, payload: &[u8]) -> Bytes {
    Prefix::from_byte(prefix)
        .encode(payload)
        .expect("a test key must fit the key length limit")
}

/// A key of the prune family that matches [`VERSION_REGEX`].
pub(crate) fn versioned_key(logical: &[u8], version: u64) -> Bytes {
    versioned_key_in(FAMILY_PREFIX, logical, version)
}

/// A key with the given prefix byte whose payload matches [`VERSION_REGEX`].
pub(crate) fn versioned_key_in(prefix: u8, logical: &[u8], version: u64) -> Bytes {
    let mut payload = logical.to_vec();
    payload.extend_from_slice(b"\0\0");
    payload.extend_from_slice(&version.to_be_bytes());
    prefixed_key(prefix, &payload)
}

/// A policy over the prune family.
pub(crate) fn family_policy(
    payload_regex: &str,
    group_by: &[&str],
    order_by: Option<(&str, OrderEncoding)>,
    retain: RetainPolicy,
) -> PrunePolicy {
    PrunePolicy {
        scope: KeysScope {
            selector: Selector {
                prefix: Bytes::from(vec![FAMILY_PREFIX]),
                payload_regex: Utf8::from(payload_regex),
            },
            group_by: GroupBy {
                capture_groups: group_by.iter().map(|group| Utf8::from(*group)).collect(),
            },
            order_by: order_by.map(|(capture_group, encoding)| OrderBy {
                capture_group: Utf8::from(capture_group),
                encoding,
            }),
        },
        retain,
    }
}

/// A policy over versioned keys, grouped by logical name and ordered by version.
pub(crate) fn version_policy_with_encoding(
    retain: RetainPolicy,
    encoding: OrderEncoding,
) -> PrunePolicy {
    family_policy(
        VERSION_REGEX,
        &["logical"],
        Some(("version", encoding)),
        retain,
    )
}

pub(crate) fn version_policy(retain: RetainPolicy) -> PrunePolicy {
    version_policy_with_encoding(retain, OrderEncoding::U64Be)
}

pub(crate) async fn apply_prune(store: &impl Prune, policies: &[PrunePolicy]) {
    store
        .apply_prune_policies(PrunePolicyDocument {
            version: PRUNE_POLICY_DOCUMENT_VERSION,
            policies: policies.to_vec(),
        })
        .await
        .expect("apply_prune_policies must succeed");
}

/// The Put request message that carries `rows`.
pub fn put_request(rows: &[(Bytes, Bytes)]) -> PutRequest {
    PutRequest {
        kvs: rows
            .iter()
            .map(|(key, value)| Entry {
                key: key.to_vec(),
                value: value.clone(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn put_deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + PUT_TIMEOUT
}

#[cfg(target_arch = "wasm32")]
fn put_deadline() -> exoware_server::ingest::Instant {
    exoware_server::ingest::Instant::now() + PUT_TIMEOUT
}

/// A Put of `rows` with a complete body, built and admitted the way the Put service does it but
/// against a budget of its own. The backend advances `notifier` once it commits the batch.
pub fn admitted_put(
    rows: &[(Bytes, Bytes)],
    notifier: &Arc<StreamHub>,
) -> (Arc<IngestBudget>, PutInput) {
    let body = Bytes::from(put_request(rows).encode_to_vec());
    let length = body.len();
    admitted_body(Full::new(body), length, notifier)
}

/// A Put that reads `body`, built and admitted for `length` bytes the way the Put service does
/// it but against a budget of its own. The backend advances `notifier` once it commits the
/// batch.
pub(crate) fn admitted_body<T>(
    body: T,
    length: usize,
    notifier: &Arc<StreamHub>,
) -> (Arc<IngestBudget>, PutInput)
where
    T: http_body::Body<Data = Bytes> + Send + 'static,
    T::Error: Display,
{
    let budget = IngestBudget::new(BudgetConfig::default());
    let admission = budget
        .try_admit(length)
        .expect("a fresh budget must admit the Put");
    let input = PutInput::new(
        box_body(body),
        PutMetadata::default(),
        PutLimits::default(),
        put_deadline(),
        admission,
    )
    .with_notifier(Some(notifier.clone() as Arc<dyn StreamNotifier>));
    (budget, input)
}

/// A Reduce row value with an int64 amount at index 0 and a utf8 name at index 1.
pub fn stored_row(amount: i64, name: &str) -> Bytes {
    StoredRow {
        values: vec![
            Some(StoredValue::Int64(amount)),
            Some(StoredValue::Utf8(name.to_string())),
        ],
    }
    .encode()
}
