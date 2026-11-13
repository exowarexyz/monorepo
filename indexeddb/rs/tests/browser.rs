//! Engine tests that need a browser. They run in headless Chrome through wasm-bindgen-test.
#![cfg(target_arch = "wasm32")]

mod support;

use buffa::Message as _;
use bytes::Bytes;
use exoware_conformance::harness::{
    admitted_put, call, drain, error_info, open_stream, put_request, request, row, scan, settle,
    stored_row, streaming, unary, unary_call, Envelope, Envelopes, LOG_GET, PUT, REDUCE, SUBSCRIBE,
    UNARY_PROTO,
};
use exoware_indexeddb::{Config, IndexedDbStore};
use exoware_sdk::{
    common::kv::v1::{Entry, Selector as StoredSelector},
    kv_codec::{KvExpr, KvFieldKind, KvFieldRef, Utf8},
    limits::{
        put_entry_encoded_len, MAX_KEY_LEN, MAX_PUT_ENTRIES, MAX_RESPONSE_ELEMENT_MEMORY_BYTES,
        MAX_RESPONSE_MESSAGE_BYTES, MAX_VALUE_LEN,
    },
    log::{ingest::v1 as ingest, retention::v1 as retention, stream::v1 as stream},
    parse_retention_policy_from_proto,
    prune_policy::{
        validate_policy_document, GroupBy, KeysScope, OrderBy, OrderEncoding, PrunePolicy,
        PrunePolicyDocument, RetainPolicy, PRUNE_POLICY_DOCUMENT_VERSION,
    },
    retention::RetentionPolicy,
    retention_policy_to_proto,
    selector::Selector,
    store::query::v1 as query,
    to_proto_reduce_params, ConnectError, ErrorCode, RangeReduceOp, RangeReduceRequest,
    RangeReducerSpec,
};
use exoware_server::{
    connect_stack, AppState, Ingest, IngestError, IngestLimits, Log, Prune, PruneSelection,
    PutMiddleware, Query, RangeScan, Retention, Sequence, StreamHub, StreamNotifier,
};
use futures::{channel::oneshot, future::BoxFuture};
use http_body_util::Full;
use js_sys::Uint8Array;
use std::sync::Arc;
use support::*;
use wasm_bindgen::{closure::Closure, JsCast, JsValue};
use wasm_bindgen_futures::spawn_local;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

const GET: &str = "/store.query.v1.Service/Get";

/// The object stores of the layout.
fn layout_stores() -> Vec<String> {
    ["kv", "log", "meta"].map(String::from).to_vec()
}

/// Reads a stored byte string through a connection of its own.
async fn raw_bytes(name: &str, store: &str, key: JsValue) -> Uint8Array {
    raw_get(name, store, key).await.unwrap().dyn_into().unwrap()
}

/// How many rows an object store holds.
async fn count(name: &str, store: &str) -> u32 {
    raw_keys(name, store).await.unwrap().length()
}

/// A policy over every key under a prefix, in one group, ordered by the bytes after the prefix.
fn policy(prefix: &'static [u8], retain: RetainPolicy) -> PrunePolicy {
    PrunePolicy {
        scope: KeysScope {
            selector: Selector {
                prefix: Bytes::from_static(prefix),
                payload_regex: Utf8::from("(?s-u)^(?P<rest>.*)$"),
            },
            group_by: GroupBy::default(),
            order_by: Some(OrderBy {
                capture_group: Utf8::from("rest"),
                encoding: OrderEncoding::BytesAsc,
            }),
        },
        retain,
    }
}

/// A document of `policies` at the current version.
const fn document(policies: Vec<PrunePolicy>) -> PrunePolicyDocument {
    PrunePolicyDocument {
        version: PRUNE_POLICY_DOCUMENT_VERSION,
        policies,
    }
}

/// A policy that deletes every key under a prefix and groups by a number of capture groups,
/// each of which captures the whole key after the prefix.
fn nested_groups(prefix: &'static [u8], captures: usize) -> PrunePolicy {
    let names: Vec<_> = (0..captures).map(|group| format!("g{group}")).collect();
    let opened: String = names.iter().map(|name| format!("(?P<{name}>")).collect();
    let regex = format!("(?s-u)^{opened}.*{}$", ")".repeat(captures));
    PrunePolicy {
        scope: KeysScope {
            selector: Selector {
                prefix: Bytes::from_static(prefix),
                payload_regex: Utf8::from(regex.as_str()),
            },
            group_by: GroupBy {
                capture_groups: names.iter().map(|name| Utf8::from(name.as_str())).collect(),
            },
            order_by: None,
        },
        retain: RetainPolicy::DropAll,
    }
}

/// What a selection for a policy holds once it was offered the keys.
fn retained(policy: &PrunePolicy, keys: &[&[u8]]) -> usize {
    let mut selection = PruneSelection::new(policy).unwrap();
    for key in keys {
        selection.push(Bytes::copy_from_slice(key));
    }
    selection.retained_bytes()
}

/// What a prune document counts for a key it deletes, the key's length plus the 64 bytes of a
/// row.
const fn pending(key: &[u8]) -> usize {
    key.len() + 64
}

/// A store on a database with a budget of its own for queries and prunes.
async fn with_query_budget(name: &str, max_query_bytes: usize) -> IndexedDbStore {
    let config = Config {
        max_query_bytes,
        ..Config::default()
    };
    IndexedDbStore::open(name, config).await.unwrap()
}

/// A retention row of a given length that an ordinary decoder reads as keep_latest with a
/// count of one. The message of the rule repeats its count, and for an odd length the last
/// repetition pads the number with a zero byte. At 66 bytes the row is `0a 40` followed by
/// `08 01` 32 times.
fn keep_latest_one(len: usize) -> Vec<u8> {
    let message = if len < 130 { len - 2 } else { len - 3 };
    let mut row = vec![0x0a];
    if message < 128 {
        row.push(message as u8);
    } else {
        row.extend([(message & 0x7f) as u8 | 0x80, (message >> 7) as u8]);
    }
    row.extend([0x08, 0x01].repeat(message / 2));
    if message % 2 == 1 {
        row.pop();
        row.extend([0x81, 0x00]);
    }
    assert_eq!(row.len(), len);
    row
}

/// A document with one policy that deletes every key under a prefix.
fn drop_all(prefix: &'static [u8]) -> PrunePolicyDocument {
    document(vec![policy(prefix, RetainPolicy::DropAll)])
}

/// A Subscribe request for every key under a prefix.
fn subscribe(prefix: &'static [u8], since: Option<u64>) -> stream::SubscribeRequest {
    stream::SubscribeRequest {
        since_sequence_number: since,
        selectors: vec![StoredSelector {
            prefix: Bytes::from_static(prefix),
            payload_regex: ".*".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// A Get request of the stream service for one batch.
fn log_get(sequence_number: u64) -> stream::GetRequest {
    stream::GetRequest {
        sequence_number,
        ..Default::default()
    }
}

/// Opens a scan from `start` to the end of the keys and reads all of it.
async fn scan_from(store: &IndexedDbStore, start: &'static [u8]) -> (u64, Vec<(Bytes, Bytes)>) {
    let mut opened = store
        .range_scan(Bytes::from_static(start), Bytes::new(), usize::MAX, true)
        .await
        .unwrap();
    (opened.sequence_number, drain(&mut opened.scan, 2).await)
}

#[wasm_bindgen_test]
async fn rows_follow_the_shared_layout() {
    let name = database("layout");
    let store = open(&name).await;
    record();
    let rows = vec![row(b"", b"empty key"), row(b"k", b"first"), row(b"k", b"")];
    assert_eq!(store.put_batch(rows).await.unwrap(), 1);
    let rule = RetentionPolicy::KeepLatest { count: 5 };
    store.set_retention(Some(rule.clone())).await.unwrap();
    let lines = restore();

    // Every key reaches IndexedDB as a buffer of exactly its bytes.
    let writes: Vec<_> = lines
        .iter()
        .filter(|line| line.starts_with("put "))
        .collect();
    assert_eq!(writes.len(), 6, "{lines:?}");
    assert!(
        writes.iter().all(|line| line.ends_with(" ArrayBuffer")),
        "{lines:?}"
    );

    // The database has the layout's version and object stores.
    assert_eq!(raw_describe(&name).await.unwrap(), "1 kv,log,meta");

    // Values own exact buffers, and the later entry for a key wins.
    for (key, expected) in [(&b""[..], &b"empty key"[..]), (b"k", b"")] {
        let value = raw_bytes(&name, "kv", js_key(key)).await;
        assert_eq!(value.to_vec(), expected);
        assert_eq!(value.byte_offset(), 0);
        assert_eq!(value.buffer().byte_length(), value.length());
    }

    // The sequence row holds the batch's number in eight big endian bytes, and the retention
    // row holds the rule as its protobuf message.
    assert_eq!(
        raw_bytes(&name, "meta", js_key(b"sequence")).await.to_vec(),
        1u64.to_be_bytes()
    );
    let stored_rule = raw_bytes(&name, "meta", js_key(b"retention"))
        .await
        .to_vec();
    let stored_rule = retention::RetentionPolicy::decode_from_slice(&stored_rule).unwrap();
    assert_eq!(
        parse_retention_policy_from_proto(&stored_rule).unwrap(),
        rule
    );

    // The log holds one batch under its big endian sequence number, with every entry in order.
    let keys = raw_keys(&name, "log").await.unwrap();
    assert_eq!(keys.length(), 1);
    assert_eq!(Uint8Array::new(&keys.get(0)).to_vec(), 1u64.to_be_bytes());
    let batch = raw_bytes(&name, "log", be64(1)).await.to_vec();
    let batch = stream::GetResponse::decode_from_slice(&batch).unwrap();
    assert_eq!(batch.sequence_number, 1);
    let entries: Vec<_> = batch
        .entries
        .iter()
        .map(|entry| (entry.key.as_slice(), entry.value.as_ref()))
        .collect();
    let expected: [(&[u8], &[u8]); 3] = [(b"", b"empty key"), (b"k", b"first"), (b"k", b"")];
    assert_eq!(entries, expected);
    store.close();
}

#[wasm_bindgen_test]
async fn reads_every_form_a_writer_may_store() {
    let name = database("forms");
    raw_create(&name, 1, layout_stores()).await.unwrap();
    raw_put(&name, "kv", js_value(b"a"), js_key(b"buffer"))
        .await
        .unwrap();
    raw_put(&name, "kv", js_key(b"b"), offset_view(b"view").into())
        .await
        .unwrap();
    let sequence = offset_view(&7u64.to_be_bytes());
    raw_put(&name, "meta", js_key(b"sequence"), sequence.into())
        .await
        .unwrap();

    let store = open(&name).await;
    assert!(!store.created());
    assert_eq!(store.current_sequence(), 7);
    let read = store.get(Bytes::from_static(b"a")).await.unwrap();
    assert_eq!(read.value.as_deref(), Some(b"buffer".as_slice()));
    assert_eq!(read.sequence_number, 7);
    let read = store.get(Bytes::from_static(b"b")).await.unwrap();
    assert_eq!(read.value.as_deref(), Some(b"view".as_slice()));

    // A retention rule is read in longer encodings that an ordinary decoder accepts, up to the
    // 1,024 bytes the layout gives the row. With the rule read, each Put leaves only its own
    // batch in the log.
    for len in [66, 1024] {
        raw_put(
            &name,
            "meta",
            js_key(b"retention"),
            js_value(&keep_latest_one(len)),
        )
        .await
        .unwrap();
        let first = store.put_batch(vec![row(b"c", b"")]).await.unwrap();
        let second = store.put_batch(vec![row(b"c", b"")]).await.unwrap();
        assert_eq!(second, first + 1);
        assert_eq!(store.oldest_retained_batch().await.unwrap(), Some(second));
    }
    store.close();
}

#[wasm_bindgen_test]
async fn open_creates_once_and_refuses_other_layouts() {
    let name = database("open");

    // Only the open that finds no database creates it.
    let store = open(&name).await;
    assert!(store.created());
    store.close();
    let store = open(&name).await;
    assert!(!store.created());
    store.close();

    // A database of a later layout version is refused and left as it is.
    let newer = database("newer");
    let mut stores = layout_stores();
    stores.push("future".to_string());
    raw_create(&newer, 2, stores).await.unwrap();
    assert!(IndexedDbStore::open(&newer, Config::default())
        .await
        .is_err());
    assert_eq!(raw_describe(&newer).await.unwrap(), "2 future,kv,log,meta");

    // A database of the layout's version with other object stores is refused and left as it
    // is.
    for (stores, described) in [
        (vec!["kv", "log"], "1 kv,log"),
        (vec!["extra", "kv", "log", "meta"], "1 extra,kv,log,meta"),
        (vec![], "1 "),
    ] {
        let other = database("other");
        let stores = stores.into_iter().map(String::from).collect();
        raw_create(&other, 1, stores).await.unwrap();
        assert!(IndexedDbStore::open(&other, Config::default())
            .await
            .is_err());
        assert_eq!(raw_describe(&other).await.unwrap(), described);
    }

    // A sequence row that is not eight bytes long fails the open.
    let corrupt = database("corrupt");
    raw_create(&corrupt, 1, layout_stores()).await.unwrap();
    raw_put(&corrupt, "meta", js_key(b"sequence"), js_value(&[1, 2, 3]))
        .await
        .unwrap();
    let error = IndexedDbStore::open(&corrupt, Config::default())
        .await
        .err();
    assert!(error.unwrap().contains("8 bytes"));
}

/// Opens, uses and closes a store, and has an open refused by a database of another layout.
async fn open_close_and_refuse(name: &str, other_layout: &str) {
    let store = open(name).await;
    store.put_batch(vec![row(b"k", b"v")]).await.unwrap();
    store.close();
    drop(store);
    assert!(IndexedDbStore::open(other_layout, Config::default())
        .await
        .is_err());
}

#[wasm_bindgen_test]
async fn a_closed_or_refused_connection_holds_nothing() {
    let name = database("released");
    let other_layout = database("other-layout");
    raw_create(&other_layout, 1, vec!["kv".to_string()])
        .await
        .unwrap();

    // Rust holds every JS object through a handle. A connection that is gone holds none,
    // and neither do the callbacks it had installed, so the number of handles does not grow
    // however often a database is opened.
    open_close_and_refuse(&name, &other_layout).await;
    let handles = wasm_bindgen::externref_heap_live_count();
    for _ in 0..4 {
        open_close_and_refuse(&name, &other_layout).await;
    }
    assert!(wasm_bindgen::externref_heap_live_count() <= handles);
}

#[wasm_bindgen_test]
async fn a_delete_from_another_connection_is_not_blocked() {
    let name = database("delete");
    let store = open(&name).await;
    store.put_batch(vec![row(b"k", b"v")]).await.unwrap();

    // The delete finishes only once this connection has closed itself.
    raw_delete(&name).await.unwrap();
    assert!(store.get(Bytes::from_static(b"k")).await.is_err());
    assert!(store.put_batch(vec![row(b"k", b"v")]).await.is_err());
}

#[wasm_bindgen_test]
async fn each_operation_is_one_transaction_with_the_layout_scope() {
    let name = database("scope");
    let store = open(&name).await;
    store.put_batch(vec![row(b"p/0", b"a")]).await.unwrap();
    let rule = RetentionPolicy::KeepLatest { count: 1 };
    store.set_retention(Some(rule.clone())).await.unwrap();

    record();
    let rows = vec![row(b"p/1", b"a"), row(b"p/2", b"b")];
    assert_eq!(store.put_batch(rows).await.unwrap(), 2);

    // Both meta rows are read before the first write, and the rule trims the log in the
    // transaction that appends to it.
    assert_eq!(
        restore(),
        [
            "transaction kv,log,meta readwrite strict",
            "get meta ArrayBuffer",
            "get meta ArrayBuffer",
            "put kv ArrayBuffer",
            "put kv ArrayBuffer",
            "put log ArrayBuffer",
            "put meta ArrayBuffer",
            "delete log IDBKeyRange",
        ]
    );
    assert_eq!(store.oldest_retained_batch().await.unwrap(), Some(2));

    // Every read is one readonly transaction over the object stores it reads.
    let key = Bytes::from_static(b"p/1");
    record();
    store.get(key.clone()).await.unwrap();
    assert_eq!(
        transactions(&restore()),
        ["transaction kv,meta readonly undefined"]
    );
    record();
    store
        .get_many(vec![key.clone(), key.clone()])
        .await
        .unwrap();
    assert_eq!(
        transactions(&restore()),
        ["transaction kv,meta readonly undefined"]
    );
    record();
    scan(&store, b"p/", b"", usize::MAX, true).await;
    assert_eq!(
        transactions(&restore()),
        ["transaction kv,meta readonly undefined"]
    );
    record();
    store.get_batch(2).await.unwrap();
    assert_eq!(
        transactions(&restore()),
        ["transaction log,meta readonly undefined"]
    );
    record();
    store.oldest_retained_batch().await.unwrap();
    assert_eq!(
        transactions(&restore()),
        ["transaction log,meta readonly undefined"]
    );

    // A retention change reads the sequence number and the oldest batch it will keep before
    // it writes the rule and trims the log.
    record();
    assert_eq!(store.set_retention(Some(rule)).await.unwrap(), Some(2));
    assert_eq!(
        restore(),
        [
            "transaction log,meta readwrite strict",
            "get meta ArrayBuffer",
            "getAllKeys log IDBKeyRange",
            "put meta ArrayBuffer",
            "delete log IDBKeyRange",
        ]
    );
    record();
    assert_eq!(store.set_retention(None).await.unwrap(), Some(2));
    assert_eq!(
        restore(),
        [
            "transaction log,meta readwrite strict",
            "get meta ArrayBuffer",
            "getAllKeys log Null",
            "delete meta ArrayBuffer",
        ]
    );

    // A prune deletes in one readwrite transaction over the current rows.
    record();
    store.apply_prune_policies(drop_all(b"p/")).await.unwrap();
    let prune = restore();
    assert_eq!(transactions(&prune), ["transaction kv readwrite strict"]);
    assert_eq!(placed(&prune, "delete kv "), 3);
    store.close();
}

#[wasm_bindgen_test]
async fn a_failed_write_leaves_nothing_behind() {
    let name = database("abort");
    let store = open(&name).await;
    uncaught();

    // A batch of two rows places four puts: the two rows, the log batch and the sequence
    // number.
    for nth in 1..=4 {
        fail("put", nth);
        let result = store
            .put_batch(vec![row(b"a", b"1"), row(b"b", b"2")])
            .await;
        restore();
        assert!(result.is_err(), "put {nth} must fail");
        assert_eq!(store.current_sequence(), 0);
        for object_store in ["kv", "log", "meta"] {
            assert_eq!(
                count(&name, object_store).await,
                0,
                "{object_store} after put {nth}"
            );
        }
    }

    // A transaction that the browser aborts for lack of space is reported as that, and it
    // leaves nothing behind either.
    abort_over_quota_after_put(4);
    let result = store
        .put_batch(vec![row(b"a", b"1"), row(b"b", b"2")])
        .await;
    restore();
    assert!(
        matches!(result, Err(IngestError::ResourceExhausted { .. })),
        "{result:?}"
    );
    assert_eq!(store.current_sequence(), 0);
    assert_eq!(count(&name, "kv").await, 0);

    // Three committed rows give the following writes a log to trim and rows to delete.
    let rows = vec![row(b"p/1", b"1"), row(b"p/2", b"2"), row(b"p/3", b"3")];
    assert_eq!(store.put_batch(rows).await.unwrap(), 1);

    // A rule whose trim cannot be placed is not installed.
    fail("delete", 1);
    let result = store.set_retention(Some(RetentionPolicy::DropAll)).await;
    restore();
    assert!(result.is_err());
    assert!(raw_get(&name, "meta", js_key(b"retention"))
        .await
        .unwrap()
        .is_undefined());
    assert!(store.get_batch(1).await.unwrap().is_some());

    // A prune that cannot place every delete deletes nothing.
    fail("delete", 2);
    let result = store.apply_prune_policies(drop_all(b"p/")).await;
    restore();
    assert!(result.is_err());
    assert_eq!(count(&name, "kv").await, 3);

    // The events of the aborted transactions found no callback that was already freed.
    assert_nothing_uncaught().await;
    store.close();
}

#[wasm_bindgen_test]
async fn a_prune_document_applies_in_order_or_not_at_all() {
    let name = database("document");
    let store = open(&name).await;
    let (b4, b5, z9): (&[u8], &[u8], &[u8]) = (b"p/b4", b"p/b5", b"p/z9");
    let rows = vec![row(b4, b""), row(b5, b""), row(z9, b"")];
    store.put_batch(rows).await.unwrap();
    let delete_z = policy(b"p/z", RetainPolicy::DropAll);
    let delete_b = policy(b"p/b", RetainPolicy::DropAll);
    uncaught();

    // A threshold has no meaning for this ordering, so the second policy fails. The first
    // policy had selected a key by then, and no delete was placed for it.
    let threshold = policy(b"p/", RetainPolicy::GreaterThan { threshold: 1 });
    record();
    let result = store
        .apply_prune_policies(document(vec![delete_z.clone(), threshold]))
        .await;
    let lines = restore();
    assert!(result.is_err());
    assert_eq!(transactions(&lines), ["transaction kv readwrite strict"]);
    assert_eq!(placed(&lines, "delete "), 0, "{lines:?}");
    assert_eq!(count(&name, "kv").await, 3);

    // A document counts what the selection of a policy holds while the policy selects, and
    // afterwards the keys the policy deletes. This budget is one byte short of what the
    // second policy holds for its two keys on top of the key the first policy deletes.
    let budget = pending(z9) + retained(&delete_b, &[b4, b5]) - 1;
    let tight = with_query_budget(&name, budget).await;
    record();
    let result = tight
        .apply_prune_policies(document(vec![delete_z.clone(), delete_b]))
        .await;
    let lines = restore();
    assert!(result.err().unwrap().contains(&format!("{budget} bytes")));
    assert_eq!(placed(&lines, "delete "), 0, "{lines:?}");
    assert_eq!(count(&name, "kv").await, 3);

    // Once a policy has selected, only the keys it deletes stay counted. The first policy
    // here holds both keys of its family and deletes one, so the second policy's selection
    // fits.
    let keep_latest_b = policy(b"p/b", RetainPolicy::KeepLatest { count: 1 });
    tight
        .apply_prune_policies(document(vec![keep_latest_b, delete_z.clone()]))
        .await
        .unwrap();
    assert_eq!(count(&name, "kv").await, 1);
    tight.close();

    // A selection can hold far more for a key than the key. This policy is one the Prune
    // RPC accepts. It groups by 32 capture groups that each repeat the key, so its
    // selection holds many times the bytes of the keys it matches. The document fits a
    // budget of exactly what the selection reports and fails one byte below it.
    let grouped = nested_groups(b"g/", 32);
    validate_policy_document(&document(vec![grouped.clone()])).unwrap();
    let keys: Vec<_> = (0..8u8)
        .map(|key| [b"g/".as_slice(), &[b'a' + key; 30]].concat())
        .collect();
    let rows = keys.iter().map(|key| row(key, b"")).collect();
    store.put_batch(rows).await.unwrap();
    let keys: Vec<_> = keys.iter().map(Vec::as_slice).collect();
    let held = retained(&grouped, &keys);
    assert!(held > 8 * keys.iter().map(|key| pending(key)).sum::<usize>());
    let short = with_query_budget(&name, held - 1).await;
    record();
    let result = short
        .apply_prune_policies(document(vec![grouped.clone()]))
        .await;
    let lines = restore();
    assert!(result
        .err()
        .unwrap()
        .contains(&format!("{} bytes", held - 1)));
    assert_eq!(placed(&lines, "delete "), 0, "{lines:?}");
    assert_eq!(count(&name, "kv").await, 9);
    short.close();
    let exact = with_query_budget(&name, held).await;
    exact
        .apply_prune_policies(document(vec![grouped]))
        .await
        .unwrap();
    assert_eq!(count(&name, "kv").await, 1);
    exact.close();

    // The second policy keeps the latest key that the first policy left. Selected against
    // the rows as they were before the document, it would keep the key the first deletes.
    let rows = vec![row(b4, b""), row(z9, b"")];
    store.put_batch(rows).await.unwrap();
    let keep_latest = policy(b"p/", RetainPolicy::KeepLatest { count: 1 });
    record();
    store
        .apply_prune_policies(document(vec![delete_z, keep_latest]))
        .await
        .unwrap();
    let lines = restore();
    assert_eq!(transactions(&lines), ["transaction kv readwrite strict"]);
    assert_eq!(placed(&lines, "delete kv "), 2);
    let left = raw_keys(&name, "kv").await.unwrap();
    assert_eq!(left.length(), 1);
    assert_eq!(Uint8Array::new(&left.get(0)).to_vec(), b5);

    // A stored key longer than `MAX_KEY_LEN` is corrupt. A document that comes across one
    // fails before it copies the key or offers it to a selection, and so does a scan. The key
    // before it has the greatest length a key can have and is read.
    let longest = [b"g/".as_slice(), &[b'a'; MAX_KEY_LEN - 2]].concat();
    let oversized = [longest.as_slice(), b"a"].concat();
    for key in [&longest, &oversized] {
        raw_put(&name, "kv", js_key(key), js_value(b""))
            .await
            .unwrap();
    }
    let (longest, oversized) = (longest.len() as u32, oversized.len() as u32);
    let too_long = format!("{oversized} bytes long");
    record();
    record_copies();
    let result = store
        .apply_prune_policies(document(vec![nested_groups(b"g/", 32)]))
        .await;
    let copies = copied();
    let lines = restore();
    assert!(result.err().unwrap().contains(&too_long));
    assert_eq!(placed(&lines, "delete "), 0, "{lines:?}");
    assert_eq!(copies, [longest]);
    record_copies();
    let scanned = store
        .range_scan(Bytes::from_static(b"g/"), Bytes::new(), usize::MAX, true)
        .await;
    let copies = copied();
    assert!(scanned.err().unwrap().contains(&too_long));
    assert!(
        copies.contains(&longest) && !copies.contains(&oversized),
        "{copies:?}"
    );
    assert_eq!(count(&name, "kv").await, 3);
    assert_nothing_uncaught().await;
    store.close();
}

#[wasm_bindgen_test]
async fn malformed_rows_are_errors_and_nothing_is_written() {
    let name = database("hostile");
    let store = open(&name).await;
    store.put_batch(vec![row(b"k", b"v")]).await.unwrap();
    let key = Bytes::from_static(b"k");
    uncaught();

    // A retention row that does not decode, or that holds a rule the request path refuses,
    // fails the Put before its first write.
    let zero = retention_policy_to_proto(&RetentionPolicy::KeepLatest { count: 0 });
    for rule in [vec![0xff, 0xff, 0xff], Vec::new(), zero.encode_to_vec()] {
        raw_put(&name, "meta", js_key(b"retention"), js_value(&rule))
            .await
            .unwrap();
        record();
        let result = store.put_batch(vec![row(b"x", b"y")]).await;
        let lines = restore();
        assert!(
            matches!(result, Err(IngestError::Internal { .. })),
            "{result:?}"
        );
        assert_eq!(placed(&lines, "put "), 0, "{lines:?}");
    }

    // A retention row longer than the layout's 1,024 bytes is refused before it is copied out
    // of JS, even when it encodes a rule. The Put still copies its eight-byte sequence row.
    raw_put(
        &name,
        "meta",
        js_key(b"retention"),
        js_value(&keep_latest_one(1025)),
    )
    .await
    .unwrap();
    record_copies();
    let result = store.put_batch(vec![row(b"x", b"y")]).await;
    let copies = copied();
    assert!(
        matches!(result, Err(IngestError::Internal { .. })),
        "{result:?}"
    );
    assert!(copies.contains(&8) && !copies.contains(&1025), "{copies:?}");
    store.set_retention(None).await.unwrap();
    assert_eq!(store.put_batch(vec![row(b"x", b"y")]).await.unwrap(), 2);

    // A sequence row of the wrong length fails every operation that reads it.
    raw_put(&name, "meta", js_key(b"sequence"), js_value(&[1, 2, 3]))
        .await
        .unwrap();
    assert!(store.get(key.clone()).await.is_err());
    assert!(store.get_many(vec![key.clone()]).await.is_err());
    assert!(store
        .range_scan(key.clone(), Bytes::new(), 1, true)
        .await
        .is_err());
    assert!(store.put_batch(vec![row(b"z", b"z")]).await.is_err());
    assert!(store.get_batch(1).await.is_err());
    assert!(store.oldest_retained_batch().await.is_err());
    assert!(store.set_retention(None).await.is_err());
    assert!(store.get(Bytes::from_static(b"z")).await.is_err());
    raw_put(
        &name,
        "meta",
        js_key(b"sequence"),
        js_value(&2u64.to_be_bytes()),
    )
    .await
    .unwrap();
    assert!(store
        .get(Bytes::from_static(b"z"))
        .await
        .unwrap()
        .value
        .is_none());

    // A row that is not a byte string fails the reads that meet it.
    raw_put(&name, "kv", js_key(b"text"), JsValue::from_str("not bytes"))
        .await
        .unwrap();
    assert!(store.get(Bytes::from_static(b"text")).await.is_err());
    assert!(store
        .range_scan(Bytes::new(), Bytes::new(), usize::MAX, true)
        .await
        .is_err());

    // A log batch is served only when it decodes, carries the sequence number of its key,
    // has an entry and holds no key longer than a Store key. Anything else fails the read,
    // for the stored bytes of a Get as for the entries of a subscription.
    let stored_batch = |sequence_number, entries: &[(Bytes, Bytes)]| {
        stream::GetResponse {
            sequence_number,
            entries: put_request(entries).kvs,
            ..Default::default()
        }
        .encode_to_vec()
    };
    let entry = [row(b"k", b"v")];
    let with_last_key_of = |len| [row(b"k", b"v"), row(&vec![b'k'; len], b"v")];
    let mut stack = connect_stack(AppState::new(Arc::new(store.clone())));
    for corrupt in [
        vec![0xff; 4],
        Vec::new(),
        stored_batch(2, &entry),
        stored_batch(1, &[]),
        stored_batch(1, &with_last_key_of(MAX_KEY_LEN + 1)),
    ] {
        raw_put(&name, "log", be64(1), js_value(&corrupt))
            .await
            .unwrap();
        assert!(store.get_batch(1).await.is_err(), "{corrupt:?}");
        let served: Result<stream::GetResponse, _> =
            unary_call(&mut stack, unary(LOG_GET, &log_get(1))).await;
        assert_eq!(served.unwrap_err().code, ErrorCode::Internal, "{corrupt:?}");
        let mut frames = open_stream(&mut stack, SUBSCRIBE, &subscribe(b"k", Some(1))).await;
        let Some(Envelope::End(Some(error))) = frames.next().await else {
            panic!("the subscription must end with an error for {corrupt:?}");
        };
        assert_eq!(error.code, ErrorCode::Internal, "{corrupt:?}");
    }

    // A batch whose longest key has the greatest length of a Store key is served whole. It is
    // the newest batch, so the subscription has no later batch to read and leaves no read
    // running when the next check replaces the answer of a read.
    let key_lengths =
        |entries: &[Entry]| -> Vec<_> { entries.iter().map(|entry| entry.key.len()).collect() };
    let longest = stored_batch(2, &with_last_key_of(MAX_KEY_LEN));
    raw_put(&name, "log", be64(2), js_value(&longest))
        .await
        .unwrap();
    assert!(store.get_batch(2).await.unwrap().is_some());
    let served: stream::GetResponse = unary_call(&mut stack, unary(LOG_GET, &log_get(2)))
        .await
        .unwrap();
    assert_eq!(key_lengths(&served.entries), [1, MAX_KEY_LEN]);
    let mut frames = open_stream(&mut stack, SUBSCRIBE, &subscribe(b"k", Some(2))).await;
    let Some(Some(Envelope::Message(frame))) = within(2_000, frames.next()).await else {
        panic!("the subscription must deliver the batch");
    };
    let frame = stream::SubscribeResponse::decode_from_slice(&frame).unwrap();
    assert_eq!(key_lengths(&frame.entries), [1, MAX_KEY_LEN]);
    drop(frames);

    // A log batch longer than the longest the decoder accepts is refused before it is
    // copied out of JS. A stored row of that length would take half a gigabyte of disk, so
    // the read is handed a buffer of that length in place of the stored row.
    let oversized = Uint8Array::new_with_length(MAX_RESPONSE_MESSAGE_BYTES as u32 + 1);
    answer_next_get("log", oversized.into());
    record_copies();
    let refused = store.get_batch(1).await;
    let copies = copied();
    restore();
    assert!(refused.err().unwrap().contains("bytes long"));
    assert!(copies.contains(&8), "{copies:?}");
    assert!(copies.iter().all(|length| *length == 8), "{copies:?}");

    // A batch holds at most as many entries as a Put may carry. An empty entry takes two
    // bytes in a row and many times that once it is decoded, so a row with one entry more is
    // refused from a count on its stored bytes, and a row with exactly that many is served.
    let (sequence_one, empty_entry) = ([0x08, 0x01], [0x12, 0x00]);
    let too_many = format!("more than {MAX_PUT_ENTRIES} entries");
    for (entries, served) in [(MAX_PUT_ENTRIES + 1, false), (MAX_PUT_ENTRIES, true)] {
        let row = repeated(&sequence_one, &empty_entry, entries as u32);
        raw_put(&name, "log", be64(1), row.into()).await.unwrap();
        match store.get_batch(1).await {
            Ok(batch) => assert!(served && batch.is_some()),
            Err(refused) => assert!(!served && refused.contains(&too_many), "{refused}"),
        }
    }

    // The count comes before the decoding. This row holds more empty entries than the
    // decoder agrees to hold in memory, and the error still names the count.
    let entries = MAX_RESPONSE_ELEMENT_MEMORY_BYTES / size_of::<Entry>() + 1;
    let row = repeated(&sequence_one, &empty_entry, entries as u32);
    raw_put(&name, "log", be64(1), row.into()).await.unwrap();
    let refused = store.get_batch(1).await.err().unwrap();
    assert!(refused.contains(&too_many), "{refused}");

    // The layout lets a reader refuse a log value that holds more than 1,000,000 fields it
    // does not know, counted over the value and its entries together. The decoder keeps
    // exactly that many, so such fields cannot fill the memory. A row that holds them is
    // served, and a row with one more, in an entry or in the value, is refused. The fields
    // carry a number that neither message defines.
    let unknown = |count: usize| [0x78, 0x00].repeat(count);
    let with_unknown_fields = |in_entry: usize, in_value: usize| {
        let mut fields = vec![0x0a, 0x01, b'k', 0x12, 0x01, b'v'];
        fields.extend(unknown(in_entry));
        let mut row = vec![0x08, 0x01, 0x12];
        buffa::encoding::encode_varint(fields.len() as u64, &mut row);
        row.extend(fields);
        row.extend(unknown(in_value));
        row
    };
    for (in_entry, in_value, served) in [
        (500_000, 500_000, true),
        (500_001, 500_000, false),
        (500_000, 500_001, false),
    ] {
        let row = with_unknown_fields(in_entry, in_value);
        raw_put(&name, "log", be64(1), js_value(&row))
            .await
            .unwrap();
        match store.get_batch(1).await {
            Ok(batch) => assert!(served && batch.is_some(), "{in_entry} {in_value}"),
            Err(refused) => assert!(!served, "{in_entry} {in_value} {refused}"),
        }
    }
    raw_put(&name, "log", be64(1), js_value(&stored_batch(1, &entry)))
        .await
        .unwrap();

    // The log holds no batch above the sequence row and none numbered zero.
    raw_put(&name, "log", be64(3), js_value(&stored_batch(3, &entry)))
        .await
        .unwrap();
    assert!(store.get_batch(3).await.is_err());
    raw_put(&name, "log", be64(0), js_value(&stored_batch(0, &entry)))
        .await
        .unwrap();
    assert!(store.get_batch(0).await.is_err());
    assert!(store.oldest_retained_batch().await.is_err());
    assert!(store.set_retention(None).await.is_err());

    // A log key that is not a sequence number.
    raw_put(&name, "log", js_key(&[0]), js_value(b"x"))
        .await
        .unwrap();
    assert!(store.oldest_retained_batch().await.is_err());
    assert_nothing_uncaught().await;
    store.close();
}

#[wasm_bindgen_test]
async fn frontier_follows_the_database_and_never_runs_ahead() {
    let name = database("frontier");
    let writer = open(&name).await;
    let reader = open(&name).await;
    let hub = Arc::new(StreamHub::new(reader.current_sequence()));
    reader.watch(hub.clone());
    uncaught();

    // A commit that fails does not move the frontier.
    fail("put", 2);
    let failed = writer.put_batch(vec![row(b"a", b"1")]).await;
    restore();
    assert!(failed.is_err());
    assert_eq!(writer.current_sequence(), 0);

    // Neither does a commit that aborts after its last write was placed.
    abort_after_put(3);
    let aborted = writer.put_batch(vec![row(b"a", b"1")]).await;
    restore();
    assert!(aborted.is_err());
    assert_eq!(writer.current_sequence(), 0);
    assert_eq!(count(&name, "kv").await, 0);

    // A notification is a hint. The number it carries is not used.
    post_hint(&name, js_value(&99u64.to_be_bytes()));
    post_hint(&name, js_value(b"junk"));
    sleep(50).await;
    assert_eq!(reader.current_sequence(), 0);
    assert_eq!(hub.current_sequence(), 0);

    // Another connection's commit arrives through the channel and wakes the watcher.
    assert_eq!(writer.put_batch(vec![row(b"a", b"1")]).await.unwrap(), 1);
    assert_eq!(writer.current_sequence(), 1);
    assert!(settle(&IndexedDbBackend, || hub.current_sequence() == 1).await);
    assert_eq!(reader.current_sequence(), 1);

    // Sequence numbers come from the shared row, whichever connection writes.
    assert_eq!(reader.put_batch(vec![row(b"b", b"2")]).await.unwrap(), 2);
    let (first, second) = futures::join!(
        writer.put_batch(vec![row(b"c", b"3")]),
        reader.put_batch(vec![row(b"d", b"4")])
    );
    let mut sequences = [first.unwrap(), second.unwrap()];
    sequences.sort_unstable();
    assert_eq!(sequences, [3, 4]);

    // Every read raises the frontier by itself. The commits below are complete and valid
    // but post no notification, so only the read that follows can tell this store of them.
    let late = open(&name).await;
    let mut sequence = late.current_sequence();
    assert_eq!(sequence, 4);
    let unnotified = Arc::new(StreamHub::new(sequence));
    late.watch(unnotified.clone());
    let key = Bytes::from_static(SILENT_KEY);

    let next = silent_commit(&name, &mut sequence, false).await;
    let read = late.get(key.clone()).await.unwrap();
    assert_eq!(
        (read.sequence_number, late.current_sequence()),
        (next, next)
    );

    let next = silent_commit(&name, &mut sequence, false).await;
    let read = late.get_many(vec![key.clone()]).await.unwrap();
    assert_eq!(
        (read.sequence_number, late.current_sequence()),
        (next, next)
    );

    let next = silent_commit(&name, &mut sequence, false).await;
    let read = late.range_scan(key, Bytes::new(), 1, true).await.unwrap();
    assert_eq!(
        (read.sequence_number, late.current_sequence()),
        (next, next)
    );

    // This commit evicts every older batch, so the batch before it is a miss at a sequence
    // number the database has reached.
    let next = silent_commit(&name, &mut sequence, true).await;
    assert!(late.get_batch(next - 1).await.unwrap().is_none());
    assert_eq!(late.current_sequence(), next);

    let next = silent_commit(&name, &mut sequence, true).await;
    assert_eq!(late.oldest_retained_batch().await.unwrap(), Some(next));
    assert_eq!(late.current_sequence(), next);

    // The stream service tells an evicted batch from one that was never written by comparing
    // it with the frontier. The batch asked for here is above the frontier this store knows,
    // so the answer is BATCH_EVICTED only if the read raises the frontier before it reports
    // the miss.
    let missed = silent_commit(&name, &mut sequence, false).await;
    silent_commit(&name, &mut sequence, true).await;
    let mut stack = connect_stack(AppState::new(Arc::new(late.clone())));
    let answer: Result<stream::GetResponse, _> =
        unary_call(&mut stack, unary(LOG_GET, &log_get(missed))).await;
    assert_eq!(error_info(&answer.unwrap_err()).reason, "BATCH_EVICTED");
    assert_eq!(unnotified.current_sequence(), 4);

    assert_nothing_uncaught().await;
    for store in [writer, reader, late] {
        store.close();
    }
}

#[wasm_bindgen_test]
async fn a_commit_is_announced_when_its_store_closes_during_the_write() {
    let name = database("closing");
    let writer = open(&name).await;
    let reader = open(&name).await;
    let hub = Arc::new(StreamHub::new(0));
    reader.watch(hub.clone());

    // The store is closed while its transaction waits to commit. The transaction finishes,
    // and the other connection still hears of the batch.
    let close = Closure::once_into_js({
        let writer = writer.clone();
        move || writer.close()
    });
    call_after_put(3, close.unchecked_ref());
    let committed = writer.put_batch(vec![row(b"k", b"v")]).await;
    restore();
    assert_eq!(committed.unwrap(), 1);
    assert!(settle(&IndexedDbBackend, || hub.current_sequence() == 1).await);
    assert_eq!(reader.current_sequence(), 1);
    assert!(writer.put_batch(vec![row(b"k", b"v")]).await.is_err());
    reader.close();
}

#[wasm_bindgen_test]
async fn a_scan_reports_the_sequence_of_the_rows_it_read() {
    let name = database("pinned");
    let store = open(&name).await;
    let states = [
        vec![row(b"k1", b"old")],
        vec![row(b"k1", b"a"), row(b"k2", b"a")],
        vec![row(b"k1", b"b"), row(b"k2", b"a"), row(b"k3", b"b")],
    ];
    assert_eq!(store.put_batch(states[0].clone()).await.unwrap(), 1);

    // A scan that races a Put sees the state before or after it, with the matching number.
    let (scanned, put) = futures::join!(
        scan_from(&store, b"k"),
        store.put_batch(vec![row(b"k1", b"a"), row(b"k2", b"a")])
    );
    assert_eq!(put.unwrap(), 2);
    assert_eq!(scanned.1, states[scanned.0 as usize - 1]);
    let (put, scanned) = futures::join!(
        store.put_batch(vec![row(b"k1", b"b"), row(b"k3", b"b")]),
        scan_from(&store, b"k")
    );
    assert_eq!(put.unwrap(), 3);
    assert_eq!(scanned.1, states[scanned.0 as usize - 1]);

    // An open cursor keeps its rows while later writes and prunes commit.
    let mut opened = store
        .range_scan(Bytes::from_static(b"k"), Bytes::new(), usize::MAX, false)
        .await
        .unwrap();
    let mut rows = opened.scan.next_batch(1).await.unwrap().rows;
    store.put_batch(vec![row(b"k2", b"c")]).await.unwrap();
    store.apply_prune_policies(drop_all(b"k")).await.unwrap();
    rows.extend(drain(&mut opened.scan, usize::MAX).await);
    rows.reverse();
    assert_eq!(opened.sequence_number, 3);
    assert_eq!(rows, states[2]);
    store.close();
}

#[wasm_bindgen_test]
async fn an_accepted_put_commits_after_its_caller_is_dropped() {
    let store = open(&database("cancel")).await;
    let hub = Arc::new(StreamHub::new(0));
    let (budget, mut input) = admitted_put(&[row(b"k", b"v")], &hub);

    // Polling without returning to the event loop takes the Put up to its commit, and the
    // commit cannot finish without IndexedDB events. The caller then goes away, and the
    // commit keeps everything the Put had reserved.
    let reserved = {
        let mut put = Box::pin(store.put(&mut input));
        for _ in 0..8 {
            assert!(futures::poll!(&mut put).is_pending());
        }
        budget.usage()
    };
    assert_eq!(budget.usage(), reserved);
    drop(input);
    assert_eq!(store.current_sequence(), 0);
    assert_eq!(
        budget.usage().0,
        1,
        "the commit must hold the request's admission"
    );

    assert!(settle(&IndexedDbBackend, || budget.usage() == (0, 0)).await);
    assert_eq!(store.current_sequence(), 1);
    assert_eq!(
        hub.current_sequence(),
        1,
        "subscribers must hear of the batch"
    );
    let read = store.get(Bytes::from_static(b"k")).await.unwrap();
    assert_eq!(read.value.as_deref(), Some(b"v".as_slice()));
    store.close();
}

#[wasm_bindgen_test]
async fn limits_reject_oversized_work() {
    let name = database("limits");
    let roomy = open(&name).await;
    let config = Config {
        max_batch_bytes: 1024,
        max_query_bytes: 4096,
    };
    let store = IndexedDbStore::open(&name, config).await.unwrap();
    let kilobyte = vec![7u8; 1024];
    uncaught();

    // A batch over the limit is refused before any transaction, on both paths.
    record();
    let direct = store.put_batch(vec![row(b"big", &kilobyte)]).await;
    assert!(
        matches!(direct, Err(IngestError::ResourceExhausted { .. })),
        "{direct:?}"
    );
    let mut stack = connect_stack(AppState::new(Arc::new(store.clone())));
    let request = unary(PUT, &put_request(&[row(b"big", &kilobyte)]));
    let refused: Result<ingest::PutResponse, _> = unary_call(&mut stack, request).await;
    assert_eq!(refused.unwrap_err().code, ErrorCode::ResourceExhausted);

    // A direct batch must be one a request could carry.
    let empty = roomy.put_batch(Vec::new()).await;
    assert!(
        matches!(empty, Err(IngestError::Internal { .. })),
        "{empty:?}"
    );
    let too_many = vec![(Bytes::new(), Bytes::new()); MAX_PUT_ENTRIES + 1];
    let too_many = roomy.put_batch(too_many).await;
    assert!(
        matches!(too_many, Err(IngestError::PutTooLarge(_))),
        "{too_many:?}"
    );
    for (key, value) in [(MAX_KEY_LEN + 1, 1), (1, MAX_VALUE_LEN + 1)] {
        let outside = roomy
            .put_batch(vec![row(&vec![1; key], &vec![1; value])])
            .await;
        assert!(
            matches!(outside, Err(IngestError::Internal { .. })),
            "{key} {value} {outside:?}"
        );
    }

    // Entries that share one buffer can make a batch far larger than the memory that holds
    // it. These 1,024 entries of 4 MiB each add up to exactly 4 GiB, and that sum wraps to
    // zero in the 32-bit `usize` of this target.
    let shared = Bytes::from(vec![0u8; (4 << 20) - 13]);
    assert_eq!(put_entry_encoded_len(b"k", &shared), 4 << 20);
    let wrapping = vec![(Bytes::from_static(b"k"), shared); 1024];
    let wrapping = roomy.put_batch(wrapping).await;
    assert!(
        matches!(wrapping, Err(IngestError::ResourceExhausted { .. })),
        "{wrapping:?}"
    );
    assert!(transactions(&restore()).is_empty());

    // A request is held to the value limit of the Store API even when the request stack was
    // given a higher one, and the refused request places no transaction. A value of exactly
    // that length is stored. The long value follows another entry, so it is refused after
    // the batch began.
    let lenient = AppState::new(Arc::new(roomy.clone())).with_ingest_limits(IngestLimits {
        max_value_len: usize::MAX,
        ..IngestLimits::default()
    });
    let mut lenient = connect_stack(lenient);
    let second_of = |len| put_request(&[row(b"short", b"v"), row(b"long", &vec![1; len])]);
    record();
    let request = unary(PUT, &second_of(MAX_VALUE_LEN + 1));
    let refused: Result<ingest::PutResponse, _> = unary_call(&mut lenient, request).await;
    assert_eq!(refused.unwrap_err().code, ErrorCode::InvalidArgument);
    assert!(transactions(&restore()).is_empty());
    let request = unary(PUT, &second_of(MAX_VALUE_LEN));
    let _: ingest::PutResponse = unary_call(&mut lenient, request).await.unwrap();
    let read = roomy.get(Bytes::from_static(b"long")).await.unwrap();
    assert_eq!(read.value.unwrap().len(), MAX_VALUE_LEN);

    // A store does not open with a batch limit above 256 MiB, the largest batch the Store
    // API allows, and the refused open creates no database. The limit itself opens.
    let ceiling = database("limits-ceiling");
    let batch_limit = |max_batch_bytes| Config {
        max_batch_bytes,
        ..Config::default()
    };
    let refused = IndexedDbStore::open(&ceiling, batch_limit((256 << 20) + 1)).await;
    let refused = refused.err().unwrap();
    assert!(
        refused.contains("max_batch_bytes") && refused.contains("268435456"),
        "{refused}"
    );
    let opened = IndexedDbStore::open(&ceiling, batch_limit(256 << 20))
        .await
        .unwrap();
    assert!(opened.created());
    opened.close();

    // A query holds at most the configured bytes of rows. A row counts its key, its value
    // and 64 bytes, so four of these rows fit and five do not.
    let keys: Vec<_> = (0..8u8).map(|i| Bytes::from(vec![b'r', i])).collect();
    let rows = keys.iter().map(|key| row(key, &kilobyte[..900])).collect();
    roomy.put_batch(rows).await.unwrap();
    let start = Bytes::from_static(b"r");
    record_copies();
    let all = store
        .range_scan(start.clone(), Bytes::new(), usize::MAX, true)
        .await;
    let copies = copied();
    assert!(all.err().unwrap().contains("4096 bytes"));

    // The fifth row is counted before it is copied, so only four values left JS.
    assert_eq!(copies.iter().filter(|length| **length == 900).count(), 4);
    let mut some = store
        .range_scan(start, Bytes::new(), 4, true)
        .await
        .unwrap();
    assert_eq!(drain(&mut some.scan, usize::MAX).await.len(), 4);
    assert!(store
        .get_many(keys.clone())
        .await
        .err()
        .unwrap()
        .contains("4096 bytes"));
    assert_eq!(
        store
            .get_many(keys[..4].to_vec())
            .await
            .unwrap()
            .value
            .len(),
        4
    );

    // The answer of a multi-key read holds a row for every key, found or not, and those
    // count before anything is read.
    record();
    let absent = store.get_many(vec![Bytes::from_static(b"none"); 64]).await;
    assert!(absent.err().unwrap().contains("4096 bytes"));
    assert!(transactions(&restore()).is_empty());

    // A point read counts the same way, to the byte.
    let fits = 4096 - 64 - 1;
    let rows = vec![row(b"g", &vec![1; fits]), row(b"h", &vec![1; fits + 1])];
    roomy.put_batch(rows).await.unwrap();
    let read = store.get(Bytes::from_static(b"g")).await.unwrap();
    assert_eq!(read.value.unwrap().len(), fits);
    record_copies();
    let over = store.get(Bytes::from_static(b"h")).await;
    let copies = copied();
    assert!(over.err().unwrap().contains("4096 bytes"));

    // The read copied the sequence row and refused the value before copying it.
    assert!(copies.contains(&8), "{copies:?}");
    assert!(!copies.contains(&(fits as u32 + 1)), "{copies:?}");

    assert_nothing_uncaught().await;
    store.close();
    roomy.close();
}

#[wasm_bindgen_test]
async fn get_many_reads_through_a_window_and_stops_at_the_budget() {
    let name = database("window");
    let roomy = open(&name).await;
    let large = vec![2u8; 256 << 10];
    let rows = vec![row(b"a", b"1"), row(b"b", b"2"), row(b"large", &large)];
    roomy.put_batch(rows).await.unwrap();
    let config = Config {
        max_query_bytes: 1 << 20,
        ..Config::default()
    };
    let store = IndexedDbStore::open(&name, config).await.unwrap();
    uncaught();

    // More keys than reads are outstanding at once, with duplicates and misses throughout.
    // The answer keeps their order and comes from one transaction.
    let cycle: [(&'static [u8], Option<&'static [u8]>); 3] =
        [(b"a", Some(b"1")), (b"missing", None), (b"b", Some(b"2"))];
    let expected: Vec<_> = (0..50).map(|i| cycle[i % 3]).collect();
    let keys = expected.iter().map(|(key, _)| Bytes::from_static(key));
    record();
    let read = store.get_many(keys.collect()).await.unwrap();
    let lines = restore();
    assert_eq!(
        transactions(&lines),
        ["transaction kv,meta readonly undefined"]
    );
    assert_eq!(placed(&lines, "get kv "), 50);
    let read: Vec<_> = read
        .value
        .iter()
        .map(|(key, value)| (key.as_ref(), value.as_deref()))
        .collect();
    assert_eq!(read, expected);

    // The budget has room for three of the large values. Asked for a thousand times after
    // twenty small rows, the value is copied three times. The fourth is refused before it is
    // copied, when 23 values were read and 16 more reads are outstanding.
    let mut keys = vec![Bytes::from_static(b"a"); 20];
    keys.resize(1020, Bytes::from_static(b"large"));
    record();
    record_copies();
    let refused = store.get_many(keys).await;
    let copies = copied();
    let lines = restore();
    assert!(refused.err().unwrap().contains("1048576 bytes"));
    assert_eq!(placed(&lines, "get kv "), 23 + 16);
    let large_copies = copies.iter().filter(|length| **length == 256 << 10);
    assert_eq!(large_copies.count(), 3);

    assert_nothing_uncaught().await;
    store.close();
    roomy.close();
}

/// A page timer as a future that is Send.
fn timer(ms: u32) -> oneshot::Receiver<()> {
    let (fire, fired) = oneshot::channel();
    spawn_local(async move {
        sleep(ms).await;
        let _ = fire.send(());
    });
    fired
}

/// Put middleware that a page timer wakes once and that never finishes.
struct Waiting;

impl PutMiddleware for Waiting {
    fn call<'a>(
        &'a self,
        _parts: &'a mut http::request::Parts,
    ) -> BoxFuture<'a, Result<(), ConnectError>> {
        Box::pin(async {
            let _ = timer(50).await;
            futures::future::pending().await
        })
    }
}

#[wasm_bindgen_test]
async fn deadlines_are_kept_with_the_clock_of_the_page() {
    let store = open(&database("deadline")).await;
    store.put_batch(vec![row(b"k", b"v")]).await.unwrap();
    let mut stack = connect_stack(AppState::new(Arc::new(store.clone())));
    let get = query::GetRequest {
        key: b"k".to_vec(),
        ..Default::default()
    };

    // A query that carries a deadline is answered, in the Connect protocol and in gRPC-Web.
    // The stack drops its deadline, because the dispatcher would time it with the standard
    // clock, and this target does not have that clock.
    let mut connect = unary(GET, &get);
    connect
        .headers_mut()
        .insert("connect-timeout-ms", "5000".parse().unwrap());
    let read: query::GetResponse = unary_call(&mut stack, connect).await.unwrap();
    assert_eq!(read.value.as_deref(), Some(b"v".as_slice()));
    let mut grpc_web = streaming(GET, &get);
    let headers = grpc_web.headers_mut();
    headers.insert(
        http::header::CONTENT_TYPE,
        "application/grpc-web+proto".parse().unwrap(),
    );
    headers.insert("grpc-timeout", "5S".parse().unwrap());
    let response = call(&mut stack, grpc_web).await;
    assert_eq!(response.status(), 200);
    let Some(Envelope::Message(message)) = Envelopes::new(response.into_body()).next().await else {
        panic!("the response must carry a gRPC-Web message");
    };
    let read = query::GetResponse::decode_from_slice(&message).unwrap();
    assert_eq!(read.value.as_deref(), Some(b"v".as_slice()));

    // A Put is refused once a poll finds its deadline passed. The middleware is still
    // waiting when the page timer wakes the request, 40 ms after the deadline.
    let mut stack = stack.with_put_middleware(Waiting);
    let mut put = unary(PUT, &put_request(&[row(b"late", b"v")]));
    put.headers_mut()
        .insert("connect-timeout-ms", "10".parse().unwrap());
    let answer = within(5_000, unary_call(&mut stack, put)).await;
    let answer: Result<ingest::PutResponse, _> = answer.expect("the deadline must end the wait");
    assert_eq!(answer.unwrap_err().code, ErrorCode::DeadlineExceeded);
    let read = store.get(Bytes::from_static(b"late")).await.unwrap();
    assert!(read.value.is_none());
    store.close();
}

#[wasm_bindgen_test]
async fn request_stack_serves_compressed_puts_and_reduce() {
    let store = Arc::new(open(&database("stack")).await);
    let mut stack = connect_stack(AppState::new(store.clone()));

    // A zstd body is decoded in the page.
    let rows = [
        (Bytes::from_static(b"n/1"), stored_row(10, "a")),
        (Bytes::from_static(b"n/2"), stored_row(32, "b")),
    ];
    let body = zstd::bulk::compress(&put_request(&rows).encode_to_vec(), 1).unwrap();
    let mut put = request(PUT, UNARY_PROTO, Full::new(Bytes::from(body)));
    let headers = put.headers_mut();
    headers.insert(http::header::CONTENT_ENCODING, "zstd".parse().unwrap());
    headers.insert("connect-timeout-ms", "5000".parse().unwrap());
    let response: ingest::PutResponse = unary_call(&mut stack, put).await.unwrap();
    assert_eq!(response.sequence_number, 1);

    // Reduce runs the server's DataFusion plan over rows read from IndexedDB.
    let amount = KvExpr::Field(KvFieldRef::Value {
        index: 0,
        kind: KvFieldKind::Int64,
        nullable: true,
    });
    let reduce = query::ReduceRequest {
        start: b"n/".to_vec(),
        end: b"n/\xff".to_vec(),
        params: Some(to_proto_reduce_params(RangeReduceRequest {
            reducers: vec![
                RangeReducerSpec {
                    op: RangeReduceOp::CountAll,
                    expr: None,
                    filter: None,
                },
                RangeReducerSpec {
                    op: RangeReduceOp::SumField,
                    expr: Some(amount),
                    filter: None,
                },
            ],
            group_by: Vec::new(),
            filter: None,
        }))
        .into(),
        ..Default::default()
    };
    let mut frames = open_stream(&mut stack, REDUCE, &reduce).await;
    let Some(Envelope::Message(frame)) = frames.next().await else {
        panic!("the Reduce must answer with a frame");
    };
    let reduced = query::ReduceResponse::decode_from_slice(&frame).unwrap();
    let text = format!("{:?}", reduced.results);
    assert!(
        text.contains("Uint64Value(2)") && text.contains("Int64Value(42)"),
        "{text}"
    );
    assert_eq!(reduced.detail.as_option().unwrap().sequence_number, 1);
    store.close();
}

#[wasm_bindgen_test]
async fn a_commit_wakes_a_live_subscriber() {
    let name = database("wake");
    let serving = open(&name).await;
    let other = open(&name).await;
    let state = AppState::new(Arc::new(serving.clone()));
    serving.watch(state.stream.clone());
    let mut stack = connect_stack(state);
    let mut frames = open_stream(&mut stack, SUBSCRIBE, &subscribe(b"s/", None)).await;

    // The subscriber hears of a batch the serving store commits without a request and of
    // one another connection commits, and receives the entries its selector matches.
    for (sequence, writer) in [(1, &serving), (2, &other)] {
        let rows = vec![row(b"s/1", b"v"), row(b"t/1", b"other")];
        assert_eq!(writer.put_batch(rows).await.unwrap(), sequence);
        let Some(Some(Envelope::Message(frame))) = within(2_000, frames.next()).await else {
            panic!("the subscriber must receive a frame for batch {sequence}");
        };
        let frame = stream::SubscribeResponse::decode_from_slice(&frame).unwrap();
        assert_eq!(frame.sequence_number, sequence);
        let keys: Vec<_> = frame.entries.iter().map(|entry| &entry.key[..]).collect();
        assert_eq!(keys, [b"s/1"]);
    }
    drop(frames);
    serving.close();
    other.close();
}
