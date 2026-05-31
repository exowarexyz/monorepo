//! Contract tests for RocksDB simulator pruning.

use std::future::Future;

use bytes::Bytes;
use exoware_sdk::keys::KeyCodec;
use exoware_sdk::kv_codec::Utf8;
use exoware_sdk::match_key::MatchKey;
use exoware_sdk::prune_policy::{
    GroupBy, KeysScope, OrderBy, OrderEncoding, PolicyScope, PrunePolicy, PrunePolicyDocument,
    RetainPolicy, PRUNE_POLICY_DOCUMENT_VERSION,
};
use exoware_server::{Ingest, Log, Prune, Query, Sequence};
use exoware_simulator::RocksStore;
use tempfile::tempdir;

const TEST_RESERVED_BITS: u8 = 4;
const TEST_PREFIX: u16 = 1;

fn block_on<T>(future: impl Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(future)
}

fn codec() -> KeyCodec {
    KeyCodec::new(TEST_RESERVED_BITS, TEST_PREFIX)
}

fn versioned_key(logical: &[u8], version: u64) -> Bytes {
    let mut payload = Vec::new();
    payload.extend_from_slice(logical);
    payload.extend_from_slice(b"\0\0");
    payload.extend_from_slice(&version.to_be_bytes());
    Bytes::copy_from_slice(codec().encode(&payload).expect("encode key").as_ref())
}

fn put_batch(store: &RocksStore, kvs: Vec<(Bytes, Bytes)>) -> u64 {
    block_on(store.put_batch(kvs)).expect("put_batch")
}

fn get_value(store: &RocksStore, key: &Bytes) -> Option<Bytes> {
    block_on(store.get(key.clone())).expect("get").0
}

fn prune_document(policies: &[PrunePolicy]) -> PrunePolicyDocument {
    PrunePolicyDocument {
        version: PRUNE_POLICY_DOCUMENT_VERSION,
        policies: policies.to_vec(),
    }
}

fn try_apply_prune(store: &RocksStore, policies: &[PrunePolicy]) -> Result<(), String> {
    block_on(store.apply_prune_policies(prune_document(policies)))
}

fn apply_prune(store: &RocksStore, policies: &[PrunePolicy]) {
    try_apply_prune(store, policies).expect("apply prune policies");
}

fn version_policy_with_encoding(retain: RetainPolicy, encoding: OrderEncoding) -> PrunePolicy {
    PrunePolicy {
        scope: PolicyScope::Keys(KeysScope {
            match_key: MatchKey {
                reserved_bits: TEST_RESERVED_BITS,
                prefix: TEST_PREFIX,
                payload_regex: Utf8::from(
                    "(?s-u)^(?P<logical>(?:\\x00\\xFF|[^\\x00])*)\\x00\\x00(?P<version>.{8})$",
                ),
            },
            group_by: GroupBy {
                capture_groups: vec![Utf8::from("logical")],
            },
            order_by: Some(OrderBy {
                capture_group: Utf8::from("version"),
                encoding,
            }),
        }),
        retain,
    }
}

fn version_policy(retain: RetainPolicy) -> PrunePolicy {
    version_policy_with_encoding(retain, OrderEncoding::U64Be)
}

fn sequence_policy(retain: RetainPolicy) -> PrunePolicy {
    PrunePolicy {
        scope: PolicyScope::Sequence,
        retain,
    }
}

#[test]
fn keys_drop_all_deletes_matching_family_keys() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    let a1 = versioned_key(b"a", 1);
    let b1 = versioned_key(b"b", 1);
    put_batch(
        &store,
        vec![
            (a1.clone(), Bytes::from_static(b"a1")),
            (b1.clone(), Bytes::from_static(b"b1")),
            (Bytes::from_static(b"raw"), Bytes::from_static(b"raw")),
        ],
    );

    apply_prune(&store, &[version_policy(RetainPolicy::DropAll)]);

    assert!(get_value(&store, &a1).is_none());
    assert!(get_value(&store, &b1).is_none());
    assert_eq!(
        get_value(&store, &Bytes::from_static(b"raw")).as_deref(),
        Some(b"raw".as_slice())
    );
}

#[test]
fn keys_keep_latest_deletes_old_versions_without_advancing_sequence() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    let v1 = versioned_key(b"row", 1);
    let v2 = versioned_key(b"row", 2);
    let v3 = versioned_key(b"row", 3);
    let initial_sequence = put_batch(
        &store,
        vec![
            (v1.clone(), Bytes::from_static(b"v1")),
            (v2.clone(), Bytes::from_static(b"v2")),
            (v3.clone(), Bytes::from_static(b"v3")),
        ],
    );

    apply_prune(
        &store,
        &[version_policy(RetainPolicy::KeepLatest { count: 1 })],
    );

    assert!(get_value(&store, &v1).is_none());
    assert!(get_value(&store, &v2).is_none());
    assert_eq!(get_value(&store, &v3).as_deref(), Some(b"v3".as_slice()));
    assert_eq!(store.current_sequence(), initial_sequence);
    assert!(block_on(store.get_batch(initial_sequence + 1))
        .expect("get batch")
        .is_none());
}

#[test]
fn key_prune_is_idempotent_when_reapplied() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    let v1 = versioned_key(b"row", 1);
    let v2 = versioned_key(b"row", 2);
    let v3 = versioned_key(b"row", 3);
    let initial_sequence = put_batch(
        &store,
        vec![
            (v1.clone(), Bytes::from_static(b"v1")),
            (v2.clone(), Bytes::from_static(b"v2")),
            (v3.clone(), Bytes::from_static(b"v3")),
        ],
    );
    let policy = version_policy(RetainPolicy::KeepLatest { count: 1 });

    apply_prune(&store, std::slice::from_ref(&policy));
    let sequence_after_first_prune = store.current_sequence();
    apply_prune(&store, &[policy]);

    assert!(get_value(&store, &v1).is_none());
    assert!(get_value(&store, &v2).is_none());
    assert_eq!(get_value(&store, &v3).as_deref(), Some(b"v3".as_slice()));
    assert_eq!(sequence_after_first_prune, initial_sequence);
    assert_eq!(store.current_sequence(), sequence_after_first_prune);
    assert!(block_on(store.get_batch(sequence_after_first_prune + 1))
        .expect("get batch")
        .is_none());
}

#[test]
fn keys_threshold_retains_greater_than_or_equal_versions() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    let v3 = versioned_key(b"row", 3);
    let v4 = versioned_key(b"row", 4);
    let v5 = versioned_key(b"row", 5);
    put_batch(
        &store,
        vec![
            (v3.clone(), Bytes::from_static(b"v3")),
            (v4.clone(), Bytes::from_static(b"v4")),
            (v5.clone(), Bytes::from_static(b"v5")),
        ],
    );

    apply_prune(
        &store,
        &[version_policy(RetainPolicy::GreaterThanOrEqual {
            threshold: 4,
        })],
    );

    assert!(get_value(&store, &v3).is_none());
    assert_eq!(get_value(&store, &v4).as_deref(), Some(b"v4".as_slice()));
    assert_eq!(get_value(&store, &v5).as_deref(), Some(b"v5".as_slice()));
}

#[test]
fn keys_threshold_retention_rejects_i64_ordering() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    let v1 = versioned_key(b"row", 1);
    put_batch(&store, vec![(v1.clone(), Bytes::from_static(b"v1"))]);

    let err = try_apply_prune(
        &store,
        &[version_policy_with_encoding(
            RetainPolicy::GreaterThanOrEqual { threshold: 1 << 63 },
            OrderEncoding::I64Be,
        )],
    )
    .expect_err("i64 threshold retention should be rejected");

    assert!(err.contains("threshold retention requires order_by.encoding = u64_be"));
    assert_eq!(get_value(&store, &v1).as_deref(), Some(b"v1".as_slice()));
}

#[test]
fn sequence_scope_prunes_log_without_advancing_sequence() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    put_batch(
        &store,
        vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))],
    );
    put_batch(
        &store,
        vec![(Bytes::from_static(b"b"), Bytes::from_static(b"2"))],
    );
    let current = put_batch(
        &store,
        vec![(Bytes::from_static(b"c"), Bytes::from_static(b"3"))],
    );

    apply_prune(
        &store,
        &[sequence_policy(RetainPolicy::KeepLatest { count: 1 })],
    );

    assert_eq!(store.current_sequence(), current);
    assert!(block_on(store.get_batch(1)).expect("get batch").is_none());
    assert!(block_on(store.get_batch(2)).expect("get batch").is_none());
    assert!(block_on(store.get_batch(3)).expect("get batch").is_some());
}

#[test]
fn overlapping_prune_policies_apply_in_input_order() {
    let sequence_then_keys_dir = tempdir().expect("tempdir");
    let sequence_then_keys = RocksStore::open(sequence_then_keys_dir.path()).expect("open db");
    let key = versioned_key(b"row", 1);
    let initial_sequence = put_batch(
        &sequence_then_keys,
        vec![(key.clone(), Bytes::from_static(b"v1"))],
    );

    apply_prune(
        &sequence_then_keys,
        &[
            sequence_policy(RetainPolicy::DropAll),
            version_policy(RetainPolicy::DropAll),
        ],
    );

    assert_eq!(sequence_then_keys.current_sequence(), initial_sequence);
    assert!(get_value(&sequence_then_keys, &key).is_none());
    assert!(block_on(sequence_then_keys.get_batch(initial_sequence))
        .expect("get batch")
        .is_none());
    assert!(block_on(sequence_then_keys.get_batch(initial_sequence + 1))
        .expect("get batch")
        .is_none());

    let keys_then_sequence_dir = tempdir().expect("tempdir");
    let keys_then_sequence = RocksStore::open(keys_then_sequence_dir.path()).expect("open db");
    let key = versioned_key(b"row", 1);
    let initial_sequence = put_batch(
        &keys_then_sequence,
        vec![(key.clone(), Bytes::from_static(b"v1"))],
    );

    apply_prune(
        &keys_then_sequence,
        &[
            version_policy(RetainPolicy::DropAll),
            sequence_policy(RetainPolicy::DropAll),
        ],
    );

    assert_eq!(keys_then_sequence.current_sequence(), initial_sequence);
    assert!(get_value(&keys_then_sequence, &key).is_none());
    assert!(block_on(keys_then_sequence.get_batch(initial_sequence))
        .expect("get batch")
        .is_none());
    assert!(block_on(keys_then_sequence.get_batch(initial_sequence + 1))
        .expect("get batch")
        .is_none());
}
