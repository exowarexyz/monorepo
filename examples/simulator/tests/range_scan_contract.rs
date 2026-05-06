//! Contract tests for store capabilities (RocksDB simulator).

use bytes::Bytes;
use exoware_server::{Ingest, Prune, Query, Sequence};
use exoware_simulator::RocksStore;
use tempfile::tempdir;

fn seed_abc(store: &RocksStore) {
    store
        .put_batch(&[
            (Bytes::from_static(b"a"), Bytes::from_static(b"1")),
            (Bytes::from_static(b"b"), Bytes::from_static(b"2")),
            (Bytes::from_static(b"c"), Bytes::from_static(b"3")),
        ])
        .expect("put_batch");
}

fn keys(rows: &[(Bytes, Bytes)]) -> Vec<&[u8]> {
    rows.iter().map(|(k, _)| k.as_ref()).collect()
}

fn scan(
    store: &RocksStore,
    start: &[u8],
    end: &[u8],
    limit: usize,
    forward: bool,
) -> Vec<(Bytes, Bytes)> {
    store
        .range_scan(start, end, limit, forward)
        .expect("open scan")
        .collect::<Result<Vec<_>, _>>()
        .expect("scan")
}

// -- get --

#[test]
fn get_returns_none_for_missing_key() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    assert!(store.get(b"missing").expect("get").is_none());
}

#[test]
fn get_returns_value_after_put() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    store
        .put_batch(&[(Bytes::from_static(b"k"), Bytes::from_static(b"v"))])
        .expect("put_batch");
    assert_eq!(
        store.get(b"k").expect("get").as_deref(),
        Some(b"v".as_slice())
    );
}

#[test]
fn get_hides_internal_seq_meta_key() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    store
        .put_batch(&[(Bytes::from_static(b"x"), Bytes::from_static(b"y"))])
        .expect("put_batch");
    assert!(store.get(b"__simulator_seq__").expect("get").is_none());
}

// -- put_batch / sequence --

#[test]
fn put_batch_returns_monotonic_sequence_numbers() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    let s1 = store
        .put_batch(&[(Bytes::from_static(b"a"), Bytes::from_static(b"1"))])
        .expect("put1");
    let s2 = store
        .put_batch(&[(Bytes::from_static(b"b"), Bytes::from_static(b"2"))])
        .expect("put2");
    assert_eq!(s1, 1);
    assert_eq!(s2, 2);
    assert_eq!(store.current_sequence(), 2);
}

// -- forward range_scan --

#[test]
fn range_scan_inclusive_end_includes_end_key() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"a", b"c", usize::MAX, true);
    assert_eq!(keys(&rows), vec![b"a".as_slice(), b"b", b"c"]);
}

#[test]
fn range_scan_empty_end_is_unbounded_above() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    store
        .put_batch(&[
            (Bytes::from_static(b"m"), Bytes::from_static(b"x")),
            (Bytes::from_static(b"z"), Bytes::from_static(b"y")),
        ])
        .expect("put_batch");

    let rows = scan(&store, b"m", b"", usize::MAX, true);
    assert_eq!(rows.len(), 2);
}

#[test]
fn range_scan_forward_respects_limit() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"a", b"c", 2, true);
    assert_eq!(keys(&rows), vec![b"a".as_slice(), b"b"]);
}

#[test]
fn range_scan_returns_empty_when_no_keys_match() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"d", b"f", usize::MAX, true);
    assert!(rows.is_empty());
}

#[test]
fn range_scan_limit_zero_returns_empty() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"a", b"c", 0, true);
    assert!(rows.is_empty());
}

#[test]
fn range_scan_excludes_seq_meta_key() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    store
        .put_batch(&[(
            Bytes::from_static(b"__simulator_seq_neighbor__"),
            Bytes::from_static(b"v"),
        )])
        .expect("put_batch");

    let rows = scan(&store, b"", b"", usize::MAX, true);
    for (k, _) in &rows {
        assert_ne!(k.as_ref(), b"__simulator_seq__");
    }
}

// -- reverse range_scan --

#[test]
fn range_scan_reverse_returns_descending_order() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"a", b"c", usize::MAX, false);
    assert_eq!(keys(&rows), vec![b"c".as_slice(), b"b", b"a"]);
}

#[test]
fn range_scan_reverse_respects_limit() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"a", b"c", 2, false);
    assert_eq!(keys(&rows), vec![b"c".as_slice(), b"b"]);
}

#[test]
fn range_scan_reverse_unbounded_end() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"a", b"", usize::MAX, false);
    assert_eq!(keys(&rows), vec![b"c".as_slice(), b"b", b"a"]);
}

#[test]
fn range_scan_single_key() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"b", b"b", usize::MAX, true);
    assert_eq!(keys(&rows), vec![b"b".as_slice()]);
}

// -- get_many --

#[test]
fn get_many_returns_found_and_missing() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    seed_abc(&store);

    let results = store.get_many(&[b"a", b"missing", b"c"]).expect("get_many");
    assert_eq!(results.len(), 3);
    assert_eq!(results[0], (b"a".to_vec(), Some(b"1".to_vec())));
    assert_eq!(results[1], (b"missing".to_vec(), None));
    assert_eq!(results[2], (b"c".to_vec(), Some(b"3".to_vec())));
}

#[test]
fn get_many_returns_none_for_seq_meta_key() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    seed_abc(&store);

    let results = store
        .get_many(&[b"__simulator_seq__", b"a"])
        .expect("get_many");
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].1, None);
    assert_eq!(results[1], (b"a".to_vec(), Some(b"1".to_vec())));
}

// -- delete_batch --

#[test]
fn delete_batch_removes_keys() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    seed_abc(&store);

    store.delete_batch(&[b"a", b"c"]).expect("delete_batch");
    assert!(store.get(b"a").expect("get").is_none());
    assert_eq!(
        store.get(b"b").expect("get").as_deref(),
        Some(b"2".as_slice())
    );
    assert!(store.get(b"c").expect("get").is_none());
}

#[test]
fn delete_batch_advances_sequence() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    let s1 = store
        .put_batch(&[(Bytes::from_static(b"x"), Bytes::from_static(b"y"))])
        .expect("put");
    let s2 = store.delete_batch(&[b"x"]).expect("delete");
    assert!(s2 > s1);
    assert_eq!(store.current_sequence(), s2);
}
