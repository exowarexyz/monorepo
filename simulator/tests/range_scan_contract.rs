//! Contract tests for `StoreEngine::range_scan` (RocksDB simulator): inclusive `[start, end]`.

use bytes::Bytes;
use exoware_server::StoreEngine;
use exoware_simulator::RocksStore;
use tempfile::tempdir;

#[test]
fn range_scan_inclusive_end_includes_end_key() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path()).expect("open db");
    store
        .put_batch(&[
            (Bytes::from_static(b"a"), Bytes::from_static(b"1")),
            (Bytes::from_static(b"b"), Bytes::from_static(b"2")),
            (Bytes::from_static(b"c"), Bytes::from_static(b"3")),
        ])
        .expect("put_batch");

    let rows = store
        .range_scan(b"a", b"c", usize::MAX, true)
        .expect("range_scan");
    let keys: Vec<&[u8]> = rows.iter().map(|(k, _)| k.as_ref()).collect();
    assert_eq!(
        keys,
        vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()]
    );
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

    let rows = store
        .range_scan(b"m", b"", usize::MAX, true)
        .expect("range_scan");
    assert_eq!(rows.len(), 2);
}
