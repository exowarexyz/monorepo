//! Contract tests for store capabilities (RocksDB simulator).

use std::future::Future;

use bytes::Bytes;
use exoware_server::{Ingest, Query, RangeScan, ReadOptions, Sequence};
use exoware_simulator::RocksStore;
use tempfile::tempdir;

fn block_on<T>(future: impl Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(future)
}

fn put_batch(store: &RocksStore, kvs: Vec<(Bytes, Bytes)>) -> u64 {
    block_on(store.put_batch(kvs)).expect("put_batch")
}

fn seed_abc(store: &RocksStore) {
    put_batch(
        store,
        vec![
            (Bytes::from_static(b"a"), Bytes::from_static(b"1")),
            (Bytes::from_static(b"b"), Bytes::from_static(b"2")),
            (Bytes::from_static(b"c"), Bytes::from_static(b"3")),
        ],
    );
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
    let mut cursor = block_on(store.range_scan(
        Bytes::copy_from_slice(start),
        Bytes::copy_from_slice(end),
        limit,
        forward,
        ReadOptions::default(),
    ))
    .expect("open scan");
    let mut rows = Vec::new();
    loop {
        let batch = block_on(cursor.next_batch(usize::MAX)).expect("scan");
        if batch.rows.is_empty() {
            break;
        }
        rows.extend(batch.rows);
    }
    rows
}

fn get_value(store: &RocksStore, key: &[u8]) -> Option<Bytes> {
    block_on(store.get(Bytes::copy_from_slice(key), ReadOptions::default()))
        .expect("get")
        .value
}

fn get_many_values(store: &RocksStore, keys: &[&[u8]]) -> Vec<(Bytes, Option<Bytes>)> {
    let keys = keys.iter().map(|key| Bytes::copy_from_slice(key)).collect();
    block_on(store.get_many(keys, ReadOptions::default()))
        .expect("get_many")
        .value
}

// -- get --

#[test]
fn get_returns_none_for_missing_key() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    assert!(get_value(&store, b"missing").is_none());
}

#[test]
fn get_returns_value_after_put() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    put_batch(
        &store,
        vec![(Bytes::from_static(b"k"), Bytes::from_static(b"v"))],
    );
    assert_eq!(get_value(&store, b"k").as_deref(), Some(b"v".as_slice()));
}

// -- put_batch / sequence --

#[test]
fn put_batch_returns_monotonic_sequence_numbers() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    let s1 = put_batch(
        &store,
        vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))],
    );
    let s2 = put_batch(
        &store,
        vec![(Bytes::from_static(b"b"), Bytes::from_static(b"2"))],
    );
    assert_eq!(s1, 1);
    assert_eq!(s2, 2);
    assert_eq!(store.current_sequence(), 2);
}

#[test]
fn sequence_persists_across_reopen() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    put_batch(
        &store,
        vec![(Bytes::from_static(b"a"), Bytes::from_static(b"1"))],
    );
    put_batch(
        &store,
        vec![(Bytes::from_static(b"b"), Bytes::from_static(b"2"))],
    );
    drop(store);

    let reopened = RocksStore::open(dir.path(), None).expect("reopen db");
    assert_eq!(reopened.current_sequence(), 2);
    let s3 = put_batch(
        &reopened,
        vec![(Bytes::from_static(b"c"), Bytes::from_static(b"3"))],
    );
    assert_eq!(s3, 3);
}

// -- forward range_scan --

#[test]
fn range_scan_inclusive_end_includes_end_key() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"a", b"c", usize::MAX, true);
    assert_eq!(keys(&rows), vec![b"a".as_slice(), b"b", b"c"]);
}

#[test]
fn range_scan_empty_end_is_unbounded_above() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    put_batch(
        &store,
        vec![
            (Bytes::from_static(b"m"), Bytes::from_static(b"x")),
            (Bytes::from_static(b"z"), Bytes::from_static(b"y")),
        ],
    );

    let rows = scan(&store, b"m", b"", usize::MAX, true);
    assert_eq!(rows.len(), 2);
}

#[test]
fn range_scan_forward_respects_limit() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"a", b"c", 2, true);
    assert_eq!(keys(&rows), vec![b"a".as_slice(), b"b"]);
}

#[test]
fn range_scan_returns_empty_when_no_keys_match() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"d", b"f", usize::MAX, true);
    assert!(rows.is_empty());
}

#[test]
fn range_scan_limit_zero_returns_empty() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"a", b"c", 0, true);
    assert!(rows.is_empty());
}

// -- reverse range_scan --

#[test]
fn range_scan_reverse_returns_descending_order() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"a", b"c", usize::MAX, false);
    assert_eq!(keys(&rows), vec![b"c".as_slice(), b"b", b"a"]);
}

#[test]
fn range_scan_reverse_respects_limit() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"a", b"c", 2, false);
    assert_eq!(keys(&rows), vec![b"c".as_slice(), b"b"]);
}

#[test]
fn range_scan_reverse_unbounded_end() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"a", b"", usize::MAX, false);
    assert_eq!(keys(&rows), vec![b"c".as_slice(), b"b", b"a"]);
}

#[test]
fn range_scan_single_key() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    seed_abc(&store);

    let rows = scan(&store, b"b", b"b", usize::MAX, true);
    assert_eq!(keys(&rows), vec![b"b".as_slice()]);
}

// -- get_many --

#[test]
fn get_many_returns_found_and_missing() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    seed_abc(&store);

    let results = get_many_values(&store, &[b"a", b"missing", b"c"]);
    assert_eq!(results.len(), 3);
    assert_eq!(
        results[0],
        (Bytes::from_static(b"a"), Some(Bytes::from_static(b"1")))
    );
    assert_eq!(results[1], (Bytes::from_static(b"missing"), None));
    assert_eq!(
        results[2],
        (Bytes::from_static(b"c"), Some(Bytes::from_static(b"3")))
    );
}

#[test]
fn snapshot_sequence_and_rows_survive_writes_between_pages() {
    for forward in [true, false] {
        let dir = tempdir().expect("tempdir");
        let store = RocksStore::open(dir.path(), None).expect("open db");
        seed_abc(&store);
        let before = store.current_sequence();
        let mut cursor = block_on(store.range_scan(
            Bytes::new(),
            Bytes::new(),
            usize::MAX,
            forward,
            ReadOptions::default(),
        ))
        .expect("scan");
        let first = block_on(cursor.next_batch(1)).expect("first page");
        let later = put_batch(
            &store,
            vec![
                (Bytes::from_static(b"b"), Bytes::from_static(b"changed")),
                (Bytes::from_static(b"bb"), Bytes::from_static(b"new")),
            ],
        );
        assert!(later > before);
        assert_eq!(cursor.sequence_number(), before);
        let rest = block_on(cursor.next_batch(10)).expect("remaining page");
        let mut all = first.rows;
        all.extend(rest.rows);
        if forward {
            assert_eq!(keys(&all), vec![b"a".as_slice(), b"b", b"c"]);
            assert_eq!(all[1].1, Bytes::from_static(b"2"));
        } else {
            assert_eq!(keys(&all), vec![b"c".as_slice(), b"b", b"a"]);
            assert_eq!(all[1].1, Bytes::from_static(b"2"));
        }
        assert!(block_on(cursor.next_batch(10))
            .expect("end")
            .rows
            .is_empty());
        assert_eq!(cursor.sequence_number(), before);
    }
}

#[test]
fn empty_queries_report_snapshot_sequence_and_enforce_floor() {
    use exoware_server::QueryError;
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    for expected in [0, 1] {
        if expected == 1 {
            seed_abc(&store);
        }
        let options = ReadOptions {
            min_sequence_number: Some(expected),
        };
        let missing =
            block_on(store.get(Bytes::from_static(b"missing"), options)).expect("missing");
        assert!(missing.value.is_none());
        assert_eq!(missing.sequence_number, expected);
        let empty = block_on(store.get_many(Vec::new(), options)).expect("empty get_many");
        assert!(empty.value.is_empty());
        assert_eq!(empty.sequence_number, expected);
        let mut scan = block_on(store.range_scan(Bytes::new(), Bytes::new(), 0, true, options))
            .expect("empty scan");
        assert_eq!(scan.sequence_number(), expected);
        assert!(block_on(scan.next_batch(1)).expect("page").rows.is_empty());
        let ahead = ReadOptions {
            min_sequence_number: Some(expected + 1),
        };
        assert!(
            matches!(block_on(store.get(Bytes::new(), ahead)), Err(QueryError::NotReady {required, current}) if required == expected + 1 && current == expected)
        );
        assert!(
            matches!(block_on(store.get_many(Vec::new(), ahead)), Err(QueryError::NotReady {required, current}) if required == expected + 1 && current == expected)
        );
        assert!(
            matches!(block_on(store.range_scan(Bytes::new(), Bytes::new(), 0, true, ahead)), Err(QueryError::NotReady {required, current}) if required == expected + 1 && current == expected)
        );
    }
}

#[test]
fn get_many_values_match_their_batch_sequence_during_commits() {
    let dir = tempdir().expect("tempdir");
    let store = RocksStore::open(dir.path(), None).expect("open db");
    let writer = store.clone();
    let done = std::thread::spawn(move || {
        for sequence in 1u64..=40 {
            let value = Bytes::copy_from_slice(&sequence.to_be_bytes());
            assert_eq!(
                put_batch(
                    &writer,
                    vec![
                        (Bytes::from_static(b"a"), value.clone()),
                        (Bytes::from_static(b"b"), value)
                    ]
                ),
                sequence
            );
        }
    });
    for _ in 0..200 {
        let result = block_on(store.get_many(
            vec![Bytes::from_static(b"a"), Bytes::from_static(b"b")],
            ReadOptions::default(),
        ))
        .expect("get_many");
        let expected = (result.sequence_number != 0)
            .then(|| Bytes::copy_from_slice(&result.sequence_number.to_be_bytes()));
        assert_eq!(result.value[0].1, expected);
        assert_eq!(result.value[1].1, expected);
    }
    done.join().expect("writer");
}
