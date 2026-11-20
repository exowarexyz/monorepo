//! Point reads, range cursors and the snapshot a query reads.

use crate::{
    rpc::{self, Envelope},
    support::{
        apply_prune, commit, commit_one, drain, fresh, get_many_values, get_value, keys, row, scan,
        seed_abc, version_policy, versioned_key,
    },
    Backend,
};
use buffa::Message as _;
use bytes::Bytes;
use exoware_sdk::{prune_policy::RetainPolicy, query};
use exoware_server::{connect_stack, AppState, Query, RangeScan, Sequence};
use std::{cell::Cell, sync::Arc};

/// The rounds of reads the consistency case performs between two pauses.
const READ_ROUNDS_PER_PAUSE: usize = 8;

pub async fn get_returns_none_for_missing_key<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    assert!(get_value(&store, b"missing").await.is_none());
    backend.close(store).await;
}

pub async fn get_returns_value_after_put<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    commit_one(backend, &store, b"k", b"v").await;
    assert_eq!(
        get_value(&store, b"k").await.as_deref(),
        Some(b"v".as_slice())
    );
    backend.close(store).await;
}

pub async fn get_many_returns_found_and_missing<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    seed_abc(backend, &store).await;

    let results = get_many_values(&store, &[b"a", b"missing", b"c"]).await;
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
    backend.close(store).await;
}

pub async fn get_many_preserves_input_order_and_duplicates<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    seed_abc(backend, &store).await;

    let requested: [&[u8]; 6] = [b"c", b"a", b"missing", b"a", b"c", b"missing"];
    let results = get_many_values(&store, &requested).await;
    let expected: Vec<(Bytes, Option<Bytes>)> = requested
        .iter()
        .map(|key| {
            let value = match *key {
                b"a" => Some(Bytes::from_static(b"1")),
                b"c" => Some(Bytes::from_static(b"3")),
                _ => None,
            };
            (Bytes::copy_from_slice(key), value)
        })
        .collect();
    assert_eq!(results, expected);
    backend.close(store).await;
}

pub async fn empty_key_and_empty_value_are_stored<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    assert!(get_value(&store, b"").await.is_none());

    commit(
        backend,
        &store,
        vec![row(b"", b"empty key"), row(b"z", b"")],
    )
    .await;
    assert_eq!(
        get_value(&store, b"").await.as_deref(),
        Some(b"empty key".as_slice())
    );
    assert_eq!(get_value(&store, b"z").await, Some(Bytes::new()));
    assert_eq!(
        get_many_values(&store, &[b"z", b"", b"missing"]).await,
        vec![
            (Bytes::from_static(b"z"), Some(Bytes::new())),
            (Bytes::new(), Some(Bytes::from_static(b"empty key"))),
            (Bytes::from_static(b"missing"), None),
        ]
    );

    // The empty key is the smallest key, so an empty start includes it.
    let rows = scan(&store, b"", b"", usize::MAX, true).await;
    assert_eq!(rows, vec![row(b"", b"empty key"), row(b"z", b"")]);
    let rows = scan(&store, b"", b"", usize::MAX, false).await;
    assert_eq!(rows, vec![row(b"z", b""), row(b"", b"empty key")]);
    backend.close(store).await;
}

pub async fn empty_queries_report_snapshot_sequence<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    for expected in [0, 1] {
        if expected == 1 {
            seed_abc(backend, &store).await;
        }
        let missing = store
            .get(Bytes::from_static(b"missing"))
            .await
            .expect("get must succeed");
        assert!(missing.value.is_none());
        assert_eq!(missing.sequence_number, expected);
        let empty = store
            .get_many(Vec::new())
            .await
            .expect("an empty get_many must succeed");
        assert!(empty.value.is_empty());
        assert_eq!(empty.sequence_number, expected);
        let result = store
            .range_scan(Bytes::new(), Bytes::new(), 0, true)
            .await
            .expect("a range_scan with limit 0 must succeed");
        assert_eq!(result.sequence_number, expected);
        let mut scan = result.scan;
        assert!(scan
            .next_batch(1)
            .await
            .expect("next_batch must succeed")
            .rows
            .is_empty());
    }
    backend.close(store).await;
}

pub async fn range_scan_inclusive_end_includes_end_key<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    seed_abc(backend, &store).await;

    let rows = scan(&store, b"a", b"c", usize::MAX, true).await;
    assert_eq!(keys(&rows), vec![b"a".as_slice(), b"b", b"c"]);
    backend.close(store).await;
}

pub async fn range_scan_empty_end_is_unbounded_above<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    commit(backend, &store, vec![row(b"m", b"x"), row(b"z", b"y")]).await;

    let rows = scan(&store, b"m", b"", usize::MAX, true).await;
    assert_eq!(rows.len(), 2);
    backend.close(store).await;
}

pub async fn range_scan_forward_respects_limit<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    seed_abc(backend, &store).await;

    let rows = scan(&store, b"a", b"c", 2, true).await;
    assert_eq!(keys(&rows), vec![b"a".as_slice(), b"b"]);
    backend.close(store).await;
}

pub async fn range_scan_returns_empty_when_no_keys_match<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    seed_abc(backend, &store).await;

    let rows = scan(&store, b"d", b"f", usize::MAX, true).await;
    assert!(rows.is_empty());
    backend.close(store).await;
}

pub async fn range_scan_limit_zero_returns_empty<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    seed_abc(backend, &store).await;

    let rows = scan(&store, b"a", b"c", 0, true).await;
    assert!(rows.is_empty());
    backend.close(store).await;
}

pub async fn range_scan_reverse_returns_descending_order<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    seed_abc(backend, &store).await;

    let rows = scan(&store, b"a", b"c", usize::MAX, false).await;
    assert_eq!(keys(&rows), vec![b"c".as_slice(), b"b", b"a"]);
    backend.close(store).await;
}

pub async fn range_scan_reverse_respects_limit<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    seed_abc(backend, &store).await;

    let rows = scan(&store, b"a", b"c", 2, false).await;
    assert_eq!(keys(&rows), vec![b"c".as_slice(), b"b"]);
    backend.close(store).await;
}

pub async fn range_scan_reverse_unbounded_end<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    seed_abc(backend, &store).await;

    let rows = scan(&store, b"a", b"", usize::MAX, false).await;
    assert_eq!(keys(&rows), vec![b"c".as_slice(), b"b", b"a"]);
    backend.close(store).await;
}

pub async fn range_scan_single_key<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    seed_abc(backend, &store).await;

    let rows = scan(&store, b"b", b"b", usize::MAX, true).await;
    assert_eq!(keys(&rows), vec![b"b".as_slice()]);
    backend.close(store).await;
}

pub async fn range_scan_start_above_end_is_empty<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    seed_abc(backend, &store).await;

    for forward in [true, false] {
        for limit in [1, usize::MAX] {
            assert!(scan(&store, b"c", b"a", limit, forward).await.is_empty());
            assert!(scan(&store, b"b\0", b"b", limit, forward).await.is_empty());
        }
    }
    backend.close(store).await;
}

pub async fn range_scan_limits_around_the_row_count<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    seed_abc(backend, &store).await;

    let ascending: [&[u8]; 3] = [b"a", b"b", b"c"];
    for forward in [true, false] {
        let mut ordered = ascending.to_vec();
        if !forward {
            ordered.reverse();
        }
        for limit in [1, 2, 3, 4, usize::MAX] {
            for end in [b"c".as_slice(), b""] {
                let rows = scan(&store, b"a", end, limit, forward).await;
                assert_eq!(
                    keys(&rows),
                    ordered[..limit.min(ordered.len())],
                    "the scan must return the first rows up to its limit, with limit {limit}, \
                     forward {forward}, end {end:?}"
                );
            }
        }
    }
    backend.close(store).await;
}

pub async fn range_scan_covers_a_key_and_its_extensions<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    commit(
        backend,
        &store,
        vec![
            row(b"a\xff", b"0"),
            row(b"b", b"1"),
            row(b"b\0", b"2"),
            row(b"ba", b"3"),
            row(b"b\xff", b"4"),
            row(b"b\xff\0", b"5"),
            row(b"c", b"6"),
        ],
    )
    .await;

    let family: [&[u8]; 4] = [b"b", b"b\0", b"ba", b"b\xff"];
    let rows = scan(&store, b"b", b"b\xff", usize::MAX, true).await;
    assert_eq!(keys(&rows), family);
    let rows = scan(&store, b"b", b"b\xff", usize::MAX, false).await;
    let mut reversed = family.to_vec();
    reversed.reverse();
    assert_eq!(keys(&rows), reversed);

    // An extension sorts after its key, so an end bound on the key excludes the extension and a
    // start bound on the key includes it.
    let rows = scan(&store, b"b", b"b", usize::MAX, true).await;
    assert_eq!(keys(&rows), [b"b".as_slice()]);
    let rows = scan(&store, b"b\0", b"ba", usize::MAX, false).await;
    assert_eq!(keys(&rows), [b"ba".as_slice(), b"b\0"]);
    let rows = scan(&store, b"b\xff", b"", usize::MAX, true).await;
    assert_eq!(keys(&rows), [b"b\xff".as_slice(), b"b\xff\0", b"c"]);
    backend.close(store).await;
}

/// A cursor yields every row of its range in order, at most the requested number per pull, and
/// then an empty batch. A cursor opened with a limit stops after that many rows.
pub async fn range_scan_pulls_page_through_the_range<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    seed_abc(backend, &store).await;

    for forward in [true, false] {
        let expected = if forward {
            [b"a".as_slice(), b"b", b"c"]
        } else {
            [b"c".as_slice(), b"b", b"a"]
        };
        for (limit, max_items, yielded) in
            [(usize::MAX, 1, 3), (usize::MAX, 2, 3), (2, 1, 2), (2, 5, 2)]
        {
            let mut cursor = store
                .range_scan(Bytes::new(), Bytes::new(), limit, forward)
                .await
                .expect("range_scan must succeed")
                .scan;
            assert_eq!(
                keys(&drain(&mut cursor, max_items).await),
                expected[..yielded],
                "the cursor must yield the range up to its limit, with limit {limit}, max_items \
                 {max_items}, forward {forward}"
            );
        }
    }
    backend.close(store).await;
}

pub async fn snapshot_sequence_and_rows_survive_writes_between_pages<B: Backend>(backend: &B) {
    for forward in [true, false] {
        let (_location, store) = fresh(backend).await;
        seed_abc(backend, &store).await;
        let before = store.current_sequence();
        let result = store
            .range_scan(Bytes::new(), Bytes::new(), usize::MAX, forward)
            .await
            .expect("range_scan must succeed");
        assert_eq!(result.sequence_number, before);
        let mut cursor = result.scan;
        let first = cursor
            .next_batch(1)
            .await
            .expect("the first pull must succeed");
        let later = commit(
            backend,
            &store,
            vec![row(b"b", b"changed"), row(b"bb", b"new")],
        )
        .await;
        assert!(later > before);
        let rest = cursor
            .next_batch(10)
            .await
            .expect("the second pull must succeed");
        let mut all = first.rows;
        all.extend(rest.rows);
        if forward {
            assert_eq!(keys(&all), vec![b"a".as_slice(), b"b", b"c"]);
            assert_eq!(all[1].1, Bytes::from_static(b"2"));
        } else {
            assert_eq!(keys(&all), vec![b"c".as_slice(), b"b", b"a"]);
            assert_eq!(all[1].1, Bytes::from_static(b"2"));
        }
        assert!(cursor
            .next_batch(10)
            .await
            .expect("the last pull must succeed")
            .rows
            .is_empty());
        drop(cursor);
        backend.close(store).await;
    }
}

pub async fn snapshot_rows_survive_a_prune_between_pulls<B: Backend>(backend: &B) {
    for forward in [true, false] {
        let (_location, store) = fresh(backend).await;
        let versions: Vec<Bytes> = (1..=3)
            .map(|version| versioned_key(b"row", version))
            .collect();
        let sequence = commit(
            backend,
            &store,
            versions
                .iter()
                .map(|key| (key.clone(), Bytes::from_static(b"v")))
                .collect(),
        )
        .await;
        let result = store
            .range_scan(Bytes::new(), Bytes::new(), usize::MAX, forward)
            .await
            .expect("range_scan must succeed");
        assert_eq!(result.sequence_number, sequence);
        let mut cursor = result.scan;
        let mut seen = cursor
            .next_batch(1)
            .await
            .expect("the first pull must succeed")
            .rows;

        apply_prune(
            &store,
            &[version_policy(RetainPolicy::KeepLatest { count: 1 })],
        )
        .await;
        seen.extend(drain(&mut cursor, 1).await);
        drop(cursor);

        let mut expected: Vec<&[u8]> = versions.iter().map(|key| key.as_ref()).collect();
        if !forward {
            expected.reverse();
        }
        assert_eq!(keys(&seen), expected);
        let current = scan(&store, b"", b"", usize::MAX, true).await;
        assert_eq!(keys(&current), [versions[2].as_ref()]);
        assert_eq!(store.current_sequence(), sequence);
        backend.close(store).await;
    }
}

/// Reads that race commits each report a sequence number and the rows committed through it. The
/// writer commits `a` and `b` in every batch, valued by the batch's sequence number, and the
/// reader checks `get`, `get_many` and a range scan in bursts between pauses.
pub async fn queries_match_their_batch_sequence_during_commits<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    let (a, b) = (Bytes::from_static(b"a"), Bytes::from_static(b"b"));
    let writing = Cell::new(true);
    let writer = async {
        for sequence in 1u64..=40 {
            let value = Bytes::copy_from_slice(&sequence.to_be_bytes());
            assert_eq!(
                commit(
                    backend,
                    &store,
                    vec![(a.clone(), value.clone()), (b.clone(), value)]
                )
                .await,
                sequence
            );
        }
        writing.set(false);
    };
    let reader = async {
        let mut bursts = 0;
        while writing.get() || bursts == 0 {
            for _ in 0..READ_ROUNDS_PER_PAUSE {
                let result = store.get(a.clone()).await.expect("get must succeed");
                assert_read_at(result.sequence_number, [result.value]);

                let result = store
                    .get_many(vec![a.clone(), b.clone()])
                    .await
                    .expect("get_many must succeed");
                assert_read_at(
                    result.sequence_number,
                    result.value.into_iter().map(|(_, value)| value),
                );

                let result = store
                    .range_scan(a.clone(), b.clone(), usize::MAX, true)
                    .await
                    .expect("range_scan must succeed");
                let mut cursor = result.scan;
                let rows = drain(&mut cursor, usize::MAX).await;
                assert_read_at(
                    result.sequence_number,
                    [&a, &b].map(|key| {
                        rows.iter()
                            .find(|(found, _)| found == key)
                            .map(|(_, value)| value.clone())
                    }),
                );
            }
            bursts += 1;
            backend.pause().await;
        }
    };
    futures::join!(writer, reader);
    backend.close(store).await;
}

/// Asserts that every value a read at `sequence` returned is the one the writer of
/// [`queries_match_their_batch_sequence_during_commits`] committed at that sequence, and that
/// a read at sequence 0 found nothing.
fn assert_read_at(sequence: u64, values: impl IntoIterator<Item = Option<Bytes>>) {
    let expected = (sequence != 0).then(|| Bytes::copy_from_slice(&sequence.to_be_bytes()));
    for value in values {
        assert_eq!(
            value, expected,
            "a read at sequence {sequence} must return the value committed at {sequence}"
        );
    }
}

pub async fn rpc_range_frames_share_one_sequence<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    let rows: Vec<_> = (0..10u8).map(|i| row(&[b'r', b'/', i], &[i])).collect();
    let sequence = commit(backend, &store, rows.clone()).await;
    let mut stack = connect_stack(AppState::new(Arc::new(store.clone())));

    let range = query::RangeRequest {
        start: b"r/".to_vec(),
        end: b"r/\xff".to_vec(),
        batch_size: 2,
        ..Default::default()
    };
    let mut envelopes = rpc::open_stream(&mut stack, rpc::RANGE, &range).await;
    let mut seen = Vec::new();
    let mut sequences = Vec::new();
    loop {
        match envelopes
            .next()
            .await
            .expect("the stream must end with an end of stream envelope")
        {
            Envelope::Message(payload) => {
                let frame =
                    query::RangeFrame::decode_from_slice(&payload).expect("a frame must decode");
                sequences.push(
                    frame
                        .detail
                        .as_option()
                        .expect("a frame must carry its detail")
                        .sequence_number,
                );
                seen.extend(
                    frame
                        .results
                        .into_iter()
                        .map(|entry| (Bytes::from(entry.key), entry.value)),
                );

                // A write while the stream is open changes a row inside the remaining range and
                // adds one.
                if sequences.len() == 1 {
                    commit(
                        backend,
                        &store,
                        vec![row(b"r/\x05", b"changed"), row(b"r/\x05\x05", b"new")],
                    )
                    .await;
                }
            }
            Envelope::End(error) => {
                assert!(
                    error.is_none(),
                    "the stream must end without an error, got {error:?}"
                );
                break;
            }
        }
    }
    drop(envelopes);
    drop(stack);

    assert!(sequences.len() > 1, "the range must span several frames");
    assert!(sequences.iter().all(|frame| *frame == sequence));
    assert_eq!(seen, rows);
    backend.close(store).await;
}
