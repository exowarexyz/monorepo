//! The sequence log, its retention rule, and what survives a reopen.

use crate::{
    rpc,
    support::{
        commit, commit_one, fresh, get_value, has_batch, ingest_put, log_entries, oldest_retained,
        reopen, row, rpc_put, set_retention, versioned_key,
    },
    Backend,
};
use bytes::Bytes;
use exoware_sdk::{
    common::kv::v1::Selector,
    retention::RetentionPolicy,
    stream::{GetRequest, GetResponse, SubscribeRequest, SubscribeResponse},
    ErrorCode,
};
use exoware_server::{connect_stack, AppState, Log, Sequence};
use std::sync::Arc;

/// `ErrorInfo` metadata key that carries the oldest retained sequence number.
const OLDEST_RETAINED: &str = "oldest_retained";

pub async fn log_get_batch_returns_entries_in_order<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    commit_one(backend, &store, b"first", b"0").await;
    let rows = vec![row(b"k2", b"v2"), row(b"k1", b""), row(b"k2", b"v3")];
    let sequence = commit(backend, &store, rows.clone()).await;

    assert_eq!(log_entries(&store, sequence).await, Some(rows.clone()));
    let mut stack = connect_stack(AppState::new(Arc::new(store.clone())));
    let response: GetResponse = rpc::unary_call(
        &mut stack,
        rpc::unary(
            rpc::LOG_GET,
            &GetRequest {
                sequence_number: sequence,
                ..Default::default()
            },
        ),
    )
    .await
    .expect("the Get RPC must succeed");
    drop(stack);

    assert_eq!(response.sequence_number, sequence);
    let entries: Vec<_> = response
        .entries
        .into_iter()
        .map(|entry| (Bytes::from(entry.key), entry.value))
        .collect();
    assert_eq!(entries, rows);
    backend.close(store).await;
}

pub async fn log_batch_above_the_frontier_is_not_found<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    let sequence = commit_one(backend, &store, b"k", b"v").await;

    assert!(store
        .get_batch(sequence + 1)
        .await
        .expect("get_batch must succeed")
        .is_none());
    let mut stack = connect_stack(AppState::new(Arc::new(store.clone())));
    let error = rpc::unary_call::<_, _, _, GetResponse>(
        &mut stack,
        rpc::unary(
            rpc::LOG_GET,
            &GetRequest {
                sequence_number: sequence + 1,
                ..Default::default()
            },
        ),
    )
    .await
    .expect_err("Get above the frontier must fail");
    drop(stack);

    assert_eq!(
        error.code,
        ErrorCode::NotFound,
        "the error must be NotFound, got {error:?}"
    );
    assert_eq!(rpc::error_info(&error).reason, "BATCH_NOT_FOUND");
    backend.close(store).await;
}

pub async fn log_evicted_batch_reports_the_oldest_retained<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    for (key, value) in [(b"a", b"1"), (b"b", b"2"), (b"c", b"3")] {
        commit_one(backend, &store, key, value).await;
    }
    assert_eq!(
        set_retention(&store, Some(RetentionPolicy::KeepLatest { count: 1 })).await,
        Some(3)
    );

    assert!(store
        .get_batch(1)
        .await
        .expect("get_batch must succeed")
        .is_none());
    let mut stack = connect_stack(AppState::new(Arc::new(store.clone())));
    let error = rpc::unary_call::<_, _, _, GetResponse>(
        &mut stack,
        rpc::unary(
            rpc::LOG_GET,
            &GetRequest {
                sequence_number: 1,
                ..Default::default()
            },
        ),
    )
    .await
    .expect_err("Get of an evicted batch must fail");
    drop(stack);

    assert_eq!(
        error.code,
        ErrorCode::OutOfRange,
        "the error must be OutOfRange, got {error:?}"
    );
    let info = rpc::error_info(&error);
    assert_eq!(info.reason, "BATCH_EVICTED");
    assert_eq!(
        info.metadata.get(OLDEST_RETAINED).map(String::as_str),
        Some("3")
    );
    backend.close(store).await;
}

/// Subscribe replays the retained batches from `since_sequence_number`, one frame per batch with
/// only its matching entries in batch order. A batch with no matching entry yields no frame.
pub async fn rpc_subscribe_replays_matching_entries<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    commit_one(backend, &store, b"x/0", b"before the cursor").await;
    let skipped = commit(backend, &store, vec![row(b"y/1", b"no match")]).await;
    let second = commit(
        backend,
        &store,
        vec![row(b"x/2", b"a"), row(b"y/2", b"b"), row(b"x/1", b"c")],
    )
    .await;
    let third = commit(backend, &store, vec![row(b"x/3", b"d"), row(b"x/3", b"e")]).await;
    let mut stack = connect_stack(AppState::new(Arc::new(store.clone())));

    let subscribe = SubscribeRequest {
        selectors: vec![Selector {
            prefix: Bytes::from_static(b"x"),
            payload_regex: "(?s-u)^/.*$".to_string(),
            ..Default::default()
        }],
        since_sequence_number: Some(skipped),
        ..Default::default()
    };
    let mut envelopes = rpc::open_stream(&mut stack, rpc::SUBSCRIBE, &subscribe).await;
    let mut frames = Vec::new();
    while frames.len() < 2 {
        match envelopes
            .next()
            .await
            .expect("the subscription must stay open")
        {
            rpc::Envelope::Message(payload) => {
                let frame: SubscribeResponse =
                    buffa::Message::decode_from_slice(&payload).expect("a frame must decode");
                let entries: Vec<_> = frame
                    .entries
                    .into_iter()
                    .map(|entry| (Bytes::from(entry.key), entry.value))
                    .collect();
                frames.push((frame.sequence_number, entries));
            }
            rpc::Envelope::End(error) => {
                panic!("the subscription must stay open, but it ended with {error:?}")
            }
        }
    }
    drop(envelopes);
    drop(stack);

    assert_eq!(
        frames,
        vec![
            (second, vec![row(b"x/2", b"a"), row(b"x/1", b"c")]),
            (third, vec![row(b"x/3", b"d"), row(b"x/3", b"e")]),
        ]
    );
    backend.close(store).await;
}

/// An installed rule keeps trimming the log as later batches arrive. The `keep_latest{2}`
/// window follows the frontier across two writes through [`Ingest::put`], the path the Put
/// service takes.
///
/// [`Ingest::put`]: exoware_server::Ingest::put
pub async fn retention_keep_latest_tracks_frontier_continuously<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    commit_one(backend, &store, b"a", b"1").await;
    commit_one(backend, &store, b"b", b"2").await;
    commit_one(backend, &store, b"c", b"3").await;

    // Installing the rule at frontier 3 trims the log to the newest two batches before it
    // returns.
    assert_eq!(
        set_retention(&store, Some(RetentionPolicy::KeepLatest { count: 2 })).await,
        Some(2)
    );
    assert!(!has_batch(&store, 1).await);
    assert!(has_batch(&store, 2).await);
    assert!(has_batch(&store, 3).await);
    assert_eq!(store.current_sequence(), 3);

    // Two more batches, no new rule. Each write applies the rule before it returns, so the
    // retained window slides forward to [4, 5].
    assert_eq!(ingest_put(&store, &[row(b"d", b"4")]).await, 4);
    assert_eq!(ingest_put(&store, &[row(b"e", b"5")]).await, 5);

    assert!(!has_batch(&store, 2).await);
    assert!(!has_batch(&store, 3).await);
    assert!(has_batch(&store, 4).await);
    assert!(has_batch(&store, 5).await);
    assert_eq!(oldest_retained(&store).await, Some(4));

    // Retention never advances the ingest frontier. It only evicts log batches.
    assert_eq!(store.current_sequence(), 5);
    backend.close(store).await;
}

pub async fn retention_greater_than_and_greater_than_or_equal_thresholds<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    commit_one(backend, &store, b"a", b"1").await;
    commit_one(backend, &store, b"b", b"2").await;
    commit_one(backend, &store, b"c", b"3").await;
    commit_one(backend, &store, b"d", b"4").await;
    commit_one(backend, &store, b"e", b"5").await;

    // `greater_than{2}` retains sequence numbers strictly above 2, so the floor is 3.
    assert_eq!(
        set_retention(&store, Some(RetentionPolicy::GreaterThan { threshold: 2 })).await,
        Some(3)
    );
    assert!(!has_batch(&store, 1).await);
    assert!(!has_batch(&store, 2).await);
    assert!(has_batch(&store, 3).await);

    // Tightening to `greater_than_or_equal{4}` moves the floor to 4, and 4 itself is retained.
    assert_eq!(
        set_retention(
            &store,
            Some(RetentionPolicy::GreaterThanOrEqual { threshold: 4 })
        )
        .await,
        Some(4)
    );
    assert!(!has_batch(&store, 3).await);
    assert!(has_batch(&store, 4).await);
    assert!(has_batch(&store, 5).await);
    assert_eq!(store.current_sequence(), 5);
    backend.close(store).await;
}

pub async fn retention_drop_all_keeps_log_empty_as_batches_arrive<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    commit_one(backend, &store, b"a", b"1").await;
    commit_one(backend, &store, b"b", b"2").await;

    // drop_all evicts everything up to the live frontier, so the log retains no batch.
    assert_eq!(
        set_retention(&store, Some(RetentionPolicy::DropAll)).await,
        None
    );
    assert_eq!(oldest_retained(&store).await, None);
    assert!(!has_batch(&store, 1).await);
    assert!(!has_batch(&store, 2).await);

    // A later batch through the Put RPC is evicted by the time its write returns, so the log
    // stays empty without another rule. The ingest frontier still advances.
    let third = rpc_put(&store, &[row(b"c", b"3")]).await;
    assert_eq!(third, 3);
    assert_eq!(store.current_sequence(), 3);
    assert_eq!(oldest_retained(&store).await, None);
    assert!(!has_batch(&store, 3).await);
    backend.close(store).await;
}

pub async fn retention_clear_stops_enforcement<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    commit_one(backend, &store, b"a", b"1").await;
    commit_one(backend, &store, b"b", b"2").await;
    commit_one(backend, &store, b"c", b"3").await;

    assert_eq!(
        set_retention(&store, Some(RetentionPolicy::KeepLatest { count: 2 })).await,
        Some(2)
    );
    assert!(!has_batch(&store, 1).await);

    // Clearing stops enforcement. Batches already evicted stay evicted.
    set_retention(&store, None).await;
    assert!(!has_batch(&store, 1).await);

    // With the rule cleared, writes stop trimming. Batches 4 and 5 join 2 and 3.
    commit_one(backend, &store, b"d", b"4").await;
    commit_one(backend, &store, b"e", b"5").await;
    assert_eq!(oldest_retained(&store).await, Some(2));
    for sequence in 2..=5 {
        assert!(
            has_batch(&store, sequence).await,
            "batch {sequence} must survive"
        );
    }
    backend.close(store).await;
}

pub async fn retention_drop_all_survives_reopen<B: Backend>(backend: &B) {
    let (location, store) = fresh(backend).await;
    commit(
        backend,
        &store,
        vec![(versioned_key(b"row", 1), Bytes::from_static(b"v1"))],
    )
    .await;
    let last = commit(
        backend,
        &store,
        vec![(versioned_key(b"row", 2), Bytes::from_static(b"v2"))],
    )
    .await;
    set_retention(&store, Some(RetentionPolicy::DropAll)).await;
    assert!(oldest_retained(&store).await.is_none());

    // Every log batch is gone, yet the reopened store must not reuse a sequence number.
    let store = reopen(backend, store, &location).await;
    assert_eq!(store.current_sequence(), last);
    let next = commit(
        backend,
        &store,
        vec![(versioned_key(b"row", 3), Bytes::from_static(b"v3"))],
    )
    .await;
    assert_eq!(next, last + 1);

    // The restored rule keeps evicting, so the new batch never lingers in the log.
    assert_eq!(oldest_retained(&store).await, None);
    backend.close(store).await;
}

pub async fn retention_rule_survives_reopen<B: Backend>(backend: &B) {
    let (location, store) = fresh(backend).await;
    assert_eq!(
        set_retention(&store, Some(RetentionPolicy::KeepLatest { count: 2 })).await,
        None,
        "an empty log must report no oldest batch"
    );
    for (key, value) in [(b"a", b"1"), (b"b", b"2"), (b"c", b"3")] {
        commit_one(backend, &store, key, value).await;
    }
    assert_eq!(oldest_retained(&store).await, Some(2));

    let store = reopen(backend, store, &location).await;
    assert_eq!(oldest_retained(&store).await, Some(2));
    assert_eq!(commit_one(backend, &store, b"d", b"4").await, 4);
    assert_eq!(oldest_retained(&store).await, Some(3));
    assert!(!has_batch(&store, 2).await);
    assert!(has_batch(&store, 4).await);
    backend.close(store).await;
}

pub async fn reopen_preserves_frontier_rows_log_and_oldest_retained<B: Backend>(backend: &B) {
    let (location, store) = fresh(backend).await;
    let batches = [
        vec![row(b"a", b"1"), row(b"b", b"1")],
        vec![row(b"b", b"2")],
        vec![row(b"c", b"3"), row(b"a", b"3")],
    ];
    for (index, rows) in batches.iter().enumerate() {
        assert_eq!(
            commit(backend, &store, rows.clone()).await,
            index as u64 + 1
        );
    }
    assert_eq!(
        set_retention(&store, Some(RetentionPolicy::GreaterThan { threshold: 1 })).await,
        Some(2)
    );
    set_retention(&store, None).await;

    let store = reopen(backend, store, &location).await;
    assert_eq!(store.current_sequence(), 3);
    for (key, value) in [(b"a", b"3"), (b"b", b"2"), (b"c", b"3")] {
        assert_eq!(
            get_value(&store, key).await.as_deref(),
            Some(value.as_slice())
        );
    }
    assert_eq!(oldest_retained(&store).await, Some(2));
    assert!(!has_batch(&store, 1).await);
    assert_eq!(log_entries(&store, 2).await.as_ref(), Some(&batches[1]));
    assert_eq!(log_entries(&store, 3).await.as_ref(), Some(&batches[2]));
    assert_eq!(commit_one(backend, &store, b"d", b"4").await, 4);
    assert_eq!(oldest_retained(&store).await, Some(2));
    backend.close(store).await;
}
