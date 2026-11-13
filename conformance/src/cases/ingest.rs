//! Writes through `put_batch`, through [`Ingest::put`] and through the Put RPC.

use crate::{
    rpc,
    support::{
        admitted_body, admitted_put, commit, commit_one, fresh, get_value, log_entries,
        put_request, reopen, row, rpc_put, settle,
    },
    Backend,
};
use buffa::Message as _;
use bytes::Bytes;
use exoware_sdk::{ingest::PutResponse, ErrorCode, MAX_KEY_LEN};
use exoware_server::{connect_stack, AppState, Ingest, Sequence, StreamHub, StreamNotifier};
use futures::channel::mpsc;
use http_body::Frame;
use http_body_util::StreamBody;
use std::{convert::Infallible, pin::pin, sync::Arc, task::Poll};

/// The most polls the cancellation case gives a Put before it drops the Put.
const MAX_POLLS_BEFORE_DROP: usize = 8;

pub async fn put_batch_returns_monotonic_sequence_numbers<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    let s1 = commit_one(backend, &store, b"a", b"1").await;
    let s2 = commit_one(backend, &store, b"b", b"2").await;
    assert_eq!(s1, 1);
    assert_eq!(s2, 2);
    assert_eq!(store.current_sequence(), 2);
    backend.close(store).await;
}

pub async fn sequence_persists_across_reopen<B: Backend>(backend: &B) {
    let (location, store) = fresh(backend).await;
    commit_one(backend, &store, b"a", b"1").await;
    commit_one(backend, &store, b"b", b"2").await;

    let reopened = reopen(backend, store, &location).await;
    assert_eq!(reopened.current_sequence(), 2);
    let s3 = commit_one(backend, &reopened, b"c", b"3").await;
    assert_eq!(s3, 3);
    backend.close(reopened).await;
}

pub async fn put_batch_duplicates_last_wins_and_log_keeps_all<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    let rows = vec![row(b"k", b"1"), row(b"j", b"x"), row(b"k", b"2")];
    let sequence = commit(backend, &store, rows.clone()).await;

    assert_eq!(
        get_value(&store, b"k").await.as_deref(),
        Some(b"2".as_slice())
    );
    assert_eq!(
        get_value(&store, b"j").await.as_deref(),
        Some(b"x".as_slice())
    );
    assert_eq!(log_entries(&store, sequence).await, Some(rows));
    backend.close(store).await;
}

pub async fn put_batch_rejects_an_empty_batch<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    let first = commit_one(backend, &store, b"a", b"1").await;

    assert!(backend.put_batch(&store, Vec::new()).await.is_err());
    assert_eq!(store.current_sequence(), first);
    assert!(log_entries(&store, first + 1).await.is_none());
    assert_eq!(commit_one(backend, &store, b"b", b"2").await, first + 1);
    backend.close(store).await;
}

/// Concurrent writes may share a sequence number. The log batch at each returned number holds
/// exactly the batches whose `put_batch` returned that number, each one contiguous and in its
/// own entry order, with the batches themselves in any order.
pub async fn concurrent_put_batches_log_every_entry_once<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    let before = commit_one(backend, &store, b"seed", b"0").await;
    let batches: Vec<Vec<(Bytes, Bytes)>> = (0..8u8)
        .map(|batch| {
            (0..3u8)
                .map(|entry| row(&[b'c', batch, entry], &[batch, entry]))
                .collect()
        })
        .collect();

    let sequences: Vec<u64> = futures::future::join_all(
        batches
            .iter()
            .map(|rows| backend.put_batch(&store, rows.clone())),
    )
    .await
    .into_iter()
    .map(|result| result.expect("put_batch must succeed"))
    .collect();
    assert!(sequences.iter().all(|sequence| *sequence > before));

    let mut distinct = sequences.clone();
    distinct.sort_unstable();
    distinct.dedup();
    for sequence in &distinct {
        let entries = log_entries(&store, *sequence)
            .await
            .expect("the log must hold every returned batch");

        // Keys are unique across batches, so the first key of each run names its batch.
        let mut assigned: Vec<_> = batches
            .iter()
            .zip(&sequences)
            .filter(|(_, returned)| *returned == sequence)
            .map(|(rows, _)| rows)
            .collect();
        let mut rest = entries.as_slice();
        while let Some((first, _)) = rest.first() {
            let index = assigned
                .iter()
                .position(|rows| rows[0].0 == first)
                .unwrap_or_else(|| {
                    panic!(
                        "log batch {sequence} must start each run with a batch assigned to it, \
                         found {first:?}"
                    )
                });
            let rows = assigned.swap_remove(index);
            assert_eq!(
                rest.get(..rows.len()),
                Some(rows.as_slice()),
                "log batch {sequence} must hold each of its batches contiguously and in order"
            );
            rest = &rest[rows.len()..];
        }
        assert!(
            assigned.is_empty(),
            "log batch {sequence} must hold every batch assigned to it"
        );
    }
    assert_eq!(
        store.current_sequence(),
        *distinct
            .last()
            .expect("some sequence number must be returned")
    );
    for (key, value) in batches.iter().flatten() {
        assert_eq!(get_value(&store, key).await.as_ref(), Some(value));
    }
    backend.close(store).await;
}

pub async fn ingest_put_commits_and_notifies<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    let before = commit_one(backend, &store, b"seed", b"0").await;
    let hub = Arc::new(StreamHub::new(before));
    let rows = vec![row(b"k1", b"v1"), row(b"k2", b""), row(b"k1", b"v3")];
    let (budget, mut input) = admitted_put(&rows, &hub);

    let sequence = store.put(&mut input).await.expect("put must succeed");
    drop(input);
    assert_eq!(sequence, before + 1);
    assert_eq!(store.current_sequence(), sequence);
    assert_eq!(hub.current_sequence(), sequence);
    assert_eq!(
        get_value(&store, b"k1").await.as_deref(),
        Some(b"v3".as_slice())
    );
    assert_eq!(get_value(&store, b"k2").await, Some(Bytes::new()));
    assert_eq!(log_entries(&store, sequence).await, Some(rows));
    assert!(
        settle(backend, || budget.usage() == (0, 0)).await,
        "the admission budget must be released"
    );
    backend.close(store).await;
}

/// Checks the cancellation contract of [`Ingest::put`]. A Put dropped before its body ended
/// leaves nothing, notifies nothing and releases its admission. A Put with a complete body that
/// is dropped after any number of polls either leaves nothing or commits its batch once with its
/// notification. A dropped Put that commits holds its admission until its batch is committed and
/// announced. If some Put with a complete body was pending at a poll, some Put dropped before it
/// finished must still commit. A backend whose put finishes on its first poll passes.
pub async fn ingest_put_survives_cancellation_after_acceptance<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;

    // A Put whose body has not ended cannot finalize its input, so no poll finishes it and
    // dropping it leaves nothing.
    let before = store.current_sequence();
    let hub = Arc::new(StreamHub::new(before));
    let rows: Vec<_> = (0..3u8)
        .map(|entry| row(&[b'u', entry], &[entry]))
        .collect();
    let body = Bytes::from(put_request(&rows).encode_to_vec());
    let (sender, frames) = mpsc::unbounded::<Result<Frame<Bytes>, Infallible>>();
    let third = body.len() / 3;
    for chunk in [body.slice(..third), body.slice(third..2 * third)] {
        sender
            .unbounded_send(Ok(Frame::data(chunk)))
            .expect("the body receiver must be open");
    }
    let (budget, mut input) = admitted_body(StreamBody::new(frames), body.len(), &hub);
    {
        let mut put = pin!(store.put(&mut input));
        for poll in 0..MAX_POLLS_BEFORE_DROP {
            if poll > 0 {
                backend.pause().await;
            }
            assert!(
                futures::poll!(put.as_mut()).is_pending(),
                "a Put whose body has not ended must stay pending, but it finished at poll {poll}"
            );
        }
    }
    drop(input);
    drop(sender);
    assert_eq!(
        commit_one(backend, &store, b"m", b"marker").await,
        before + 1
    );
    for (key, _) in &rows {
        assert!(
            get_value(&store, key).await.is_none(),
            "a dropped Put must not write {key:?}"
        );
    }
    assert_eq!(hub.current_sequence(), before);
    assert!(
        settle(backend, || budget.usage() == (0, 0)).await,
        "the admission budget must be released, but it holds {:?}",
        budget.usage()
    );

    // Puts with a complete body, each dropped after a growing number of polls.
    let mut pending_seen = false;
    let mut committed_after_drop = false;
    for polls in 1..=MAX_POLLS_BEFORE_DROP {
        let before = store.current_sequence();
        let hub = Arc::new(StreamHub::new(before));
        let rows: Vec<_> = (0..3u8)
            .map(|entry| row(&[b'p', polls as u8, entry], &[entry]))
            .collect();
        let (budget, mut input) = admitted_put(&rows, &hub);

        // Poll the Put the given number of times, pausing between polls so background work of
        // the backend can move it forward, then drop it with its input.
        let mut finished = None;
        {
            let mut put = pin!(store.put(&mut input));
            for poll in 0..polls {
                if poll > 0 {
                    backend.pause().await;
                }
                match futures::poll!(put.as_mut()) {
                    Poll::Ready(result) => {
                        finished = Some(result.expect("put must succeed"));
                        break;
                    }
                    Poll::Pending => pending_seen = true,
                }
            }
        }
        drop(input);

        // Accepted work releases its admission only after its batch is committed and announced.
        // Reading the admission before the notifier therefore observes at least one of the two
        // for a Put that commits after its drop.
        let held = budget.usage().0 == 1;
        let notified = hub.current_sequence() > before;

        let marker = commit_one(backend, &store, &[b'm', polls as u8], b"marker").await;
        if get_value(&store, &rows[0].0).await.is_none() {
            assert!(finished.is_none(), "a finished Put must be readable");
            assert_eq!(
                marker,
                before + 1,
                "after {polls} polls the marker must take the next sequence number"
            );
            for (key, _) in &rows {
                assert!(
                    get_value(&store, key).await.is_none(),
                    "after {polls} polls a Put that left nothing must not write {key:?}"
                );
            }
            assert_eq!(
                hub.current_sequence(),
                before,
                "after {polls} polls a Put that left nothing must not notify"
            );
        } else {
            // The marker may share the Put's sequence number or precede it, so search every
            // batch committed since the Put began.
            let mut sequence = None;
            for candidate in before + 1..=store.current_sequence() {
                let entries = log_entries(&store, candidate)
                    .await
                    .expect("the log must hold every batch committed since the Put began");
                let ours: Vec<_> = entries
                    .into_iter()
                    .filter(|(key, _)| key.starts_with(&[b'p', polls as u8]))
                    .collect();
                if !ours.is_empty() {
                    assert_eq!(
                        ours, rows,
                        "after {polls} polls the Put's batch must be logged whole"
                    );
                    assert!(sequence.is_none(), "the batch must be logged once");
                    sequence = Some(candidate);
                }
            }
            let sequence = sequence.expect("the committed batch must be logged");
            if let Some(finished) = finished {
                assert_eq!(
                    finished, sequence,
                    "after {polls} polls a finished Put must return its batch's sequence number"
                );
            } else {
                assert!(
                    notified || held,
                    "after {polls} polls accepted work must hold its admission until its batch is \
                     committed and announced"
                );
                committed_after_drop = true;
            }
            for (key, value) in &rows {
                assert_eq!(get_value(&store, key).await.as_ref(), Some(value));
            }
            assert!(
                settle(backend, || hub.current_sequence() == sequence).await,
                "after {polls} polls the notifier must reach {sequence}, but it is at {}",
                hub.current_sequence()
            );
        }
        assert!(
            settle(backend, || budget.usage() == (0, 0)).await,
            "after {polls} polls the admission budget must be released, but it holds {:?}",
            budget.usage()
        );
    }
    assert!(
        !pending_seen || committed_after_drop,
        "some Put dropped before it finished must commit when a Put with a complete body was \
         pending"
    );
    backend.close(store).await;
}

pub async fn rpc_put_identity_body<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    let before = commit_one(backend, &store, b"seed", b"0").await;

    let rows = vec![row(b"a/1", b"one"), row(b"a/2", b""), row(b"a/1", b"two")];
    assert_eq!(rpc_put(&store, &rows).await, before + 1);
    assert_eq!(store.current_sequence(), before + 1);
    assert_eq!(
        get_value(&store, b"a/1").await.as_deref(),
        Some(b"two".as_slice())
    );
    assert_eq!(get_value(&store, b"a/2").await, Some(Bytes::new()));
    assert_eq!(log_entries(&store, before + 1).await, Some(rows));
    backend.close(store).await;
}

pub async fn rpc_put_body_in_many_frames<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    let mut stack = connect_stack(AppState::new(Arc::new(store.clone())));

    let rows: Vec<_> = (0..100u8)
        .map(|entry| row(&[b'f', entry], &[entry; 3]))
        .collect();
    let body = Bytes::from(put_request(&rows).encode_to_vec());
    let frames: Vec<_> = body
        .chunks(8)
        .map(|chunk| Ok::<_, Infallible>(http_body::Frame::data(Bytes::copy_from_slice(chunk))))
        .collect();
    assert!(frames.len() > 64);
    let request = rpc::request(
        rpc::PUT,
        rpc::UNARY_PROTO,
        StreamBody::new(futures::stream::iter(frames)),
    );
    let response: PutResponse = rpc::unary_call(&mut stack, request)
        .await
        .expect("the Put RPC must succeed");
    drop(stack);

    assert_eq!(response.sequence_number, 1);
    assert_eq!(log_entries(&store, 1).await, Some(rows.clone()));
    for (key, value) in &rows {
        assert_eq!(get_value(&store, key).await.as_ref(), Some(value));
    }
    backend.close(store).await;
}

/// The server validates a Put before the backend sees it, so every backend answers an empty
/// Put and an oversized key with the same code.
pub async fn rpc_put_rejections_come_from_the_server<B: Backend>(backend: &B) {
    let (_location, store) = fresh(backend).await;
    let before = commit_one(backend, &store, b"seed", b"0").await;
    let mut stack = connect_stack(AppState::new(Arc::new(store.clone())));

    let long_key = vec![b'k'; MAX_KEY_LEN + 1];
    for rows in [Vec::new(), vec![row(&long_key, b"v")]] {
        let error = rpc::unary_call::<_, _, _, PutResponse>(
            &mut stack,
            rpc::unary(rpc::PUT, &put_request(&rows)),
        )
        .await
        .expect_err("the server must reject the Put");
        assert_eq!(
            error.code,
            ErrorCode::InvalidArgument,
            "the rejection must be InvalidArgument, got {error:?}"
        );
    }
    drop(stack);

    assert_eq!(store.current_sequence(), before);
    assert!(get_value(&store, &long_key).await.is_none());
    backend.close(store).await;
}
