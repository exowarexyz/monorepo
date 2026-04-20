use std::time::Duration;

use bytes::Bytes;
use store_qmdb::prune::{drop_all_batches, keep_latest_batches};
use exoware_sdk_rs::keys::{Key, KeyCodec};
use exoware_sdk_rs::kv_codec::Utf8;
use exoware_sdk_rs::match_key::MatchKey;
use exoware_sdk_rs::stream_filter::StreamFilter;
use exoware_sdk_rs::{RetryConfig, StoreClient};
use tempfile::tempdir;

async fn spawn_client() -> (tokio::task::JoinHandle<()>, StoreClient) {
    let dir = tempdir().expect("tempdir");
    let dir_path = dir.path().to_owned();
    let _dir = dir;
    let (handle, url) = exoware_simulator::spawn_for_test(&dir_path)
        .await
        .expect("spawn_for_test");
    let client = StoreClient::builder()
        .url(&url)
        .retry_config(RetryConfig::disabled())
        .build()
        .expect("build client");
    (handle, client)
}

fn key(family: u16, payload: &[u8]) -> Key {
    KeyCodec::new(4, family).encode(payload).expect("encode")
}

fn filter(family: u16) -> StreamFilter {
    StreamFilter {
        match_keys: vec![MatchKey {
            reserved_bits: 4,
            prefix: family,
            payload_regex: Utf8::from("(?s).*"),
        }],
    }
}

async fn next_with_timeout(
    sub: &mut exoware_sdk_rs::StreamSubscription,
    ms: u64,
) -> Option<exoware_sdk_rs::StreamSubscriptionFrame> {
    tokio::time::timeout(Duration::from_millis(ms), sub.next())
        .await
        .ok()
        .and_then(|r| r.expect("stream error"))
}

// ---------- live subscribe ----------

#[tokio::test]
async fn live_subscribe_delivers_matching_entries() {
    let (_h, client) = spawn_client().await;
    let mut sub = client
        .subscribe_stream(filter(1), None)
        .await
        .expect("subscribe");

    // Give the subscription time to register on the server before we publish.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let k = key(1, b"hello");
    let seq = client.put(&[(&k, b"world")]).await.expect("put");

    let frame = next_with_timeout(&mut sub, 1_000)
        .await
        .expect("should receive a frame");
    assert_eq!(frame.sequence_number, seq);
    assert_eq!(frame.entries.len(), 1);
    assert_eq!(frame.entries[0].key.as_ref(), k.as_ref());
    assert_eq!(frame.entries[0].value.as_ref(), b"world");
}

#[tokio::test]
async fn non_matching_put_yields_no_frame() {
    let (_h, client) = spawn_client().await;
    let mut sub = client
        .subscribe_stream(filter(1), None)
        .await
        .expect("subscribe");
    tokio::time::sleep(Duration::from_millis(50)).await;

    client
        .put(&[(&key(2, b"miss"), b"v")])
        .await
        .expect("put");

    assert!(
        next_with_timeout(&mut sub, 200).await.is_none(),
        "should NOT receive a frame"
    );
}

#[tokio::test]
async fn multiple_match_keys_delivered_once_per_put() {
    let (_h, client) = spawn_client().await;
    let f = StreamFilter {
        match_keys: vec![
            MatchKey {
                reserved_bits: 4,
                prefix: 1,
                payload_regex: Utf8::from("(?s).*"),
            },
            MatchKey {
                reserved_bits: 4,
                prefix: 2,
                payload_regex: Utf8::from("(?s).*"),
            },
        ],
    };
    let mut sub = client.subscribe_stream(f, None).await.expect("subscribe");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let ka = key(1, b"a");
    let kb = key(2, b"b");
    client
        .put(&[(&ka, b"1"), (&kb, b"2")])
        .await
        .expect("put");

    let frame = next_with_timeout(&mut sub, 1_000)
        .await
        .expect("frame received");
    assert_eq!(frame.entries.len(), 2);
    // Both families deliver in one frame (one PUT → one frame, atomic).
    let keys: Vec<&[u8]> = frame.entries.iter().map(|e| e.key.as_ref()).collect();
    assert!(keys.contains(&ka.as_ref()));
    assert!(keys.contains(&kb.as_ref()));
}

#[tokio::test]
async fn two_puts_yield_two_distinct_frames() {
    let (_h, client) = spawn_client().await;
    let mut sub = client
        .subscribe_stream(filter(1), None)
        .await
        .expect("subscribe");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let seq1 = client
        .put(&[(&key(1, b"a"), b"1")])
        .await
        .expect("put1");
    let seq2 = client
        .put(&[(&key(1, b"b"), b"2")])
        .await
        .expect("put2");

    let f1 = next_with_timeout(&mut sub, 1_000)
        .await
        .expect("frame 1");
    let f2 = next_with_timeout(&mut sub, 1_000)
        .await
        .expect("frame 2");
    assert_eq!(f1.sequence_number, seq1);
    assert_eq!(f2.sequence_number, seq2);
    assert!(f2.sequence_number > f1.sequence_number);
}

// ---------- replay via since_sequence_number ----------

#[tokio::test]
async fn replay_since_delivers_retained_batches_then_live() {
    let (_h, client) = spawn_client().await;
    let mut seen_seqs = Vec::new();
    for i in 0..5u8 {
        let seq = client
            .put(&[(&key(1, &[b'a' + i]), &[b'v', i])])
            .await
            .expect("put");
        seen_seqs.push(seq);
    }

    // Subscribe from seq 3 → should replay 3, 4, 5 then continue live.
    let start = seen_seqs[2];
    let mut sub = client
        .subscribe_stream(filter(1), Some(start))
        .await
        .expect("subscribe");

    // Expect replay frames for seq 3, 4, 5 in order.
    let mut replayed = Vec::new();
    for _ in 0..3 {
        let frame = next_with_timeout(&mut sub, 1_000)
            .await
            .expect("replay frame");
        replayed.push(frame.sequence_number);
    }
    assert_eq!(replayed, vec![seen_seqs[2], seen_seqs[3], seen_seqs[4]]);

    // Now live: a new PUT should arrive with its actual seq.
    let live_seq = client
        .put(&[(&key(1, b"live"), b"hot")])
        .await
        .expect("put live");
    let live = next_with_timeout(&mut sub, 1_000)
        .await
        .expect("live frame");
    assert_eq!(live.sequence_number, live_seq);
    assert!(live.sequence_number > seen_seqs[4]);
}

#[tokio::test]
async fn replay_past_end_delivers_only_live() {
    let (_h, client) = spawn_client().await;
    let current = client
        .put(&[(&key(1, b"seed"), b"v")])
        .await
        .expect("put");

    let mut sub = client
        .subscribe_stream(filter(1), Some(current + 10))
        .await
        .expect("subscribe");

    // No replay — should not receive a frame for current+10 since it doesn't
    // exist and since > current triggers the unset-cursor path.
    assert!(next_with_timeout(&mut sub, 200).await.is_none());

    // Next live PUT lands with its actual seq (no synthetic gaps).
    let live_seq = client
        .put(&[(&key(1, b"next"), b"n")])
        .await
        .expect("put next");
    let frame = next_with_timeout(&mut sub, 1_000)
        .await
        .expect("live frame");
    assert_eq!(frame.sequence_number, live_seq);
}

#[tokio::test]
async fn replay_miss_after_prune_returns_batch_evicted() {
    let (_h, client) = spawn_client().await;
    for i in 0..20u8 {
        client
            .put(&[(&key(1, &[i]), &[b'v', i])])
            .await
            .expect("put");
    }
    // Prune via compact batch-log policy: keep last 10.
    client
        .prune(&[keep_latest_batches(10)])
        .await
        .expect("prune keep_latest batches");

    // Subscribing from seq 1 should fail with BATCH_EVICTED. The error may
    // surface either on the subscribe call itself or on the first next()
    // depending on whether the transport has flushed headers before the
    // server-side error returns.
    let err_msg = match client.subscribe_stream(filter(1), Some(1)).await {
        Err(err) => format!("{err:?}"),
        Ok(mut sub) => format!("{:?}", sub.next().await.expect_err("stream should error")),
    };
    assert!(
        err_msg.contains("out_of_range")
            || err_msg.contains("OutOfRange")
            || err_msg.contains("BATCH_EVICTED")
            || err_msg.contains("evicted"),
        "unexpected error: {err_msg}"
    );
}

// ---------- GetBatch ----------

#[tokio::test]
async fn get_batch_returns_whole_batch_unfiltered() {
    let (_h, client) = spawn_client().await;
    let ka = key(1, b"a");
    let kb = key(2, b"b");
    let seq = client
        .put(&[(&ka, b"1"), (&kb, b"2")])
        .await
        .expect("put");

    let got = client.get_batch(seq).await.expect("get_batch").expect("some");
    assert_eq!(got.len(), 2);
    // Order must match write order.
    assert_eq!(got[0].0.as_ref(), ka.as_ref());
    assert_eq!(got[0].1.as_ref(), b"1");
    assert_eq!(got[1].0.as_ref(), kb.as_ref());
    assert_eq!(got[1].1.as_ref(), b"2");
}

#[tokio::test]
async fn get_batch_missing_seq_returns_none() {
    let (_h, client) = spawn_client().await;
    client.put(&[(&key(1, b"a"), b"1")]).await.expect("put");
    let current = client.sequence_number();
    let got = client
        .get_batch(current + 100)
        .await
        .expect("get_batch should not error");
    assert!(got.is_none());
}

#[tokio::test]
async fn get_batch_after_drop_all_returns_none() {
    let (_h, client) = spawn_client().await;
    let seq = client.put(&[(&key(1, b"a"), b"1")]).await.expect("put");
    client.prune(&[drop_all_batches()]).await.expect("prune");

    let got = client.get_batch(seq).await.expect("get_batch");
    assert!(got.is_none(), "pruned batch should return None");
}

#[tokio::test]
async fn get_batch_after_keep_latest_evicts_old_but_keeps_new() {
    let (_h, client) = spawn_client().await;
    let mut seqs = Vec::new();
    for i in 0..20u8 {
        let s = client
            .put(&[(&key(1, &[i]), &[b'v', i])])
            .await
            .expect("put");
        seqs.push(s);
    }
    client
        .prune(&[keep_latest_batches(10)])
        .await
        .expect("prune keep_latest batches");

    // Earliest seq should be evicted.
    assert!(client.get_batch(seqs[0]).await.expect("get").is_none());
    // Latest seq should survive.
    let last = client
        .get_batch(*seqs.last().unwrap())
        .await
        .expect("get last")
        .expect("some");
    assert_eq!(last.len(), 1);
    assert_eq!(last[0].1.as_ref(), &[b'v', 19]);
}

// ---------- slow subscriber is dropped without blocking ingest ----------

#[tokio::test]
async fn slow_subscriber_drops_without_blocking_ingest() {
    let (_h, client) = spawn_client().await;
    // Open subscription but never drain it. Internal cap = 256 frames.
    let _sub = client
        .subscribe_stream(filter(1), None)
        .await
        .expect("subscribe");
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Flood enough matching PUTs to exceed the subscriber channel.
    // Ingest latency must stay bounded: if the subscriber ever blocked
    // ingest, this loop would hang.
    let started = std::time::Instant::now();
    for i in 0..512u16 {
        let k = key(1, &i.to_be_bytes());
        client.put(&[(&k, b"x")]).await.expect("put");
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(30),
        "ingest should not stall on slow subscriber (took {elapsed:?})"
    );
    // Small verification that the store actually still serves reads.
    let last = Bytes::copy_from_slice(client.get(&key(1, &511u16.to_be_bytes())).await.expect("get").expect("some").as_ref());
    assert_eq!(last.as_ref(), b"x");
}
