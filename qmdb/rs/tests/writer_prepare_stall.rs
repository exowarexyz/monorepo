//! Regression coverage for executor and lock stalls during `prepare_upload`.
//!
//! The writer core runs the variant build (encoding, leaf hashing,
//! merklization) through the strategy's `spawn` boundary and only takes the
//! writer state mutex to snapshot and commit frontier state. If the build
//! ever moves back inline under that mutex, these tests fail. The first
//! observes the event loop stalling for the build's duration and the second
//! observes a cheap watermark read queued behind an in-flight build.

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use commonware_parallel::Strategy as _;
use commonware_storage::merkle::{mmr, Location};
use commonware_storage::qmdb::any::value::VariableEncoding;
use commonware_storage::qmdb::keyless;
use exoware_qmdb::KeylessWriter;
use exoware_sdk::{PrefixedStoreClient, StoreClient};

type Op = keyless::Operation<mmr::Family, VariableEncoding<Vec<u8>>>;
type Writer = KeylessWriter<
    mmr::Family,
    commonware_cryptography::Sha256,
    Vec<u8>,
    VariableEncoding<Vec<u8>>,
    commonware_parallel::Manual<commonware_parallel::Rayon>,
>;

// Debug hashing is slow enough to reproduce the stall with a smaller batch.
#[cfg(debug_assertions)]
const OPS: usize = 200_000;

// Release hashing needs the full reported workload to cross the threshold.
#[cfg(not(debug_assertions))]
const OPS: usize = 1_000_000;

fn operations(count: usize) -> Vec<Op> {
    let mut ops = Vec::with_capacity(count);
    for i in 0..count - 1 {
        let mut value = vec![0u8; 64];
        value[..8].copy_from_slice(&(i as u64).to_be_bytes());
        ops.push(Op::Append(value));
    }
    ops.push(Op::Commit(None, Location::new(0)));
    ops
}

fn rayon_writer() -> Writer {
    let strategy = commonware_parallel::Rayon::new(NonZeroUsize::new(4).expect("non-zero"))
        .expect("construct Rayon strategy")
        .manual();

    // prepare_upload never touches the network, so a dummy endpoint suffices.
    let client = StoreClient::new("http://127.0.0.1:9");
    Writer::fresh_with_strategy(PrefixedStoreClient::empty(client), strategy)
}

// The event loop must stay responsive while a batch merklizes on the Rayon
// pool. If the build runs inline under the writer mutex, this current_thread
// executor parks inside the pool and the heartbeat gap grows to the full
// build time.
#[tokio::test]
async fn prepare_upload_keeps_event_loop_responsive() {
    let writer = rayon_writer();
    let ops = operations(OPS);

    let max_gap_us = Arc::new(AtomicU64::new(0));
    let gap = max_gap_us.clone();
    let heartbeat = tokio::spawn(async move {
        let mut last = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_millis(1)).await;
            let now = Instant::now();
            gap.fetch_max(
                now.duration_since(last).as_micros() as u64,
                Ordering::Relaxed,
            );
            last = now;
        }
    });

    // Let the heartbeat establish its baseline before the build starts.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let started = Instant::now();
    let _prepared = writer.prepare_upload(ops).await.expect("prepare");
    let build = started.elapsed();

    // Let the heartbeat tick once more so a stalled gap is recorded.
    tokio::time::sleep(Duration::from_millis(10)).await;
    heartbeat.abort();

    let max_gap = Duration::from_micros(max_gap_us.load(Ordering::Relaxed));
    println!("build took {build:?}, max heartbeat gap {max_gap:?}");
    assert!(
        max_gap < Duration::from_millis(100),
        "event loop stalled for {max_gap:?} during a {build:?} prepare_upload"
    );
}

// A cheap read that takes the writer state mutex must not queue behind an
// in-flight build. If the build holds the mutex, this probe waits for the
// build's remainder.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn watermark_read_is_not_delayed_by_inflight_build() {
    let writer = Arc::new(rayon_writer());
    let ops = operations(OPS);

    let build_writer = writer.clone();
    let build = tokio::spawn(async move {
        let started = Instant::now();
        let _ = build_writer.prepare_upload(ops).await.expect("prepare");
        started.elapsed()
    });

    // Probe mid-build.
    tokio::time::sleep(Duration::from_millis(30)).await;
    let probe_started = Instant::now();
    let _ = writer.latest_published_watermark().await;
    let probe = probe_started.elapsed();
    let build = build.await.expect("build task");

    println!("build took {build:?}, watermark probe waited {probe:?}");
    assert!(
        probe < Duration::from_millis(50),
        "watermark read waited {probe:?} behind an in-flight {build:?} build"
    );
}
