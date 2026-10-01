//! Ingest throughput benchmark for the RocksDB-backed simulator store.
//!
//! Compares the direct writer with streaming protobuf decode and batch assembly.
//! Rust allocation peaks exclude native storage allocations. Reservation peaks
//! are samples taken at ingest observation events.
//!
//! Run with `cargo bench -p exoware-simulator --bench ingest`.
//! Environment overrides are `BENCH_BATCHES`, `BENCH_KEYS_PER_BATCH`,
//! `BENCH_VALUE_LEN`, `BENCH_WRITERS`, `BENCH_FRAGMENT_BYTES`, and
//! `BENCH_MEMORY_BYTES`.

use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use buffa::Message;
use bytes::Bytes;
use exoware_sdk::common::kv::v1::Entry;
use exoware_sdk::log::ingest::v1::PutRequest;
use exoware_server::ingest::{
    box_body, BudgetConfig, IngestBudget, IngestEvent, IngestObserver, PutLimits, PutMetadata,
};
use exoware_server::{Ingest, PutInput};
use exoware_simulator::RocksStore;

// Track Rust allocations across decode tasks and writer threads, including spare
// vector capacity and simultaneous old and replacement backing allocations.
struct MeasuredAllocator;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);

fn allocated(bytes: usize) {
    let live = LIVE_BYTES.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for MeasuredAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = mimalloc::MiMalloc.alloc(layout);
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = mimalloc::MiMalloc.alloc_zeroed(layout);
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        mimalloc::MiMalloc.dealloc(pointer, layout);
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let pointer = mimalloc::MiMalloc.realloc(pointer, layout, size);
        if !pointer.is_null() {
            if size >= layout.size() {
                allocated(size - layout.size());
            } else {
                LIVE_BYTES.fetch_sub(layout.size() - size, Ordering::Relaxed);
            }
        }
        pointer
    }
}

#[global_allocator]
static ALLOC: MeasuredAllocator = MeasuredAllocator;

struct Observed {
    budget: Arc<IngestBudget>,
    chunks: AtomicUsize,
    reservation_peak: AtomicUsize,
    decode_nanos: AtomicUsize,
}

impl IngestObserver for Observed {
    fn observe(&self, event: IngestEvent) {
        self.reservation_peak
            .fetch_max(self.budget.usage().1, Ordering::Relaxed);
        match event {
            IngestEvent::Batch { .. } => {
                self.chunks.fetch_add(1, Ordering::Relaxed);
            }
            IngestEvent::DecodeElapsed(elapsed) => {
                self.decode_nanos
                    .fetch_add(elapsed.as_nanos() as usize, Ordering::Relaxed);
            }
            _ => {}
        }
    }
}

enum Batch {
    Direct(Vec<(Bytes, Bytes)>),
    Stream(Bytes),
}

fn encode_batch(kvs: Vec<(Bytes, Bytes)>) -> Bytes {
    Bytes::from(
        PutRequest {
            kvs: kvs
                .into_iter()
                .map(|(key, value)| Entry {
                    key: key.to_vec(),
                    value,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
        .encode_to_vec(),
    )
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(default)
}

// Unique keys keep the writer workload stable across serial and concurrent runs.
fn build_batch(batch_index: usize, keys_per_batch: usize, value_len: usize) -> Vec<(Bytes, Bytes)> {
    let mut kvs = Vec::with_capacity(keys_per_batch);
    for i in 0..keys_per_batch {
        let mut key = Vec::with_capacity(32);
        key.extend_from_slice(b"bench/");
        key.extend_from_slice(&(batch_index as u64).to_be_bytes());
        key.extend_from_slice(&(i as u64).to_be_bytes());

        // Mix the tail so keys are not fully sequential in memcmp order.
        let mixed = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        key.extend_from_slice(&mixed.to_be_bytes());

        let mut value = vec![0u8; value_len];
        let mut state = mixed ^ (batch_index as u64);
        for chunk in value.chunks_mut(8) {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let bytes = state.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        kvs.push((Bytes::from(key), Bytes::from(value)));
    }
    kvs
}

fn batch_payload_bytes(batches: &[Vec<(Bytes, Bytes)>]) -> usize {
    batches
        .iter()
        .flatten()
        .map(|(k, v)| k.len() + v.len())
        .sum()
}

async fn run(
    store: Arc<RocksStore>,
    batches: Vec<Batch>,
    writers: usize,
    fragment_bytes: usize,
    observed: Arc<Observed>,
) -> (f64, usize, usize) {
    let mut queues: Vec<Vec<Batch>> = (0..writers).map(|_| Vec::new()).collect();
    for (index, batch) in batches.into_iter().enumerate() {
        queues[index % writers].push(batch);
    }

    let initial = LIVE_BYTES.load(Ordering::Relaxed);
    PEAK_BYTES.store(initial, Ordering::Relaxed);
    let start = Instant::now();
    let mut tasks = Vec::with_capacity(writers);
    for queue in queues {
        let store = store.clone();
        let observed = observed.clone();
        tasks.push(tokio::spawn(async move {
            for batch in queue {
                match batch {
                    Batch::Direct(batch) => {
                        store.put_batch(batch).await.expect("put batch");
                    }
                    Batch::Stream(wire) => {
                        let admission =
                            observed.budget.try_admit(wire.len()).expect("admit stream");
                        let length = wire.len();
                        let frames =
                            futures::stream::unfold((wire, 0), move |(wire, offset)| async move {
                                if offset == wire.len() {
                                    return None;
                                }
                                let end = (offset + fragment_bytes).min(wire.len());
                                Some((
                                    Ok::<_, std::io::Error>(wire.slice(offset..end)),
                                    (wire, end),
                                ))
                            });
                        let mut input = PutInput::new(
                            box_body(axum::body::Body::from_stream(frames)),
                            PutMetadata {
                                content_length: Some(length),
                                ..Default::default()
                            },
                            PutLimits::default(),
                            tokio::time::Instant::now() + Duration::from_secs(300),
                            admission,
                        )
                        .with_observer(observed.clone());
                        store.put(&mut input).await.expect("streaming put");
                    }
                }
            }
        }));
    }
    for task in tasks {
        task.await.expect("writer task");
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while observed.budget.usage() != (0, 0) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("release completed request reservations");
    let peak = PEAK_BYTES.load(Ordering::Relaxed);
    (
        start.elapsed().as_secs_f64(),
        peak,
        peak.saturating_sub(initial),
    )
}

fn main() {
    let batches = env_usize("BENCH_BATCHES", 16).max(1);
    let keys_per_batch = env_usize("BENCH_KEYS_PER_BATCH", 250_000).max(1);
    let value_len = env_usize("BENCH_VALUE_LEN", 128);
    let writers = env_usize("BENCH_WRITERS", 4).max(1);
    let fragment_bytes = env_usize("BENCH_FRAGMENT_BYTES", 16 * 1024).max(1);
    let memory_bytes = env_usize("BENCH_MEMORY_BYTES", 1024 * 1024 * 1024);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build runtime");

    println!(
        "workload: {batches} batches x {keys_per_batch} keys, {value_len}B values, {writers} concurrent writers, {fragment_bytes}B frames"
    );

    for (label, streaming, concurrency) in [
        ("direct serial", false, 1),
        ("direct concurrent", false, writers),
        ("stream serial", true, 1),
        ("stream concurrent", true, writers),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(RocksStore::open(dir.path(), None).expect("open store"));
        let data: Vec<_> = (0..batches)
            .map(|batch| build_batch(batch, keys_per_batch, value_len))
            .collect();
        let payload = batch_payload_bytes(&data);
        let keys = batches * keys_per_batch;
        let data = data
            .into_iter()
            .map(|batch| {
                if streaming {
                    Batch::Stream(encode_batch(batch))
                } else {
                    Batch::Direct(batch)
                }
            })
            .collect();
        let observed = Arc::new(Observed {
            budget: IngestBudget::new(BudgetConfig {
                max_requests: concurrency.max(256),
                max_bytes: memory_bytes,
            }),
            chunks: AtomicUsize::new(0),
            reservation_peak: AtomicUsize::new(0),
            decode_nanos: AtomicUsize::new(0),
        });
        let (elapsed, peak, extra) = runtime.block_on(run(
            store.clone(),
            data,
            concurrency,
            fragment_bytes,
            observed.clone(),
        ));
        println!(
            "{label} | {keys} keys | {elapsed:.3}s | {:.0} keys/s | {:.1} MiB/s | Rust peak {peak}B | extra {extra}B | sampled reservation peak {}B | {} chunks | decode {:.3}s",
            keys as f64 / elapsed,
            payload as f64 / (1024.0 * 1024.0) / elapsed,
            observed.reservation_peak.load(Ordering::Relaxed),
            observed.chunks.load(Ordering::Relaxed),
            observed.decode_nanos.load(Ordering::Relaxed) as f64 / 1e9,
        );
        assert_eq!(observed.budget.usage(), (0, 0));
        drop(store);
    }
}
