//! Ingest throughput benchmark for the RocksDB-backed simulator store.
//!
//! Direct serial, direct concurrent, stream serial, and stream concurrent runs
//! compare the direct writer against streaming protobuf decode plus batch
//! assembly. Rust allocation peaks exclude native storage allocations.
//! Reservation peaks are samples taken at streaming ingest observation events.
//! Direct writes use the store's own budget of 256 requests and 1 GiB, excluded
//! from those samples. `BENCH_MEMORY_BYTES` controls only the streaming budget.
//!
//! Run with
//! `BENCH_REQUEST_ROWS=<rows> cargo bench -p exoware-simulator --bench ingest`.
//! `BENCH_REQUEST_ROWS` caps the rows per request, and all of a batch's requests
//! are sent together. `BENCH_BATCHES`, `BENCH_WRITERS`, `BENCH_FRAGMENT_BYTES`,
//! and `BENCH_MEMORY_BYTES` apply to every workload and default to 16, 4, 16384,
//! and 1 GiB.
//!
//! `BENCH_WORKLOAD` selects the row shape. The default `uniform` writes
//! `BENCH_KEYS_PER_BATCH` keys with `BENCH_VALUE_LEN`-byte values per batch,
//! 250,000 and 128 by default. The default `BENCH_KEY_ORDER=batch` gives each
//! batch its own key range, so state files overlap only when concurrent writers'
//! batches are committed together. `random` spreads each batch's keys over the
//! whole key space, so every state file overlaps and compaction runs.
//! `constantinople` makes each batch one block of `BENCH_TRANSACTIONS`
//! transactions, 51,670 by default for about 310k rows in six key families with
//! mixed value sizes. The block's 7.45 MB artifact follows as its own put.
//! Unknown values and non-numeric settings are rejected.

use buffa::Message;
use bytes::Bytes;
use commonware_allocator::mimalloc::{Config, MiMalloc, Purge, Reserve};
use exoware_sdk::{common::kv::v1::Entry, log::ingest::v1::PutRequest};
use exoware_server::{
    ingest::{
        box_body, BudgetConfig, IngestBudget, IngestEvent, IngestObserver, PutLimits, PutMetadata,
    },
    Ingest, PutInput,
};
use exoware_simulator::RocksStore;
use std::{
    alloc::{GlobalAlloc, Layout},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

// Track Rust allocations across decode tasks and writer threads, including spare
// vector capacity and simultaneous old and replacement backing allocations.
struct MeasuredAllocator;

// `MeasuredAllocator` wraps the simulator binary's allocator configuration so
// the benchmark runs on the production allocator.
static INNER_ALLOC: MiMalloc = MiMalloc::new(Config {
    purge: Purge::After(Duration::from_secs(10)),
    reserve: Some(Reserve::pinned(2 << 30)),
    ..Config::DEFAULT
});

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);

fn allocated(bytes: usize) {
    let live = LIVE_BYTES.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
}

// SAFETY: Every method passes its arguments unchanged to `MiMalloc`, which upholds the
// `GlobalAlloc` contract. The bookkeeping only updates atomics and never allocates.
unsafe impl GlobalAlloc for MeasuredAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = INNER_ALLOC.alloc(layout);
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = INNER_ALLOC.alloc_zeroed(layout);
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        INNER_ALLOC.dealloc(pointer, layout);
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let pointer = INNER_ALLOC.realloc(pointer, layout, size);
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

/// One unit of a writer's queue. A block's requests are submitted together, then its
/// optional artifact is put once they are all acknowledged.
struct Block {
    requests: Vec<Batch>,
    artifact: Option<Batch>,
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
    parse_env_usize(name).unwrap_or(default)
}

/// Reads a numeric setting when it is set, rejecting a value that is not a number.
fn parse_env_usize(name: &str) -> Option<usize> {
    let raw = std::env::var(name).ok()?;
    Some(
        raw.parse()
            .unwrap_or_else(|_| panic!("{name} must be a number, not {raw}")),
    )
}

/// Key layouts the benchmark can generate. Keys are unique in both layouts.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyOrder {
    /// Keys of `bench/`, batch index, row index, and a mixed tail, so each batch occupies
    /// its own key range and its state file never overlaps earlier ones. The default.
    Batch,
    /// Keys of `bench/` and a 192-bit mix of batch and row index, so every batch spans
    /// the whole key space as fresh versioned keys do in production.
    Random,
}

impl KeyOrder {
    fn from_env() -> Self {
        match std::env::var("BENCH_KEY_ORDER").as_deref() {
            Err(_) | Ok("batch") => Self::Batch,
            Ok("random") => Self::Random,
            Ok(other) => panic!("BENCH_KEY_ORDER must be batch or random, not {other}"),
        }
    }
}

/// Row shapes the benchmark can generate, each carrying the settings only it reads.
#[derive(Clone, Copy)]
enum Workload {
    /// `keys_per_batch` rows of `value_len` bytes per batch, laid out by `key_order`. The
    /// default.
    Uniform {
        keys_per_batch: usize,
        value_len: usize,
        key_order: KeyOrder,
    },
    /// One Constantinople block of `transactions` transactions per batch, as
    /// [`build_constantinople_block`] shapes it, followed by the block's artifact as its
    /// own put.
    Constantinople { transactions: usize },
}

impl Workload {
    fn from_env() -> Self {
        match std::env::var("BENCH_WORKLOAD").as_deref() {
            Err(_) | Ok("uniform") => Self::Uniform {
                keys_per_batch: env_usize("BENCH_KEYS_PER_BATCH", 250_000).max(1),
                value_len: env_usize("BENCH_VALUE_LEN", 128),
                key_order: KeyOrder::from_env(),
            },
            Ok("constantinople") => Self::Constantinople {
                transactions: env_usize("BENCH_TRANSACTIONS", 51_670).max(1),
            },
            Ok(other) => panic!("BENCH_WORKLOAD must be uniform or constantinople, not {other}"),
        }
    }
}

// Unique keys keep the writer workload stable across serial and concurrent runs.
fn build_batch(
    batch_index: usize,
    keys_per_batch: usize,
    value_len: usize,
    order: KeyOrder,
) -> Vec<(Bytes, Bytes)> {
    let mut kvs = Vec::with_capacity(keys_per_batch);
    for i in 0..keys_per_batch {
        let mut key = Vec::with_capacity(32);
        key.extend_from_slice(b"bench/");
        let mixed = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        match order {
            KeyOrder::Batch => {
                key.extend_from_slice(&(batch_index as u64).to_be_bytes());
                key.extend_from_slice(&(i as u64).to_be_bytes());

                // Mix the tail so keys are not fully sequential in memcmp order.
                key.extend_from_slice(&mixed.to_be_bytes());
            }
            KeyOrder::Random => {
                let seed = ((batch_index as u64) << 32) | i as u64;
                for salt in [
                    0x9E37_79B9_7F4A_7C15u64,
                    0xD1B5_4A32_D192_ED03,
                    0x8CB9_2BA7_2F3D_8DD7,
                ] {
                    key.extend_from_slice(&splitmix64(seed ^ salt).to_be_bytes());
                }
            }
        }

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

/// The SplitMix64 finalizer, a bijective mix, so distinct seeds give distinct outputs.
const fn splitmix64(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Pseudo-random value bytes derived from `seed`.
fn filled_value(seed: u64, len: usize) -> Bytes {
    let mut value = vec![0u8; len];
    let mut state = seed;
    for chunk in value.chunks_mut(8) {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let bytes = state.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    Bytes::from(value)
}

/// A 32-byte digest-like key tail derived from `seed` and `salt`.
fn digest(seed: u64, salt: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, word) in out.chunks_mut(8).enumerate() {
        word.copy_from_slice(&splitmix64(seed ^ salt.wrapping_add(i as u64)).to_be_bytes());
    }
    out
}

/// Encoded bytes of the block artifact in the 310k-row profile.
const BLOCK_ARTIFACT_BYTES: usize = 7_450_286;

/// The rows one block of `transactions` transactions publishes, shaped like the
/// Constantinople indexer's. Each transaction writes six Store rows across families that
/// are either ordered by block position or keyed by a digest, so successive blocks
/// interleave within the digest-keyed families and append within the ordered ones.
fn build_constantinople_block(block: usize, transactions: usize) -> Vec<(Bytes, Bytes)> {
    let mut rows = Vec::with_capacity(6 * transactions);
    for t in 0..transactions {
        let seed = ((block as u64) << 32) | t as u64;
        let position = |family: u8| {
            let mut key = Vec::with_capacity(13);
            key.push(family);
            key.extend_from_slice(&(block as u64).to_be_bytes());
            key.extend_from_slice(&(t as u32).to_be_bytes());
            key
        };
        let hashed = |family: u8, salt: u64| {
            let mut key = Vec::with_capacity(33);
            key.push(family);
            key.extend_from_slice(&digest(seed, salt));
            key
        };
        // Transaction by hash, its location, the account version it creates, the
        // operation location, and two Merkle nodes.
        rows.push((Bytes::from(hashed(1, 0x1111)), filled_value(seed ^ 1, 200)));
        rows.push((Bytes::from(position(2)), filled_value(seed ^ 2, 16)));
        rows.push((Bytes::from(hashed(3, 0x3333)), filled_value(seed ^ 3, 150)));
        rows.push((Bytes::from(position(4)), filled_value(seed ^ 4, 16)));
        rows.push((Bytes::from(hashed(5, 0x5555)), filled_value(seed ^ 5, 64)));
        rows.push((Bytes::from(hashed(6, 0x6666)), filled_value(seed ^ 6, 64)));
    }
    rows
}

/// The block artifact, one row keyed by height with the encoded block as its value.
fn build_block_artifact(block: usize) -> Vec<(Bytes, Bytes)> {
    let mut key = Vec::with_capacity(9);
    key.push(7);
    key.extend_from_slice(&(block as u64).to_be_bytes());
    vec![(
        Bytes::from(key),
        filled_value((block as u64) << 40, BLOCK_ARTIFACT_BYTES),
    )]
}

fn rows_bytes(rows: &[(Bytes, Bytes)]) -> usize {
    rows.iter().map(|(k, v)| k.len() + v.len()).sum()
}

/// Submits one request through the direct or streaming ingest path.
async fn submit(store: &RocksStore, batch: Batch, fragment_bytes: usize, observed: &Arc<Observed>) {
    match batch {
        Batch::Direct(batch) => {
            store.put_batch(batch).await.expect("put batch");
        }
        Batch::Stream(wire) => {
            let admission = observed.budget.try_admit(wire.len()).expect("admit stream");
            let length = wire.len();
            let frames = futures::stream::unfold((wire, 0), move |(wire, offset)| async move {
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

async fn run(
    store: Arc<RocksStore>,
    blocks: Vec<Block>,
    writers: usize,
    fragment_bytes: usize,
    observed: Arc<Observed>,
) -> (f64, usize, usize) {
    let mut queues: Vec<Vec<Block>> = (0..writers).map(|_| Vec::new()).collect();
    for (index, block) in blocks.into_iter().enumerate() {
        queues[index % writers].push(block);
    }

    let initial = LIVE_BYTES.load(Ordering::Relaxed);
    PEAK_BYTES.store(initial, Ordering::Relaxed);
    let start = Instant::now();
    let mut tasks = Vec::with_capacity(writers);
    for queue in queues {
        let store = store.clone();
        let observed = observed.clone();
        tasks.push(tokio::spawn(async move {
            for block in queue {
                // A block's requests are in flight together, as the publisher sends them, and
                // its artifact follows once every request is acknowledged.
                let requests = block
                    .requests
                    .into_iter()
                    .map(|batch| submit(&store, batch, fragment_bytes, &observed));
                futures::future::join_all(requests).await;
                if let Some(artifact) = block.artifact {
                    submit(&store, artifact, fragment_bytes, &observed).await;
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
    let writers = env_usize("BENCH_WRITERS", 4).max(1);
    let fragment_bytes = env_usize("BENCH_FRAGMENT_BYTES", 16 * 1024).max(1);
    let memory_bytes = env_usize("BENCH_MEMORY_BYTES", 1024 * 1024 * 1024);
    let workload = Workload::from_env();
    let request_rows = parse_env_usize("BENCH_REQUEST_ROWS")
        .expect("BENCH_REQUEST_ROWS must be set to the rows per request");
    assert!(request_rows > 0, "BENCH_REQUEST_ROWS must be at least 1");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build runtime");

    match workload {
        Workload::Uniform {
            keys_per_batch,
            value_len,
            key_order,
        } => println!(
            "workload: {batches} batches x {keys_per_batch} keys, {value_len}B values, requests of {request_rows} rows, {writers} concurrent writers, {fragment_bytes}B frames, {} keys",
            if key_order == KeyOrder::Random { "random" } else { "batch-ordered" }
        ),
        Workload::Constantinople { transactions } => println!(
            "workload: {batches} blocks x {transactions} transactions (6 rows each) plus a {BLOCK_ARTIFACT_BYTES}B artifact, requests of {request_rows} rows, {writers} concurrent writers, {fragment_bytes}B frames"
        ),
    }

    for (label, streaming, concurrency) in [
        ("direct serial", false, 1),
        ("direct concurrent", false, writers),
        ("stream serial", true, 1),
        ("stream concurrent", true, writers),
    ] {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(RocksStore::open(dir.path(), None).expect("open store"));
        let encode = |rows: Vec<(Bytes, Bytes)>| {
            if streaming {
                Batch::Stream(encode_batch(rows))
            } else {
                Batch::Direct(rows)
            }
        };
        let mut payload = 0usize;
        let mut keys = 0usize;
        let mut data = Vec::with_capacity(batches);
        for batch in 0..batches {
            let (rows, artifact) = match workload {
                Workload::Uniform {
                    keys_per_batch,
                    value_len,
                    key_order,
                } => (
                    build_batch(batch, keys_per_batch, value_len, key_order),
                    None,
                ),
                Workload::Constantinople { transactions } => (
                    build_constantinople_block(batch, transactions),
                    Some(build_block_artifact(batch)),
                ),
            };
            payload += rows_bytes(&rows);
            keys += rows.len();
            if let Some(artifact) = &artifact {
                payload += rows_bytes(artifact);
                keys += artifact.len();
            }

            // Split the block into the requests a publisher would send, all in flight together.
            let requests = if rows.len() <= request_rows {
                vec![encode(rows)]
            } else {
                let mut rows = rows;
                let mut requests = Vec::with_capacity(rows.len().div_ceil(request_rows));
                while !rows.is_empty() {
                    let rest = rows.split_off(rows.len().min(request_rows));
                    requests.push(encode(rows));
                    rows = rest;
                }
                requests
            };
            data.push(Block {
                requests,
                artifact: artifact.map(encode),
            });
        }
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
