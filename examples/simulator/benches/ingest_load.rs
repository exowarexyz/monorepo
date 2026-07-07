//! Ingest load benchmark: measures `put_batch` throughput and latency under concurrent load.
//!
//! Modes:
//! - `ordered`: the production [`exoware_simulator::RocksStore`] write pipeline (contiguous
//!   sequence numbers assigned before a single synced commit per group).
//! - `unordered`: the experimental [`exoware_simulator::UnorderedRocksStore`] pipeline
//!   (concurrent unsynced data writes, sequence numbers assigned after by a tiny synced write).
//! - `unordered-uw`: same store with RocksDB's `unordered_write=true`, which relaxes RocksDB's
//!   internal write ordering to admit more memtable concurrency.
//! - `raw-nosync`: concurrent RocksDB writes without sync, sequence numbers, or a batch log.
//!   Upper bound for what the disk + RocksDB can do with zero ordering or durability work.
//! - `raw-sync`: concurrent RocksDB writes with `sync=true` on every write (RocksDB group
//!   commit only). Shows what naive per-request fsync costs.
//!
//! Usage (all flags optional):
//!   cargo bench -p exoware-simulator --bench ingest_load -- \
//!     [--modes ordered,unordered,unordered-uw,raw-nosync,raw-sync] [--concurrency 1,8,64,256] \
//!     [--value-sizes 128,1024,16384] [--kvs-per-put 1] [--measure-secs 5] [--warmup-secs 1]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use exoware_server::Ingest;
use exoware_simulator::{RocksStore, UnorderedRocksConfig, UnorderedRocksStore};
use tempfile::tempdir;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Ordered,
    Unordered,
    UnorderedUw,
    RawNoSync,
    RawSync,
}

impl Mode {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "ordered" => Some(Self::Ordered),
            "unordered" => Some(Self::Unordered),
            "unordered-uw" => Some(Self::UnorderedUw),
            "raw-nosync" => Some(Self::RawNoSync),
            "raw-sync" => Some(Self::RawSync),
            _ => None,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Ordered => "ordered",
            Self::Unordered => "unordered",
            Self::UnorderedUw => "unordered-uw",
            Self::RawNoSync => "raw-nosync",
            Self::RawSync => "raw-sync",
        }
    }
}

/// One engine under test, reduced to the put path.
#[derive(Clone)]
enum Engine {
    Ordered(RocksStore),
    Unordered(UnorderedRocksStore),
    Raw { db: Arc<rocksdb::DB>, sync: bool },
}

impl Engine {
    async fn put_batch(&self, kvs: Vec<(Bytes, Bytes)>) -> Result<(), String> {
        match self {
            Self::Ordered(store) => store.put_batch(kvs).await.map(|_| ()),
            Self::Unordered(store) => store.put_batch(kvs).await.map(|_| ()),
            Self::Raw { db, sync } => {
                let db = db.clone();
                let sync = *sync;
                tokio::task::spawn_blocking(move || {
                    let mut batch = rocksdb::WriteBatch::default();
                    for (k, v) in &kvs {
                        batch.put(k.as_ref(), v.as_ref());
                    }
                    let mut options = rocksdb::WriteOptions::default();
                    options.set_sync(sync);
                    db.write_opt(batch, &options).map_err(|e| e.to_string())
                })
                .await
                .map_err(|e| e.to_string())?
            }
        }
    }
}

struct CellConfig {
    mode: Mode,
    concurrency: usize,
    value_size: usize,
    kvs_per_put: usize,
    warmup: Duration,
    measure: Duration,
}

struct CellResult {
    puts: u64,
    elapsed: Duration,
    latencies_us: Vec<u64>,
}

fn percentile(sorted_us: &[u64], p: f64) -> f64 {
    if sorted_us.is_empty() {
        return 0.0;
    }
    let rank = (p * (sorted_us.len() - 1) as f64).round() as usize;
    sorted_us[rank.min(sorted_us.len() - 1)] as f64 / 1000.0
}

async fn run_cell(config: &CellConfig) -> CellResult {
    let dir = tempdir().expect("tempdir");
    let engine = match config.mode {
        Mode::Ordered => Engine::Ordered(RocksStore::open(dir.path(), None).expect("open")),
        Mode::Unordered => {
            Engine::Unordered(UnorderedRocksStore::open(dir.path(), None).expect("open"))
        }
        Mode::UnorderedUw => {
            let mut config = UnorderedRocksConfig::default();
            config.db_options.set_unordered_write(true);
            Engine::Unordered(UnorderedRocksStore::open(dir.path(), Some(config)).expect("open"))
        }
        Mode::RawNoSync | Mode::RawSync => {
            let mut options = rocksdb::Options::default();
            options.create_if_missing(true);
            Engine::Raw {
                db: Arc::new(rocksdb::DB::open(&options, dir.path()).expect("open")),
                sync: config.mode == Mode::RawSync,
            }
        }
    };

    let recording = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let next_task = Arc::new(AtomicU64::new(0));
    let mut workers = Vec::with_capacity(config.concurrency);
    for _ in 0..config.concurrency {
        let engine = engine.clone();
        let recording = recording.clone();
        let stop = stop.clone();
        let task_id = next_task.fetch_add(1, Ordering::Relaxed);
        let value = Bytes::from(vec![0xAB; config.value_size]);
        let kvs_per_put = config.kvs_per_put;
        workers.push(tokio::spawn(async move {
            let mut latencies_us = Vec::new();
            let mut puts = 0u64;
            let mut op = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let mut kvs = Vec::with_capacity(kvs_per_put);
                for i in 0..kvs_per_put {
                    let mut key = [0u8; 20];
                    key[..8].copy_from_slice(&task_id.to_be_bytes());
                    key[8..16].copy_from_slice(&op.to_be_bytes());
                    key[16..20].copy_from_slice(&(i as u32).to_be_bytes());
                    kvs.push((Bytes::copy_from_slice(&key), value.clone()));
                }
                op += 1;
                let started = Instant::now();
                engine.put_batch(kvs).await.expect("put");
                if recording.load(Ordering::Relaxed) {
                    puts += 1;
                    latencies_us.push(started.elapsed().as_micros() as u64);
                }
            }
            (puts, latencies_us)
        }));
    }

    tokio::time::sleep(config.warmup).await;
    recording.store(true, Ordering::Relaxed);
    let measure_started = Instant::now();
    tokio::time::sleep(config.measure).await;
    recording.store(false, Ordering::Relaxed);
    let elapsed = measure_started.elapsed();
    stop.store(true, Ordering::Relaxed);

    let mut puts = 0u64;
    let mut latencies_us = Vec::new();
    for worker in workers {
        let (worker_puts, worker_latencies) = worker.await.expect("worker");
        puts += worker_puts;
        latencies_us.extend(worker_latencies);
    }
    latencies_us.sort_unstable();
    CellResult {
        puts,
        elapsed,
        latencies_us,
    }
}

fn parse_list<T: std::str::FromStr>(value: &str) -> Vec<T>
where
    T::Err: std::fmt::Debug,
{
    value
        .split(',')
        .map(|part| part.trim().parse().expect("parse list element"))
        .collect()
}

fn main() {
    let mut modes = vec![
        Mode::Ordered,
        Mode::Unordered,
        Mode::UnorderedUw,
        Mode::RawNoSync,
        Mode::RawSync,
    ];
    let mut concurrency = vec![1usize, 8, 64, 256];
    let mut value_sizes = vec![128usize, 1024, 16384];
    let mut kvs_per_put = 1usize;
    let mut measure_secs = 5u64;
    let mut warmup_secs = 1u64;

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--modes" => {
                i += 1;
                modes = args[i]
                    .split(',')
                    .map(|m| Mode::parse(m.trim()).expect("unknown mode"))
                    .collect();
            }
            "--concurrency" => {
                i += 1;
                concurrency = parse_list(&args[i]);
            }
            "--value-sizes" => {
                i += 1;
                value_sizes = parse_list(&args[i]);
            }
            "--kvs-per-put" => {
                i += 1;
                kvs_per_put = args[i].parse().expect("kvs per put");
            }
            "--measure-secs" => {
                i += 1;
                measure_secs = args[i].parse().expect("measure secs");
            }
            "--warmup-secs" => {
                i += 1;
                warmup_secs = args[i].parse().expect("warmup secs");
            }
            // `cargo bench` passes --bench through to the harness; ignore it.
            "--bench" => {}
            other => panic!("unknown argument: {other}"),
        }
        i += 1;
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");

    println!(
        "{:<11} {:>5} {:>7} {:>4} | {:>9} {:>9} | {:>8} {:>8} {:>8} {:>9}",
        "mode", "conc", "vsize", "kvs", "puts/s", "MiB/s", "p50 ms", "p95 ms", "p99 ms", "max ms"
    );
    for &mode in &modes {
        for &conc in &concurrency {
            for &value_size in &value_sizes {
                let config = CellConfig {
                    mode,
                    concurrency: conc,
                    value_size,
                    kvs_per_put,
                    warmup: Duration::from_secs(warmup_secs),
                    measure: Duration::from_secs(measure_secs),
                };
                let result = runtime.block_on(run_cell(&config));
                let seconds = result.elapsed.as_secs_f64();
                let puts_per_sec = result.puts as f64 / seconds;
                let mib_per_sec =
                    puts_per_sec * (kvs_per_put * (value_size + 20)) as f64 / (1024.0 * 1024.0);
                println!(
                    "{:<11} {:>5} {:>7} {:>4} | {:>9.0} {:>9.1} | {:>8.2} {:>8.2} {:>8.2} {:>9.2}",
                    mode.name(),
                    conc,
                    value_size,
                    kvs_per_put,
                    puts_per_sec,
                    mib_per_sec,
                    percentile(&result.latencies_us, 0.50),
                    percentile(&result.latencies_us, 0.95),
                    percentile(&result.latencies_us, 0.99),
                    percentile(&result.latencies_us, 1.0),
                );
            }
        }
    }
}
