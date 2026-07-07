//! Ingest load benchmark: measures `put_batch` throughput and latency under concurrent load.
//!
//! Modes:
//! - `ordered`: the production [`exoware_simulator::RocksStore`] write pipeline (contiguous
//!   sequence numbers assigned before a single synced commit per group).
//! - `ordered-nowal`: same pipeline with `CommitDurability::NoWalFlush` (WAL disabled; each
//!   commit group is made durable by one atomic memtable flush instead of a WAL fsync).
//! - `unordered`: the experimental [`exoware_simulator::UnorderedRocksStore`] pipeline
//!   (concurrent unsynced data writes, sequence numbers assigned after by a tiny synced write).
//! - `unordered-nowal`: unordered pipeline with `CommitDurability::NoWalFlush`.
//! - `unordered-uw`: unordered pipeline with RocksDB's `unordered_write=true`, which relaxes
//!   RocksDB's internal write ordering to admit more memtable concurrency.
//! - `raw-nosync`: concurrent RocksDB writes without sync, sequence numbers, or a batch log.
//!   Upper bound for what the disk + RocksDB can do with zero ordering or durability work.
//! - `raw-sync`: concurrent RocksDB writes with `sync=true` on every write (RocksDB group
//!   commit only). Shows what naive per-request fsync costs.
//! - `flatfile`: the real [`exoware_simulator::FlatFileRocksStore`] engine. Each upload is
//!   written and fsynced to its own checksummed flat file (parallel durability, no shared log);
//!   a sequencer assigns sequence numbers by renaming files and fsyncing the directory once per
//!   wave; applier threads populate RocksDB (WAL disabled) from a bounded in-memory queue.
//! - `flatfile-nodb`: prototype of the same ack path with the RocksDB apply skipped; isolates
//!   the durability path (file write + fsync + rename + dir fsync) as the design's ceiling.
//!
//! Usage (all flags optional):
//!   cargo bench -p exoware-simulator --bench ingest_load -- \
//!     [--modes ordered,ordered-nowal,unordered,unordered-nowal,unordered-uw,raw-nosync,raw-sync] \
//!     [--concurrency 1,8,64,256] [--value-sizes 128,1024,16384] [--kvs-per-put 1] \
//!     [--measure-secs 5] [--warmup-secs 1]
//!
//! Large-batch ingest (the primary production shape, 250k+ keys per put):
//!   cargo bench -p exoware-simulator --bench ingest_load -- \
//!     --modes ordered,ordered-nowal,unordered,unordered-nowal,raw-nosync \
//!     --concurrency 1,4 --value-sizes 128 --kvs-per-put 250000 --measure-secs 20
//!
//! `--tuned` sizes RocksDB for bulk ingest (512 MiB write buffers, 8 background jobs, relaxed
//! L0 stall thresholds) to separate pipeline costs from stock-option write stalls.

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use bytes::Bytes;
use exoware_server::Ingest;
use exoware_simulator::{
    CommitDurability, FlatFileConfig, FlatFileRocksStore, RocksConfig, RocksStore,
    RocksWritePipelineConfig, UnorderedRocksConfig, UnorderedRocksStore,
};
use tempfile::tempdir;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Ordered,
    OrderedNoWal,
    Unordered,
    UnorderedNoWal,
    UnorderedUw,
    RawNoSync,
    RawSync,
    FlatFile,
    FlatFileNoDb,
}

impl Mode {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "ordered" => Some(Self::Ordered),
            "ordered-nowal" => Some(Self::OrderedNoWal),
            "unordered" => Some(Self::Unordered),
            "unordered-nowal" => Some(Self::UnorderedNoWal),
            "unordered-uw" => Some(Self::UnorderedUw),
            "raw-nosync" => Some(Self::RawNoSync),
            "raw-sync" => Some(Self::RawSync),
            "flatfile" => Some(Self::FlatFile),
            "flatfile-nodb" => Some(Self::FlatFileNoDb),
            _ => None,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Ordered => "ordered",
            Self::OrderedNoWal => "ordered-nowal",
            Self::Unordered => "unordered",
            Self::UnorderedNoWal => "unordered-nowal",
            Self::UnorderedUw => "unordered-uw",
            Self::RawNoSync => "raw-nosync",
            Self::RawSync => "raw-sync",
            Self::FlatFile => "flatfile",
            Self::FlatFileNoDb => "flatfile-nodb",
        }
    }
}

/// One engine under test, reduced to the put path.
#[derive(Clone)]
enum Engine {
    Ordered(RocksStore),
    Unordered(UnorderedRocksStore),
    Raw { db: Arc<rocksdb::DB>, sync: bool },
    FlatFile(FlatFileRocksStore),
    FlatAck(Arc<FlatAckPipeline>),
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
            Self::FlatFile(store) => store.put_batch(kvs).await.map(|_| ()),
            Self::FlatAck(pipeline) => pipeline.put_batch(kvs).await.map(|_| ()),
        }
    }
}

/// Max tickets sequenced (renamed + acked) per directory fsync.
const FLAT_MAX_WAVE: usize = 4096;

/// A durable (written + fsynced) flat file waiting for its sequence number.
struct FlatAckTicket {
    tmp_path: PathBuf,
    ack: tokio::sync::oneshot::Sender<u64>,
}

/// Ack-path-only prototype of the flat-file design: checksummed file write + fsync per upload,
/// then a sequencer that renames a wave of files and fsyncs the directory once before acking.
/// No RocksDB apply happens (files are deleted at sequencing time), so this isolates the
/// durability path as the design's ceiling.
struct FlatAckPipeline {
    staging: PathBuf,
    next_id: AtomicU64,
    sender: Mutex<Option<mpsc::Sender<FlatAckTicket>>>,
    sequencer: Mutex<Option<thread::JoinHandle<()>>>,
}

impl FlatAckPipeline {
    fn open(root: &std::path::Path) -> Arc<Self> {
        let staging = root.join("staging");
        std::fs::create_dir_all(&staging).expect("create staging dir");
        let (tx, rx) = mpsc::channel::<FlatAckTicket>();
        let sequencer_staging = staging.clone();
        let sequencer_handle = thread::Builder::new()
            .name("bench-flat-sequencer".to_string())
            .spawn(move || run_flat_ack_sequencer(sequencer_staging, rx))
            .expect("spawn sequencer");
        Arc::new(Self {
            staging,
            next_id: AtomicU64::new(0),
            sender: Mutex::new(Some(tx)),
            sequencer: Mutex::new(Some(sequencer_handle)),
        })
    }

    async fn put_batch(&self, kvs: Vec<(Bytes, Bytes)>) -> Result<u64, String> {
        // Phase 1 (parallel across callers): durable, checksummed flat file under a temp name.
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let tmp_path = self.staging.join(format!("{id:020}.tmp"));
        let write_path = tmp_path.clone();
        tokio::task::spawn_blocking(move || {
            let mut payload_len = 4usize;
            for (k, v) in &kvs {
                payload_len += 8 + k.len() + v.len();
            }
            let mut buf = Vec::with_capacity(payload_len + 4);
            buf.extend_from_slice(&(kvs.len() as u32).to_le_bytes());
            for (k, v) in &kvs {
                buf.extend_from_slice(&(k.len() as u32).to_le_bytes());
                buf.extend_from_slice(&(v.len() as u32).to_le_bytes());
                buf.extend_from_slice(k.as_ref());
                buf.extend_from_slice(v.as_ref());
            }
            let crc = crc32fast::hash(&buf);
            buf.extend_from_slice(&crc.to_le_bytes());
            let mut file = File::create(&write_path).map_err(|e| e.to_string())?;
            file.write_all(&buf).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| e.to_string())??;

        // Phase 2: wait for the sequencer to rename the file to its sequence number.
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        self.sender
            .lock()
            .map_err(|e| e.to_string())?
            .as_ref()
            .ok_or_else(|| "sequencer stopped".to_string())?
            .send(FlatAckTicket {
                tmp_path,
                ack: ack_tx,
            })
            .map_err(|_| "sequencer stopped".to_string())?;
        ack_rx
            .await
            .map_err(|_| "sequencer dropped ack".to_string())
    }
}

impl Drop for FlatAckPipeline {
    fn drop(&mut self) {
        if let Ok(mut sender) = self.sender.lock() {
            sender.take();
        }
        if let Ok(mut handle) = self.sequencer.lock() {
            if let Some(handle) = handle.take() {
                let _ = handle.join();
            }
        }
    }
}

fn run_flat_ack_sequencer(staging: PathBuf, receiver: mpsc::Receiver<FlatAckTicket>) {
    let dir_handle = File::open(&staging).expect("open staging dir");
    let mut next_seq = 1u64;
    while let Ok(first) = receiver.recv() {
        let mut wave = vec![first];
        while wave.len() < FLAT_MAX_WAVE {
            match receiver.try_recv() {
                Ok(ticket) => wave.push(ticket),
                Err(_) => break,
            }
        }

        // Assign sequence numbers by renaming within the staging directory, then make the whole
        // wave's renames durable with one directory fsync before acking anyone.
        let mut sequenced = Vec::with_capacity(wave.len());
        for ticket in wave {
            let seq = next_seq;
            next_seq += 1;
            let seq_path = staging.join(format!("{seq:020}.seq"));
            std::fs::rename(&ticket.tmp_path, &seq_path).expect("rename to sequence");
            sequenced.push((seq, seq_path, ticket));
        }
        dir_handle.sync_all().expect("fsync staging dir");

        for (seq, seq_path, ticket) in sequenced {
            let _ = ticket.ack.send(seq);
            let _ = std::fs::remove_file(&seq_path);
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
    tuned: bool,
}

/// Bulk-ingest RocksDB options: large write buffers so flushes are infrequent and well-sized,
/// more background jobs so flush/compaction keeps up, and relaxed L0 stall thresholds so the
/// pipelines under test are measured instead of stock-option write stalls.
fn tuned_db_options() -> rocksdb::Options {
    let mut options = rocksdb::Options::default();
    options.set_write_buffer_size(512 * 1024 * 1024);
    options.set_max_write_buffer_number(4);
    options.set_max_background_jobs(8);
    options.set_level_zero_slowdown_writes_trigger(40);
    options.set_level_zero_stop_writes_trigger(60);
    options
}

fn tuned_cf_options() -> rocksdb::Options {
    tuned_db_options()
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
    let ordered_config = |durability: CommitDurability| {
        let mut ordered = RocksConfig {
            write_pipeline: RocksWritePipelineConfig {
                durability,
                ..Default::default()
            },
            ..Default::default()
        };
        if config.tuned {
            ordered.db_options = tuned_db_options();
            ordered.default_cf_options = tuned_cf_options();
        }
        ordered
    };
    let unordered_config = |durability: CommitDurability| {
        let mut unordered = UnorderedRocksConfig {
            durability,
            ..Default::default()
        };
        if config.tuned {
            unordered.db_options = tuned_db_options();
            unordered.default_cf_options = tuned_cf_options();
            unordered.staged_cf_options = tuned_cf_options();
        }
        unordered
    };
    let engine = match config.mode {
        Mode::Ordered => {
            let config = ordered_config(CommitDurability::SyncWal);
            Engine::Ordered(RocksStore::open(dir.path(), Some(config)).expect("open"))
        }
        Mode::OrderedNoWal => {
            let config = ordered_config(CommitDurability::NoWalFlush);
            Engine::Ordered(RocksStore::open(dir.path(), Some(config)).expect("open"))
        }
        Mode::Unordered => {
            let config = unordered_config(CommitDurability::SyncWal);
            Engine::Unordered(UnorderedRocksStore::open(dir.path(), Some(config)).expect("open"))
        }
        Mode::UnorderedNoWal => {
            let config = unordered_config(CommitDurability::NoWalFlush);
            Engine::Unordered(UnorderedRocksStore::open(dir.path(), Some(config)).expect("open"))
        }
        Mode::UnorderedUw => {
            let mut config = unordered_config(CommitDurability::SyncWal);
            config.db_options.set_unordered_write(true);
            Engine::Unordered(UnorderedRocksStore::open(dir.path(), Some(config)).expect("open"))
        }
        Mode::RawNoSync | Mode::RawSync => {
            let mut options = if config.tuned {
                tuned_db_options()
            } else {
                rocksdb::Options::default()
            };
            options.create_if_missing(true);
            Engine::Raw {
                db: Arc::new(rocksdb::DB::open(&options, dir.path()).expect("open")),
                sync: config.mode == Mode::RawSync,
            }
        }
        Mode::FlatFile => {
            let mut flat = FlatFileConfig::default();
            if config.tuned {
                flat.db_options = tuned_db_options();
                flat.default_cf_options = tuned_cf_options();
                flat.log_cf_options = tuned_cf_options();
            }
            Engine::FlatFile(FlatFileRocksStore::open(dir.path(), Some(flat)).expect("open"))
        }
        Mode::FlatFileNoDb => Engine::FlatAck(FlatAckPipeline::open(dir.path())),
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
    let mut tuned = false;

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
            "--tuned" => tuned = true,
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
                    tuned,
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
