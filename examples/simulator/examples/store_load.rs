//! Load driver for the RocksDB store. It records Put latency and the number of live SST files
//! against the commit count, which is how a per-commit cost that grows with the store's file
//! count shows up.
//!
//! Run with
//! `LOAD_DIR=<empty dir> cargo run --release -p exoware-simulator --example store_load`.
//!
//! `LOAD_MODE=small` (the default) issues one Put at a time, shaped like a chain indexer
//! following empty blocks: per block a few SQL and QMDB rows, a certificate, and a tiny
//! publication barrier, each as its own Put. `LOAD_MODE=mixed` adds a 14,000-row, 1.26 MB
//! Put per block and issues blocks from `LOAD_WRITERS` tasks (default 4) at once.
//! `LOAD_COMMITS` is the number of Puts (default 100,000), `LOAD_WINDOW` the number of
//! Puts per output row (default 1,000), and `LOAD_MAX_GIB` the on-disk size at which the run
//! aborts (default 15). `LOAD_MERGE_FILES` is the number of commit groups between log file
//! merges (default 1,024). The store otherwise uses the chain indexer's settings.
//! `LOAD_SLOW_MS`, when set, reports every Put slower than that on stderr with the wall-clock
//! time it finished, to line up with the RocksDB info log. `LOAD_BACKGROUND_JOBS`, when set,
//! overrides RocksDB's `max_background_jobs`.
//!
//! `LOAD_MODE=verify` writes nothing. It opens a store that a `small` run filled and checks
//! that every sequence is in the log and in the state exactly as that run wrote it, then
//! prints the SST file count before and after the checks.
//!
//! Each output row is
//! `commits,elapsed_s,puts_per_s,mean_us,p50_us,p99_us,max_us,sst_files,disk_mib`.

use bytes::Bytes;
use exoware_simulator::{
    rocksdb::Options, Log, Query, RocksConfig, RocksStore, RocksWritePipelineConfig, Sequence,
};
use std::{
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

const BLOCK_ROWS: u64 = 14_000;
const NS_QMDB: u8 = 0x00;
const NS_SIMPLEX: u8 = 0x02;
const NS_SQL: u8 = 0x03;
const NS_TARGET: u8 = 0x04;

fn setting<T: std::str::FromStr>(name: &str, default: T) -> T {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse()
            .unwrap_or_else(|_| panic!("{name} is not a valid value: {raw}")),
        Err(_) => default,
    }
}

const fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// A value of `len` bytes that does not repeat across rows.
fn value(seed: u64, len: usize) -> Bytes {
    let mut out = Vec::with_capacity(len + 8);
    let mut word = seed;
    while out.len() < len {
        word = mix(word);
        out.extend_from_slice(&word.to_le_bytes());
    }
    out.truncate(len);
    Bytes::from(out)
}

/// A key in `namespace` ordered by block height and row.
fn ordered_key(namespace: u8, height: u64, row: u64) -> Bytes {
    let mut key = Vec::with_capacity(33);
    key.push(namespace);
    key.extend_from_slice(&height.to_be_bytes());
    key.extend_from_slice(&row.to_be_bytes());
    key.extend_from_slice(&[0u8; 16]);
    Bytes::from(key)
}

/// A digest-like key in `namespace`, spread over the whole key space.
fn digest_key(namespace: u8, height: u64, row: u64) -> Bytes {
    let mut key = Vec::with_capacity(33);
    key.push(namespace);
    let mut word = mix(height ^ row.rotate_left(32));
    for _ in 0..4 {
        word = mix(word);
        key.extend_from_slice(&word.to_be_bytes());
    }
    Bytes::from(key)
}

/// A block's rows: half ordered SQL rows and half digest-keyed QMDB rows.
fn block_rows(height: u64, rows: u64, value_len: usize) -> Vec<(Bytes, Bytes)> {
    (0..rows)
        .map(|row| {
            let key = if row % 2 == 0 {
                ordered_key(NS_SQL, height, row)
            } else {
                digest_key(NS_QMDB, height, row)
            };
            (key, value(height ^ (row << 40), value_len))
        })
        .collect()
}

fn certificate(height: u64) -> Vec<(Bytes, Bytes)> {
    vec![(ordered_key(NS_SIMPLEX, height, 0), value(!height, 400))]
}

fn barrier(height: u64) -> Vec<(Bytes, Bytes)> {
    vec![(
        ordered_key(NS_TARGET, height, 0),
        Bytes::copy_from_slice(&height.to_be_bytes()),
    )]
}

/// Live SST files and total bytes under the store directory, staging files excluded.
fn disk_usage(dir: &Path) -> (usize, u64) {
    let mut files = 0;
    let mut bytes = 0;
    for entry in std::fs::read_dir(dir)
        .expect("read store directory")
        .flatten()
    {
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        bytes += metadata.len();
        if entry.path().extension().is_some_and(|ext| ext == "sst") {
            files += 1;
        }
    }
    (files, bytes)
}

struct Report {
    dir: PathBuf,
    window: usize,
    max_bytes: u64,
    slow: Option<Duration>,
    started: Instant,
    window_started: Instant,
    commits: usize,
    latencies: Vec<u64>,
}

impl Report {
    fn new(dir: PathBuf, window: usize, max_bytes: u64, slow: Option<Duration>) -> Self {
        println!("commits,elapsed_s,puts_per_s,mean_us,p50_us,p99_us,max_us,sst_files,disk_mib");
        let now = Instant::now();
        Self {
            dir,
            window,
            max_bytes,
            slow,
            started: now,
            window_started: now,
            commits: 0,
            latencies: Vec::with_capacity(window),
        }
    }

    /// Records one Put and prints a row at each window boundary. Returns false once the store
    /// has outgrown the disk cap.
    fn record(&mut self, latency: Duration) -> bool {
        self.commits += 1;
        if self.slow.is_some_and(|slow| latency > slow) {
            let finished = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock is after the epoch");
            eprintln!(
                "slow put {} finished at {}.{:06} after {} ms",
                self.commits,
                finished.as_secs(),
                finished.subsec_micros(),
                latency.as_millis()
            );
        }
        self.latencies.push(latency.as_micros() as u64);
        if self.latencies.len() < self.window {
            return true;
        }
        self.latencies.sort_unstable();
        let count = self.latencies.len();
        let mean = self.latencies.iter().sum::<u64>() / count as u64;
        let (files, bytes) = disk_usage(&self.dir);
        println!(
            "{},{:.1},{:.0},{},{},{},{},{},{}",
            self.commits,
            self.started.elapsed().as_secs_f64(),
            count as f64 / self.window_started.elapsed().as_secs_f64(),
            mean,
            self.latencies[count / 2],
            self.latencies[count * 99 / 100],
            self.latencies[count - 1],
            files,
            bytes >> 20,
        );
        self.latencies.clear();
        self.window_started = Instant::now();
        bytes <= self.max_bytes
    }
}

fn open(dir: &Path, log_merge_files: usize) -> RocksStore {
    let mut db_options = Options::default();
    db_options.set_max_open_files(16_384);
    db_options.set_max_subcompactions(8);
    if let Ok(jobs) = std::env::var("LOAD_BACKGROUND_JOBS") {
        db_options.set_max_background_jobs(jobs.parse().expect("LOAD_BACKGROUND_JOBS"));
    }
    db_options.set_bytes_per_sync(8 * 1024 * 1024);
    db_options.set_compaction_readahead_size(8 * 1024 * 1024);
    let four = NonZeroUsize::new(4).expect("nonzero");
    let config = RocksConfig {
        db_options,
        write_pipeline: RocksWritePipelineConfig {
            max_commit_batch_bytes: NonZeroUsize::new(256 * 1024 * 1024).expect("nonzero"),
            stage_workers: four,
            max_queued_waves: four,
            log_merge_files: NonZeroUsize::new(log_merge_files).expect("LOAD_MERGE_FILES is zero"),
        },
    };
    RocksStore::open(dir, Some(config)).expect("open store")
}

async fn timed_put(store: &RocksStore, rows: Vec<(Bytes, Bytes)>) -> Duration {
    let start = Instant::now();
    store.put_batch(rows).await.expect("put");
    start.elapsed()
}

/// The rows of the `commit`-th Put of a `small` run, three Puts per block.
fn small_rows(commit: u64) -> Vec<(Bytes, Bytes)> {
    let height = commit / 3;
    match commit % 3 {
        0 => block_rows(height, 12, 150),
        1 => certificate(height),
        _ => barrier(height),
    }
}

/// One Put at a time, continuing after the Puts already in the store.
async fn run_small(store: RocksStore, commits: usize, mut report: Report) {
    let first = store.current_sequence();
    for commit in first..first + commits as u64 {
        if !report.record(timed_put(&store, small_rows(commit)).await) {
            eprintln!("disk cap reached after {} commits", commit + 1);
            return;
        }
    }
}

/// Checks every sequence of a `small` run against the rows that run wrote.
async fn run_verify(store: RocksStore, dir: &Path) {
    let newest = store.current_sequence();
    eprintln!(
        "verifying {newest} sequences, {} sst files",
        disk_usage(dir).0
    );
    for sequence in 1..=newest {
        let rows = small_rows(sequence - 1);
        let logged = store
            .get_batch(sequence)
            .await
            .expect("get batch")
            .unwrap_or_else(|| panic!("sequence {sequence} is missing from the log"))
            .decode_response()
            .expect("decode batch");
        let logged: Vec<_> = logged
            .entries
            .into_iter()
            .map(|entry| (Bytes::from(entry.key), entry.value))
            .collect();
        assert_eq!(logged, rows, "log row of sequence {sequence}");
        for (key, value) in rows {
            let stored = store.get(key).await.expect("get").value;
            assert_eq!(stored, Some(value), "state of sequence {sequence}");
        }
    }
    eprintln!(
        "verified {newest} sequences, {} sst files",
        disk_usage(dir).0
    );
}

/// Blocks issued from several tasks at once: a large Put, then the certificate and barrier.
async fn run_mixed(store: RocksStore, commits: usize, writers: u64, mut report: Report) {
    let blocks = (commits as u64).div_ceil(3);
    let next = Arc::new(AtomicU64::new(0));
    let (sender, mut latencies) = mpsc::unbounded_channel();
    let value_len = (1_260_000 / BLOCK_ROWS as usize) - 33;
    for _ in 0..writers {
        let store = store.clone();
        let next = next.clone();
        let sender = sender.clone();
        tokio::spawn(async move {
            loop {
                let height = next.fetch_add(1, Ordering::Relaxed);
                if height >= blocks {
                    return;
                }
                let rows =
                    tokio::task::spawn_blocking(move || block_rows(height, BLOCK_ROWS, value_len))
                        .await
                        .expect("build block");
                for rows in [rows, certificate(height), barrier(height)] {
                    if sender.send(timed_put(&store, rows).await).is_err() {
                        return;
                    }
                }
            }
        });
    }
    drop(sender);
    while let Some(latency) = latencies.recv().await {
        if !report.record(latency) {
            eprintln!("disk cap reached after {} commits", report.commits);
            return;
        }
    }
}

fn main() {
    let dir = PathBuf::from(std::env::var("LOAD_DIR").expect("LOAD_DIR is required"));
    let mode = setting("LOAD_MODE", "small".to_string());
    let commits = setting("LOAD_COMMITS", 100_000usize);
    let window = setting("LOAD_WINDOW", 1_000usize);
    let writers = setting("LOAD_WRITERS", 4u64);
    let max_bytes = setting("LOAD_MAX_GIB", 15u64) << 30;
    let log_merge_files = setting("LOAD_MERGE_FILES", 1_024usize);
    let slow = std::env::var("LOAD_SLOW_MS")
        .ok()
        .map(|raw| Duration::from_millis(raw.parse().expect("LOAD_SLOW_MS is not a number")));

    // Stock RocksDB keeps every table file open.
    rlimit::increase_nofile_limit(u64::MAX).expect("raise the open-file limit");
    std::fs::create_dir_all(&dir).expect("create LOAD_DIR");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build runtime");
    runtime.block_on(async {
        let store = open(&dir, log_merge_files);
        let report = Report::new(dir.clone(), window, max_bytes, slow);
        let started = Instant::now();
        match mode.as_str() {
            "small" => run_small(store.clone(), commits, report).await,
            "mixed" => run_mixed(store.clone(), commits, writers, report).await,
            "verify" => run_verify(store.clone(), &dir).await,
            other => panic!("unknown LOAD_MODE {other}"),
        }
        let (files, bytes) = disk_usage(&dir);
        eprintln!(
            "done: {:.1}s, {files} sst files, {} MiB",
            started.elapsed().as_secs_f64(),
            bytes >> 20
        );
    });
}
