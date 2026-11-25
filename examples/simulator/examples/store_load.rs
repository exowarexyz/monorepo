//! Load driver for the RocksDB store. It reports Put latency and the SST file count as the
//! commit count grows, so a per-commit cost that grows with the file count shows up as rising
//! latency.
//!
//! Run with
//! `LOAD_DIR=<empty dir> cargo run --release -p exoware-simulator --example store_load`.
//!
//! `LOAD_MODE` picks the workload:
//!
//! - `small` (the default) issues one Put at a time, shaped like a chain indexer following empty
//!   blocks. Each block is three Puts: twelve SQL and QMDB rows, a certificate, and a publication
//!   barrier.
//! - `mixed` makes the first Put of each block `LOAD_BLOCK_ROWS` rows of 90 bytes (default
//!   14,000, or 1.26 MB) and issues blocks from `LOAD_WRITERS` tasks at once (default 4).
//! - `verify` issues no Puts. It opens a store that a `small` run filled, checks that every
//!   sequence is in the log and in the state exactly as that run wrote it, and prints the SST
//!   file count before and after the checks.
//!
//! The other settings are:
//!
//! - `LOAD_COMMITS`, the number of Puts (default 100,000).
//! - `LOAD_WINDOW`, the number of Puts per output row (default 1,000).
//! - `LOAD_MAX_GIB`, the on-disk size at which the run stops (default 15).
//! - `LOAD_MERGE_FILES`, the store's `log_merge_files` (default 1,024).
//! - `LOAD_SLOW_MS`, when set, reports every Put slower than that many milliseconds on stderr
//!   with a wall-clock timestamp, to line up with the RocksDB info log.
//! - `LOAD_BACKGROUND_JOBS` and `LOAD_SUBCOMPACTIONS`, when set, override RocksDB's
//!   `max_background_jobs` and `max_subcompactions`.
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

// Key namespaces of the chain indexer's rows.
const NS_QMDB: u8 = 0x00;
const NS_TRANSACTIONS: u8 = 0x01;
const NS_SIMPLEX: u8 = 0x02;
const NS_SQL: u8 = 0x03;
const NS_TARGET: u8 = 0x04;

/// Row family of a QMDB watermark, the byte after the namespace.
const QMDB_WATERMARK: u8 = 0x03;

/// Reads setting `name` from the environment, or `default` when it is unset.
fn setting<T: std::str::FromStr>(name: &str, default: T) -> T {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse()
            .unwrap_or_else(|_| panic!("{name} must be a valid value, got {raw}")),
        Err(_) => default,
    }
}

/// SplitMix64's output for state `x`.
const fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// A pseudo-random value of `len` bytes derived from `seed`.
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

/// A digest-like key in `namespace`, spread uniformly over it.
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

/// A block's rows, alternating ordered SQL rows and digest-keyed QMDB rows.
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

/// A block's certificate, one 400-byte row.
fn certificate(height: u64) -> Vec<(Bytes, Bytes)> {
    vec![(ordered_key(NS_SIMPLEX, height, 0), value(!height, 400))]
}

/// A block's publication barrier, shaped like the chain indexer's publication request for one
/// block. It holds the watermarks of the account-state and transaction QMDBs, with the block
/// height standing in for both operation locations, and the block's target, a 32-byte digest
/// keyed by the height.
fn barrier(height: u64) -> Vec<(Bytes, Bytes)> {
    let key = |prefix: &[u8]| Bytes::from([prefix, &height.to_be_bytes()].concat());
    vec![
        (key(&[NS_QMDB, QMDB_WATERMARK]), Bytes::new()),
        (key(&[NS_TRANSACTIONS, QMDB_WATERMARK]), Bytes::new()),
        (key(&[NS_TARGET]), value(height, 32)),
    ]
}

/// SST files and total bytes of the files in the store directory. The staging subdirectory is
/// not counted.
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

/// Collects Put latencies and prints one output row per window of Puts.
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

        // A slow Put is reported with the wall-clock time, to line up with the RocksDB info log.
        if self.slow.is_some_and(|slow| latency > slow) {
            let finished = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("the clock must be after the Unix epoch");
            eprintln!(
                "slow put {} finished at {}.{:06} after {} ms",
                self.commits,
                finished.as_secs(),
                finished.subsec_micros(),
                latency.as_millis()
            );
        }

        // Latencies accumulate until the window is full, and then one row summarizes it.
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

/// Opens the store with the load driver's settings and the environment's overrides.
fn open(dir: &Path, log_merge_files: usize) -> RocksStore {
    let mut db_options = Options::default();
    db_options.set_max_open_files(16_384);
    db_options.set_max_subcompactions(8);
    if let Ok(jobs) = std::env::var("LOAD_BACKGROUND_JOBS") {
        db_options.set_max_background_jobs(
            jobs.parse()
                .expect("LOAD_BACKGROUND_JOBS must be an integer"),
        );
    }
    if let Ok(threads) = std::env::var("LOAD_SUBCOMPACTIONS") {
        db_options.set_max_subcompactions(
            threads
                .parse()
                .expect("LOAD_SUBCOMPACTIONS must be an integer"),
        );
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
            log_merge_files: NonZeroUsize::new(log_merge_files)
                .expect("LOAD_MERGE_FILES must be nonzero"),
        },
    };
    RocksStore::open(dir, Some(config)).expect("open store")
}

/// Puts `rows` and returns how long the Put took.
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
        // The log row must hold exactly the rows that Put wrote.
        let rows = small_rows(sequence - 1);
        let logged = store
            .get_batch(sequence)
            .await
            .expect("get batch")
            .unwrap_or_else(|| panic!("sequence {sequence} must be in the log"))
            .decode_response()
            .expect("decode batch");
        let logged: Vec<_> = logged
            .entries
            .into_iter()
            .map(|entry| (Bytes::from(entry.key), entry.value))
            .collect();
        assert_eq!(logged, rows, "log row of sequence {sequence}");

        // Each row must read back from the state as written.
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

/// Issues blocks from several tasks at once. Each block is a large Put, then the certificate
/// and the barrier.
async fn run_mixed(
    store: RocksStore,
    commits: usize,
    writers: u64,
    rows_per_block: u64,
    mut report: Report,
) {
    let blocks = (commits as u64).div_ceil(3);
    let next = Arc::new(AtomicU64::new(0));
    let (sender, mut latencies) = mpsc::unbounded_channel();
    let mut tasks = tokio::task::JoinSet::new();

    // A 90-byte row is a 33-byte key and a 57-byte value.
    let value_len = 90 - 33;

    // Each writer claims the next block height until every block is issued.
    for _ in 0..writers {
        let store = store.clone();
        let next = next.clone();
        let sender = sender.clone();
        tasks.spawn(async move {
            loop {
                let height = next.fetch_add(1, Ordering::Relaxed);
                if height >= blocks {
                    return;
                }

                // Building a block is CPU work, so it runs off the async threads.
                let rows = tokio::task::spawn_blocking(move || {
                    block_rows(height, rows_per_block, value_len)
                })
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

    // Only the writers hold senders after this drop, so the channel closes when they finish.
    drop(sender);
    while let Some(latency) = latencies.recv().await {
        if !report.record(latency) {
            eprintln!("disk cap reached after {} commits", report.commits);
            break;
        }
    }

    // Closing the channel stops each writer at its next Put. A writer that panicked fails the
    // run, because the Puts of its unfinished block are missing from the report.
    drop(latencies);
    while let Some(writer) = tasks.join_next().await {
        writer.expect("every writer must finish without a panic");
    }
}

fn main() {
    let dir = PathBuf::from(std::env::var("LOAD_DIR").expect("LOAD_DIR must be set"));
    let mode = setting("LOAD_MODE", "small".to_string());
    let commits = setting("LOAD_COMMITS", 100_000usize);
    let window = setting("LOAD_WINDOW", 1_000usize);
    let writers = setting("LOAD_WRITERS", 4u64);
    let max_bytes = setting("LOAD_MAX_GIB", 15u64) << 30;
    let log_merge_files = setting("LOAD_MERGE_FILES", 1_024usize);
    let rows_per_block = setting("LOAD_BLOCK_ROWS", 14_000u64);
    let slow = std::env::var("LOAD_SLOW_MS")
        .ok()
        .map(|raw| Duration::from_millis(raw.parse().expect("LOAD_SLOW_MS must be an integer")));

    // The store may keep thousands of table files open.
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
            "mixed" => run_mixed(store.clone(), commits, writers, rows_per_block, report).await,
            "verify" => run_verify(store.clone(), &dir).await,
            other => panic!("LOAD_MODE must be small, mixed, or verify, got {other}"),
        }
        let (files, bytes) = disk_usage(&dir);
        eprintln!(
            "done: {:.1}s, {files} sst files, {} MiB",
            started.elapsed().as_secs_f64(),
            bytes >> 20
        );
    });
}
