//! Kills a writing store while its log files are being merged and checks that the reopened
//! store still holds every row.
//!
//! The writer is this test binary run again as a child process, so the kill is a real process
//! crash at a point the test does not choose: mid-ingestion, mid-merge, or between the two.
//! A kill leaves the operating system's page cache intact, so this covers crash consistency
//! of the engine's own steps and not what a power loss does to unsynced files.

use bytes::Bytes;
use exoware_server::{Log, Query, Sequence};
use exoware_simulator::{RocksConfig, RocksStore, RocksWritePipelineConfig};
use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader},
    num::NonZeroUsize,
    path::Path,
    process::{Command, Stdio},
};

/// Set for the child process to the directory it writes to.
const WRITER_DIR: &str = "LOG_MERGE_CRASH_WRITER_DIR";
const MERGE_FILES: usize = 8;
const ROWS: u64 = 4;
const VALUE_LEN: usize = 64 * 1024;

fn open(path: &Path) -> RocksStore {
    RocksStore::open(
        path,
        Some(RocksConfig {
            write_pipeline: RocksWritePipelineConfig {
                log_merge_files: NonZeroUsize::new(MERGE_FILES).expect("nonzero"),
                ..Default::default()
            },
            ..Default::default()
        }),
    )
    .expect("open store")
}

/// The rows of the batch committed as `sequence`. Even sequences are large enough that a
/// merge takes a while and that their state is ingested as a file, and odd ones are small
/// enough that their state is written as a batch.
fn batch(sequence: u64) -> Vec<(Bytes, Bytes)> {
    let (rows, value_len) = if sequence.is_multiple_of(2) {
        (ROWS, VALUE_LEN)
    } else {
        (1, 64)
    };
    (0..rows)
        .map(|row| {
            let mut key = sequence.to_be_bytes().to_vec();
            key.extend_from_slice(&row.to_be_bytes());
            let fill = (sequence.wrapping_mul(31).wrapping_add(row)) as u8;
            (Bytes::from(key), Bytes::from(vec![fill; value_len]))
        })
        .collect()
}

/// Appends batches until killed, printing each sequence once its Put is acknowledged.
async fn write_until_killed(dir: &Path) -> ! {
    let store = open(dir);
    let mut sequence = store.current_sequence();
    loop {
        sequence += 1;
        let committed = store.put_batch(batch(sequence)).await.expect("put");
        assert_eq!(committed, sequence);
        println!("ack {sequence}");
    }
}

/// Counts the log column family's compactions the killed process started and never reported
/// finished, from the RocksDB info log it left behind.
fn interrupted_merges(dir: &Path) -> usize {
    let log = std::fs::read_to_string(dir.join("LOG")).expect("read RocksDB info log");
    let jobs = |event: &str, family: &str| -> BTreeSet<u64> {
        log.lines()
            .filter(|line| line.contains(event) && line.contains(family))
            .filter_map(|line| {
                line.split("\"job\": ")
                    .nth(1)?
                    .split(',')
                    .next()?
                    .parse()
                    .ok()
            })
            .collect()
    };

    // Only the start event names the column family.
    let started = jobs("\"event\": \"compaction_started\"", "\"cf_name\": \"log\"");
    let finished = jobs("\"event\": \"compaction_finished\"", "");
    started.difference(&finished).count()
}

#[tokio::test(flavor = "multi_thread")]
async fn killed_writer_reopens_with_every_acknowledged_row() {
    if let Some(dir) = std::env::var_os(WRITER_DIR) {
        write_until_killed(Path::new(&dir)).await;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let mut interrupted = 0;
    let mut round = 0;
    while interrupted < 5 {
        round += 1;
        assert!(round <= 60, "no kill landed inside a merge");
        let mut writer = Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "killed_writer_reopens_with_every_acknowledged_row",
                "--exact",
                "--nocapture",
            ])
            .env(WRITER_DIR, dir.path())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn writer");

        // A merge starts right after every MERGE_FILES-th commit of the process, so a kill
        // shortly after one of those acknowledgements tends to find it running.
        let wanted = MERGE_FILES * (2 + round % 5) + round % 2;
        let mut acked = 0;
        let mut seen = 0;
        for line in BufReader::new(writer.stdout.take().expect("writer stdout")).lines() {
            let line = line.expect("read writer output");
            if let Some(sequence) = line.strip_prefix("ack ") {
                acked = sequence.parse().expect("sequence");
                seen += 1;
                if seen == wanted {
                    break;
                }
            }
        }
        writer.kill().expect("kill writer");
        writer.wait().expect("reap writer");
        assert_eq!(seen, wanted, "the writer stopped by itself");
        interrupted += interrupted_merges(dir.path());

        let store = open(dir.path());
        let frontier = store.current_sequence();
        assert!(
            frontier >= acked,
            "acknowledged sequence {acked} is above the reopened frontier {frontier}"
        );
        assert_eq!(
            store.oldest_retained_batch().await.expect("oldest"),
            Some(1)
        );
        for sequence in 1..=frontier {
            let logged = store
                .get_batch(sequence)
                .await
                .expect("get batch")
                .unwrap_or_else(|| panic!("round {round}: batch {sequence} is missing"))
                .decode_response()
                .expect("decode batch");
            let logged: Vec<_> = logged
                .entries
                .into_iter()
                .map(|entry| (Bytes::from(entry.key), entry.value))
                .collect();
            assert_eq!(logged, batch(sequence), "round {round}: batch {sequence}");
            for (key, value) in batch(sequence) {
                let stored = store.get(key).await.expect("get").value;
                assert_eq!(stored, Some(value), "round {round}: state of {sequence}");
            }
        }
        assert!(
            store.get_batch(frontier + 1).await.expect("get").is_none(),
            "a batch above the frontier is readable"
        );
    }
}
