//! Cost of compressing query and stream responses at several zstd levels.
//!
//! `connect_compression_registry()` compresses responses of 1 KiB or more with
//! zstd. This bench compresses and decompresses protobuf response bodies through
//! connectrpc's `ZstdProvider` (the pooled compressor servers use, and the decoder
//! Rust clients use) at levels 3 (connectrpc's default), 1, -1 and -3. A faster
//! level can produce a bigger frame, so before timing it prints each body's
//! compressed size at every level.
//!
//! Every body is synthetic and seeded, so each run compresses the same bytes:
//! - `range_26_58` and `get_many_26_58` hold 4096 rows with 26 B keys (an 8-byte
//!   big-endian counter plus a random tail) and 58 B values (two-thirds random,
//!   the rest zero). Range keys are consecutive and GetMany keys are random.
//! - `capture_*` bodies use rows from a port of kv-mk1's
//!   `crates/ct-flusher/benches/support/synthetic.rs` (`CAPTURE_SHAPED_SYNTHETIC`,
//!   as of kv-mk1 1b84f89b). That fixture reproduces the row families, key
//!   layouts and value sizes of a captured Constantinople indexer sequence. Each
//!   `capture_range_*` body is a window of 4096 consecutive rows at a point in the
//!   sorted keyspace, so different windows hold different row families. The
//!   `capture_range_55pct` window holds 10 B keys and 2 B values, the most
//!   compressible shape here. `capture_stream` is the whole sequence (1,540,003
//!   rows, about 139 MB) in WAL-like order, as one stream batch.
//!
//! Run with `cargo bench -p exoware-sdk --bench response_compression`. Pass a
//! filter such as `-- capture_range` to run a subset.

use buffa::Message;
use bytes::Bytes;
use connectrpc::compression::{CompressionProvider, ZstdProvider};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use exoware_sdk::{
    common::Entry,
    query::{GetManyEntry, GetManyFrame, RangeFrame},
    stream::GetResponse,
};

/// zstd levels to compare. 3 is connectrpc's default.
const LEVELS: [i32; 4] = [3, 1, -1, -3];

/// Rows in each Range and GetMany frame.
const FRAME_ROWS: usize = 4096;

/// Points of the sorted capture keyspace where Range windows start, in percent.
const CAPTURE_WINDOWS: [usize; 5] = [5, 30, 55, 80, 95];

/// Bodies larger than this take long enough to compress that criterion's
/// default of 100 samples would take minutes per level.
const LARGE_BODY_BYTES: usize = 16 << 20;

const fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut word = *state;
    word = (word ^ (word >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    word = (word ^ (word >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    word ^ (word >> 31)
}

fn fill_random(out: &mut [u8], state: &mut u64) {
    for chunk in out.chunks_mut(8) {
        let word = splitmix64(state).to_be_bytes();
        chunk.copy_from_slice(&word[..chunk.len()]);
    }
}

fn entry(key: Vec<u8>, value: Bytes) -> Entry {
    Entry {
        key,
        value,
        ..Default::default()
    }
}

// Simple rows: an 8-byte big-endian counter plus a random key tail, and values
// whose first two-thirds are random.

const SIMPLE_KEY_LEN: usize = 26;
const SIMPLE_VALUE_LEN: usize = 58;

fn simple_row(counter: u64, state: &mut u64) -> (Vec<u8>, Bytes) {
    let mut key = vec![0u8; SIMPLE_KEY_LEN];
    key[..8].copy_from_slice(&counter.to_be_bytes());
    fill_random(&mut key[8..], state);
    let mut value = vec![0u8; SIMPLE_VALUE_LEN];
    fill_random(&mut value[..(SIMPLE_VALUE_LEN * 2).div_ceil(3)], state);
    (key, Bytes::from(value))
}

fn simple_range_frame(state: &mut u64) -> Vec<u8> {
    let first = splitmix64(state) >> 8;
    RangeFrame {
        results: (0..FRAME_ROWS as u64)
            .map(|i| {
                let (key, value) = simple_row(first + i, state);
                entry(key, value)
            })
            .collect(),
        ..Default::default()
    }
    .encode_to_vec()
}

fn simple_get_many_frame(state: &mut u64) -> Vec<u8> {
    GetManyFrame {
        results: (0..FRAME_ROWS)
            .map(|_| {
                let counter = splitmix64(state);
                let (key, value) = simple_row(counter, state);
                GetManyEntry {
                    key,
                    value: Some(value),
                    ..Default::default()
                }
            })
            .collect(),
        ..Default::default()
    }
    .encode_to_vec()
}

// Port of kv-mk1's `CAPTURE_SHAPED_SYNTHETIC` fixture. Each transaction adds
// four SQL primary rows and one account-state QMDB update row, then each of six
// QMDB operation or Merkle-node families adds one row per transaction. Three
// tail rows add one overwrite and two sparse key families. The generated
// sequence and its byte counts match the original.

const CAPTURE_TRANSACTIONS: usize = 140_000;
const CAPTURE_SEED: u64 = 13;
const CAPTURE_RANDOM_VALUE_PERCENT: usize = 67;
const CAPTURE_DISORDER_STRIDE: usize = 48;

// Outer Store namespaces assigned by Constantinople.
const ACCOUNT_STATE_QMDB_NAMESPACE: u8 = 0;
const TRANSACTION_HISTORY_QMDB_NAMESPACE: u8 = 1;
const SQL_METADATA_NAMESPACE: u8 = 3;

// QMDB family bytes identify row semantics within a Store namespace.
const QMDB_UPDATE_FAMILY: u8 = 1;
const QMDB_OPERATION_FAMILY: u8 = 4;
const QMDB_MERKLE_NODE_FAMILY: u8 = 5;

// SQL packs the table prefix into the high nibble and the primary-row
// discriminator into the low nibble.
const TX_META_PRIMARY_FAMILY: u8 = 0x10;
const TX_ACTIVITY_PRIMARY_FAMILY: u8 = 0x20;
const ACCOUNT_META_PRIMARY_FAMILY: u8 = 0x30;
const SYNTHETIC_SQL_TAIL_FAMILY: u8 = 0x40;

fn capture_identity(state: &mut u64) -> [u8; 32] {
    let mut identity = [0u8; 32];
    fill_random(&mut identity, state);
    identity
}

/// A zero prefix followed by pseudorandom bytes.
fn capture_value(len: usize, state: &mut u64) -> Bytes {
    let mut value = vec![0u8; len];
    let random_len = len * CAPTURE_RANDOM_VALUE_PERCENT / 100;
    fill_random(&mut value[len - random_len..], state);
    Bytes::from(value)
}

fn sql_primary_key(row_family: u8, identity: &[u8; 32], key_len: usize, ordinal: u64) -> Vec<u8> {
    let mut key = vec![0u8; key_len];
    key[0] = SQL_METADATA_NAMESPACE;
    key[1] = row_family;
    let identity_len = identity.len().min(key_len.saturating_sub(2));
    key[2..2 + identity_len].copy_from_slice(&identity[..identity_len]);
    let ordinal = ordinal.to_be_bytes();
    let suffix_len = ordinal.len().min(key_len.saturating_sub(2 + identity_len));
    key[key_len - suffix_len..].copy_from_slice(&ordinal[ordinal.len() - suffix_len..]);
    key
}

const fn state_update_key_len(location: usize) -> usize {
    match location {
        0..123_349 => 44,
        123_349..139_047 => 45,
        139_047..139_964 => 46,
        139_964..139_999 => 47,
        _ => 48,
    }
}

fn state_update_key(identity: &[u8; 32], location: usize) -> Vec<u8> {
    let key_len = state_update_key_len(location);
    let mut key = vec![0u8; key_len];
    key[0] = ACCOUNT_STATE_QMDB_NAMESPACE;
    key[1] = QMDB_UPDATE_FAMILY;
    key[2..34].copy_from_slice(identity);
    key[key_len - 8..].copy_from_slice(&(location as u64).to_be_bytes());
    key
}

fn qmdb_location_key(store_namespace: u8, row_family: u8, location: u64) -> Vec<u8> {
    let mut key = vec![0u8; 10];
    key[0] = store_namespace;
    key[1] = row_family;
    key[2..].copy_from_slice(&location.to_be_bytes());
    key
}

/// Returns the capture-shaped rows in WAL-like order: sorted by key, then with
/// every 48th row swapped with a random one.
fn capture_rows() -> Vec<(Vec<u8>, Bytes)> {
    let mut rows = Vec::with_capacity(CAPTURE_TRANSACTIONS * 11 + 3);
    let mut state = CAPTURE_SEED;

    let mut overwritten_account_meta_key = Vec::new();
    for transaction in 0..CAPTURE_TRANSACTIONS {
        let primary = capture_identity(&mut state);
        let secondary = capture_identity(&mut state);
        let ordinal = transaction as u64;
        let account_meta_key =
            sql_primary_key(ACCOUNT_META_PRIMARY_FAMILY, &secondary, 34, ordinal);
        if transaction == 0 {
            overwritten_account_meta_key = account_meta_key.clone();
        }
        let shapes = [
            (
                sql_primary_key(TX_META_PRIMARY_FAMILY, &primary, 34, ordinal),
                164,
            ),
            (
                sql_primary_key(TX_ACTIVITY_PRIMARY_FAMILY, &primary, 58, ordinal),
                96,
            ),
            (
                sql_primary_key(TX_ACTIVITY_PRIMARY_FAMILY, &secondary, 58, ordinal),
                96,
            ),
            (account_meta_key, 43),
            (state_update_key(&primary, transaction), 58),
        ];
        for (key, value_len) in shapes {
            rows.push((key, capture_value(value_len, &mut state)));
        }
    }

    // The first seven 33-byte QMDB values take these lengths instead.
    let rare_value_lens = [1, 1, 1, 1, 2, 43, 58];
    let mut rare_value_index = 0;
    let qmdb_shapes = [
        (ACCOUNT_STATE_QMDB_NAMESPACE, QMDB_OPERATION_FAMILY, 43),
        (ACCOUNT_STATE_QMDB_NAMESPACE, QMDB_MERKLE_NODE_FAMILY, 33),
        (ACCOUNT_STATE_QMDB_NAMESPACE, QMDB_MERKLE_NODE_FAMILY, 33),
        (
            TRANSACTION_HISTORY_QMDB_NAMESPACE,
            QMDB_OPERATION_FAMILY,
            33,
        ),
        (
            TRANSACTION_HISTORY_QMDB_NAMESPACE,
            QMDB_MERKLE_NODE_FAMILY,
            33,
        ),
        (
            TRANSACTION_HISTORY_QMDB_NAMESPACE,
            QMDB_MERKLE_NODE_FAMILY,
            2,
        ),
    ];
    for (shape, (store_namespace, row_family, default_value_len)) in
        qmdb_shapes.into_iter().enumerate()
    {
        for transaction in 0..CAPTURE_TRANSACTIONS {
            let mut value_len = default_value_len;
            if default_value_len == 33 {
                if let Some(&rare) = rare_value_lens.get(rare_value_index) {
                    value_len = rare;
                    rare_value_index += 1;
                }
            }
            let location = (transaction + shape * CAPTURE_TRANSACTIONS) as u64;
            rows.push((
                qmdb_location_key(store_namespace, row_family, location),
                capture_value(value_len, &mut state),
            ));
        }
    }

    let tail_rows = [
        (overwritten_account_meta_key, 43),
        (
            sql_primary_key(
                SYNTHETIC_SQL_TAIL_FAMILY,
                &capture_identity(&mut state),
                10,
                CAPTURE_TRANSACTIONS as u64,
            ),
            58,
        ),
        (
            state_update_key(&capture_identity(&mut state), CAPTURE_TRANSACTIONS),
            113,
        ),
    ];
    for (key, value_len) in tail_rows {
        rows.push((key, capture_value(value_len, &mut state)));
    }

    rows.sort_by(|left, right| left.0.cmp(&right.0));
    let mut disorder = CAPTURE_SEED ^ 0xA076_1D64_78BD_642F;
    for i in (1..rows.len().saturating_sub(1)).step_by(CAPTURE_DISORDER_STRIDE) {
        let j = splitmix64(&mut disorder) as usize % rows.len();
        if rows[i].0 != rows[j].0 {
            rows.swap(i, j);
        }
    }
    rows
}

struct Body {
    name: String,
    /// Key and value sizes, for the size table.
    shape: String,
    bytes: Vec<u8>,
}

fn bodies() -> Vec<Body> {
    let mut state = 0x5EED;
    let mut bodies = vec![
        Body {
            name: "range_26_58".into(),
            shape: format!("{SIMPLE_KEY_LEN} B keys, {SIMPLE_VALUE_LEN} B values"),
            bytes: simple_range_frame(&mut state),
        },
        Body {
            name: "get_many_26_58".into(),
            shape: format!("{SIMPLE_KEY_LEN} B keys, {SIMPLE_VALUE_LEN} B values"),
            bytes: simple_get_many_frame(&mut state),
        },
    ];

    let wal = capture_rows();
    let mut sorted = wal.clone();
    sorted.sort_by(|left, right| left.0.cmp(&right.0));
    for percent in CAPTURE_WINDOWS {
        let start = (sorted.len() - FRAME_ROWS) * percent / 100;
        let window = &sorted[start..start + FRAME_ROWS];
        let key_bytes: usize = window.iter().map(|(key, _)| key.len()).sum();
        let value_bytes: usize = window.iter().map(|(_, value)| value.len()).sum();
        bodies.push(Body {
            name: format!("capture_range_{percent}pct"),
            shape: format!(
                "avg {} B keys, {} B values",
                key_bytes / FRAME_ROWS,
                value_bytes / FRAME_ROWS
            ),
            bytes: RangeFrame {
                results: window
                    .iter()
                    .map(|(key, value)| entry(key.clone(), value.clone()))
                    .collect(),
                ..Default::default()
            }
            .encode_to_vec(),
        });
    }
    drop(sorted);

    let rows = wal.len();
    bodies.push(Body {
        name: "capture_stream".into(),
        shape: format!("{rows} rows, WAL order"),
        bytes: GetResponse {
            sequence_number: 1,
            entries: wal
                .into_iter()
                .map(|(key, value)| entry(key, value))
                .collect(),
            ..Default::default()
        }
        .encode_to_vec(),
    });
    bodies
}

/// Checks that every body round-trips at every level and prints its sizes.
fn print_sizes(bodies: &[Body], providers: &[(i32, ZstdProvider)]) {
    let levels: Vec<String> = providers
        .iter()
        .map(|(level, _)| level.to_string())
        .collect();
    println!("compressed bytes at zstd levels {}", levels.join(" / "));
    for body in bodies {
        let sizes: Vec<String> = providers
            .iter()
            .map(|(_, provider)| {
                let compressed = provider.compress(&body.bytes).unwrap();
                let decompressed = provider
                    .decompress_with_limit(&compressed, body.bytes.len())
                    .unwrap();
                assert_eq!(decompressed.as_ref(), body.bytes.as_slice());
                compressed.len().to_string()
            })
            .collect();
        println!(
            "  {} ({}): {} raw, {}",
            body.name,
            body.shape,
            body.bytes.len(),
            sizes.join(" / ")
        );
    }
}

fn response_compression(c: &mut Criterion) {
    let bodies = bodies();
    let providers: Vec<(i32, ZstdProvider)> = LEVELS
        .iter()
        .map(|&level| (level, ZstdProvider::with_level(level)))
        .collect();
    print_sizes(&bodies, &providers);

    for body in &bodies {
        let mut group = c.benchmark_group(format!("response_compression/{}", body.name));
        group.throughput(Throughput::Bytes(body.bytes.len() as u64));
        if body.bytes.len() > LARGE_BODY_BYTES {
            group.sample_size(10);
        }
        for (level, provider) in &providers {
            group.bench_with_input(
                BenchmarkId::new("compress", level),
                &body.bytes,
                |b, raw| b.iter(|| provider.compress(raw).unwrap()),
            );
            let compressed = provider.compress(&body.bytes).unwrap();
            group.bench_with_input(
                BenchmarkId::new("decompress", level),
                &compressed,
                |b, compressed| {
                    b.iter(|| {
                        provider
                            .decompress_with_limit(compressed, body.bytes.len())
                            .unwrap()
                    })
                },
            );
        }
        group.finish();
    }
}

criterion_group!(benches, response_compression);
criterion_main!(benches);
