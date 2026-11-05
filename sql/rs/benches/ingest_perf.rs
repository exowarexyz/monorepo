//! Cost of encoding inserted rows into store entries, for a 12-column table with a composite
//! primary key and two covered secondary indexes (3 entries per row).
//!
//! `batch_writer_insert` passes rows as cell values to `BatchWriter::insert` and never touches
//! the network. `sql_insert` runs `INSERT INTO events SELECT * FROM src` from an in-memory table,
//! so it also reads the cells out of arrow batches, and then sends the entries over loopback to an
//! in-process store that decodes and discards them. Before measuring, each case prints one
//! `INGEST_PROFILE` line with the allocation calls and bytes of a single run.
//!
//! The `stage_*` cases measure what an indexer does with a block's SQL rows: `BatchWriter::insert`
//! for every row, then `prepare_flush` and `stage_flush` into a `StoreWriteBatch`, under a
//! one-byte Store namespace (the cases above use the identity namespace, which stages keys
//! without copying them). `stage_constantinople` uses Constantinople's four tables, which have
//! 8- to 56-byte primary keys and no secondary indexes. `stage_events` uses the 12-column table
//! with two indexes from the cases above.

use axum::Router;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use datafusion::{
    arrow::{
        array::{
            ArrayRef, BinaryArray, BooleanArray, Date32Array, Decimal128Array, Float64Array,
            Int64Array, RecordBatch, StringArray, TimestampMicrosecondArray, UInt64Array,
        },
        datatypes::{DataType, Field, Schema, TimeUnit},
    },
    datasource::MemTable,
};
use exoware_sdk::{StoreClient, StoreKeyPrefix, StoreWriteBatch};
use exoware_server::{Ingest, IngestState, PutError, PutInput};
use exoware_sql::{CellValue, IndexSpec, KvSchema, SqlContext, TableColumnConfig};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

const ROWS: usize = 100_000;
const BATCH_ROWS: usize = 8192;

static ALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

struct CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

// SAFETY: Every method passes its arguments unchanged to `System`, which upholds the
// `GlobalAlloc` contract. The bookkeeping only updates atomics and never allocates.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        // SAFETY: The caller's guarantees for `layout` pass straight through.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        // SAFETY: The caller's guarantees for `layout` pass straight through.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: The caller's guarantees for `ptr` and `layout` pass straight through.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        // SAFETY: The caller's guarantees for `ptr`, `layout` and `new_size` pass straight through.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

fn profile(case: &str, rows: usize, run: impl FnOnce()) {
    ALLOC_CALLS.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);
    run();
    println!(
        "INGEST_PROFILE {}",
        serde_json::json!({
            "case": case,
            "rows": rows,
            "allocation_calls": ALLOC_CALLS.load(Ordering::Relaxed),
            "allocation_bytes": ALLOC_BYTES.load(Ordering::Relaxed),
        })
    );
}

/// Drains every Put and keeps nothing.
#[derive(Default)]
struct Discard(AtomicU64);

impl Ingest for Discard {
    async fn put(&self, input: &mut PutInput) -> Result<u64, PutError> {
        while input
            .next_batch(exoware_server::ingest::DecodeBuffers::default())
            .await?
            .is_some()
        {}
        input.finish().await?;
        Ok(self.0.fetch_add(1, Ordering::Relaxed) + 1)
    }
}

fn columns() -> Vec<TableColumnConfig> {
    vec![
        TableColumnConfig::new("tenant", DataType::Utf8, false),
        TableColumnConfig::new("id", DataType::UInt64, false),
        TableColumnConfig::new("status", DataType::Utf8, false),
        TableColumnConfig::new("kind", DataType::Utf8, false),
        TableColumnConfig::new("amount", DataType::Float64, false),
        TableColumnConfig::new("qty", DataType::Int64, false),
        TableColumnConfig::new("flag", DataType::Boolean, false),
        TableColumnConfig::new("day", DataType::Date32, false),
        TableColumnConfig::new(
            "ts",
            DataType::Timestamp(TimeUnit::Microsecond, None),
            false,
        ),
        TableColumnConfig::new("price", DataType::Decimal128(18, 2), false),
        TableColumnConfig::new("note", DataType::Utf8, true),
        TableColumnConfig::new("payload", DataType::Binary, false),
    ]
}

fn schema(client: StoreClient) -> KvSchema {
    events_schema(client, StoreKeyPrefix::identity())
}

fn events_schema(client: StoreClient, namespace: StoreKeyPrefix) -> KvSchema {
    KvSchema::new(client.prefixed(namespace))
        .table(
            "events",
            columns(),
            vec!["tenant".into(), "id".into()],
            vec![
                IndexSpec::lexicographic("status_ts", vec!["status".into(), "ts".into()])
                    .unwrap()
                    .with_cover_columns(vec!["amount".into()]),
                IndexSpec::lexicographic("kind_day", vec!["kind".into(), "day".into()])
                    .unwrap()
                    .with_cover_columns(vec!["note".into()]),
            ],
        )
        .unwrap()
}

const STATUSES: [&str; 4] = ["open", "pending", "shipped", "cancelled"];
const KINDS: [&str; 3] = ["purchase", "refund", "adjustment"];

fn cells(i: usize) -> Vec<CellValue> {
    vec![
        CellValue::Utf8(format!("tenant-{:03}", i % 97)),
        CellValue::UInt64(i as u64),
        CellValue::Utf8(STATUSES[i % 4].into()),
        CellValue::Utf8(KINDS[i % 3].into()),
        CellValue::Float64(i as f64 * 0.25),
        CellValue::Int64(i as i64 % 1000 - 500),
        CellValue::Boolean(i.is_multiple_of(2)),
        CellValue::Date32(19_000 + (i % 365) as i32),
        CellValue::Timestamp(1_700_000_000_000_000 + i as i64 * 1000),
        CellValue::Decimal128(i as i128 * 100 + 99),
        if i.is_multiple_of(5) {
            CellValue::Null
        } else {
            CellValue::Utf8(format!("note for row {i}"))
        },
        CellValue::Binary(vec![(i % 251) as u8; 32]),
    ]
}

fn record_batches() -> (Arc<Schema>, Vec<RecordBatch>) {
    let schema = Arc::new(Schema::new(
        columns()
            .into_iter()
            .map(|col| Field::new(col.name, col.data_type, col.nullable))
            .collect::<Vec<_>>(),
    ));
    let batches = (0..ROWS)
        .step_by(BATCH_ROWS)
        .map(|start| {
            let rows = start..(start + BATCH_ROWS).min(ROWS);
            let arrays: Vec<ArrayRef> = vec![
                Arc::new(StringArray::from_iter_values(
                    rows.clone().map(|i| format!("tenant-{:03}", i % 97)),
                )),
                Arc::new(UInt64Array::from_iter_values(
                    rows.clone().map(|i| i as u64),
                )),
                Arc::new(StringArray::from_iter_values(
                    rows.clone().map(|i| STATUSES[i % 4]),
                )),
                Arc::new(StringArray::from_iter_values(
                    rows.clone().map(|i| KINDS[i % 3]),
                )),
                Arc::new(Float64Array::from_iter_values(
                    rows.clone().map(|i| i as f64 * 0.25),
                )),
                Arc::new(Int64Array::from_iter_values(
                    rows.clone().map(|i| i as i64 % 1000 - 500),
                )),
                Arc::new(BooleanArray::from_iter(
                    rows.clone().map(|i| Some(i.is_multiple_of(2))),
                )),
                Arc::new(Date32Array::from_iter_values(
                    rows.clone().map(|i| 19_000 + (i % 365) as i32),
                )),
                Arc::new(TimestampMicrosecondArray::from_iter_values(
                    rows.clone()
                        .map(|i| 1_700_000_000_000_000 + i as i64 * 1000),
                )),
                Arc::new(
                    Decimal128Array::from_iter_values(rows.clone().map(|i| i as i128 * 100 + 99))
                        .with_precision_and_scale(18, 2)
                        .unwrap(),
                ),
                Arc::new(StringArray::from_iter(rows.clone().map(|i| {
                    (!i.is_multiple_of(5)).then(|| format!("note for row {i}"))
                }))),
                Arc::new(BinaryArray::from_iter_values(
                    rows.map(|i| vec![(i % 251) as u8; 32]),
                )),
            ];
            RecordBatch::try_new(schema.clone(), arrays).unwrap()
        })
        .collect();
    (schema, batches)
}

fn batch_writer_insert(c: &mut Criterion) {
    let schema = schema(StoreClient::new("http://127.0.0.1:1"));
    let rows = || (0..ROWS).map(cells).collect::<Vec<_>>();
    let insert_all = |rows: Vec<Vec<CellValue>>| {
        let mut writer = schema.batch_writer();
        for row in rows {
            writer.insert("events", row).unwrap();
        }
        assert_eq!(writer.pending_count(), ROWS * 3);
        writer
    };
    let input = rows();
    profile("batch_writer_insert", ROWS, || drop(insert_all(input)));
    c.bench_function("batch_writer_insert", |b| {
        b.iter_batched(rows, insert_all, BatchSize::PerIteration)
    });
}

fn sql_insert(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let app = Router::new().route_service(
        "/log.ingest.v1.Service/Put",
        exoware_server::ingest_service(IngestState::new(Arc::new(Discard::default()))),
    );
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = runtime.spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = StoreClient::builder()
        .url(&url)
        .client_transport(connectrpc::client::HttpClient::plaintext_http2_only())
        .build()
        .unwrap();
    let ctx = SqlContext::new(client.prefixed(StoreKeyPrefix::identity()));
    ctx.register_schema(schema(client)).unwrap();
    let (src_schema, batches) = record_batches();
    ctx.register_table(
        "src",
        Arc::new(MemTable::try_new(src_schema, vec![batches]).unwrap()),
    )
    .unwrap();
    let insert = || {
        runtime.block_on(async {
            let inserted = ctx
                .sql("INSERT INTO events SELECT * FROM src")
                .await
                .unwrap()
                .collect()
                .await
                .unwrap();
            assert_eq!(inserted.len(), 1);
        })
    };
    profile("sql_insert", ROWS, insert);
    c.bench_function("sql_insert", |b| b.iter(insert));
    server.abort();
}

/// Constantinople's SQL namespace.
const SQL_NAMESPACE: u8 = 0x03;
/// Transactions per staged block. Each adds five rows (one `tx_meta`, two `tx_activity`, two
/// `account_meta`), and the block adds one `block_meta` row.
const BLOCK_TXS: usize = 4_000;
const BLOCK_ROWS: usize = 1 + BLOCK_TXS * 5;
/// Rows staged per `stage_events` iteration.
const EVENTS_ROWS: usize = 20_000;

fn constantinople_schema(client: StoreClient) -> KvSchema {
    let col = |name: &str, data_type| TableColumnConfig::new(name, data_type, false);
    let digest = || DataType::FixedSizeBinary(32);
    KvSchema::new(client.prefixed(StoreKeyPrefix::new(vec![SQL_NAMESPACE]).unwrap()))
        .table(
            "block_meta",
            vec![
                col("height", DataType::UInt64),
                col("digest", digest()),
                col("tx_count", DataType::UInt64),
                col("transactions_root", digest()),
                col("transactions_tip", DataType::UInt64),
                col("view", DataType::UInt64),
                col(
                    "finalized_ts",
                    DataType::Timestamp(TimeUnit::Microsecond, None),
                ),
            ],
            vec!["height".into()],
            vec![],
        )
        .unwrap()
        .table(
            "tx_meta",
            vec![
                col("tx_digest", digest()),
                col("qmdb_location", DataType::UInt64),
                col("body_hex", DataType::Utf8),
            ],
            vec!["tx_digest".into()],
            vec![],
        )
        .unwrap()
        .table(
            "tx_activity",
            vec![
                col("account", digest()),
                col("height", DataType::UInt64),
                col("index", DataType::UInt64),
                col("role", DataType::UInt64),
                col("tx_digest", digest()),
                col("counterparty", digest()),
                col("value", DataType::UInt64),
                col("nonce", DataType::UInt64),
            ],
            vec![
                "account".into(),
                "height".into(),
                "index".into(),
                "role".into(),
            ],
            vec![],
        )
        .unwrap()
        .table(
            "account_meta",
            vec![
                col("account", digest()),
                col("balance", DataType::UInt64),
                col("nonce_base", DataType::UInt64),
                col("nonce_bitmap", DataType::UInt64),
                col("qmdb_location", DataType::UInt64),
            ],
            vec!["account".into()],
            vec![],
        )
        .unwrap()
}

/// Deterministic pseudo-random 32-byte values (splitmix64), standing in for digests and
/// account addresses.
fn digest32(seed: u64) -> CellValue {
    let mut state = seed;
    let mut out = Vec::with_capacity(32);
    for _ in 0..4 {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        out.extend_from_slice(&(z ^ (z >> 31)).to_be_bytes());
    }
    CellValue::FixedBinary(out)
}

/// One block's SQL rows in the order Constantinople's indexer inserts them.
fn constantinople_rows() -> Vec<(&'static str, Vec<CellValue>)> {
    let height = 1_000_000u64;
    let mut rows = Vec::with_capacity(BLOCK_ROWS);
    rows.push((
        "block_meta",
        vec![
            CellValue::UInt64(height),
            digest32(1),
            CellValue::UInt64(BLOCK_TXS as u64),
            digest32(2),
            CellValue::UInt64(height * 10),
            CellValue::UInt64(0),
            CellValue::Timestamp(1_700_000_000_000_000),
        ],
    ));
    for tx in 0..BLOCK_TXS as u64 {
        let seed = 16 + tx * 8;
        let (digest, sender, receiver) = (digest32(seed), digest32(seed + 1), digest32(seed + 2));
        // A typical transfer body, hex encoded.
        rows.push((
            "tx_meta",
            vec![
                digest.clone(),
                CellValue::UInt64(height * 10 + tx),
                CellValue::Utf8("ab".repeat(120)),
            ],
        ));
        for (role, account, counterparty) in [(0, &sender, &receiver), (1, &receiver, &sender)] {
            rows.push((
                "tx_activity",
                vec![
                    account.clone(),
                    CellValue::UInt64(height),
                    CellValue::UInt64(tx),
                    CellValue::UInt64(role),
                    digest.clone(),
                    counterparty.clone(),
                    CellValue::UInt64(1_000 + tx),
                    CellValue::UInt64(tx),
                ],
            ));
        }
        for account in [sender, receiver] {
            rows.push((
                "account_meta",
                vec![
                    account,
                    CellValue::UInt64(1_000_000 - tx),
                    CellValue::UInt64(tx),
                    CellValue::UInt64(0),
                    CellValue::UInt64(height * 10 + tx),
                ],
            ));
        }
    }
    rows
}

/// Inserts every row, then prepares and stages the batch, as an indexer does before its Put.
fn stage_rows(schema: &KvSchema, rows: Vec<(&'static str, Vec<CellValue>)>) -> StoreWriteBatch {
    let mut writer = schema.batch_writer();
    for (table, row) in rows {
        writer.insert(table, row).unwrap();
    }
    let prepared = writer.prepare_flush().unwrap().unwrap();
    let mut batch = StoreWriteBatch::new();
    writer.stage_flush(&prepared, &mut batch).unwrap();
    batch
}

fn stage_constantinople(c: &mut Criterion) {
    let schema = constantinople_schema(StoreClient::new("http://127.0.0.1:1"));
    let input = constantinople_rows();
    profile("stage_constantinople", BLOCK_ROWS, || {
        assert_eq!(stage_rows(&schema, input).len(), BLOCK_ROWS)
    });
    c.bench_function("stage_constantinople", |b| {
        b.iter_batched(
            constantinople_rows,
            |rows| stage_rows(&schema, rows),
            BatchSize::PerIteration,
        )
    });
}

fn stage_events(c: &mut Criterion) {
    let schema = events_schema(
        StoreClient::new("http://127.0.0.1:1"),
        StoreKeyPrefix::new(vec![SQL_NAMESPACE]).unwrap(),
    );
    let rows = || {
        (0..EVENTS_ROWS)
            .map(|i| ("events", cells(i)))
            .collect::<Vec<_>>()
    };
    let input = rows();
    profile("stage_events", EVENTS_ROWS, || {
        assert_eq!(stage_rows(&schema, input).len(), EVENTS_ROWS * 3)
    });
    c.bench_function("stage_events", |b| {
        b.iter_batched(
            rows,
            |rows| stage_rows(&schema, rows),
            BatchSize::PerIteration,
        )
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = batch_writer_insert, sql_insert, stage_constantinople, stage_events
}
criterion_main!(benches);
