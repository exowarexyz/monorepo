//! Cost of encoding inserted rows into store entries, for a 12-column table with a composite
//! primary key and two covered secondary indexes (3 entries per row).
//!
//! `batch_writer_insert` passes rows as cell values to `BatchWriter::insert` and never touches
//! the network. `sql_insert` runs `INSERT INTO events SELECT * FROM src` from an in-memory table,
//! so it also reads the cells out of arrow batches, and then sends the entries over loopback to an
//! in-process store that decodes and discards them. Before measuring, each case prints one
//! `INGEST_PROFILE` line with the allocation calls and bytes of a single run.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::Router;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use datafusion::arrow::array::{
    ArrayRef, BinaryArray, BooleanArray, Date32Array, Decimal128Array, Float64Array, Int64Array,
    RecordBatch, StringArray, TimestampMicrosecondArray, UInt64Array,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use datafusion::datasource::MemTable;
use exoware_sdk::{StoreClient, StoreKeyPrefix};
use exoware_server::{Ingest, IngestState, PutError, PutInput};
use exoware_sql::{CellValue, IndexSpec, KvSchema, SqlContext, TableColumnConfig};

const ROWS: usize = 100_000;
const BATCH_ROWS: usize = 8192;

static ALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

struct CountingAllocator;

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

fn profile(case: &str, run: impl FnOnce()) {
    ALLOC_CALLS.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);
    run();
    println!(
        "INGEST_PROFILE {}",
        serde_json::json!({
            "case": case,
            "rows": ROWS,
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
    KvSchema::new(client.prefixed(StoreKeyPrefix::identity()))
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
    profile("batch_writer_insert", || drop(insert_all(input)));
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
    profile("sql_insert", insert);
    c.bench_function("sql_insert", |b| b.iter(insert));
    server.abort();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = batch_writer_insert, sql_insert
}
criterion_main!(benches);
