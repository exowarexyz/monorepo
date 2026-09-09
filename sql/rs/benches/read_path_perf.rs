//! Run serially with the same fixture on each revision. Planning includes SQL parsing and
//! optimization. Execution resets native operator state, reuses the physical plan, and includes
//! loopback HTTP/2 Store RPCs on a persistent connection. Allocation
//! profiles include both client and in-process server work. Backend counters measure fetched key
//! and value bytes, while body counters measure encoded Connect traffic without HTTP headers.
//! SQL RPC cases include protobuf response decoding, but not client-side result materialization.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Included, Unbounded};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use axum::body::Body;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
    Router,
};
use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use datafusion::arrow::datatypes::DataType;
use datafusion::physical_plan::execution_plan::reset_plan_states;
use datafusion::physical_plan::{collect, ExecutionPlan};
use datafusion::prelude::SessionContext;
use exoware_sdk::{StoreClient, StoreKeyPrefix};
use exoware_server::{
    Ingest, IngestError, IngestState, Query, QueryExtra, QueryState, RangeScan, RangeScanBatch,
    Sequence,
};
use exoware_sql::proto::sql::v1::{QueryRequest, ServiceClient};
use exoware_sql::{CellValue, IndexSpec, KvSchema, TableColumnConfig};
use http_body::{Body as HttpBody, Frame, SizeHint};
use tokio::runtime::Runtime;

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

#[derive(Default)]
struct Traffic {
    get: AtomicU64,
    get_many: AtomicU64,
    range: AtomicU64,
    reduce: AtomicU64,
    lookup_keys: AtomicU64,
    backend_rows: AtomicU64,
    backend_bytes: AtomicU64,
    request_body_bytes: Arc<AtomicU64>,
    response_body_bytes: Arc<AtomicU64>,
    sql_request_body_bytes: Arc<AtomicU64>,
    sql_response_body_bytes: Arc<AtomicU64>,
}

impl Traffic {
    fn reset(&self) {
        for counter in [
            &self.get,
            &self.get_many,
            &self.range,
            &self.reduce,
            &self.lookup_keys,
            &self.backend_rows,
            &self.backend_bytes,
            &self.request_body_bytes,
            &self.response_body_bytes,
            &self.sql_request_body_bytes,
            &self.sql_response_body_bytes,
        ] {
            counter.store(0, Ordering::Relaxed);
        }
        ALLOC_CALLS.store(0, Ordering::Relaxed);
        ALLOC_BYTES.store(0, Ordering::Relaxed);
    }
    fn profile(&self, name: &str, phase: &str) {
        println!(
            "READ_PATH_PROFILE {}",
            serde_json::json!({
                "case": name, "phase": phase,
                "allocation_calls": ALLOC_CALLS.load(Ordering::Relaxed),
                "allocation_bytes": ALLOC_BYTES.load(Ordering::Relaxed),
                "get": self.get.load(Ordering::Relaxed),
                "get_many": self.get_many.load(Ordering::Relaxed),
                "range": self.range.load(Ordering::Relaxed),
                "reduce": self.reduce.load(Ordering::Relaxed),
                "lookup_keys": self.lookup_keys.load(Ordering::Relaxed),
                "backend_rows": self.backend_rows.load(Ordering::Relaxed),
                "backend_bytes": self.backend_bytes.load(Ordering::Relaxed),
                "request_body_bytes": self.request_body_bytes.load(Ordering::Relaxed),
                "response_body_bytes": self.response_body_bytes.load(Ordering::Relaxed),
                "sql_request_body_bytes": self.sql_request_body_bytes.load(Ordering::Relaxed),
                "sql_response_body_bytes": self.sql_response_body_bytes.load(Ordering::Relaxed),
            })
        );
    }
    fn returned(&self, key: &Bytes, value: &Bytes) {
        self.backend_rows.fetch_add(1, Ordering::Relaxed);
        self.backend_bytes
            .fetch_add((key.len() + value.len()) as u64, Ordering::Relaxed);
    }
}

// Encoded Connect bodies after compression, excluding HTTP headers and transport overhead
struct MeasuredBody {
    inner: Body,
    bytes: Arc<AtomicU64>,
}

impl HttpBody for MeasuredBody {
    type Data = Bytes;
    type Error = axum::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let frame = Pin::new(&mut self.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &frame {
            if let Some(data) = frame.data_ref() {
                self.bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
            }
        }
        frame
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

async fn measure_traffic(
    State((traffic, sql)): State<(Arc<Traffic>, bool)>,
    request: Request,
    next: Next,
) -> Response {
    match request.uri().path().rsplit('/').next() {
        Some("Get") => {
            traffic.get.fetch_add(1, Ordering::Relaxed);
        }
        Some("GetMany") => {
            traffic.get_many.fetch_add(1, Ordering::Relaxed);
        }
        Some("Range") => {
            traffic.range.fetch_add(1, Ordering::Relaxed);
        }
        Some("Reduce") => {
            traffic.reduce.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
    let (request_bytes, response_bytes) = if sql {
        (
            &traffic.sql_request_body_bytes,
            &traffic.sql_response_body_bytes,
        )
    } else {
        (&traffic.request_body_bytes, &traffic.response_body_bytes)
    };
    let (parts, body) = request.into_parts();
    let request = Request::from_parts(
        parts,
        Body::new(MeasuredBody {
            inner: body,
            bytes: request_bytes.clone(),
        }),
    );
    let response = next.run(request).await;
    let (parts, body) = response.into_parts();
    Response::from_parts(
        parts,
        Body::new(MeasuredBody {
            inner: body,
            bytes: response_bytes.clone(),
        }),
    )
}

#[derive(Default)]
struct Backend {
    kv: Arc<Mutex<BTreeMap<Bytes, Bytes>>>,
    sequence: AtomicU64,
    traffic: Arc<Traffic>,
}

impl Sequence for Backend {
    fn current_sequence(&self) -> u64 {
        self.sequence.load(Ordering::Relaxed)
    }
}

impl Ingest for Backend {
    async fn put_batch(&self, kvs: Vec<(Bytes, Bytes)>) -> Result<u64, IngestError> {
        self.kv.lock().unwrap().extend(kvs);
        Ok(self.sequence.fetch_add(1, Ordering::Relaxed) + 1)
    }
}

struct Cursor {
    kv: Arc<Mutex<BTreeMap<Bytes, Bytes>>>,
    traffic: Arc<Traffic>,
    start: Bytes,
    end: Bytes,
    after: Option<Bytes>,
    remaining: usize,
    forward: bool,
}

impl RangeScan for Cursor {
    async fn next_batch(&mut self, max_items: usize) -> Result<RangeScanBatch, String> {
        let low = if self.forward {
            self.after
                .as_ref()
                .map(Excluded)
                .unwrap_or(Included(&self.start))
        } else {
            Included(&self.start)
        };
        let high = match (self.forward, self.after.as_ref()) {
            (false, Some(after)) => Excluded(after),
            _ if self.end.is_empty() => Unbounded,
            _ => Included(&self.end),
        };
        let kv = self.kv.lock().unwrap();
        let range = kv.range::<Bytes, _>((low, high));
        let iter: Box<dyn Iterator<Item = (&Bytes, &Bytes)> + Send> = if self.forward {
            Box::new(range)
        } else {
            Box::new(range.rev())
        };
        let rows = iter
            .take(max_items.min(self.remaining))
            .map(|(key, value)| {
                self.traffic.returned(key, value);
                (key.clone(), value.clone())
            })
            .collect::<Vec<_>>();
        self.remaining -= rows.len();
        if let Some((key, _)) = rows.last() {
            self.after = Some(key.clone());
        }
        Ok(RangeScanBatch {
            rows,
            extra: QueryExtra::new(),
        })
    }
}

impl Query for Backend {
    type RangeScan = Cursor;
    async fn get(&self, key: Bytes) -> Result<(Option<Bytes>, QueryExtra), String> {
        self.traffic.lookup_keys.fetch_add(1, Ordering::Relaxed);
        let value = self.kv.lock().unwrap().get(&key).cloned();
        if let Some(value) = &value {
            self.traffic.returned(&key, value);
        }
        Ok((value, QueryExtra::new()))
    }
    async fn get_many(
        &self,
        keys: Vec<Bytes>,
    ) -> Result<(Vec<(Bytes, Option<Bytes>)>, QueryExtra), String> {
        self.traffic
            .lookup_keys
            .fetch_add(keys.len() as u64, Ordering::Relaxed);
        let kv = self.kv.lock().unwrap();
        let rows = keys
            .into_iter()
            .map(|key| {
                let value = kv.get(&key).cloned();
                if let Some(value) = &value {
                    self.traffic.returned(&key, value);
                }
                (key, value)
            })
            .collect();
        Ok((rows, QueryExtra::new()))
    }
    async fn range_scan(
        &self,
        start: Bytes,
        end: Bytes,
        limit: usize,
        forward: bool,
    ) -> Result<Cursor, String> {
        Ok(Cursor {
            kv: self.kv.clone(),
            traffic: self.traffic.clone(),
            start,
            end,
            after: None,
            remaining: limit,
            forward,
        })
    }
}

struct Fixture {
    runtime: Runtime,
    ctx: SessionContext,
    sql_client: ServiceClient<connectrpc::client::HttpClient>,
    traffic: Arc<Traffic>,
    servers: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for server in &self.servers {
            server.abort();
        }
    }
}

impl Fixture {
    fn new() -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let backend = Arc::new(Backend::default());
        let traffic = backend.traffic.clone();
        let app = Router::new()
            .route_service(
                "/log.ingest.v1.Service/Put",
                exoware_server::ingest_service(IngestState::new(backend.clone())),
            )
            .fallback_service(exoware_server::query_service(QueryState::new(backend)))
            .layer(axum::middleware::from_fn_with_state(
                (traffic.clone(), false),
                measure_traffic,
            ));
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
        let mut schema = KvSchema::new(client.prefixed(StoreKeyPrefix::identity()));
        for name in ["orders", "covered_orders", "text_orders"] {
            let mut indexes = vec![
                IndexSpec::lexicographic("status_idx", vec!["status".into()])
                    .unwrap()
                    .with_cover_columns(vec!["amount_cents".into()]),
            ];
            if name == "covered_orders" {
                indexes.push(
                    IndexSpec::lexicographic(
                        "status_amount_idx",
                        vec!["status".into(), "amount_cents".into()],
                    )
                    .unwrap()
                    .with_cover_columns(vec!["payload".into()]),
                );
            }
            schema = schema
                .table(
                    name,
                    vec![
                        TableColumnConfig::new(
                            "id",
                            if name == "text_orders" {
                                DataType::Utf8
                            } else {
                                DataType::Int64
                            },
                            false,
                        ),
                        TableColumnConfig::new("status", DataType::Utf8, false),
                        TableColumnConfig::new("amount_cents", DataType::Int64, false),
                        TableColumnConfig::new("payload", DataType::Utf8, false),
                    ],
                    vec!["id".into()],
                    indexes,
                )
                .unwrap();
        }
        runtime.block_on(async {
            let mut writer = schema.batch_writer();
            for name in ["orders", "covered_orders", "text_orders"] {
                for i in 0..6000i64 {
                    writer
                        .insert(
                            name,
                            vec![
                                if name == "text_orders" {
                                    CellValue::Utf8(format!("order{i:05}"))
                                } else {
                                    CellValue::Int64(i)
                                },
                                CellValue::Utf8(if i % 2 == 0 { "open" } else { "closed" }.into()),
                                CellValue::Int64(i * 10),
                                CellValue::Utf8(format!("row{i:05}-{}", "x".repeat(256))),
                            ],
                        )
                        .unwrap();
                }
            }
            writer.flush().await.unwrap();
        });
        let sql_server = Arc::new(exoware_sql::SqlServer::new(schema).unwrap());
        let ctx = sql_server.session().clone();
        let app = Router::new()
            .fallback_service(exoware_sql::sql_connect_stack(sql_server))
            .layer(axum::middleware::from_fn_with_state(
                (traffic.clone(), true),
                measure_traffic,
            ));
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let sql_uri = format!("http://{}", listener.local_addr().unwrap());
        let sql_server = runtime.spawn(async move { axum::serve(listener, app).await.unwrap() });
        let sql_client = ServiceClient::new(
            connectrpc::client::HttpClient::plaintext_http2_only(),
            connectrpc::client::ClientConfig::new(sql_uri.parse().unwrap())
                .with_compression(exoware_sdk::connect_compression_registry())
                .with_default_header("accept-encoding", "zstd, gzip")
                .with_default_max_message_size(256 * 1024 * 1024),
        );
        Self {
            runtime,
            ctx,
            sql_client,
            traffic,
            servers: vec![server, sql_server],
        }
    }
    fn plan(&self, sql: &str) -> Arc<dyn ExecutionPlan> {
        self.runtime.block_on(async {
            self.ctx
                .sql(sql)
                .await
                .unwrap()
                .create_physical_plan()
                .await
                .unwrap()
        })
    }
    fn execute(&self, plan: Arc<dyn ExecutionPlan>) -> usize {
        let plan = reset_plan_states(plan).unwrap();
        self.runtime.block_on(async {
            collect(plan, self.ctx.task_ctx())
                .await
                .unwrap()
                .iter()
                .map(|batch| batch.num_rows())
                .sum()
        })
    }

    fn query_rpc(&self, sql: &str) {
        self.runtime.block_on(async {
            std::hint::black_box(
                self.sql_client
                    .query(QueryRequest {
                        sql: sql.into(),
                        ..Default::default()
                    })
                    .await
                    .unwrap(),
            );
        });
    }
}

fn read_path_perf(c: &mut Criterion) {
    let fixture = Fixture::new();
    let points = (0..257)
        .map(|i| (i * 20).to_string())
        .collect::<Vec<_>>()
        .join(",");
    let cases = [
        ("exact_cover", "SELECT id, amount_cents FROM orders WHERE status = 'open' AND amount_cents >= 0 LIMIT 1000".to_string(), 1000),
        ("residual_cover", "SELECT id, amount_cents FROM orders WHERE status = 'open' AND amount_cents % 100 = 0 LIMIT 25".to_string(), 25),
        ("residual_base_lookup", "SELECT payload FROM orders WHERE status = 'open' AND amount_cents % 100 = 0 LIMIT 25".to_string(), 25),
        ("numeric_points_257", format!("SELECT id, amount_cents FROM orders WHERE id IN ({points}) ORDER BY id DESC"), 257),
        ("string_points", "SELECT id FROM text_orders WHERE id IN ('order00000', 'order00100', 'order00500', 'missing') ORDER BY id DESC".to_string(), 3),
        ("covering_selection", "SELECT payload FROM covered_orders WHERE status = 'open' LIMIT 1000".to_string(), 1000),
        ("covering_suffix_topk", "SELECT amount_cents, payload FROM covered_orders WHERE status = 'open' ORDER BY amount_cents DESC LIMIT 10".to_string(), 10),
        ("primary_topk", "SELECT id FROM orders ORDER BY id DESC LIMIT 10".to_string(), 10),
        ("primary_point_limit1", "SELECT payload FROM orders WHERE id = 42 LIMIT 1".to_string(), 1),
        ("residual_lookup_limit1", "SELECT payload FROM orders WHERE status = 'open' AND amount_cents % 100 = 0 LIMIT 1".to_string(), 1),
        ("distinct_limit1", "SELECT DISTINCT id FROM orders LIMIT 1".to_string(), 1),
        ("aggregate_fused", "SELECT COUNT(*), SUM(amount_cents), AVG(amount_cents), MIN(amount_cents), MAX(amount_cents) FROM orders WHERE status = 'open'".to_string(), 1),
        ("aggregate_scalar", "SELECT SUM(amount_cents) FROM orders WHERE id = 42".to_string(), 1),
        ("aggregate_grouped", "SELECT id, COUNT(*), SUM(amount_cents), AVG(amount_cents), MIN(amount_cents), MAX(amount_cents) FROM orders GROUP BY id".to_string(), 6000),
        ("aggregate_float_grouped", "SELECT status, COUNT(*), SUM(amount_cents::DOUBLE), AVG(amount_cents::DOUBLE), MIN(amount_cents::DOUBLE), MAX(amount_cents::DOUBLE) FROM orders GROUP BY status".to_string(), 2),
        ("aggregate_float_ranges", "SELECT status, COUNT(*), SUM(amount_cents::DOUBLE), AVG(amount_cents::DOUBLE), MIN(amount_cents::DOUBLE), MAX(amount_cents::DOUBLE) FROM orders WHERE id IN (0, 100, 200, 300, 400, 500, 600, 700) GROUP BY status".to_string(), 1),
        ("aggregate_expression", "SELECT LOWER(status), SUM((amount_cents + 10) * 2 - 5), AVG(amount_cents::DOUBLE / 1000) FROM orders GROUP BY LOWER(status)".to_string(), 2),
        ("aggregate_expression_point", "SELECT SUM((amount_cents + 10) * 2 - 5) FROM orders WHERE id = 42".to_string(), 1),
        ("aggregate_cast_point", "SELECT SUM(amount_cents::DOUBLE) FROM orders WHERE id = 42".to_string(), 1),
        ("aggregate_expression_filtered", "SELECT SUM((amount_cents + 10) * 2 - 5) FROM orders WHERE status = 'open' AND amount_cents >= 59960".to_string(), 1),
        ("aggregate_variable_division", "SELECT status, SUM(amount_cents / (id + 1)) FROM orders GROUP BY status".to_string(), 2),
        ("aggregate_filtered_index", "SELECT SUM(amount_cents) FILTER (WHERE status = 'open' AND amount_cents >= 59960) FROM covered_orders".to_string(), 1),
        ("aggregate_filtered_index_grouped", "SELECT id, SUM(amount_cents) FILTER (WHERE status = 'open' AND amount_cents >= 59960) FROM covered_orders GROUP BY id".to_string(), 6000),
        ("aggregate_grouped_ranges", "SELECT status, SUM(amount_cents), AVG(amount_cents) FROM orders WHERE id IN (0, 100, 200, 300, 400, 500, 600, 700) GROUP BY status".to_string(), 1),
        ("aggregate_sparse", format!("SELECT id, {} FROM orders GROUP BY id", (0..8).map(|i| format!("SUM(amount_cents) FILTER (WHERE amount_cents >= {})", i * 1000)).collect::<Vec<_>>().join(", ")), 6000),
    ];
    // Profiles include client and in-process server allocations on one runtime thread
    for (name, sql, expected_rows) in &cases {
        let plan = fixture.plan(sql);
        assert_eq!(fixture.execute(plan), *expected_rows, "{name}");
        fixture.traffic.reset();
        let plan = fixture.plan(sql);
        fixture.traffic.profile(name, "planning");
        fixture.traffic.reset();
        assert_eq!(fixture.execute(plan.clone()), *expected_rows, "{name}");
        fixture.traffic.profile(name, "execution");
        c.bench_with_input(
            BenchmarkId::new("exoware_sql_planning", name),
            sql,
            |b, sql| {
                b.iter(|| std::hint::black_box(fixture.plan(sql)));
            },
        );
        c.bench_with_input(
            BenchmarkId::new("exoware_sql_execution", name),
            &plan,
            |b, plan| {
                b.iter(|| assert_eq!(fixture.execute(plan.clone()), *expected_rows));
            },
        );
    }
    c.bench_function("exoware_sql_end_to_end_index_scan", |b| {
        b.iter(|| assert_eq!(fixture.execute(fixture.plan(&cases[0].1)), 1000));
    });
    for (name, sql, expected_rows) in [
        ("scalar", "SELECT 1", 1),
        (
            "single_row",
            "SELECT id, amount_cents, payload FROM orders WHERE id = 42",
            1,
        ),
        (
            "large_result",
            "SELECT id, amount_cents, payload FROM orders",
            6000,
        ),
    ] {
        assert_eq!(fixture.execute(fixture.plan(sql)), expected_rows, "{name}");
        fixture.query_rpc(sql);
        fixture.traffic.reset();
        fixture.query_rpc(sql);
        fixture.traffic.profile(name, "sql_rpc");
        c.bench_with_input(BenchmarkId::new("exoware_sql_rpc", name), &sql, |b, sql| {
            b.iter(|| fixture.query_rpc(sql));
        });
    }
}

criterion_group!(benches, read_path_perf);
criterion_main!(benches);
