use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::ops::Bound::{Included, Unbounded};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::Router;
use bytes::Bytes;
use connectrpc::{Chain, ConnectRpcService, Context};
use criterion::{criterion_group, criterion_main, Criterion};
use datafusion::arrow::datatypes::DataType;
use datafusion::prelude::SessionContext;
use exoware_common::keys::Key;
use exoware_sdk_rs as exoware_proto;
use exoware_proto::connect_compression_registry;
use exoware_proto::store::ingest::v1::{
    PutResponse as ProtoPutResponse, Service as IngestService, ServiceServer as IngestServiceServer,
};
use exoware_proto::store::query::v1::RangeEntry as ProtoRangeEntry;
use exoware_proto::store::query::v1::{
    GetResponse as ProtoGetResponse, RangeFrame as ProtoRangeFrame,
    ReduceResponse as ProtoReduceResponse, Service as QueryService,
    ServiceServer as QueryServiceServer,
};
use exoware_sdk_rs::StoreClient;
use futures::stream;
use std::pin::Pin;
use exoware_sql::{CellValue, IndexSpec, KvSchema, TableColumnConfig};
use tokio::runtime::Runtime;
use tokio::sync::oneshot;

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

#[derive(Debug, Clone, Copy)]
struct AllocStats {
    calls: u64,
    bytes: u64,
}

fn allocation_profile<T>(f: impl FnOnce() -> T) -> (T, AllocStats) {
    ALLOC_CALLS.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);
    let out = f();
    let stats = AllocStats {
        calls: ALLOC_CALLS.load(Ordering::Relaxed),
        bytes: ALLOC_BYTES.load(Ordering::Relaxed),
    };
    (out, stats)
}

#[derive(Clone)]
struct MockState {
    kv: Arc<Mutex<BTreeMap<Key, Bytes>>>,
    sequence_number: Arc<AtomicU64>,
}

#[derive(Clone)]
struct BenchIngest {
    state: MockState,
}

impl IngestService for BenchIngest {
    async fn put(
        &self,
        ctx: Context,
        request: buffa::view::OwnedView<exoware_proto::store::ingest::v1::PutRequestView<'static>>,
    ) -> Result<(ProtoPutResponse, Context), connectrpc::ConnectError> {
        let mut parsed = Vec::<(Key, Bytes)>::new();
        for kv in request.kvs.iter() {
            parsed.push((kv.key.to_vec().into(), Bytes::copy_from_slice(kv.value)));
        }
        let mut guard = self.state.kv.lock().expect("kv mutex poisoned");
        for (key, value) in parsed.iter() {
            guard.insert(key.clone(), value.clone());
        }
        let seq = self
            .state
            .sequence_number
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        Ok((
            ProtoPutResponse {
                sequence_number: seq,
                ..Default::default()
            },
            ctx,
        ))
    }
}

#[derive(Clone)]
struct BenchQuery {
    state: MockState,
}

impl QueryService for BenchQuery {
    async fn get(
        &self,
        _ctx: Context,
        _request: buffa::view::OwnedView<exoware_proto::store::query::v1::GetRequestView<'static>>,
    ) -> Result<(ProtoGetResponse, Context), connectrpc::ConnectError> {
        Err(connectrpc::ConnectError::unimplemented("bench"))
    }

    async fn range(
        &self,
        _ctx: Context,
        request: buffa::view::OwnedView<exoware_proto::store::query::v1::RangeRequestView<'static>>,
    ) -> Result<
        (
            Pin<
                Box<
                    dyn futures::Stream<Item = Result<ProtoRangeFrame, connectrpc::ConnectError>>
                        + Send,
                >,
            >,
            Context,
        ),
        connectrpc::ConnectError,
    > {
        let start_key = Key::from(request.start.to_vec());
        let end_key = Key::from(request.end.to_vec());
        let limit = request.limit.map(|v| v as usize).unwrap_or(usize::MAX);
        let batch_size = usize::try_from(request.batch_size).unwrap_or(usize::MAX);
        let batch = batch_size.max(1);

        let guard = self.state.kv.lock().expect("kv mutex poisoned");
        let mut results: Vec<ProtoRangeEntry> = Vec::new();
        let range: (std::ops::Bound<&Key>, std::ops::Bound<&Key>) = (
            Included(&start_key),
            if end_key.is_empty() {
                Unbounded
            } else {
                Included(&end_key)
            },
        );
        for (key, value) in guard.range::<Key, _>(range).take(limit) {
            results.push(ProtoRangeEntry {
                key: key.to_vec(),
                value: value.to_vec(),
                ..Default::default()
            });
        }
        drop(guard);
        let token = self
            .state
            .sequence_number
            .load(std::sync::atomic::Ordering::Relaxed);
        let mut frames: Vec<Result<ProtoRangeFrame, connectrpc::ConnectError>> = Vec::new();
        for chunk in results.chunks(batch) {
            frames.push(Ok(ProtoRangeFrame {
                results: chunk.to_vec(),
                ..Default::default()
            }));
        }
        let detail = exoware_proto::store::query::v1::Detail {
            sequence_number: token,
            read_stats: Default::default(),
            ..Default::default()
        };
        Ok((
            Box::pin(stream::iter(frames)),
            exoware_proto::with_query_detail_trailer(Context::default(), &detail),
        ))
    }

    async fn reduce(
        &self,
        _ctx: Context,
        _request: buffa::view::OwnedView<
            exoware_proto::store::query::v1::ReduceRequestView<'static>,
        >,
    ) -> Result<(ProtoReduceResponse, Context), connectrpc::ConnectError> {
        Err(connectrpc::ConnectError::unimplemented("bench"))
    }
}

async fn run_query_once(ctx: Arc<SessionContext>) -> usize {
    let frame = ctx
        .sql(
            "SELECT id, amount_cents \
             FROM orders \
             WHERE status = 'open' AND amount_cents >= 0 \
             LIMIT 1000",
        )
        .await
        .expect("query should compile");
    let batches = frame.collect().await.expect("query should execute");
    batches.iter().map(|b| b.num_rows()).sum()
}

fn build_dataset(schema: &KvSchema, runtime: &Runtime) {
    runtime.block_on(async {
        let mut writer = schema.batch_writer();
        for i in 0..6_000i64 {
            let status = if i % 2 == 0 { "open" } else { "closed" };
            writer
                .insert(
                    "orders",
                    vec![
                        CellValue::Int64(i),
                        CellValue::Utf8(status.to_string()),
                        CellValue::Int64(i * 10),
                    ],
                )
                .expect("row encode should succeed");
        }
        writer.flush().await.expect("seed ingest should succeed");
    });
}

fn bench_exoware_sql_end_to_end_index_scan(c: &mut Criterion) {
    let runtime = Runtime::new().expect("runtime");
    let state = MockState {
        kv: Arc::new(Mutex::new(BTreeMap::new())),
        sequence_number: Arc::new(AtomicU64::new(0)),
    };
    let connect = ConnectRpcService::new(Chain(
        IngestServiceServer::new(BenchIngest {
            state: state.clone(),
        }),
        QueryServiceServer::new(BenchQuery { state }),
    ))
    .with_compression(connect_compression_registry());
    let app = Router::new().fallback_service(connect);

    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .expect("bind mock server");
    let addr = listener.local_addr().expect("local addr");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    runtime.spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("mock server should run");
    });

    let base_url = format!("http://{addr}");
    let client = StoreClient::new(&base_url);
    let schema = KvSchema::new(client.clone())
        .table(
            "orders",
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("status", DataType::Utf8, false),
                TableColumnConfig::new("amount_cents", DataType::Int64, false),
            ],
            vec!["id".to_string()],
            vec![
                IndexSpec::lexicographic("status_idx", vec!["status".to_string()])
                    .expect("valid index")
                    .with_cover_columns(vec!["amount_cents".to_string()]),
            ],
        )
        .expect("valid schema");

    build_dataset(&schema, &runtime);

    let ctx = SessionContext::new();
    schema.register_all(&ctx).expect("register table");
    let ctx = Arc::new(ctx);

    let warmup_rows = runtime.block_on(run_query_once(ctx.clone()));
    assert_eq!(warmup_rows, 1_000);

    let query_start = Instant::now();
    let (_rows, allocs) = allocation_profile(|| runtime.block_on(run_query_once(ctx.clone())));
    let query_elapsed = query_start.elapsed();
    println!(
        "exoware-sql end-to-end allocs: calls={} bytes={}",
        allocs.calls, allocs.bytes
    );
    println!(
        "exoware-sql query elapsed={:.3}ms",
        query_elapsed.as_secs_f64() * 1000.0,
    );

    c.bench_function("exoware_sql_end_to_end_index_scan", |b| {
        b.iter(|| {
            let rows = runtime.block_on(run_query_once(ctx.clone()));
            assert_eq!(rows, 1_000);
        });
    });

    let _ = shutdown_tx.send(());
}

fn read_path_perf(c: &mut Criterion) {
    bench_exoware_sql_end_to_end_index_scan(c);
}

criterion_group!(benches, read_path_perf);
criterion_main!(benches);
