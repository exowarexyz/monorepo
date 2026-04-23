use std::sync::Arc;
use std::time::Duration;

use axum::{routing::get, Router};
use bytes::Bytes;
use commonware_cryptography::Sha256;
use commonware_storage::mmr::Location;
use commonware_storage::qmdb::keyless::Operation as KeylessOperation;
use connectrpc::client::ClientConfig;
use datafusion::arrow::array::Int64Array;
use datafusion::arrow::datatypes::DataType;
use datafusion::prelude::SessionContext;
use exoware_sdk_rs::keys::Key;
use exoware_sdk_rs::kv_codec::Utf8;
use exoware_sdk_rs::match_key::MatchKey;
use exoware_sdk_rs::proto::PreferZstdHttpClient;
use exoware_sdk_rs::store::qmdb::v1::SubscribeRequest as QmdbSubscribeRequest;
use exoware_sdk_rs::store::sql::v1::{
    cell, ServiceClient as SqlServiceClient, SubscribeRequest as SqlSubscribeRequest,
};
use exoware_sdk_rs::stream_filter::StreamFilter;
use exoware_sdk_rs::{
    RetryConfig, StoreClient, StoreKeyPrefix, StoreWriteBatch, StreamSubscription,
    StreamSubscriptionFrame,
};
use exoware_sql::{sql_connect_stack, CellValue, KvSchema, SqlServer, TableColumnConfig};
use futures::stream::{FuturesUnordered, StreamExt};
use store_qmdb::{
    keyless_range_connect_stack, KeylessClient, KeylessRangeConnectClient, KeylessWriter,
    QmdbError, RangeSubscribeProof,
};

type Digest = commonware_cryptography::sha256::Digest;
type QmdbOp = KeylessOperation<Vec<u8>>;
type QmdbReader = KeylessClient<Sha256, Vec<u8>>;
type QmdbWriter = KeylessWriter<Sha256, Vec<u8>>;
type QmdbConnectClient = KeylessRangeConnectClient<PreferZstdHttpClient, Sha256, Vec<u8>>;

async fn local_store_client() -> (tempfile::TempDir, tokio::task::JoinHandle<()>, StoreClient) {
    let dir = tempfile::tempdir().expect("tempdir");
    let (handle, url) = exoware_simulator::spawn_for_test(dir.path())
        .await
        .expect("spawn simulator");
    let client = StoreClient::builder()
        .url(&url)
        .retry_config(RetryConfig::disabled())
        .build()
        .expect("build store client");
    (dir, handle, client)
}

async fn health() -> &'static str {
    "ok"
}

async fn wait_for_health(base: &str) {
    let url = format!("{base}/health");
    let client = reqwest::Client::new();
    for _ in 0..200 {
        if client
            .get(&url)
            .send()
            .await
            .ok()
            .is_some_and(|response| response.status().is_success())
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("server did not become ready at {url}");
}

async fn spawn_sql_service(schema: KvSchema) -> (tokio::task::JoinHandle<()>, String) {
    let server = Arc::new(SqlServer::new(schema).expect("sql server"));
    let app = Router::new()
        .route("/health", get(health))
        .fallback_service(sql_connect_stack(server));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind sql service");
    let port = listener.local_addr().expect("sql addr").port();
    let url = format!("http://127.0.0.1:{port}");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    wait_for_health(&url).await;
    (handle, url)
}

async fn spawn_qmdb_service(client: StoreClient) -> (tokio::task::JoinHandle<()>, String) {
    let reader = Arc::new(keyless_reader(client));
    let app = Router::new()
        .route("/health", get(health))
        .fallback_service(keyless_range_connect_stack(reader));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind qmdb service");
    let port = listener.local_addr().expect("qmdb addr").port();
    let url = format!("http://127.0.0.1:{port}");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    wait_for_health(&url).await;
    (handle, url)
}

fn sql_rpc_client(base: &str) -> SqlServiceClient<PreferZstdHttpClient> {
    SqlServiceClient::new(
        PreferZstdHttpClient::plaintext(),
        ClientConfig::new(base.parse().expect("sql uri")),
    )
}

fn qmdb_rpc_client(base: &str) -> QmdbConnectClient {
    QmdbConnectClient::plaintext(base, ((0..=10000).into(), ()))
}

fn store_prefix(prefix: u16) -> StoreKeyPrefix {
    StoreKeyPrefix::new(4, prefix).expect("valid integration prefix")
}

fn all_logical_keys_filter() -> StreamFilter {
    StreamFilter {
        match_keys: vec![MatchKey {
            reserved_bits: 0,
            prefix: 0,
            payload_regex: Utf8::from("(?s-u).*"),
        }],
        value_filters: vec![],
    }
}

async fn next_frame(
    sub: &mut StreamSubscription,
    timeout_ms: u64,
) -> Option<StreamSubscriptionFrame> {
    tokio::time::timeout(Duration::from_millis(timeout_ms), sub.next())
        .await
        .ok()
        .and_then(|result| result.expect("stream frame"))
}

fn keyless_reader(client: StoreClient) -> QmdbReader {
    QmdbReader::from_client(client, ((0..=10000).into(), ()))
}

fn keyless_writer(client: StoreClient) -> QmdbWriter {
    QmdbWriter::empty(client)
}

fn qops(label: &str, batch: usize) -> Vec<QmdbOp> {
    vec![
        QmdbOp::Append(format!("{label}-append-{batch}-0").into_bytes()),
        QmdbOp::Append(format!("{label}-append-{batch}-1").into_bytes()),
        QmdbOp::Commit(Some(format!("{label}-commit-{batch}").into_bytes())),
    ]
}

async fn retry_qmdb<F, Fut, T>(f: F, label: &str) -> T
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, QmdbError>>,
{
    for attempt in 1..=20 {
        match f().await {
            Ok(value) => return value,
            Err(err) if attempt < 20 => {
                eprintln!("{label}: attempt {attempt} failed: {err}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(err) => panic!("{label}: failed after {attempt} attempts: {err}"),
        }
    }
    unreachable!("retry loop always returns or panics")
}

async fn drive_qmdb_writer(
    writer: Arc<QmdbWriter>,
    batches: Vec<Vec<QmdbOp>>,
) -> (Vec<QmdbOp>, Vec<store_qmdb::UploadReceipt>) {
    let expected: Vec<QmdbOp> = batches.iter().flatten().cloned().collect();
    let mut in_flight = FuturesUnordered::new();
    for batch in batches {
        let writer = writer.clone();
        in_flight.push(async move { writer.upload_and_publish(&batch).await });
    }
    let mut receipts = Vec::new();
    while let Some(result) = in_flight.next().await {
        receipts.push(result.expect("qmdb upload"));
    }
    writer.flush().await.expect("qmdb flush");
    (expected, receipts)
}

fn sorted_ops(mut ops: Vec<QmdbOp>) -> Vec<QmdbOp> {
    ops.sort();
    ops
}

fn row_int64(row: &exoware_sdk_rs::store::sql::v1::Row, index: usize) -> i64 {
    match row.cells.get(index).and_then(|cell| cell.kind.as_ref()) {
        Some(cell::Kind::Int64Value(value)) => *value,
        other => panic!("expected int64 cell at {index}, got {other:?}"),
    }
}

fn expected_qmdb_frame(ops: &[QmdbOp]) -> Vec<(Location, QmdbOp)> {
    ops.iter()
        .enumerate()
        .map(|(idx, op)| (Location::new(idx as u64), op.clone()))
        .collect()
}

fn collect_int64_column(
    batches: &[datafusion::arrow::record_batch::RecordBatch],
    index: usize,
) -> Vec<i64> {
    let mut out = Vec::new();
    for batch in batches {
        let col = batch
            .column(index)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("int64 column");
        for row in 0..batch.num_rows() {
            out.push(col.value(row));
        }
    }
    out
}

#[tokio::test]
async fn raw_prefixes_support_atomic_batch_fetch_range_and_stream() {
    let (_dir, _server, base) = local_store_client().await;
    let a = base.with_key_prefix(store_prefix(1));
    let b = base.with_key_prefix(store_prefix(2));

    let mut sub_a = a
        .stream()
        .subscribe(all_logical_keys_filter(), None)
        .await
        .expect("subscribe a");
    let mut sub_b = b
        .stream()
        .subscribe(all_logical_keys_filter(), None)
        .await
        .expect("subscribe b");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let shared = Bytes::from_static(b"shared-key");
    let only_a = Bytes::from_static(b"only-a");
    let mut batch = StoreWriteBatch::new();
    batch.push(&a, &shared, b"value-a").expect("push a shared");
    batch.push(&b, &shared, b"value-b").expect("push b shared");
    batch.push(&a, &only_a, b"value-a2").expect("push a only");
    let sequence = batch
        .commit(&base)
        .await
        .expect("commit cross-prefix batch");

    assert_eq!(
        a.query().get(&shared).await.expect("get a").as_deref(),
        Some(&b"value-a"[..])
    );
    assert_eq!(
        b.query().get(&shared).await.expect("get b").as_deref(),
        Some(&b"value-b"[..])
    );
    assert!(
        base.query().get(&shared).await.expect("base get").is_none(),
        "unprefixed client must not see logical prefixed key"
    );

    let a_rows = a
        .query()
        .range(&Key::new(), &Key::new(), 10)
        .await
        .expect("range a");
    assert_eq!(a_rows.len(), 2);
    assert!(a_rows
        .iter()
        .any(|(key, value)| key == &shared && value.as_ref() == b"value-a"));
    assert!(a_rows
        .iter()
        .any(|(key, value)| key == &only_a && value.as_ref() == b"value-a2"));

    let stream_batch_a = a
        .stream()
        .get(sequence)
        .await
        .expect("stream get a")
        .expect("batch a");
    assert_eq!(stream_batch_a.len(), 2);
    assert!(stream_batch_a
        .iter()
        .all(|(key, _)| key == &shared || key == &only_a));

    let frame_a = next_frame(&mut sub_a, 1_000).await.expect("stream frame a");
    let frame_b = next_frame(&mut sub_b, 1_000).await.expect("stream frame b");
    assert_eq!(frame_a.sequence_number, sequence);
    assert_eq!(frame_b.sequence_number, sequence);
    assert_eq!(frame_a.entries.len(), 2);
    assert_eq!(frame_b.entries.len(), 1);
    assert_eq!(frame_b.entries[0].key, shared);
    assert_eq!(frame_b.entries[0].value.as_ref(), b"value-b");
}

#[tokio::test]
async fn sql_schemas_are_isolated_by_store_prefix() {
    let (_dir, _server, base) = local_store_client().await;
    let schema_a = make_sql_schema(base.with_key_prefix(store_prefix(3)));
    let schema_b = make_sql_schema(base.with_key_prefix(store_prefix(4)));

    let mut writer_a = schema_a.batch_writer();
    writer_a
        .insert("items", vec![CellValue::Int64(1), CellValue::Int64(100)])
        .expect("insert a1")
        .insert("items", vec![CellValue::Int64(2), CellValue::Int64(200)])
        .expect("insert a2");
    let mut writer_b = schema_b.batch_writer();
    writer_b
        .insert("items", vec![CellValue::Int64(1), CellValue::Int64(1000)])
        .expect("insert b1")
        .insert("items", vec![CellValue::Int64(3), CellValue::Int64(3000)])
        .expect("insert b3");

    let (seq_a, seq_b) = tokio::join!(writer_a.flush(), writer_b.flush());
    assert!(seq_a.expect("flush a") > 0);
    assert!(seq_b.expect("flush b") > 0);

    assert_eq!(
        query_sql_items(base.with_key_prefix(store_prefix(3))).await,
        (vec![1, 2], vec![100, 200])
    );
    assert_eq!(
        query_sql_items(base.with_key_prefix(store_prefix(4))).await,
        (vec![1, 3], vec![1000, 3000])
    );
}

#[tokio::test]
async fn sql_streaming_is_isolated_by_store_prefix() {
    let (_dir, _server, base) = local_store_client().await;
    let client_a = base.with_key_prefix(store_prefix(7));
    let client_b = base.with_key_prefix(store_prefix(8));
    let (_sql_server_a, sql_url_a) = spawn_sql_service(make_sql_schema(client_a.clone())).await;
    let (_sql_server_b, sql_url_b) = spawn_sql_service(make_sql_schema(client_b.clone())).await;
    let sql_a = sql_rpc_client(&sql_url_a);
    let sql_b = sql_rpc_client(&sql_url_b);

    let mut sub_a = sql_a
        .subscribe(SqlSubscribeRequest {
            table: "items".to_string(),
            ..Default::default()
        })
        .await
        .expect("subscribe sql a");
    let mut sub_b = sql_b
        .subscribe(SqlSubscribeRequest {
            table: "items".to_string(),
            ..Default::default()
        })
        .await
        .expect("subscribe sql b");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut writer_b = make_sql_schema(client_b.clone()).batch_writer();
    writer_b
        .insert("items", vec![CellValue::Int64(9), CellValue::Int64(900)])
        .expect("insert b stream");
    let seq_b = writer_b.flush().await.expect("flush b stream");
    assert!(seq_b > 0);

    assert!(
        tokio::time::timeout(Duration::from_millis(200), sub_a.message())
            .await
            .is_err(),
        "sql prefix A subscriber must not receive prefix B rows"
    );
    let frame_b = tokio::time::timeout(Duration::from_secs(2), sub_b.message())
        .await
        .expect("sql b timeout")
        .expect("sql b stream")
        .expect("sql b frame")
        .to_owned_message();
    assert_eq!(frame_b.sequence_number, seq_b);
    assert_eq!(frame_b.column, vec!["id", "amount_cents"]);
    assert_eq!(frame_b.rows.len(), 1);
    assert_eq!(row_int64(&frame_b.rows[0], 0), 9);
    assert_eq!(row_int64(&frame_b.rows[0], 1), 900);

    let mut writer_a = make_sql_schema(client_a).batch_writer();
    writer_a
        .insert("items", vec![CellValue::Int64(4), CellValue::Int64(400)])
        .expect("insert a stream");
    let seq_a = writer_a.flush().await.expect("flush a stream");
    assert!(seq_a > 0);

    let frame_a = tokio::time::timeout(Duration::from_secs(2), sub_a.message())
        .await
        .expect("sql a timeout")
        .expect("sql a stream")
        .expect("sql a frame")
        .to_owned_message();
    assert_eq!(frame_a.sequence_number, seq_a);
    assert_eq!(frame_a.column, vec!["id", "amount_cents"]);
    assert_eq!(frame_a.rows.len(), 1);
    assert_eq!(row_int64(&frame_a.rows[0], 0), 4);
    assert_eq!(row_int64(&frame_a.rows[0], 1), 400);
}

fn make_sql_schema(client: StoreClient) -> KvSchema {
    KvSchema::new(client)
        .table(
            "items",
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("amount_cents", DataType::Int64, false),
            ],
            vec!["id".to_string()],
            vec![],
        )
        .expect("sql schema")
}

async fn query_sql_items(client: StoreClient) -> (Vec<i64>, Vec<i64>) {
    let ctx = SessionContext::new();
    make_sql_schema(client)
        .register_all(&ctx)
        .expect("register schema");
    let batches = ctx
        .sql("SELECT id, amount_cents FROM items ORDER BY id")
        .await
        .expect("sql")
        .collect()
        .await
        .expect("collect");
    (
        collect_int64_column(&batches, 0),
        collect_int64_column(&batches, 1),
    )
}

#[tokio::test]
async fn prefixed_qmdb_writers_handle_concurrent_inflight_batches_per_instance() {
    let (_dir, _server, base) = local_store_client().await;
    let client_a = base.with_key_prefix(store_prefix(5));
    let client_b = base.with_key_prefix(store_prefix(6));
    let writer_a = Arc::new(keyless_writer(client_a.clone()));
    let writer_b = Arc::new(keyless_writer(client_b.clone()));

    let batches_a: Vec<Vec<QmdbOp>> = (0..8).map(|idx| qops("a", idx)).collect();
    let batches_b: Vec<Vec<QmdbOp>> = (0..8).map(|idx| qops("b", idx)).collect();
    let total_a: usize = batches_a.iter().map(Vec::len).sum();
    let total_b: usize = batches_b.iter().map(Vec::len).sum();

    let ((expected_a, receipts_a), (expected_b, receipts_b)) = tokio::join!(
        drive_qmdb_writer(writer_a, batches_a),
        drive_qmdb_writer(writer_b, batches_b)
    );
    assert!(
        receipts_a
            .iter()
            .any(|receipt| receipt.writer_location_watermark.is_none()),
        "writer a should exercise a pipelined upload without an inline watermark"
    );
    assert!(
        receipts_b
            .iter()
            .any(|receipt| receipt.writer_location_watermark.is_none()),
        "writer b should exercise a pipelined upload without an inline watermark"
    );

    let latest_a = Location::new((total_a - 1) as u64);
    let latest_b = Location::new((total_b - 1) as u64);
    let reader_a = keyless_reader(client_a);
    let reader_b = keyless_reader(client_b);

    let proof_a = retry_qmdb(
        || {
            let reader = reader_a.clone();
            async move {
                reader
                    .operation_range_proof(latest_a, Location::new(0), total_a as u32)
                    .await
            }
        },
        "reader a proof",
    )
    .await;
    let proof_b = retry_qmdb(
        || {
            let reader = reader_b.clone();
            async move {
                reader
                    .operation_range_proof(latest_b, Location::new(0), total_b as u32)
                    .await
            }
        },
        "reader b proof",
    )
    .await;

    let root_a = retry_qmdb(
        || {
            let reader = reader_a.clone();
            async move { reader.root_at(latest_a).await }
        },
        "reader a root",
    )
    .await;
    let root_b = retry_qmdb(
        || {
            let reader = reader_b.clone();
            async move { reader.root_at(latest_b).await }
        },
        "reader b root",
    )
    .await;

    assert_eq!(proof_a.root, root_a);
    assert_eq!(proof_b.root, root_b);
    assert_eq!(sorted_ops(proof_a.operations), sorted_ops(expected_a));
    assert_eq!(sorted_ops(proof_b.operations), sorted_ops(expected_b));
    assert_ne!(root_a, root_b, "instances wrote different operations");
}

#[tokio::test]
async fn qmdb_streaming_is_isolated_by_store_prefix() {
    let (_dir, _server, base) = local_store_client().await;
    let client_a = base.with_key_prefix(store_prefix(9));
    let client_b = base.with_key_prefix(store_prefix(10));
    let (_qmdb_server_a, qmdb_url_a) = spawn_qmdb_service(client_a.clone()).await;
    let (_qmdb_server_b, qmdb_url_b) = spawn_qmdb_service(client_b.clone()).await;
    let qmdb_a = qmdb_rpc_client(&qmdb_url_a);
    let qmdb_b = qmdb_rpc_client(&qmdb_url_b);

    let mut sub_a = qmdb_a
        .subscribe(QmdbSubscribeRequest::default())
        .await
        .expect("subscribe qmdb a");
    let mut sub_b = qmdb_b
        .subscribe(QmdbSubscribeRequest::default())
        .await
        .expect("subscribe qmdb b");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let ops_b = qops("stream-b", 0);
    keyless_writer(client_b)
        .upload_and_publish(&ops_b)
        .await
        .expect("upload b stream");

    assert!(
        tokio::time::timeout(Duration::from_millis(200), sub_a.message())
            .await
            .is_err(),
        "qmdb prefix A subscriber must not receive prefix B operations"
    );
    let frame_b: RangeSubscribeProof<Digest, QmdbOp> =
        tokio::time::timeout(Duration::from_secs(5), sub_b.message())
            .await
            .expect("qmdb b timeout")
            .expect("qmdb b stream")
            .expect("qmdb b frame");
    assert!(frame_b.resume_sequence_number > 0);
    assert_eq!(frame_b.operations, expected_qmdb_frame(&ops_b));

    let ops_a = qops("stream-a", 0);
    keyless_writer(client_a)
        .upload_and_publish(&ops_a)
        .await
        .expect("upload a stream");

    let frame_a: RangeSubscribeProof<Digest, QmdbOp> =
        tokio::time::timeout(Duration::from_secs(5), sub_a.message())
            .await
            .expect("qmdb a timeout")
            .expect("qmdb a stream")
            .expect("qmdb a frame");
    assert!(frame_a.resume_sequence_number > 0);
    assert_eq!(frame_a.operations, expected_qmdb_frame(&ops_a));
    assert_ne!(frame_a.root, frame_b.root);
}
