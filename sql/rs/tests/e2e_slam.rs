//! SQL E2E slam test against a local Rocks-backed simulator (ephemeral port + temp dir).

mod common;

use axum::{
    serve::{Listener, ListenerExt},
    Router,
};
use connectrpc::{client::ClientConfig, ConnectError, ErrorCode};
use datafusion::{
    arrow::{
        array::{ArrayRef, AsArray, Int64Array},
        datatypes::{DataType, Field, Int64Type, Schema, SchemaRef},
        ipc::reader::StreamReader,
        record_batch::RecordBatch,
    },
    catalog::{Session, TableProvider},
    common::{exec_err, Result as DataFusionResult, ScalarValue},
    datasource::{MemTable, ViewTable},
    execution::context::{FunctionFactory, RegisterFunction, SessionState},
    logical_expr::{create_udf, CreateFunction, Expr, TableType, Volatility},
    physical_plan::ExecutionPlan,
};
use exoware_sdk::{
    proto::PreferZstdHttpClient, transport::set_tcp_nodelay, StoreClient, StoreKeyPrefix,
};
use exoware_sql::{
    proto::sql::v1::{QueryRequest, ServiceClient, SubscribeRequest},
    sql_stack, CellValue, IndexSpec, KvSchema, SqlContext, SqlServer, TableColumnConfig,
};
use std::sync::Arc;

fn result_row_count(results: &[u8]) -> usize {
    StreamReader::try_new(results, None)
        .expect("Arrow IPC results")
        .map(|batch| batch.expect("Arrow IPC batch").num_rows())
        .sum()
}

#[tokio::test]
async fn sql_full_pipeline_insert_and_query() {
    let write_client = common::local_store_client().await;
    let read_client = write_client.clone();

    let write_schema = KvSchema::new(write_client.unprefixed())
        .table(
            "slam_orders",
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("region", DataType::Utf8, false),
                TableColumnConfig::new("amount_cents", DataType::Int64, false),
            ],
            vec!["id".to_string()],
            vec![
                IndexSpec::lexicographic("region_idx", vec!["region".to_string()])
                    .expect("valid index spec")
                    .with_cover_columns(vec!["amount_cents".to_string()]),
            ],
        )
        .expect("schema");

    let mut writer = write_schema.batch_writer();
    for (id, region, amount) in [
        (1i64, "us-east", 100i64),
        (2, "us-west", 200),
        (3, "us-east", 300),
        (4, "eu-west", 400),
        (5, "us-east", 500),
        (6, "eu-west", 600),
        (7, "us-west", 700),
        (8, "us-east", 800),
    ] {
        writer
            .insert(
                "slam_orders",
                vec![
                    CellValue::Int64(id),
                    CellValue::Utf8(region.to_string()),
                    CellValue::Int64(amount),
                ],
            )
            .expect("insert row");
    }
    let min_sequence = writer
        .flush()
        .await
        .expect("flush batch")
        .expect("rows pending");
    assert!(min_sequence > 0);
    let read_schema = KvSchema::new(read_client.unprefixed())
        .table(
            "slam_orders",
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("region", DataType::Utf8, false),
                TableColumnConfig::new("amount_cents", DataType::Int64, false),
            ],
            vec!["id".to_string()],
            vec![
                IndexSpec::lexicographic("region_idx", vec!["region".to_string()])
                    .expect("valid index spec")
                    .with_cover_columns(vec!["amount_cents".to_string()]),
            ],
        )
        .expect("schema");

    let ctx = exoware_sql::SqlContext::new(read_client.unprefixed());
    ctx.register_schema(read_schema).expect("register tables");

    // Full scan (all rows are now visible)
    let batches = ctx
        .sql("SELECT id, amount_cents FROM slam_orders ORDER BY id")
        .await
        .expect("full scan query")
        .collect()
        .await
        .expect("collect full scan");
    let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(total_rows, 8, "full scan should return all 8 rows");

    let mut ids = Vec::new();
    let mut amounts = Vec::new();
    for batch in &batches {
        let id_col = batch
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("id column");
        let amt_col = batch
            .column(1)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("amount column");
        for i in 0..batch.num_rows() {
            ids.push(id_col.value(i));
            amounts.push(amt_col.value(i));
        }
    }
    assert_eq!(ids, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(amounts, vec![100, 200, 300, 400, 500, 600, 700, 800]);

    // Filtered query via secondary index
    let filtered = ctx
        .sql(
            "SELECT id, amount_cents FROM slam_orders \
             WHERE region = 'us-east' ORDER BY id",
        )
        .await
        .expect("filtered query")
        .collect()
        .await
        .expect("collect filtered");
    let mut filtered_ids = Vec::new();
    let mut filtered_amounts = Vec::new();
    for batch in &filtered {
        let id_col = batch
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("id column");
        let amt_col = batch
            .column(1)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("amount column");
        for i in 0..batch.num_rows() {
            filtered_ids.push(id_col.value(i));
            filtered_amounts.push(amt_col.value(i));
        }
    }
    assert_eq!(filtered_ids, vec![1, 3, 5, 8]);
    assert_eq!(filtered_amounts, vec![100, 300, 500, 800]);

    // Aggregate pushdown
    let agg = ctx
        .sql(
            "SELECT COUNT(*) AS cnt, SUM(amount_cents) AS total \
             FROM slam_orders WHERE region = 'us-east'",
        )
        .await
        .expect("aggregate query")
        .collect()
        .await
        .expect("collect aggregate");
    assert_eq!(agg.len(), 1);
    let batch = &agg[0];
    assert_eq!(batch.num_rows(), 1);

    let count = ScalarValue::try_from_array(batch.column(0), 0).expect("count scalar");
    match count {
        ScalarValue::Int64(Some(v)) => assert_eq!(v, 4),
        ScalarValue::UInt64(Some(v)) => assert_eq!(v, 4),
        other => panic!("unexpected count type: {other:?}"),
    }
    let total = ScalarValue::try_from_array(batch.column(1), 0).expect("sum scalar");
    match total {
        ScalarValue::Int64(Some(v)) => assert_eq!(v, 1700),
        other => panic!("unexpected sum type: {other:?}"),
    }

    // Inclusive end: worker range reads are [start, end] inclusive; SQL `<=` / `BETWEEN` must match.
    let lte = ctx
        .sql("SELECT id FROM slam_orders WHERE id <= 3 ORDER BY id")
        .await
        .expect("pk lte")
        .collect()
        .await
        .expect("collect lte");
    let mut lte_ids = Vec::new();
    for batch in &lte {
        let id_col = batch
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("id");
        for i in 0..batch.num_rows() {
            lte_ids.push(id_col.value(i));
        }
    }
    assert_eq!(lte_ids, vec![1, 2, 3]);

    let between_scan = ctx
        .sql("SELECT id FROM slam_orders WHERE id BETWEEN 5 AND 7 ORDER BY id")
        .await
        .expect("between scan")
        .collect()
        .await
        .expect("collect between scan");
    let mut between_ids = Vec::new();
    for batch in &between_scan {
        let id_col = batch
            .column(0)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("id");
        for i in 0..batch.num_rows() {
            between_ids.push(id_col.value(i));
        }
    }
    assert_eq!(between_ids, vec![5, 6, 7]);

    let between_agg = ctx
        .sql(
            "SELECT COUNT(*) AS c, SUM(amount_cents) AS s \
             FROM slam_orders WHERE id BETWEEN 2 AND 4",
        )
        .await
        .expect("between aggregate")
        .collect()
        .await
        .expect("collect between aggregate");
    assert_eq!(between_agg.len(), 1);
    let b = &between_agg[0];
    assert_eq!(b.num_rows(), 1);
    let bc = ScalarValue::try_from_array(b.column(0), 0).expect("count");
    match bc {
        ScalarValue::Int64(Some(v)) => assert_eq!(v, 3),
        ScalarValue::UInt64(Some(v)) => assert_eq!(v, 3),
        other => panic!("unexpected count type: {other:?}"),
    }
    let bs = ScalarValue::try_from_array(b.column(1), 0).expect("sum");
    match bs {
        ScalarValue::Int64(Some(v)) => assert_eq!(v, 200 + 300 + 400),
        other => panic!("unexpected sum type: {other:?}"),
    }
}

async fn serve_sql(
    server: Arc<SqlServer>,
) -> (
    ServiceClient<PreferZstdHttpClient>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind SQL server")
        .tap_io(set_tcp_nodelay);
    let base = format!("http://{}", listener.local_addr().expect("SQL address"));
    let app = Router::new().fallback_service(sql_stack(server));
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve SQL");
    });
    let client = ServiceClient::new(
        PreferZstdHttpClient::plaintext(),
        ClientConfig::new(base.parse().expect("SQL URI")),
    );
    (client, handle)
}

async fn query_error(client: &ServiceClient<PreferZstdHttpClient>, sql: &str) -> ConnectError {
    let Err(error) = client
        .query(QueryRequest {
            sql: sql.to_string(),
            ..Default::default()
        })
        .await
    else {
        panic!("{} must be rejected", sql.trim_end());
    };
    error
}

async fn query_row_count(client: &ServiceClient<PreferZstdHttpClient>, sql: &str) -> usize {
    let response = client
        .query(QueryRequest {
            sql: sql.to_string(),
            ..Default::default()
        })
        .await
        .expect(sql)
        .into_view()
        .to_owned_message();
    result_row_count(&response.results)
}

fn items_schema(store: &StoreClient) -> KvSchema {
    KvSchema::new(store.unprefixed())
        .table(
            "items",
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("value", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            Vec::new(),
        )
        .expect("the items schema must build")
}

#[tokio::test]
async fn connect_query_rejects_server_file_and_runtime_access() {
    let store = common::local_store_client().await;
    let server = Arc::new(SqlServer::new(items_schema(&store)).expect("the server must build"));
    let (client, handle) = serve_sql(server.clone()).await;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock must be past the Unix epoch")
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("exoware-sql-files-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("the temp dir must be created");
    std::fs::write(dir.join("local.csv"), "local\n").expect("the local file must be written");
    let path = |name: &str| dir.join(name).display().to_string();

    // Each statement would read or write server files, or replace the runtime environment.
    for (sql, written) in [
        (
            format!(
                "EXPLAIN ANALYZE COPY (SELECT 1 AS id) TO '{}' STORED AS CSV",
                path("explained.csv")
            ),
            Some("explained.csv"),
        ),
        (
            format!(
                "CREATE EXTERNAL TABLE local_file (line VARCHAR) STORED AS CSV LOCATION '{}'",
                path("local.csv")
            ),
            None,
        ),
        (
            format!(
                "COPY (SELECT 1 AS id) TO '{}' STORED AS CSV",
                path("copied.csv")
            ),
            Some("copied.csv"),
        ),
        (
            format!(
                "SET datafusion.runtime.temp_directory = '{}'",
                path("spill")
            ),
            Some("spill"),
        ),
        ("RESET datafusion.runtime.temp_directory".to_string(), None),
    ] {
        let error = query_error(&client, &sql).await;
        assert_eq!(error.code, ErrorCode::InvalidArgument, "{sql}: {error:?}");
        if let Some(written) = written {
            assert!(!dir.join(written).exists(), "{sql}");
        }
    }
    assert!(server.context().table_provider("local_file").await.is_err());

    // Queries, Store writes, session settings, and prepared statements remain available.
    assert_eq!(
        query_row_count(&client, "INSERT INTO items VALUES (1, 'one')").await,
        1
    );
    assert_eq!(
        query_row_count(&client, "SELECT value FROM items WHERE id = 1").await,
        1
    );
    query_row_count(&client, "SET datafusion.execution.batch_size = 17").await;
    query_row_count(
        &client,
        "PREPARE item AS SELECT value FROM items WHERE id = 1",
    )
    .await;
    assert_eq!(query_row_count(&client, "EXECUTE item").await, 1);

    std::fs::remove_dir_all(&dir).expect("the temp dir must be removable");
    handle.abort();
}

#[tokio::test]
async fn connect_query_rejects_shared_catalog_changes() {
    let store = common::local_store_client().await;
    let schema = items_schema(&store);

    // The served table holds one row that a replaced or dropped table would lose.
    let mut writer = schema.batch_writer();
    writer
        .insert(
            "items",
            vec![CellValue::Int64(1), CellValue::Utf8("one".to_string())],
        )
        .expect("the insert must succeed");
    writer
        .flush()
        .await
        .expect("the flush must succeed")
        .expect("the writer must hold a row");
    let server = Arc::new(SqlServer::new(schema).expect("the server must build"));
    let (client, handle) = serve_sql(server.clone()).await;

    // Each statement would change the catalog, or how names resolve in it, for every caller.
    for sql in [
        "CREATE OR REPLACE TABLE items AS SELECT 2 AS id, 'two' AS value",
        "DROP TABLE items",
        "CREATE OR REPLACE VIEW items AS SELECT 3 AS id, 'three' AS value",
        "CREATE TABLE copied_items AS SELECT * FROM items",
        "CREATE TABLE empty_items (id BIGINT)",
        "CREATE VIEW item_values AS SELECT value FROM items",
        "CREATE SCHEMA scratch",
        "CREATE DATABASE scratch_catalog",
        "DROP SCHEMA public CASCADE",
        "SET datafusion.catalog.default_schema = 'scratch'",
        "SET datafusion.catalog.information_schema = true",
        "RESET datafusion.catalog.default_schema",
    ] {
        let error = query_error(&client, sql).await;
        assert_eq!(error.code, ErrorCode::InvalidArgument, "{sql}: {error:?}");
    }

    let response = client
        .query(QueryRequest {
            sql: "SELECT value FROM items WHERE id = 1".to_string(),
            ..Default::default()
        })
        .await
        .expect("the served table must still answer")
        .into_view()
        .to_owned_message();
    let batches = StreamReader::try_new(response.results.as_ref(), None)
        .expect("the results must be an Arrow IPC stream")
        .collect::<Result<Vec<_>, _>>()
        .expect("each Arrow IPC batch must decode");
    let values: Vec<_> = batches
        .iter()
        .flat_map(|batch| {
            let column = batch.column(0).as_string::<i32>();
            column
                .iter()
                .map(|value| value.map(str::to_string))
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(values, vec![Some("one".to_string())]);

    // No rejected statement reached the server's catalog or options, and the accepted one did.
    let ctx = server.context();
    for table in ["copied_items", "empty_items", "item_values"] {
        assert!(ctx.table_provider(table).await.is_err(), "{table}");
    }
    assert!(ctx.datafusion().catalog("scratch_catalog").is_none());
    let catalog = ctx
        .datafusion()
        .catalog("datafusion")
        .expect("the default catalog must exist");
    assert!(catalog.schema("scratch").is_none());
    let options = ctx.datafusion().state().config().options().clone();
    assert_eq!(options.catalog.default_schema, "public");
    assert!(!options.catalog.information_schema);
    handle.abort();
}

async fn sorted_ids(ctx: &SqlContext, table: &str) -> Vec<i64> {
    let batches = ctx
        .sql(&format!("SELECT id FROM {table} ORDER BY id"))
        .await
        .expect("the id query must plan")
        .collect()
        .await
        .expect("the id query must run");
    batches
        .iter()
        .flat_map(|batch| {
            batch
                .column(0)
                .as_primitive::<Int64Type>()
                .values()
                .to_vec()
        })
        .collect()
}

#[tokio::test]
async fn connect_query_rejects_writes_other_than_insert() {
    let schema = KvSchema::new(common::local_store_client().await.unprefixed());
    let server = Arc::new(SqlServer::new(schema).expect("the server must build"));
    let batch = RecordBatch::try_from_iter(vec![(
        "id",
        Arc::new(Int64Array::from(vec![1, 2, 3])) as ArrayRef,
    )])
    .expect("the configured batch must build");
    let table = MemTable::try_new(batch.schema(), vec![vec![batch]])
        .expect("the configured table must build");
    server
        .context()
        .register_table("configured_ids", Arc::new(table))
        .expect("the configured table must register");
    let (client, handle) = serve_sql(server.clone()).await;

    // A MemTable applies DELETE and UPDATE while its physical plan is built, so EXPLAIN alone
    // would change its rows.
    for sql in [
        "DELETE FROM configured_ids WHERE id = 1",
        "UPDATE configured_ids SET id = 9 WHERE id = 2",
        "EXPLAIN DELETE FROM configured_ids WHERE id = 3",
        "PREPARE remove_id AS DELETE FROM configured_ids WHERE id = $1",
    ] {
        let error = query_error(&client, sql).await;
        assert_eq!(error.code, ErrorCode::InvalidArgument, "{sql}: {error:?}");
    }
    let error = query_error(&client, "EXECUTE remove_id(1)").await;
    assert_eq!(error.code, ErrorCode::InvalidArgument, "{error:?}");
    assert_eq!(
        sorted_ids(server.context(), "configured_ids").await,
        [1, 2, 3]
    );

    assert_eq!(
        query_row_count(&client, "INSERT INTO configured_ids VALUES (4)").await,
        1
    );
    assert_eq!(
        sorted_ids(server.context(), "configured_ids").await,
        [1, 2, 3, 4]
    );
    handle.abort();
}

#[tokio::test]
async fn connect_query_reports_invalid_values_as_invalid_argument() {
    let schema = KvSchema::new(common::local_store_client().await.unprefixed());
    let server = Arc::new(SqlServer::new(schema).expect("the server must build"));
    let (client, handle) = serve_sql(server).await;

    // Division by zero, failed casts, and integer overflow come from the caller's values.
    for sql in [
        "SELECT 1/0",
        "SELECT CAST('abc' AS BIGINT)",
        "SELECT CAST('x' AS TIMESTAMP)",
        "SELECT -(-9223372036854775807 - 1)",
    ] {
        let error = query_error(&client, sql).await;
        assert_eq!(error.code, ErrorCode::InvalidArgument, "{sql}: {error:?}");
    }
    handle.abort();
}

#[tokio::test]
async fn connect_query_reports_failed_session_commands_as_invalid_argument() {
    let schema = KvSchema::new(common::local_store_client().await.unprefixed());
    let server = Arc::new(SqlServer::new(schema).expect("the server must build"));
    let (client, handle) = serve_sql(server).await;
    query_row_count(&client, "PREPARE taken AS SELECT 1").await;

    // Each command gives a setting a bad value, reuses a name, or names nothing that exists.
    for sql in [
        "SET datafusion.execution.batch_size = 'abc'",
        "PREPARE taken AS SELECT 2",
        "EXECUTE nope",
        "DEALLOCATE nope",
        "DROP FUNCTION nope",
    ] {
        let error = query_error(&client, sql).await;
        assert_eq!(error.code, ErrorCode::InvalidArgument, "{sql}: {error:?}");
    }
    handle.abort();
}

/// A function factory whose backend is down, so every `CREATE FUNCTION` fails on the server.
#[derive(Debug)]
struct UnavailableFunctionFactory;

#[async_trait::async_trait]
impl FunctionFactory for UnavailableFunctionFactory {
    async fn create(
        &self,
        _state: &SessionState,
        _statement: CreateFunction,
    ) -> DataFusionResult<RegisterFunction> {
        exec_err!("function backend is unavailable")
    }
}

/// A table whose source is down, so building a plan that scans it fails on the server.
#[derive(Debug)]
struct UnavailableTable;

#[async_trait::async_trait]
impl TableProvider for UnavailableTable {
    fn schema(&self) -> SchemaRef {
        Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, false)]))
    }

    fn table_type(&self) -> TableType {
        TableType::Base
    }

    async fn scan(
        &self,
        _state: &dyn Session,
        _projection: Option<&Vec<usize>>,
        _filters: &[Expr],
        _limit: Option<usize>,
    ) -> DataFusionResult<Arc<dyn ExecutionPlan>> {
        exec_err!("table source is unavailable")
    }
}

#[tokio::test]
async fn connect_query_keeps_server_faults_around_session_commands_internal() {
    let schema = KvSchema::new(common::local_store_client().await.unprefixed());
    let server = Arc::new(SqlServer::new(schema).expect("the server must build"));
    let ctx = server.context();
    ctx.datafusion()
        .state_ref()
        .write()
        .set_function_factory(Arc::new(UnavailableFunctionFactory));
    ctx.register_udf(create_udf(
        "broken",
        vec![DataType::Int64],
        DataType::Int64,
        Volatility::Volatile,
        Arc::new(|_| exec_err!("function backend is unavailable")),
    ));
    ctx.register_table("unavailable", Arc::new(UnavailableTable))
        .expect("the unavailable table must register");
    let (client, handle) = serve_sql(server).await;
    for sql in [
        "PREPARE scan_unavailable AS SELECT id FROM unavailable",
        "PREPARE call_broken AS SELECT broken(1)",
    ] {
        query_row_count(&client, sql).await;
    }

    // The embedder's function factory fails, and the statement an EXECUTE starts fails when its
    // plan is built or while it runs. None of these is the caller's mistake.
    for sql in [
        "CREATE FUNCTION f(BIGINT) RETURNS BIGINT RETURN $1",
        "EXECUTE scan_unavailable",
        "EXECUTE call_broken",
    ] {
        let error = query_error(&client, sql).await;
        assert_eq!(error.code, ErrorCode::Internal, "{sql}: {error:?}");
    }
    handle.abort();
}

/// Returns the error a subscription ends with, whether the call or its first message carries it.
async fn subscribe_error(
    client: &ServiceClient<PreferZstdHttpClient>,
    request: SubscribeRequest,
) -> ConnectError {
    let mut stream = match client.subscribe(request).await {
        Ok(stream) => stream,
        Err(error) => return error,
    };
    match tokio::time::timeout(std::time::Duration::from_secs(1), stream.message()).await {
        Ok(Err(error)) => error,
        _ => panic!("the subscription must be rejected"),
    }
}

#[tokio::test]
async fn connect_requests_enforce_declared_field_lengths() {
    let store = common::local_store_client().await;
    let server = Arc::new(SqlServer::new(items_schema(&store)).expect("the server must build"));
    let (client, handle) = serve_sql(server).await;
    let padded = |prefix: &str, len: usize| format!("{prefix}{}", " ".repeat(len - prefix.len()));

    // A statement at its 65,535-character limit runs.
    assert_eq!(
        query_row_count(&client, &padded("SELECT 1", 65_535)).await,
        1
    );

    // Each request breaks one declared length, by one past its limit or by an empty table name.
    let mut errors = vec![(
        "sql",
        query_error(&client, &padded("SELECT 1", 65_536)).await,
    )];
    for (field, request) in [
        (
            "table",
            SubscribeRequest {
                table: "x".repeat(256),
                ..Default::default()
            },
        ),
        (
            "table",
            SubscribeRequest {
                table: String::new(),
                ..Default::default()
            },
        ),
        (
            "where_sql",
            SubscribeRequest {
                table: "items".to_string(),
                where_sql: padded("id = 1", 4_097),
                ..Default::default()
            },
        ),
    ] {
        errors.push((field, subscribe_error(&client, request).await));
    }

    // Each rejection is invalid_argument, names its field, and carries the sql error domain.
    for (field, error) in errors {
        assert_eq!(error.code, ErrorCode::InvalidArgument, "{field}: {error:?}");
        let details = exoware_sdk::proto::decode_connect_error(&error)
            .expect("the error must carry decodable details");
        assert_eq!(
            details
                .bad_request
                .expect("the details must include a BadRequest")
                .field_violations[0]
                .field,
            field
        );
        assert_eq!(
            details
                .error_info
                .expect("the details must include an ErrorInfo")
                .domain,
            "sql"
        );
    }

    // A predicate at its 4,096-character limit opens a subscription that stays open.
    let mut stream = client
        .subscribe(SubscribeRequest {
            table: "items".to_string(),
            where_sql: padded("id = 1", 4_096),
            ..Default::default()
        })
        .await
        .expect("a subscription at the length limit must be accepted");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(500), stream.message())
            .await
            .is_err(),
        "a subscription at the length limit must stay open"
    );
    handle.abort();
}

#[tokio::test]
async fn connect_query_preserves_session_settings() {
    let schema = KvSchema::new(common::local_store_client().await.unprefixed());
    let server = Arc::new(SqlServer::new(schema).expect("SQL server"));
    let initial_batch_size = server.context().datafusion().state().config().batch_size();
    let (client, handle) = serve_sql(server.clone()).await;

    for (sql, expected) in [
        ("SET datafusion.execution.batch_size = 17", 17),
        ("RESET datafusion.execution.batch_size", initial_batch_size),
    ] {
        client
            .query(QueryRequest {
                sql: sql.to_string(),
                ..Default::default()
            })
            .await
            .expect("update session setting");
        assert_eq!(
            server.context().datafusion().state().config().batch_size(),
            expected,
            "{sql}"
        );
    }

    client
        .query(QueryRequest {
            sql: "DROP FUNCTION abs".to_string(),
            ..Default::default()
        })
        .await
        .expect("drop session function");
    client
        .query(QueryRequest {
            sql: "SELECT abs(-7)".to_string(),
            ..Default::default()
        })
        .await
        .expect_err("function remains absent in the next request");
    handle.abort();
}

#[tokio::test]
async fn connect_query_enforces_sequence_floor_and_returns_evaluated_sequence() {
    let store_client = common::local_store_client().await;
    let schema = KvSchema::new(store_client.unprefixed())
        .table(
            "items",
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("value", DataType::Utf8, false),
                TableColumnConfig::new("amount", DataType::Int64, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::lexicographic("value_idx", vec!["value".to_string()]).expect("index")],
        )
        .expect("schema");
    let mut writer = schema.batch_writer();
    writer
        .insert(
            "items",
            vec![
                CellValue::Int64(1),
                CellValue::Utf8("one".to_string()),
                CellValue::Int64(10),
            ],
        )
        .expect("insert");
    let write_sequence = writer.flush().await.expect("flush").expect("rows pending");

    let server = Arc::new(SqlServer::new(schema).expect("SQL server"));
    let (client, handle) = serve_sql(server).await;

    for sql in [
        "SELECT value FROM items WHERE id = 1",
        "SELECT id FROM items ORDER BY id DESC LIMIT 1",
        "SELECT id FROM items WHERE value = 'one'",
        "SELECT amount FROM items WHERE value = 'one'",
        "SELECT COUNT(*) FROM items",
        "SELECT value, SUM(amount) AS total FROM items GROUP BY value",
        "SELECT a.value FROM items a JOIN items b ON a.id = b.id",
    ] {
        for min_sequence_number in [None, Some(write_sequence)] {
            let response = client
                .query(QueryRequest {
                    sql: sql.to_string(),
                    min_sequence_number,
                    ..Default::default()
                })
                .await
                .expect("query")
                .into_view()
                .to_owned_message();
            assert!(response.sequence_number.unwrap() >= write_sequence, "{sql}");
            assert_eq!(result_row_count(&response.results), 1, "{sql}");
        }

        let error = client
            .query(QueryRequest {
                sql: sql.to_string(),
                min_sequence_number: Some(u64::MAX),
                ..Default::default()
            })
            .await
            .expect_err("unavailable sequence floor");
        assert_eq!(error.code, ErrorCode::Aborted, "{sql} returned {error:?}");
        let details =
            exoware_sdk::proto::decode_connect_error(&error).expect("Store error details");
        let info = details.error_info.expect("consistency error info");
        assert_eq!(info.reason, "CONSISTENCY_NOT_READY");
        assert_eq!(info.domain, "store.query");
        assert_eq!(
            info.metadata["required_sequence_number"],
            u64::MAX.to_string()
        );
        let current = info.metadata["current_sequence_number"]
            .parse::<u64>()
            .unwrap();
        assert!(current >= write_sequence && current < u64::MAX);
        assert!(details.retry_info.is_some());
        assert!(details.query_detail.unwrap().sequence_number >= current);
    }

    let response = client
        .query(QueryRequest {
            sql: "SELECT value FROM items WHERE id = 2".to_string(),
            min_sequence_number: Some(write_sequence),
            ..Default::default()
        })
        .await
        .expect("empty query")
        .into_view()
        .to_owned_message();
    assert!(response.sequence_number.unwrap() >= write_sequence);
    assert_eq!(result_row_count(&response.results), 0);

    for sql in ["SELECT 1", "SELECT value FROM items WHERE false"] {
        let response = client
            .query(QueryRequest {
                sql: sql.to_string(),
                min_sequence_number: Some(u64::MAX),
                ..Default::default()
            })
            .await
            .expect("query without Store reads")
            .into_view()
            .to_owned_message();
        assert_eq!(response.sequence_number, None, "{sql}");
    }

    handle.abort();
}

#[tokio::test]
async fn connect_query_reports_the_commit_sequence_of_an_insert() {
    let store = common::local_store_client().await;
    let server = Arc::new(SqlServer::new(items_schema(&store)).expect("the server must build"));
    let (client, handle) = serve_sql(server).await;
    let query = async |sql: &str, min_sequence_number: Option<u64>| {
        client
            .query(QueryRequest {
                sql: sql.to_string(),
                min_sequence_number,
                ..Default::default()
            })
            .await
            .expect(sql)
            .into_view()
            .to_owned_message()
    };

    // The response carries the sequence of the batch the INSERT committed.
    let sequence = query("INSERT INTO items VALUES (1, 'one')", None)
        .await
        .sequence_number
        .expect("an INSERT must report its commit sequence");
    let batch = store
        .unprefixed()
        .stream()
        .get_batch(sequence)
        .await
        .expect("the Store log must be readable")
        .expect("the commit must be in the Store log");
    assert_eq!(batch.entries.len(), 1, "the INSERT must write one row");

    // A read that requires the commit sees the row.
    let response = query("SELECT value FROM items WHERE id = 1", Some(sequence)).await;
    assert_eq!(result_row_count(&response.results), 1);
    assert!(response.sequence_number >= Some(sequence));

    // An INSERT that writes no rows reports no sequence.
    let response = query("INSERT INTO items SELECT 2, 'two' WHERE false", None).await;
    assert_eq!(response.sequence_number, None);
    handle.abort();
}

#[tokio::test]
async fn connect_query_preserves_configured_tables_and_views() {
    let store_client = common::local_store_client().await;
    let schema = KvSchema::new(store_client.unprefixed())
        .table(
            "items",
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("value", DataType::Utf8, false),
            ],
            vec!["id".to_string()],
            Vec::new(),
        )
        .expect("schema");
    let mut writer = schema.batch_writer();
    writer
        .insert(
            "items",
            vec![CellValue::Int64(1), CellValue::Utf8("one".to_string())],
        )
        .expect("insert");
    let write_sequence = writer.flush().await.expect("flush").expect("rows pending");

    let other_schema =
        KvSchema::new(store_client.prefixed(StoreKeyPrefix::new("other/").expect("prefix")))
            .table(
                "other_items",
                vec![TableColumnConfig::new("id", DataType::Int64, false)],
                vec!["id".to_string()],
                Vec::new(),
            )
            .expect("other schema");
    let mut other_writer = other_schema.batch_writer();
    other_writer
        .insert("other_items", vec![CellValue::Int64(2)])
        .expect("insert other item");
    let other_sequence = other_writer
        .flush()
        .await
        .expect("flush other item")
        .expect("rows pending");

    let configured_batch = RecordBatch::try_from_iter(vec![(
        "id",
        Arc::new(Int64Array::from(vec![1])) as ArrayRef,
    )])
    .expect("configured batch");
    let configured_table =
        MemTable::try_new(configured_batch.schema(), vec![vec![configured_batch]])
            .expect("configured table");
    let server = SqlServer::new(schema).expect("SQL server");
    server
        .context()
        .register_schema(other_schema)
        .expect("register other namespace");
    server
        .context()
        .register_table("configured_ids", Arc::new(configured_table))
        .expect("register configured table");
    server
        .context()
        .sql("CREATE VIEW configured_items AS SELECT value FROM items WHERE id = 1")
        .await
        .expect("create configured view");
    let programmatic_plan = server
        .context()
        .sql("SELECT value FROM items WHERE id = 1")
        .await
        .expect("plan programmatic view")
        .into_unoptimized_plan();
    server
        .context()
        .register_table(
            "programmatic_items",
            Arc::new(ViewTable::new(programmatic_plan, None)),
        )
        .expect("register programmatic view");
    let server = Arc::new(server);

    let (client, handle) = serve_sql(server).await;

    let response = client
        .query(QueryRequest {
            sql: "SELECT items.value FROM items JOIN configured_ids USING (id)".to_string(),
            min_sequence_number: Some(write_sequence),
            ..Default::default()
        })
        .await
        .expect("query configured table")
        .into_view()
        .to_owned_message();
    assert!(response.sequence_number.unwrap() >= write_sequence);
    assert_eq!(result_row_count(&response.results), 1);

    client
        .query(QueryRequest {
            sql: "PREPARE other_item AS SELECT id FROM other_items WHERE id = 2".to_string(),
            ..Default::default()
        })
        .await
        .expect("prepare namespaced query");

    for sql in [
        "EXECUTE other_item",
        "SELECT id FROM other_items WHERE id = 2",
        "SELECT SUM(id) AS id FROM other_items",
    ] {
        let response = client
            .query(QueryRequest {
                sql: sql.to_string(),
                min_sequence_number: Some(other_sequence),
                ..Default::default()
            })
            .await
            .expect("query other namespace")
            .into_view()
            .to_owned_message();
        assert_eq!(result_row_count(&response.results), 1, "{sql}");
        let mut ids = Vec::new();
        for batch in
            StreamReader::try_new(response.results.as_ref(), None).expect("Arrow IPC results")
        {
            let batch = batch.expect("Arrow IPC batch");
            assert_eq!(batch.num_columns(), 1, "{sql}");
            let column = batch
                .column(0)
                .as_any()
                .downcast_ref::<Int64Array>()
                .expect("id column");
            ids.extend(column.iter());
        }
        assert_eq!(ids, vec![Some(2)], "{sql}");
        assert!(response.sequence_number.unwrap() >= other_sequence);
    }

    for sql in [
        "EXECUTE other_item",
        "INSERT INTO items SELECT id, 'copied' FROM other_items",
    ] {
        let error = client
            .query(QueryRequest {
                sql: sql.to_string(),
                min_sequence_number: Some(u64::MAX),
                ..Default::default()
            })
            .await
            .expect_err("data reads retain their request floor");
        assert_eq!(error.code, ErrorCode::Aborted, "{sql}");
    }
    client
        .query(QueryRequest {
            sql: "DEALLOCATE other_item".to_string(),
            ..Default::default()
        })
        .await
        .expect("deallocate prepared query");
    client
        .query(QueryRequest {
            sql: "EXECUTE other_item".to_string(),
            ..Default::default()
        })
        .await
        .expect_err("prepared query remains absent in the next request");

    let response = client
        .query(QueryRequest {
            sql: "SELECT value FROM configured_items".to_string(),
            min_sequence_number: Some(write_sequence),
            ..Default::default()
        })
        .await
        .expect("query configured view")
        .into_view()
        .to_owned_message();
    assert!(response.sequence_number.unwrap() >= write_sequence);
    assert_eq!(result_row_count(&response.results), 1);

    let response = client
        .query(QueryRequest {
            sql: "SELECT value FROM programmatic_items".to_string(),
            min_sequence_number: Some(write_sequence),
            ..Default::default()
        })
        .await
        .expect("query programmatic view")
        .into_view()
        .to_owned_message();
    assert!(response.sequence_number.unwrap() >= write_sequence);
    assert_eq!(result_row_count(&response.results), 1);

    let error = client
        .query(QueryRequest {
            sql: "SELECT value FROM configured_items".to_string(),
            min_sequence_number: Some(u64::MAX),
            ..Default::default()
        })
        .await
        .expect_err("unavailable sequence floor through view");
    assert_eq!(error.code, ErrorCode::Aborted);

    let error = client
        .query(QueryRequest {
            sql: "SELECT value FROM programmatic_items".to_string(),
            min_sequence_number: Some(u64::MAX),
            ..Default::default()
        })
        .await
        .expect_err("unavailable sequence floor through programmatic view");
    assert_eq!(error.code, ErrorCode::Aborted);

    handle.abort();
}
