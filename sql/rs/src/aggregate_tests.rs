use super::*;
use buffa::Message;
use std::sync::{
    atomic::{AtomicUsize, Ordering as AtomicOrdering},
    Mutex,
};

use axum::{extract::Request, middleware::Next, response::Response, Router};
use bytes::Bytes;
use datafusion::arrow::array::{
    ArrayRef, Decimal128Array, FixedSizeBinaryBuilder, Float64Array, Int64Array, StringArray,
    UInt64Array,
};
use datafusion::datasource::MemTable;
use datafusion::prelude::SessionContext;
use exoware_sdk::StoreClient;
use exoware_server::{Query, QueryExtra, QueryState, RangeScan, RangeScanBatch, Sequence};

#[derive(Default)]
struct Rows {
    values: Mutex<BTreeMap<Bytes, Bytes>>,
    paths: Mutex<Vec<String>>,
    reductions: Mutex<Vec<exoware_sdk::query::ReduceRequest>>,
    scanned_rows: AtomicUsize,
}

impl Sequence for Rows {
    fn current_sequence(&self) -> u64 {
        7
    }
}

struct Cursor(std::vec::IntoIter<(Bytes, Bytes)>);

impl RangeScan for Cursor {
    async fn next_batch(&mut self, max_items: usize) -> Result<RangeScanBatch, String> {
        Ok(RangeScanBatch {
            rows: self.0.by_ref().take(max_items).collect(),
            extra: QueryExtra::new(),
        })
    }
}

impl Query for Rows {
    type RangeScan = Cursor;

    async fn get(&self, key: Bytes) -> Result<(Option<Bytes>, QueryExtra), String> {
        Ok((
            self.values.lock().unwrap().get(&key).cloned(),
            QueryExtra::new(),
        ))
    }

    async fn get_many(
        &self,
        keys: Vec<Bytes>,
    ) -> Result<(Vec<(Bytes, Option<Bytes>)>, QueryExtra), String> {
        let values = self.values.lock().unwrap();
        Ok((
            keys.into_iter()
                .map(|key| {
                    let value = values.get(&key).cloned();
                    (key, value)
                })
                .collect(),
            QueryExtra::new(),
        ))
    }

    async fn range_scan(
        &self,
        start: Bytes,
        end: Bytes,
        limit: usize,
        forward: bool,
    ) -> Result<Cursor, String> {
        let mut rows = self
            .values
            .lock()
            .unwrap()
            .iter()
            .filter(|(key, _)| **key >= start && (end.is_empty() || **key <= end))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        if !forward {
            rows.reverse();
        }
        rows.truncate(limit);
        self.scanned_rows
            .fetch_add(rows.len(), AtomicOrdering::Relaxed);
        Ok(Cursor(rows.into_iter()))
    }
}

struct Fixture {
    store: SessionContext,
    native: SessionContext,
    rows: Arc<Rows>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fixture {
    async fn new() -> Self {
        Self::with_amounts([Some(10), Some(30), None, Some(20)]).await
    }

    async fn with_amounts(amounts: [Option<i64>; 4]) -> Self {
        let rows = Arc::new(Rows::default());
        let observed = rows.clone();
        let app = Router::new()
            .fallback_service(exoware_server::query_service(QueryState::new(rows.clone())))
            .layer(axum::middleware::from_fn(
                move |request: Request, next: Next| {
                    let observed = observed.clone();
                    async move {
                        observed
                            .paths
                            .lock()
                            .unwrap()
                            .push(request.uri().path().to_string());
                        let request = if request.uri().path().ends_with("/Reduce") {
                            let (parts, body) = request.into_parts();
                            let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
                            observed.reductions.lock().unwrap().push(
                                exoware_sdk::query::ReduceRequest::decode_from_slice(&body)
                                    .unwrap(),
                            );
                            Request::from_parts(parts, axum::body::Body::from(body))
                        } else {
                            request
                        };
                        let response: Response = next.run(request).await;
                        response
                    }
                },
            ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let store = crate::session_context();
        let schema = crate::KvSchema::new(PrefixedStoreClient::empty(StoreClient::new(&url)))
            .table(
                "orders",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("region", DataType::Utf8, true),
                    TableColumnConfig::new("status", DataType::Utf8, false),
                    TableColumnConfig::new("amount", DataType::Int64, true),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap();
        schema.register_all(&store).unwrap();
        let provider = store.table_provider("orders").await.unwrap();
        let model = &provider.downcast_ref::<KvTable>().unwrap().model;
        let regions = [Some("east"), Some("east"), Some("west"), None];
        let statuses = ["open", "closed", "closed", "open"];
        for idx in 0..4 {
            let row = KvRow {
                values: vec![
                    CellValue::Int64(idx as i64 + 1),
                    regions[idx]
                        .map(|s| CellValue::Utf8(s.to_string()))
                        .unwrap_or(CellValue::Null),
                    CellValue::Utf8(statuses[idx].to_string()),
                    amounts[idx]
                        .map(CellValue::Int64)
                        .unwrap_or(CellValue::Null),
                ],
            };
            let key = crate::codec::encode_primary_key_from_row(0, &row, model).unwrap();
            let value = crate::writer::encode_base_row_value(&row, model).unwrap();
            rows.values.lock().unwrap().insert(key, value.into());
        }
        let batch = RecordBatch::try_new(
            model.schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1, 2, 3, 4])),
                Arc::new(StringArray::from(regions.to_vec())),
                Arc::new(StringArray::from(statuses.to_vec())),
                Arc::new(Int64Array::from(amounts.to_vec())),
            ],
        )
        .unwrap();
        let native = SessionContext::new();
        native
            .register_table(
                "orders",
                Arc::new(MemTable::try_new(batch.schema(), vec![vec![batch]]).unwrap()),
            )
            .unwrap();
        Self {
            store,
            native,
            rows,
            server,
        }
    }

    async fn install_indexed_table(
        &self,
        name: &str,
        columns: Vec<TableColumnConfig>,
        primary_key: &[&str],
        indexes: Vec<IndexSpec>,
        rows: Vec<KvRow>,
        arrays: Vec<ArrayRef>,
    ) {
        let provider = self.store.table_provider("orders").await.unwrap();
        let client = provider.downcast_ref::<KvTable>().unwrap().client.clone();
        let schema = crate::KvSchema::new(client)
            .table(
                name,
                columns,
                primary_key.iter().map(|name| name.to_string()).collect(),
                indexes,
            )
            .unwrap();
        schema.register_all(&self.store).unwrap();
        let provider = self.store.table_provider(name).await.unwrap();
        let table = provider.downcast_ref::<KvTable>().unwrap();
        let mut stored = self.rows.values.lock().unwrap();
        stored.clear();
        for row in rows {
            stored.insert(
                crate::codec::encode_primary_key_from_row(0, &row, &table.model).unwrap(),
                crate::writer::encode_base_row_value(&row, &table.model)
                    .unwrap()
                    .into(),
            );
            for spec in table.index_specs.iter() {
                stored.insert(
                    crate::codec::encode_secondary_index_key(0, spec, &table.model, &row).unwrap(),
                    crate::writer::encode_secondary_index_value(&row, &table.model, spec)
                        .unwrap()
                        .into(),
                );
            }
        }
        drop(stored);
        let batch = RecordBatch::try_new(table.model.schema.clone(), arrays).unwrap();
        self.native
            .register_table(
                name,
                Arc::new(MemTable::try_new(batch.schema(), vec![vec![batch]]).unwrap()),
            )
            .unwrap();
    }

    async fn replace_value_column(
        &self,
        data_type: DataType,
        values: Vec<CellValue>,
        array: ArrayRef,
    ) {
        let provider = self.store.table_provider("orders").await.unwrap();
        let client = provider.downcast_ref::<KvTable>().unwrap().client.clone();
        let schema = crate::KvSchema::new(client)
            .table(
                "numbers",
                vec![
                    TableColumnConfig::new("id", DataType::Int64, false),
                    TableColumnConfig::new("value", data_type, true),
                ],
                vec!["id".to_string()],
                vec![],
            )
            .unwrap();
        schema.register_all(&self.store).unwrap();
        let provider = self.store.table_provider("numbers").await.unwrap();
        let model = &provider.downcast_ref::<KvTable>().unwrap().model;
        let mut stored = self.rows.values.lock().unwrap();
        stored.clear();
        for (idx, value) in values.into_iter().enumerate() {
            let row = KvRow {
                values: vec![CellValue::Int64(idx as i64), value],
            };
            stored.insert(
                crate::codec::encode_primary_key_from_row(0, &row, model).unwrap(),
                crate::writer::encode_base_row_value(&row, model)
                    .unwrap()
                    .into(),
            );
        }
        let batch = RecordBatch::try_new(
            model.schema.clone(),
            vec![
                Arc::new(Int64Array::from_iter_values(0..array.len() as i64)),
                array,
            ],
        )
        .unwrap();
        self.native
            .register_table(
                "numbers",
                Arc::new(MemTable::try_new(batch.schema(), vec![vec![batch]]).unwrap()),
            )
            .unwrap();
    }

    async fn check(&self, sql: &str, reductions: usize) {
        let expected = values(&self.native, sql).await.unwrap();
        self.rows.paths.lock().unwrap().clear();
        self.rows.reductions.lock().unwrap().clear();
        self.rows.scanned_rows.store(0, AtomicOrdering::Relaxed);
        let actual = values(&self.store, sql).await.unwrap();
        assert_eq!(actual, expected, "{sql}");
        let requests = self.rows.reductions.lock().unwrap();
        for (idx, request) in requests.iter().enumerate() {
            assert_eq!(
                request.min_sequence_number,
                (idx > 0).then_some(7),
                "shared read floor: {sql}"
            );
        }
        let paths = self.rows.paths.lock().unwrap();
        assert_eq!(
            paths.iter().filter(|p| p.ends_with("/Reduce")).count(),
            reductions,
            "{sql}: {paths:?}"
        );
        assert!(
            !paths
                .iter()
                .any(|p| p.ends_with("/Range") || p.ends_with("/GetMany")),
            "{sql}: {paths:?}"
        );
    }
}

async fn values(ctx: &SessionContext, sql: &str) -> DataFusionResult<Vec<Vec<ScalarValue>>> {
    let batches = ctx.sql(sql).await?.collect().await?;
    batches
        .iter()
        .flat_map(|batch| {
            (0..batch.num_rows()).map(|row| {
                (0..batch.num_columns())
                    .map(|col| ScalarValue::try_from_array(batch.column(col), row))
                    .collect()
            })
        })
        .collect()
}

#[tokio::test]
async fn existing_reduce_capabilities_use_one_request() {
    let fixture = Fixture::new().await;
    for sql in [
        "SELECT SUM(amount), MIN(amount), MAX(amount), AVG(amount) FROM orders",
        "SELECT SUM(amount) FROM orders WHERE status = 'open'",
        "SELECT DISTINCT region FROM orders ORDER BY region",
        "SELECT region FROM orders GROUP BY region ORDER BY region",
        "SELECT SUM(q.v), AVG(q.v) FROM (SELECT amount AS v FROM orders) q",
    ] {
        fixture.check(sql, 1).await;
    }
}

#[tokio::test]
async fn limited_distinct_preserves_native_aggregation_limits() {
    use datafusion::physical_plan::aggregates::AggregateExec;

    let fixture = Fixture::new().await;
    for ctx in [&fixture.native, &fixture.store] {
        values(ctx, "SET datafusion.execution.target_partitions = 1")
            .await
            .unwrap();
    }
    for (sql, unordered_input) in [
        ("SELECT DISTINCT id FROM orders LIMIT 1", false),
        ("SELECT DISTINCT status FROM orders LIMIT 1", true),
    ] {
        let native_plan = fixture
            .native
            .sql(sql)
            .await
            .unwrap()
            .create_physical_plan()
            .await
            .unwrap();
        assert!(native_plan
            .exists(|node| Ok(node
                .downcast_ref::<AggregateExec>()
                .and_then(AggregateExec::limit_options)
                .is_some_and(|options| options.limit() == 1)))
            .unwrap());
        let frame = fixture.store.sql(sql).await.unwrap();
        let logical = frame.clone().into_optimized_plan().unwrap();
        let physical = frame.create_physical_plan().await.unwrap();
        let expected = values(&fixture.native, sql).await.unwrap();
        fixture.rows.paths.lock().unwrap().clear();
        fixture.rows.reductions.lock().unwrap().clear();
        let actual = values(&fixture.store, sql).await.unwrap();
        let paths = fixture.rows.paths.lock().unwrap().clone();
        assert_eq!(
            paths
                .iter()
                .filter(|path| path.ends_with("/Reduce"))
                .count(),
            0,
            "{sql}: {paths:?}\n{}",
            datafusion::physical_plan::displayable(physical.as_ref()).indent(true),
        );
        assert_eq!(
            paths.iter().filter(|path| path.ends_with("/Range")).count(),
            1,
            "{sql}: {paths:?}",
        );
        assert_eq!(actual, expected, "{sql}");
        assert!(logical
            .exists(|node| Ok(
                matches!(node, LogicalPlan::Aggregate(aggregate) if aggregate.aggr_expr.is_empty())
            ))
            .unwrap());
        assert!(physical
            .exists(|node| Ok(node.downcast_ref::<AggregateExec>().is_some()))
            .unwrap());
        if unordered_input {
            assert!(physical
                .exists(|node| Ok(node
                    .downcast_ref::<AggregateExec>()
                    .and_then(AggregateExec::limit_options)
                    .is_some_and(|options| options.limit() == 1)))
                .unwrap());
        }
    }
    fixture
        .check("SELECT DISTINCT id FROM orders ORDER BY id", 1)
        .await;
    fixture
        .check("SELECT COUNT(*) FROM orders LIMIT 1", 1)
        .await;
}

#[tokio::test]
async fn interleaved_jobs_preserve_output_positions() {
    let fixture = Fixture::new().await;
    fixture.check("SELECT SUM(amount), COUNT(*) FILTER (WHERE status = 'open'), AVG(amount), MIN(amount), MAX(amount) FROM orders", 2).await;
    fixture.check("SELECT region, SUM(amount), COUNT(*) FILTER (WHERE status = 'open'), AVG(amount), MIN(amount), MAX(amount) FROM orders GROUP BY region ORDER BY region", 2).await;
}

#[tokio::test]
async fn filtered_groups_keep_empty_aggregates_and_avoid_duplicate_seed() {
    let fixture = Fixture::new().await;
    fixture.check("SELECT region, COUNT(*), COUNT(*) FILTER (WHERE status = 'open') FROM orders GROUP BY region ORDER BY region", 2).await;
    fixture.check("SELECT region, SUM(amount) FILTER (WHERE status = 'open'), COUNT(*) FILTER (WHERE status = 'open') FROM orders GROUP BY region ORDER BY region", 2).await;
}

#[tokio::test]
async fn integer_arithmetic_matches_native_in_both_ansi_modes() {
    let fixture = Fixture::new().await;
    let sql = "SELECT COUNT(*), SUM(amount + 9223372036854775807) FROM orders";
    fixture.check(sql, 1).await;
    for ctx in [&fixture.native, &fixture.store] {
        values(ctx, "SET datafusion.execution.enable_ansi_mode = true")
            .await
            .unwrap();
    }
    fixture.check(sql, 1).await;
}

#[tokio::test]
async fn avg_converts_each_integer_before_accumulation() {
    let fixture = Fixture::with_amounts([Some(i64::MAX), Some(i64::MAX), None, Some(3)]).await;
    fixture
        .check(
            "SELECT SUM(amount), AVG(amount), MIN(amount), MAX(amount) FROM orders",
            1,
        )
        .await;
}

#[tokio::test]
async fn unsupported_casts_division_and_filters_keep_native_semantics() {
    let fixture = Fixture::with_amounts([Some(257), Some(30), None, Some(20)]).await;
    for sql in [
        "SELECT SUM(amount / 2), COUNT(*) FROM orders",
        "SELECT SUM(TRY_CAST(amount AS TINYINT)) FROM orders",
        "SELECT COUNT(*) FROM orders WHERE TRY_CAST(status AS BIGINT) IS NULL",
        "SELECT SUM(amount) FROM orders WHERE status = 'open' AND amount % 3 = 1",
        "SELECT COUNT(*) FILTER (WHERE amount / 2 > 10) FROM orders",
        "SELECT SUM(amount) FROM (SELECT amount FROM orders LIMIT 2) q",
    ] {
        let expected = values(&fixture.native, sql).await.unwrap();
        let actual = values(&fixture.store, sql).await.unwrap();
        assert_eq!(actual, expected, "{sql}");
    }
    let sql = "SELECT SUM(CAST(amount AS TINYINT)) FROM orders";
    assert!(values(&fixture.native, sql).await.is_err());
    assert!(values(&fixture.store, sql).await.is_err());
}

#[tokio::test]
async fn empty_inputs_and_null_groups_preserve_aggregate_shapes() {
    let fixture = Fixture::with_amounts([None; 4]).await;
    fixture
        .check(
            "SELECT SUM(amount), AVG(amount), MIN(amount), MAX(amount), COUNT(amount) FROM orders",
            1,
        )
        .await;
    fixture
        .check(
            "SELECT SUM(amount), AVG(amount), COUNT(*) FROM orders WHERE status = 'missing'",
            1,
        )
        .await;
    fixture
        .check(
            "SELECT DISTINCT region FROM orders WHERE status = 'missing'",
            1,
        )
        .await;
}

#[tokio::test]
async fn float_groups_and_worker_filters_match_native_ordering() {
    let fixture = Fixture::new().await;
    let values = vec![
        Some(-0.0),
        Some(0.0),
        Some(f64::NEG_INFINITY),
        Some(f64::INFINITY),
        Some(f64::NAN),
        Some(-f64::NAN),
        None,
    ];
    fixture
        .replace_value_column(
            DataType::Float64,
            values
                .iter()
                .map(|value| value.map(CellValue::Float64).unwrap_or(CellValue::Null))
                .collect(),
            Arc::new(Float64Array::from(values)),
        )
        .await;
    for sql in [
        "SELECT value, COUNT(*) FROM numbers GROUP BY value ORDER BY value",
        "SELECT MIN(value), MAX(value) FROM numbers",
        "SELECT COUNT(*) FROM numbers WHERE value = 0.0",
        "SELECT COUNT(*) FROM numbers WHERE value > 0.0",
        "SELECT COUNT(*) FROM numbers WHERE value < 0.0",
        "SELECT COUNT(*) FROM numbers WHERE value >= 'NaN'::DOUBLE",
    ] {
        fixture.check(sql, 1).await;
    }
}

#[tokio::test]
async fn fixed_binary_value_widths_preserve_native_aggregates() {
    let mut failures = Vec::new();
    for width in [0, 255, 256, 300] {
        let fixture = Fixture::new().await;
        let mut array = FixedSizeBinaryBuilder::new(width);
        let mut cells = Vec::new();
        for byte in [Some(1), Some(1), Some(2), None] {
            if let Some(byte) = byte {
                let value = vec![byte; width as usize];
                array.append_value(&value).unwrap();
                cells.push(CellValue::FixedBinary(value));
            } else {
                array.append_null();
                cells.push(CellValue::Null);
            }
        }
        fixture
            .replace_value_column(
                DataType::FixedSizeBinary(width),
                cells,
                Arc::new(array.finish()),
            )
            .await;
        for sql in [
            "SELECT COUNT(value) FROM numbers",
            "SELECT value, COUNT(*) FROM numbers GROUP BY value ORDER BY value",
            "SELECT COUNT(*) FROM numbers WHERE value IS NOT NULL",
        ] {
            // Native grouping cannot materialize zero-width binary output arrays
            if width == 0 && sql.contains("GROUP BY") {
                continue;
            }
            let expected = values(&fixture.native, sql).await.unwrap();
            fixture.rows.paths.lock().unwrap().clear();
            match values(&fixture.store, sql).await {
                Ok(actual) => {
                    assert_eq!(actual, expected, "width {width}: {sql}");
                    let paths = fixture.rows.paths.lock().unwrap();
                    assert_eq!(
                        paths
                            .iter()
                            .filter(|path| path.ends_with("/Reduce"))
                            .count(),
                        usize::from(width <= 255),
                        "width {width}: {sql}: {paths:?}"
                    );
                    assert_eq!(
                        paths.iter().filter(|path| path.ends_with("/Range")).count(),
                        usize::from(width > 255),
                        "width {width}: {sql}: {paths:?}"
                    );
                }
                Err(error) => failures.push(format!("width {width}: {sql}: {error}")),
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn count_output_uses_native_checked_conversion() {
    let output = AggregateOutputPlan::Direct {
        reducer_idx: 0,
        data_type: DataType::Int64,
    };
    let reducers = [RangeReducerSpec {
        op: RangeReduceOp::CountAll,
        expr: None,
    }];
    for count in [0, i64::MAX as u64, i64::MAX as u64 + 1, u64::MAX] {
        let native = ScalarValue::UInt64(Some(count)).cast_to(&DataType::Int64);
        let actual = finalize_aggregate_output(
            &output,
            Some(&[RangeReduceResult {
                value: Some(KvReducedValue::UInt64(count)),
            }]),
            &reducers,
        );
        if count <= i64::MAX as u64 {
            assert_eq!(actual.unwrap(), native.unwrap());
        } else {
            assert!(native.is_err());
            assert!(actual.is_err());
        }
    }
}

#[tokio::test]
async fn unsigned_and_decimal_accumulation_match_native() {
    let fixture = Fixture::new().await;
    fixture
        .replace_value_column(
            DataType::UInt64,
            vec![
                CellValue::UInt64(u64::MAX),
                CellValue::UInt64(2),
                CellValue::Null,
            ],
            Arc::new(UInt64Array::from(vec![Some(u64::MAX), Some(2), None])),
        )
        .await;
    fixture
        .check(
            "SELECT SUM(value), MIN(value), MAX(value), AVG(value) FROM numbers",
            1,
        )
        .await;
    fixture
        .check(
            "SELECT SUM(value + CAST(1 AS BIGINT UNSIGNED)) FROM numbers",
            1,
        )
        .await;
    let fixture = Fixture::new().await;
    fixture
        .replace_value_column(
            DataType::Decimal128(10, 2),
            vec![
                CellValue::Decimal128(1234),
                CellValue::Decimal128(-501),
                CellValue::Null,
            ],
            Arc::new(
                Decimal128Array::from(vec![Some(1234), Some(-501), None])
                    .with_precision_and_scale(10, 2)
                    .unwrap(),
            ),
        )
        .await;
    fixture
        .check(
            "SELECT SUM(value), MIN(value), MAX(value), COUNT(value) FROM numbers",
            1,
        )
        .await;
    fixture
        .check(
            "SELECT SUM(value), MIN(value), MAX(value) FROM numbers WHERE id > 5",
            1,
        )
        .await;
    for sql in [
        "SELECT AVG(value) FROM numbers",
        "SELECT SUM(CAST(value AS DECIMAL(10, 1))) FROM numbers",
    ] {
        assert_eq!(
            values(&fixture.store, sql).await.unwrap(),
            values(&fixture.native, sql).await.unwrap(),
            "{sql}"
        );
    }
}

#[tokio::test]
async fn sum_case_one_preserves_null_when_no_rows_contribute() {
    let fixture = Fixture::new().await;
    fixture.check("SELECT SUM(CASE WHEN status = 'missing' THEN 1 END), COUNT(CASE WHEN status = 'missing' THEN 1 END) FROM orders", 1).await;
    fixture.check("SELECT region, SUM(CASE WHEN status = 'open' THEN 1 END), COUNT(*) FROM orders GROUP BY region ORDER BY region", 2).await;
}

#[tokio::test]
async fn variable_text_keys_use_stored_fields_or_native_decoding() {
    let fixture = Fixture::new().await;
    let provider = fixture.store.table_provider("orders").await.unwrap();
    let client = provider.downcast_ref::<KvTable>().unwrap().client.clone();
    let schema = crate::KvSchema::new(client)
        .table(
            "texts",
            vec![
                TableColumnConfig::new("id", DataType::Utf8, false),
                TableColumnConfig::new("suffix", DataType::Int64, false),
                TableColumnConfig::new("label", DataType::Utf8, false),
                TableColumnConfig::new("measure", DataType::Int64, false),
            ],
            vec!["id".to_string(), "suffix".to_string()],
            vec![IndexSpec::new("label_idx", vec!["label".to_string()])
                .unwrap()
                .with_cover_columns(vec!["measure".to_string()])],
        )
        .unwrap();
    schema.register_all(&fixture.store).unwrap();
    let provider = fixture.store.table_provider("texts").await.unwrap();
    let table = provider.downcast_ref::<KvTable>().unwrap();
    let ids = [
        "short",
        "very-long-primary-key-over-sixteen-bytes",
        "a\0b",
        "a\u{1}b",
    ];
    let labels = [
        "x",
        "label-longer-than-sixteen-bytes",
        "label\0zero",
        "label\u{1}escape",
    ];
    {
        let mut stored = fixture.rows.values.lock().unwrap();
        stored.clear();
        for idx in 0..4 {
            let row = KvRow {
                values: vec![
                    CellValue::Utf8(ids[idx].to_string()),
                    CellValue::Int64(idx as i64),
                    CellValue::Utf8(labels[idx].to_string()),
                    CellValue::Int64(10),
                ],
            };
            stored.insert(
                crate::codec::encode_primary_key_from_row(0, &row, &table.model).unwrap(),
                crate::writer::encode_base_row_value(&row, &table.model)
                    .unwrap()
                    .into(),
            );
            let spec = &table.index_specs[0];
            stored.insert(
                crate::codec::encode_secondary_index_key(0, spec, &table.model, &row).unwrap(),
                crate::writer::encode_secondary_index_value(&row, &table.model, spec)
                    .unwrap()
                    .into(),
            );
        }
    }
    let batch = RecordBatch::try_new(
        table.model.schema.clone(),
        vec![
            Arc::new(StringArray::from(ids.to_vec())),
            Arc::new(Int64Array::from(vec![0, 1, 2, 3])),
            Arc::new(StringArray::from(labels.to_vec())),
            Arc::new(Int64Array::from(vec![10; 4])),
        ],
    )
    .unwrap();
    fixture
        .native
        .register_table(
            "texts",
            Arc::new(MemTable::try_new(batch.schema(), vec![vec![batch]]).unwrap()),
        )
        .unwrap();
    fixture.check("SELECT label, SUM(measure), COUNT(*) FROM texts WHERE label = 'label-longer-than-sixteen-bytes' GROUP BY label ORDER BY label", 1).await;
    for sql in [
        "SELECT id, SUM(suffix) FROM texts GROUP BY id ORDER BY id",
        "SELECT SUM(suffix) FROM texts",
    ] {
        assert_eq!(
            values(&fixture.store, sql).await.unwrap(),
            values(&fixture.native, sql).await.unwrap(),
            "{sql}"
        );
    }
}

#[tokio::test]
async fn fusion_and_seed_elimination_reduce_store_rows_with_one_session() {
    let fixture = Fixture::new().await;
    fixture
        .check(
            "SELECT SUM(amount), MIN(amount), MAX(amount), AVG(amount) FROM orders",
            1,
        )
        .await;
    assert_eq!(fixture.rows.scanned_rows.load(AtomicOrdering::Relaxed), 4);
    fixture.check("SELECT region, COUNT(*), COUNT(*) FILTER (WHERE status = 'open') FROM orders GROUP BY region ORDER BY region", 2).await;
    assert_eq!(fixture.rows.scanned_rows.load(AtomicOrdering::Relaxed), 8);
    fixture
        .check(
            "SELECT SUM(amount), MIN(amount), MAX(amount) FROM orders WHERE id IN (1, 4)",
            2,
        )
        .await;
    assert_eq!(fixture.rows.scanned_rows.load(AtomicOrdering::Relaxed), 2);
}

#[tokio::test]
async fn deterministic_reduce_errors_are_not_retried_by_the_sdk() {
    let fixture = Fixture::new().await;
    let provider = fixture.store.table_provider("orders").await.unwrap();
    let session = provider
        .downcast_ref::<KvTable>()
        .unwrap()
        .client
        .create_session();
    let start = Bytes::from_static(&[0]);
    let end = Bytes::from_static(&[1]);
    let invalid = RangeReduceRequest {
        reducers: vec![RangeReducerSpec {
            op: RangeReduceOp::CountAll,
            expr: Some(KvExpr::Literal(KvReducedValue::Int64(1))),
        }],
        group_by: vec![],
        filter: None,
    };
    let error = session
        .range_reduce_response(&start, &end, &invalid)
        .await
        .unwrap_err();
    assert_eq!(
        error.rpc_code(),
        Some(connectrpc::ErrorCode::InvalidArgument)
    );
    assert_eq!(fixture.rows.reductions.lock().unwrap().len(), 1);
    assert_eq!(fixture.rows.scanned_rows.load(AtomicOrdering::Relaxed), 0);
    fixture.rows.reductions.lock().unwrap().clear();
    *fixture
        .rows
        .values
        .lock()
        .unwrap()
        .first_entry()
        .unwrap()
        .get_mut() = Bytes::from_static(b"invalid row");
    let request = RangeReduceRequest {
        reducers: vec![RangeReducerSpec {
            op: RangeReduceOp::SumField,
            expr: Some(KvExpr::Field(KvFieldRef::Value {
                index: 3,
                kind: KvFieldKind::Int64,
                nullable: true,
            })),
        }],
        group_by: vec![],
        filter: None,
    };
    let error = session
        .range_reduce_response(&start, &end, &request)
        .await
        .unwrap_err();
    assert_eq!(
        error.rpc_code(),
        Some(connectrpc::ErrorCode::FailedPrecondition)
    );
    assert_eq!(fixture.rows.reductions.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn overlapping_secondary_ranges_do_not_double_count_rows() {
    let fixture = Fixture::new().await;
    let provider = fixture.store.table_provider("orders").await.unwrap();
    let client = provider.downcast_ref::<KvTable>().unwrap().client.clone();
    let schema = crate::KvSchema::new(client)
        .table(
            "points",
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("x", DataType::Int64, false),
                TableColumnConfig::new("y", DataType::Int64, false),
                TableColumnConfig::new("measure", DataType::Int64, false),
            ],
            vec!["id".to_string()],
            vec![IndexSpec::new("xy", vec!["x".to_string(), "y".to_string()])
                .unwrap()
                .with_cover_columns(vec!["measure".to_string()])],
        )
        .unwrap();
    schema.register_all(&fixture.store).unwrap();
    let provider = fixture.store.table_provider("points").await.unwrap();
    let table = provider.downcast_ref::<KvTable>().unwrap();
    {
        let mut stored = fixture.rows.values.lock().unwrap();
        stored.clear();
        for id in [1, 2] {
            let row = KvRow {
                values: vec![
                    CellValue::Int64(id),
                    CellValue::Int64(2),
                    CellValue::Int64(id),
                    CellValue::Int64(id * 10),
                ],
            };
            stored.insert(
                crate::codec::encode_primary_key_from_row(0, &row, &table.model).unwrap(),
                crate::writer::encode_base_row_value(&row, &table.model)
                    .unwrap()
                    .into(),
            );
            let spec = &table.index_specs[0];
            stored.insert(
                crate::codec::encode_secondary_index_key(0, spec, &table.model, &row).unwrap(),
                crate::writer::encode_secondary_index_value(&row, &table.model, spec)
                    .unwrap()
                    .into(),
            );
        }
    }
    let batch = RecordBatch::try_new(
        table.model.schema.clone(),
        vec![
            Arc::new(Int64Array::from(vec![1, 2])),
            Arc::new(Int64Array::from(vec![2, 2])),
            Arc::new(Int64Array::from(vec![1, 2])),
            Arc::new(Int64Array::from(vec![10, 20])),
        ],
    )
    .unwrap();
    fixture
        .native
        .register_table(
            "points",
            Arc::new(MemTable::try_new(batch.schema(), vec![vec![batch]]).unwrap()),
        )
        .unwrap();
    fixture
        .check(
            "SELECT COUNT(*), SUM(measure) FROM points WHERE x BETWEEN 1 AND 3 AND y IN (1, 2)",
            1,
        )
        .await;
    assert_eq!(fixture.rows.scanned_rows.load(AtomicOrdering::Relaxed), 2);
}

#[tokio::test]
async fn timestamp_casts_preserve_native_values_and_reduce_identity_casts() {
    use datafusion::arrow::array::TimestampMicrosecondArray;

    for source_timezone in [None, Some(Arc::<str>::from("+02:00"))] {
        let fixture = Fixture::new().await;
        fixture
            .replace_value_column(
                DataType::Timestamp(TimeUnit::Microsecond, source_timezone.clone()),
                vec![CellValue::Timestamp(0), CellValue::Null],
                Arc::new(
                    TimestampMicrosecondArray::from(vec![Some(0), None])
                        .with_timezone_opt(source_timezone.clone()),
                ),
            )
            .await;
        for target_timezone in [None, Some("-05:00"), Some("UTC")] {
            let expr = format!("arrow_cast(value, 'Timestamp(Microsecond, {target_timezone:?})')");
            let identity = source_timezone.is_some() || target_timezone.is_none();
            for sql in [
                format!("SELECT MIN({expr}), MAX({expr}) FROM numbers"),
                format!("SELECT {expr}, COUNT(*) FROM numbers GROUP BY {expr} ORDER BY 1"),
            ] {
                if identity {
                    fixture.check(&sql, 1).await;
                } else {
                    let expected = values(&fixture.native, &sql).await.unwrap();
                    fixture.rows.reductions.lock().unwrap().clear();
                    let actual = values(&fixture.store, &sql).await.unwrap();
                    assert_eq!(actual, expected, "{sql}");
                    assert!(fixture.rows.reductions.lock().unwrap().is_empty(), "{sql}");
                }
            }
        }
    }
}

#[tokio::test]
async fn naive_timestamp_casts_preserve_native_errors_and_nulls() {
    use datafusion::arrow::array::TimestampMicrosecondArray;
    use datafusion::functions_aggregate::expr_fn::min;
    use datafusion::logical_expr::{Cast, TryCast};
    use datafusion::prelude::col;

    let fixture = Fixture::new().await;
    fixture
        .replace_value_column(
            DataType::Timestamp(TimeUnit::Microsecond, None),
            vec![CellValue::Timestamp(i64::MAX)],
            Arc::new(TimestampMicrosecondArray::from(vec![i64::MAX])),
        )
        .await;
    for try_cast in [true, false] {
        let target = DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into()));
        let expr = if try_cast {
            Expr::TryCast(TryCast::new(Box::new(col("value")), target.clone()))
        } else {
            Expr::Cast(Cast::new(Box::new(col("value")), target.clone()))
        };
        let mut results = Vec::new();
        fixture.rows.reductions.lock().unwrap().clear();
        for ctx in [&fixture.native, &fixture.store] {
            results.push(
                ctx.table("numbers")
                    .await
                    .unwrap()
                    .aggregate(vec![], vec![min(expr.clone())])
                    .unwrap()
                    .collect()
                    .await,
            );
        }
        for result in results {
            if try_cast {
                let batches = result.unwrap();
                assert_eq!(
                    ScalarValue::try_from_array(batches[0].column(0), 0).unwrap(),
                    ScalarValue::try_new_null(&target).unwrap()
                );
            } else {
                assert!(result.is_err());
            }
        }
        assert!(fixture.rows.reductions.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn tagged_date_trunc_preserves_native_timestamp_overflow_errors() {
    use datafusion::arrow::array::TimestampMicrosecondArray;
    for timezone in [
        Some(Arc::<str>::from("UTC")),
        Some(Arc::<str>::from("+00:00")),
        None,
    ] {
        let fixture = Fixture::new().await;
        let timestamp = 10_000_000_000_000_000;
        fixture
            .replace_value_column(
                DataType::Timestamp(TimeUnit::Microsecond, timezone.clone()),
                vec![CellValue::Timestamp(timestamp)],
                Arc::new(
                    TimestampMicrosecondArray::from(vec![timestamp])
                        .with_timezone_opt(timezone.clone()),
                ),
            )
            .await;
        let sql = "SELECT date_trunc('day', value), COUNT(*) FROM numbers GROUP BY date_trunc('day', value)";
        if timezone.is_some() {
            let native_error = values(&fixture.native, sql).await.unwrap_err();
            assert!(
                native_error.to_string().contains("out of range"),
                "{native_error}"
            );
            let store_error = values(&fixture.store, sql).await.unwrap_err();
            assert!(
                store_error.to_string().contains("out of range"),
                "{store_error}"
            );
            assert!(fixture.rows.reductions.lock().unwrap().is_empty());
        } else {
            fixture.check(sql, 1).await;
        }
    }
}

#[tokio::test]
async fn secondary_float_boundaries_are_rechecked_before_reduction() {
    let fixture = Fixture::new().await;
    fixture
        .install_indexed_table(
            "scores",
            vec![
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("score", DataType::Float64, false),
            ],
            &["id"],
            vec![IndexSpec::new("score_idx", vec!["score".to_string()]).unwrap()],
            (0..4)
                .map(|id| KvRow {
                    values: vec![CellValue::Int64(id), CellValue::Float64(id as f64)],
                })
                .collect(),
            vec![
                Arc::new(Int64Array::from(vec![0, 1, 2, 3])),
                Arc::new(Float64Array::from(vec![0.0, 1.0, 2.0, 3.0])),
            ],
        )
        .await;
    for sql in [
        "SELECT COUNT(*), SUM(id) FROM scores WHERE score > 1.0",
        "SELECT COUNT(*), SUM(id) FROM scores WHERE score < 2.0",
    ] {
        fixture.check(sql, 1).await;
        assert!(fixture.rows.reductions.lock().unwrap()[0]
            .params
            .filter
            .as_option()
            .is_some());
    }
}

#[tokio::test]
async fn secondary_variable_key_prefix_does_not_skip_primary_suffix_filter() {
    let fixture = Fixture::new().await;
    let entries = [(0, 2), (1, 1), (1, 2), (2, 3)];
    fixture
        .install_indexed_table(
            "tenants",
            vec![
                TableColumnConfig::new("tenant", DataType::Int64, false),
                TableColumnConfig::new("id", DataType::Int64, false),
                TableColumnConfig::new("status", DataType::Utf8, false),
            ],
            &["tenant", "id"],
            vec![IndexSpec::new("status_idx", vec!["status".to_string()]).unwrap()],
            entries
                .iter()
                .map(|(tenant, id)| KvRow {
                    values: vec![
                        CellValue::Int64(*tenant),
                        CellValue::Int64(*id),
                        CellValue::Utf8("open".to_string()),
                    ],
                })
                .collect(),
            vec![
                Arc::new(Int64Array::from(vec![0, 1, 1, 2])),
                Arc::new(Int64Array::from(vec![2, 1, 2, 3])),
                Arc::new(StringArray::from(vec!["open"; 4])),
            ],
        )
        .await;
    let sql = "SELECT COUNT(*) FROM tenants WHERE status = 'open' AND id = 2";
    assert_eq!(
        values(&fixture.store, sql).await.unwrap(),
        values(&fixture.native, sql).await.unwrap()
    );
    assert!(fixture.rows.reductions.lock().unwrap().is_empty());
}
