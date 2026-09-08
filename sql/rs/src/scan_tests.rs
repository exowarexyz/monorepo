use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use bytes::Bytes;
use datafusion::arrow::array::{
    ArrayRef, Decimal128Array, FixedSizeBinaryArray, Float64Array, Int64Array, StringArray,
    TimestampMicrosecondArray, UInt64Array,
};
use datafusion::arrow::datatypes::{DataType, TimeUnit};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::common::{Result as DataFusionResult, ScalarValue};
use datafusion::datasource::MemTable;
use datafusion::prelude::SessionContext;
use exoware_sdk::{StoreClient, StoreKeyPrefix};
use exoware_server::{Query, QueryExtra, QueryState, RangeScan, RangeScanBatch, Sequence};

use crate::types::KvTable;
use crate::{IndexSpec, KvSchema, TableColumnConfig};

#[derive(Clone, Debug)]
enum Request {
    Get(Bytes),
    GetMany(Vec<Bytes>),
    Range {
        start: Bytes,
        end: Bytes,
        limit: usize,
        forward: bool,
    },
}

#[derive(Default)]
struct Rows {
    values: Mutex<BTreeMap<Bytes, Bytes>>,
    requests: Mutex<Vec<Request>>,
    returned_rows: Arc<AtomicUsize>,
    returned_bytes: Arc<AtomicUsize>,
}

impl Sequence for Rows {
    fn current_sequence(&self) -> u64 {
        7
    }
}

struct Cursor {
    rows: std::vec::IntoIter<(Bytes, Bytes)>,
    returned_rows: Arc<AtomicUsize>,
    returned_bytes: Arc<AtomicUsize>,
}

impl RangeScan for Cursor {
    async fn next_batch(&mut self, max_items: usize) -> Result<RangeScanBatch, String> {
        let rows: Vec<_> = self.rows.by_ref().take(max_items).collect();
        self.returned_rows.fetch_add(rows.len(), Ordering::SeqCst);
        self.returned_bytes.fetch_add(
            rows.iter()
                .map(|(key, value)| key.len() + value.len())
                .sum(),
            Ordering::SeqCst,
        );
        Ok(RangeScanBatch {
            rows,
            extra: QueryExtra::new(),
        })
    }
}

impl Query for Rows {
    type RangeScan = Cursor;

    async fn get(&self, key: Bytes) -> Result<(Option<Bytes>, QueryExtra), String> {
        self.requests
            .lock()
            .unwrap()
            .push(Request::Get(key.clone()));
        Ok((
            self.values.lock().unwrap().get(&key).cloned(),
            QueryExtra::new(),
        ))
    }

    async fn get_many(
        &self,
        keys: Vec<Bytes>,
    ) -> Result<(Vec<(Bytes, Option<Bytes>)>, QueryExtra), String> {
        self.requests
            .lock()
            .unwrap()
            .push(Request::GetMany(keys.clone()));
        let values = self.values.lock().unwrap();
        let rows: Vec<_> = keys
            .into_iter()
            .rev()
            .map(|key| {
                let value = values.get(&key).cloned();
                (key, value)
            })
            .collect();
        self.returned_rows.fetch_add(rows.len(), Ordering::SeqCst);
        self.returned_bytes.fetch_add(
            rows.iter()
                .map(|(key, value)| key.len() + value.as_ref().map_or(0, Bytes::len))
                .sum(),
            Ordering::SeqCst,
        );
        Ok((rows, QueryExtra::new()))
    }

    async fn range_scan(
        &self,
        start: Bytes,
        end: Bytes,
        limit: usize,
        forward: bool,
    ) -> Result<Cursor, String> {
        self.requests.lock().unwrap().push(Request::Range {
            start: start.clone(),
            end: end.clone(),
            limit,
            forward,
        });
        let mut rows: Vec<_> = self
            .values
            .lock()
            .unwrap()
            .iter()
            .filter(|(key, _)| **key >= start && (end.is_empty() || **key <= end))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        if !forward {
            rows.reverse();
        }
        rows.truncate(limit);
        Ok(Cursor {
            rows: rows.into_iter(),
            returned_rows: self.returned_rows.clone(),
            returned_bytes: self.returned_bytes.clone(),
        })
    }
}

struct Fixture {
    store: SessionContext,
    native: SessionContext,
    rows: Arc<Rows>,
    table: Arc<KvTable>,
    prefix: StoreKeyPrefix,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Fixture {
    async fn new(
        columns: Vec<TableColumnConfig>,
        primary_key: &[&str],
        indexes: Vec<IndexSpec>,
        arrays: Vec<ArrayRef>,
    ) -> Self {
        let rows = Arc::new(Rows::default());
        let app = Router::new()
            .fallback_service(exoware_server::query_service(QueryState::new(rows.clone())));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let prefix = StoreKeyPrefix::new(Bytes::from_static(b"scan-tests/")).unwrap();
        let schema = KvSchema::new(StoreClient::new(&url).prefixed(prefix.clone()))
            .table(
                "orders",
                columns,
                primary_key.iter().map(|name| name.to_string()).collect(),
                indexes,
            )
            .unwrap();
        let table = schema.tables()[0].1.clone();
        let batch = RecordBatch::try_new(table.model.schema.clone(), arrays).unwrap();
        let entries =
            crate::writer::encode_insert_entries(&batch, &table.model, &table.index_specs).unwrap();
        rows.values.lock().unwrap().extend(
            entries
                .into_iter()
                .map(|(key, value)| (prefix.encode_key(&key).unwrap(), Bytes::from(value))),
        );
        let store = crate::session_context();
        schema.register_all(&store).unwrap();
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
            table,
            prefix,
            server,
        }
    }

    async fn check(&self, sql: &str) -> Vec<Request> {
        let expected = values(&self.native, sql).await.unwrap();
        self.rows.requests.lock().unwrap().clear();
        self.rows.returned_rows.store(0, Ordering::SeqCst);
        self.rows.returned_bytes.store(0, Ordering::SeqCst);
        let actual = values(&self.store, sql).await.unwrap();
        assert_eq!(actual, expected, "{sql}");
        let requests = self.rows.requests.lock().unwrap().clone();
        for request in &requests {
            match request {
                Request::Get(key) => assert!(self.prefix.matches(key)),
                Request::GetMany(keys) => assert!(keys.iter().all(|key| self.prefix.matches(key))),
                Request::Range { start, end, .. } => {
                    assert!(self.prefix.matches(start));
                    assert!(self.prefix.matches(end));
                }
            }
        }
        requests
    }

    fn index_matches(&self, index: usize, key: &Bytes) -> bool {
        let key = self.prefix.decode_key(key).unwrap();
        self.table.index_specs[index].prefix.matches(&key)
    }
}

async fn values(ctx: &SessionContext, sql: &str) -> DataFusionResult<Vec<Vec<ScalarValue>>> {
    let batches = ctx.sql(sql).await?.collect().await?;
    batches
        .iter()
        .flat_map(|batch| {
            (0..batch.num_rows()).map(|row| {
                (0..batch.num_columns())
                    .map(|column| ScalarValue::try_from_array(batch.column(column), row))
                    .collect()
            })
        })
        .collect()
}

fn column(name: &str, data_type: DataType, nullable: bool) -> TableColumnConfig {
    TableColumnConfig::new(name, data_type, nullable)
}

fn index(name: &str, keys: &[&str], cover: &[&str]) -> IndexSpec {
    IndexSpec::lexicographic(name, keys.iter().map(|name| name.to_string()).collect())
        .unwrap()
        .with_cover_columns(cover.iter().map(|name| name.to_string()).collect())
}

#[tokio::test]
async fn limit_continues_after_invalid_value_at_namespace_key_capacity() {
    let width = exoware_sdk::keys::MAX_KEY_LEN - b"scan-tests/".len() - 1;
    let invalid_pk = vec![0; width];
    let mut valid_pk = invalid_pk.clone();
    valid_pk[width - 1] = 1;
    let fixture = Fixture::new(
        vec![
            column("id", DataType::FixedSizeBinary(width as i32), false),
            column("amount", DataType::Int64, false),
        ],
        &["id"],
        vec![],
        vec![
            Arc::new(FixedSizeBinaryArray::try_from_iter([valid_pk].into_iter()).unwrap()),
            Arc::new(Int64Array::from(vec![42])),
        ],
    )
    .await;
    let logical_key = crate::codec::encode_primary_key(
        fixture.table.model.table_prefix,
        &[&crate::types::CellValue::FixedBinary(invalid_pk)],
        &fixture.table.model,
    )
    .unwrap();
    let invalid_key = fixture.prefix.encode_key(&logical_key).unwrap();
    assert_eq!(invalid_key.len(), exoware_sdk::keys::MAX_KEY_LEN);
    let next_key = exoware_sdk::keys::next_key(&invalid_key).unwrap();
    fixture
        .rows
        .values
        .lock()
        .unwrap()
        .insert(invalid_key, Bytes::from_static(b"invalid row"));

    let requests = fixture.check("SELECT amount FROM orders LIMIT 1").await;
    assert_eq!(requests.len(), 2);
    assert_eq!(fixture.rows.returned_rows.load(Ordering::SeqCst), 2);
    for (i, request) in requests.iter().enumerate() {
        let Request::Range {
            start,
            end,
            limit,
            forward,
        } = request
        else {
            panic!("expected Range, got {request:?}");
        };
        assert_eq!(*limit, 1);
        assert!(*forward);
        assert!(start.len() <= exoware_sdk::keys::MAX_KEY_LEN);
        assert!(end.len() <= exoware_sdk::keys::MAX_KEY_LEN);
        if i == 1 {
            assert_eq!(start, &next_key);
        }
    }
}

#[tokio::test]
async fn native_residuals_preserve_casts_nulls_functions_and_limits() {
    let fixture = Fixture::new(
        vec![
            column("id", DataType::Int64, false),
            column("status", DataType::Utf8, true),
            column("amount", DataType::Int64, false),
        ],
        &["id"],
        vec![],
        vec![
            Arc::new(Int64Array::from(vec![1, 2, 3, 4])),
            Arc::new(StringArray::from(vec![
                Some("open"),
                Some("12"),
                None,
                Some("closed"),
            ])),
            Arc::new(Int64Array::from(vec![10, 20, 30, 40])),
        ],
    )
    .await;
    for sql in [
        "SELECT id FROM orders WHERE TRY_CAST(status AS BIGINT) IS NULL ORDER BY id",
        "SELECT id FROM orders WHERE TRY_CAST(status AS BIGINT) IS NOT NULL ORDER BY id",
        "SELECT id FROM orders WHERE CAST(id AS VARCHAR) = '2' ORDER BY id",
        "SELECT id FROM orders WHERE upper(status) = 'OPEN' ORDER BY id",
        "SELECT id FROM orders WHERE coalesce(status, 'missing') = 'missing' ORDER BY id",
        "SELECT id FROM orders WHERE id > 0 AND CAST(amount AS DOUBLE) / 3 > 8.5 ORDER BY id DESC LIMIT 1",
        "SELECT id FROM orders WHERE id > 0 AND (status LIKE 'op%' OR amount % 3 = 0) ORDER BY id DESC LIMIT 1",
        "SELECT id FROM orders WHERE CASE WHEN status IS NULL THEN TRUE ELSE amount > 30 END ORDER BY id",
        "SELECT 1 FROM orders WHERE upper(status) = 'OPEN'",
        "SELECT 1 FROM orders WHERE TRY_CAST(status AS BIGINT) IS NULL LIMIT 1",
        "SELECT id FROM orders WHERE id > 0 AND random() >= 0 ORDER BY id DESC LIMIT 2",
        "SELECT id FROM orders WHERE NULL",
    ] { fixture.check(sql).await; }
}

#[tokio::test]
async fn numeric_points_batch_missing_keys_and_restore_wire_order() {
    let fixture = Fixture::new(
        vec![
            column("id", DataType::UInt64, false),
            column("amount", DataType::Int64, false),
        ],
        &["id"],
        vec![],
        vec![
            Arc::new(UInt64Array::from(vec![1, 3, 7, u64::MAX])),
            Arc::new(Int64Array::from(vec![10, 30, 70, 90])),
        ],
    )
    .await;
    let requests = fixture.check("SELECT id, amount FROM orders WHERE id IN (1, 2, 7, 18446744073709551615) ORDER BY id DESC").await;
    assert!(
        matches!(requests.as_slice(), [Request::GetMany(keys)] if keys.len() == 4),
        "{requests:?}"
    );
    let requests = fixture.check("SELECT id, amount FROM orders WHERE id IN (1, 2, 3, 7) AND abs(amount - 70) < 1 ORDER BY id LIMIT 1").await;
    assert!(
        matches!(requests.as_slice(), [Request::GetMany(keys)] if keys.len() == 4),
        "{requests:?}"
    );
}

#[tokio::test]
async fn string_points_batch_missing_keys_and_residual_limit() {
    let fixture = Fixture::new(
        vec![
            column("id", DataType::Utf8, false),
            column("amount", DataType::Int64, false),
        ],
        &["id"],
        vec![],
        vec![
            Arc::new(StringArray::from(vec!["a", "b", "c", "d"])),
            Arc::new(Int64Array::from(vec![10, 20, 30, 40])),
        ],
    )
    .await;
    let requests = fixture
        .check("SELECT id FROM orders WHERE id IN ('missing', 'a', 'd', 'b') ORDER BY id DESC")
        .await;
    assert!(
        matches!(requests.as_slice(), [Request::GetMany(keys)] if keys.len() == 4),
        "{requests:?}"
    );
    let overlong = "x".repeat(exoware_sdk::keys::MAX_KEY_LEN + 1);
    fixture
        .check(&format!(
            "SELECT id FROM orders WHERE id IN ('a', '{overlong}') ORDER BY id"
        ))
        .await;
    fixture
        .check(&format!(
            "SELECT id FROM orders WHERE id IN ('{overlong}', '{overlong}y') ORDER BY id"
        ))
        .await;
    let requests = fixture.check("SELECT id FROM orders WHERE id IN ('a', 'b', 'c', 'd') AND amount > 25 ORDER BY id LIMIT 1").await;
    assert!(
        matches!(requests.as_slice(), [Request::GetMany(keys)] if keys.len() == 4),
        "{requests:?}"
    );
}

#[tokio::test]
async fn composite_point_products_restore_descending_order() {
    let fixture = Fixture::new(
        vec![
            column("tenant", DataType::Utf8, false),
            column("version", DataType::Int64, false),
            column("amount", DataType::Int64, false),
        ],
        &["tenant", "version"],
        vec![],
        vec![
            Arc::new(StringArray::from(vec!["a", "a", "a", "b", "b", "b"])),
            Arc::new(Int64Array::from(vec![1, 2, 3, 1, 2, 3])),
            Arc::new(Int64Array::from(vec![10, 20, 30, 40, 50, 60])),
        ],
    )
    .await;
    let requests = fixture.check("SELECT tenant, version, amount FROM orders WHERE tenant IN ('a', 'b') AND version IN (1, 3, 99) ORDER BY tenant DESC, version DESC").await;
    assert!(
        matches!(requests.as_slice(), [Request::GetMany(keys)] if keys.len() == 6),
        "{requests:?}"
    );
    fixture.check("SELECT tenant, version FROM orders WHERE tenant IN ('a', 'b') AND version IN (1, 3, 99) AND amount > 20 ORDER BY tenant DESC, version DESC LIMIT 2").await;
}

#[tokio::test]
async fn covering_selection_includes_projected_and_residual_columns() {
    let fixture = Fixture::new(
        vec![
            column("id", DataType::Int64, false),
            column("status", DataType::Utf8, false),
            column("amount", DataType::Int64, false),
        ],
        &["id"],
        vec![
            index("plain", &["status"], &[]),
            index("cover", &["status"], &["amount"]),
        ],
        vec![
            Arc::new(Int64Array::from(vec![1, 2, 3])),
            Arc::new(StringArray::from(vec!["open", "closed", "open"])),
            Arc::new(Int64Array::from(vec![10, 20, 30])),
        ],
    )
    .await;
    let requests = fixture
        .check("SELECT amount FROM orders WHERE status = 'open' ORDER BY amount")
        .await;
    assert!(
        matches!(requests.as_slice(), [Request::Range { start, .. }] if fixture.index_matches(1, start)),
        "{requests:?}"
    );
    let requests = fixture
        .check("SELECT id FROM orders WHERE status = 'open' AND abs(amount - 30) < 1 ORDER BY id")
        .await;
    assert!(
        matches!(requests.as_slice(), [Request::Range { start, .. }] if fixture.index_matches(1, start)),
        "{requests:?}"
    );
}

#[tokio::test]
async fn covering_index_supplies_reverse_suffix_order_and_limit() {
    let fixture = Fixture::new(
        vec![
            column("id", DataType::Int64, false),
            column("account", DataType::Int64, false),
            column("height", DataType::Int64, false),
            column("payload", DataType::Utf8, false),
        ],
        &["id"],
        vec![index(
            "account_height",
            &["account", "height"],
            &["payload"],
        )],
        vec![
            Arc::new(Int64Array::from(vec![1, 2, 3, 4, 5])),
            Arc::new(Int64Array::from(vec![7, 7, 7, 7, 8])),
            Arc::new(Int64Array::from(vec![10, 20, 30, 40, 99])),
            Arc::new(StringArray::from(vec!["a", "b", "c", "d", "other"])),
        ],
    )
    .await;
    let requests = fixture
        .check("SELECT height, payload FROM orders WHERE account = 7 ORDER BY height DESC LIMIT 2")
        .await;
    assert!(
        matches!(requests.as_slice(), [Request::Range { start, forward: false, limit: 2, .. }] if fixture.index_matches(0, start)),
        "{requests:?}"
    );
    let requests = fixture.check("SELECT height, payload FROM orders WHERE account = 7 AND upper(payload) <> 'D' ORDER BY height DESC LIMIT 2").await;
    assert!(
        matches!(
            requests.as_slice(),
            [Request::Range {
                forward: false,
                limit: usize::MAX,
                ..
            }]
        ),
        "{requests:?}"
    );
    fixture
        .check("SELECT height FROM orders WHERE account = 7 ORDER BY height DESC LIMIT 1 OFFSET 2")
        .await;
}

#[tokio::test]
async fn covering_index_with_multiple_prefix_values_retains_global_sort() {
    let fixture = Fixture::new(
        vec![
            column("id", DataType::Int64, false),
            column("status", DataType::Utf8, false),
            column("amount", DataType::Int64, false),
        ],
        &["id"],
        vec![index("status_amount", &["status", "amount"], &[])],
        vec![
            Arc::new(Int64Array::from(vec![1, 2, 3, 4])),
            Arc::new(StringArray::from(vec!["a", "a", "z", "z"])),
            Arc::new(Int64Array::from(vec![30, 10, 40, 20])),
        ],
    )
    .await;
    for sql in [
        "SELECT amount FROM orders WHERE status IN ('a', 'z') ORDER BY amount LIMIT 3",
        "SELECT amount FROM orders WHERE status IN ('a', 'z') ORDER BY amount DESC LIMIT 3",
    ] {
        let requests = fixture.check(sql).await;
        assert!(
            requests.iter().all(|request| matches!(request,
                Request::Range { start, .. } if fixture.index_matches(0, start)
            )),
            "{requests:?}"
        );
    }
}

#[tokio::test]
async fn bounded_point_expansion_handles_large_lists_and_products() {
    let fixture = Fixture::new(
        vec![column("id", DataType::Int64, false)],
        &["id"],
        vec![],
        vec![Arc::new(Int64Array::from(vec![1, 257, 513]))],
    )
    .await;
    let list = (0..257)
        .map(|i| (2 * i + 1).to_string())
        .collect::<Vec<_>>()
        .join(",");
    let requests = fixture
        .check(&format!(
            "SELECT id FROM orders WHERE id IN ({list}) ORDER BY id DESC"
        ))
        .await;
    assert!(
        matches!(requests.as_slice(), [Request::GetMany(keys)] if keys.len() == 257),
        "{requests:?}"
    );

    let fixture = Fixture::new(
        vec![
            column("tenant", DataType::Utf8, false),
            column("version", DataType::Int64, false),
        ],
        &["tenant", "version"],
        vec![],
        vec![
            Arc::new(StringArray::from(vec![
                "tenant00", "tenant00", "tenant64", "other",
            ])),
            Arc::new(Int64Array::from(vec![0, 64, 64, 0])),
        ],
    )
    .await;
    let tenants = (0..65)
        .map(|i| format!("'tenant{i:02}'"))
        .collect::<Vec<_>>()
        .join(",");
    let versions = (0..65).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
    let requests = fixture.check(&format!("SELECT tenant, version FROM orders WHERE tenant IN ({tenants}) AND version IN ({versions}) ORDER BY tenant, version")).await;
    assert!(
        requests
            .iter()
            .any(|request| matches!(request, Request::Range { .. })),
        "{requests:?}"
    );
    assert!(
        requests
            .iter()
            .all(|request| !matches!(request, Request::GetMany(keys) if keys.len() > 4096)),
        "{requests:?}"
    );
}

#[tokio::test]
async fn decimal_scale_and_timestamp_casts_preserve_native_predicates() {
    for indexed in [false, true] {
        let fixture = Fixture::new(
            vec![
                column("id", DataType::Int64, false),
                column("amount", DataType::Decimal128(12, 2), !indexed),
                column(
                    "happened_at",
                    DataType::Timestamp(TimeUnit::Microsecond, None),
                    !indexed,
                ),
            ],
            &["id"],
            if indexed {
                vec![
                    index("amount", &["amount"], &[]),
                    index("happened_at", &["happened_at"], &[]),
                ]
            } else {
                vec![]
            },
            vec![
                Arc::new(Int64Array::from(if indexed {
                    vec![1, 2, 3, 4]
                } else {
                    vec![1, 2, 3, 4, 5]
                })),
                Arc::new(
                    Decimal128Array::from(if indexed {
                        vec![Some(100), Some(199), Some(200), Some(201)]
                    } else {
                        vec![Some(100), Some(199), Some(200), Some(201), None]
                    })
                    .with_precision_and_scale(12, 2)
                    .unwrap(),
                ),
                Arc::new(TimestampMicrosecondArray::from(if indexed {
                    vec![Some(0), Some(1), Some(1_000_000), Some(1_000_001)]
                } else {
                    vec![Some(0), Some(1), Some(1_000_000), Some(1_000_001), None]
                })),
            ],
        )
        .await;
        for sql in [
            "SELECT id FROM orders WHERE amount > 1.995 ORDER BY id",
            "SELECT id FROM orders WHERE amount = CAST(2 AS DECIMAL(12, 2)) ORDER BY id",
            "SELECT id FROM orders WHERE CAST(amount AS DECIMAL(12, 1)) = 2.0 ORDER BY id",
            "SELECT id FROM orders WHERE CAST(amount AS DOUBLE) < 2.001 ORDER BY id",
            "SELECT id FROM orders WHERE amount IS NULL ORDER BY id",
            "SELECT id FROM orders WHERE happened_at > TIMESTAMP '1970-01-01 00:00:01' ORDER BY id",
            "SELECT id FROM orders WHERE happened_at = TIMESTAMP '1970-01-01 00:00:00.000001' ORDER BY id",
            "SELECT id FROM orders WHERE CAST(happened_at AS BIGINT) > 1000000 ORDER BY id",
            "SELECT id FROM orders WHERE CAST(happened_at AS DATE) = DATE '1970-01-01' ORDER BY id",
            "SELECT id FROM orders WHERE happened_at IS NULL ORDER BY id",
        ] {
            fixture.check(&format!("{sql} /* indexed={indexed} */")).await;
        }
    }
}

#[tokio::test]
async fn covering_predicates_reject_rows_before_base_lookups() {
    let fixture = Fixture::new(
        vec![
            column("id", DataType::Int64, false),
            column("status", DataType::Utf8, false),
            column("amount", DataType::Int64, false),
            column("payload", DataType::Utf8, false),
        ],
        &["id"],
        vec![index("status_amount", &["status"], &["amount"])],
        vec![
            Arc::new(Int64Array::from(vec![1, 2, 3, 4])),
            Arc::new(StringArray::from(vec!["open", "open", "closed", "open"])),
            Arc::new(Int64Array::from(vec![10, 20, 30, 40])),
            Arc::new(StringArray::from(vec!["a", "b", "c", "d"])),
        ],
    )
    .await;
    let requests = fixture.check("SELECT payload FROM orders WHERE status = 'open' AND abs(amount - 40) < 1 ORDER BY payload").await;
    let lookup_keys: Vec<_> = requests
        .iter()
        .filter_map(|request| match request {
            Request::GetMany(keys) => Some(keys),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(lookup_keys.len(), 1, "{requests:?}");
    assert!(
        matches!(requests.first(), Some(Request::Range { start, .. }) if fixture.index_matches(0, start)),
        "{requests:?}"
    );
}

#[tokio::test]
async fn full_primary_points_win_over_secondary_filters() {
    let fixture = Fixture::new(
        vec![
            column("id", DataType::Utf8, false),
            column("status", DataType::Utf8, false),
        ],
        &["id"],
        vec![index("status", &["status"], &[])],
        vec![
            Arc::new(StringArray::from(vec!["a", "b", "c"])),
            Arc::new(StringArray::from(vec!["open", "open", "closed"])),
        ],
    )
    .await;
    let requests = fixture
        .check("SELECT id FROM orders WHERE id = 'b' AND status = 'open'")
        .await;
    assert!(
        matches!(requests.as_slice(), [Request::GetMany(keys)] if keys.len() == 1),
        "{requests:?}"
    );
}

#[tokio::test]
async fn float_predicates_match_native_total_order_with_and_without_indexes() {
    for indexed in [false, true] {
        let fixture = Fixture::new(
            vec![
                column("id", DataType::Int64, false),
                column("score", DataType::Float64, false),
            ],
            &["id"],
            if indexed {
                vec![index("score", &["score"], &[])]
            } else {
                vec![]
            },
            vec![
                Arc::new(Int64Array::from(vec![1, 2, 3, 4, 5, 6, 7, 8])),
                Arc::new(Float64Array::from(vec![
                    -f64::NAN,
                    f64::NEG_INFINITY,
                    -0.0,
                    0.0,
                    1.0,
                    f64::INFINITY,
                    f64::NAN,
                    f64::from_bits(f64::NAN.to_bits() + 1),
                ])),
            ],
        )
        .await;
        for sql in [
            "SELECT id FROM orders WHERE score = 0.0 ORDER BY id",
            "SELECT id FROM orders WHERE score = CAST('-0' AS DOUBLE) ORDER BY id",
            "SELECT id FROM orders WHERE score >= 0.0 ORDER BY id",
            "SELECT id FROM orders WHERE score < 0.0 ORDER BY id",
            "SELECT id FROM orders WHERE score > CAST('Infinity' AS DOUBLE) ORDER BY id",
            "SELECT id FROM orders WHERE score <= CAST('-Infinity' AS DOUBLE) ORDER BY id",
            "SELECT id FROM orders WHERE score = CAST('NaN' AS DOUBLE) ORDER BY id",
            "SELECT id FROM orders WHERE score >= CAST('NaN' AS DOUBLE) ORDER BY id",
            "SELECT id FROM orders WHERE score <= CAST('-NaN' AS DOUBLE) ORDER BY id",
            "SELECT id FROM orders WHERE score <> 0.0 ORDER BY id",
        ] {
            fixture
                .check(&format!("{sql} /* indexed={indexed} */"))
                .await;
        }
    }
}
