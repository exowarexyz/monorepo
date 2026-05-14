//! SQL E2E slam test against a local Rocks-backed simulator (ephemeral port + temp dir).

mod common;

use datafusion::arrow::array::Int64Array;
use datafusion::arrow::datatypes::DataType;
use datafusion::common::ScalarValue;
use datafusion::prelude::SessionContext;
use exoware_sql::{CellValue, IndexSpec, KvSchema, TableColumnConfig};

#[tokio::test]
async fn sql_full_pipeline_insert_and_query() {
    let (_dir, _server, write_client) = common::local_store_client().await;
    let read_client = write_client.clone();

    let write_schema = KvSchema::new(write_client)
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
    let min_sequence = writer.flush().await.expect("flush batch");
    assert!(min_sequence > 0);
    let read_schema = KvSchema::new(read_client)
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

    let ctx = SessionContext::new();
    read_schema.register_all(&ctx).expect("register tables");

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
