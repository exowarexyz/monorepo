mod common;

use datafusion::arrow::array::{Int64Array, StringArray, UInt64Array};
use datafusion::arrow::datatypes::DataType;
use datafusion::common::ScalarValue;
use datafusion::prelude::SessionContext;
use exoware_sql::{default_orders_index_specs, CellValue, IndexSpec, KvSchema, TableColumnConfig};

fn collect_i64_rows(batches: &[datafusion::arrow::record_batch::RecordBatch], col: usize) -> Vec<i64> {
    let mut out = Vec::new();
    for batch in batches {
        let values = batch
            .column(col)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("int64 column");
        for row in 0..batch.num_rows() {
            out.push(values.value(row));
        }
    }
    out
}

fn collect_i64_pairs(
    batches: &[datafusion::arrow::record_batch::RecordBatch],
    col_a: usize,
    col_b: usize,
) -> Vec<(i64, i64)> {
    let mut out = Vec::new();
    for batch in batches {
        let a = batch
            .column(col_a)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("first int64 column");
        let b = batch
            .column(col_b)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("second int64 column");
        for row in 0..batch.num_rows() {
            out.push((a.value(row), b.value(row)));
        }
    }
    out
}

fn collect_string_i64_rows(
    batches: &[datafusion::arrow::record_batch::RecordBatch],
    col_a: usize,
    col_b: usize,
) -> Vec<(String, i64)> {
    let mut out = Vec::new();
    for batch in batches {
        let a = batch
            .column(col_a)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("string column");
        let b = batch
            .column(col_b)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("int64 column");
        for row in 0..batch.num_rows() {
            out.push((a.value(row).to_string(), b.value(row)));
        }
    }
    out
}

fn collect_two_strings(
    batches: &[datafusion::arrow::record_batch::RecordBatch],
    col_a: usize,
    col_b: usize,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for batch in batches {
        let a = batch
            .column(col_a)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("first string column");
        let b = batch
            .column(col_b)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("second string column");
        for row in 0..batch.num_rows() {
            out.push((a.value(row).to_string(), b.value(row).to_string()));
        }
    }
    out
}

#[tokio::test]
async fn orders_example_queries_work_end_to_end() {
    let (_dir, _server, client) = common::local_store_client().await;
    let ctx = SessionContext::new();

    KvSchema::new(client)
        .orders_table("orders_kv", default_orders_index_specs())
        .expect("orders schema")
        .register_all(&ctx)
        .expect("register");

    ctx.sql(
        "INSERT INTO orders_kv (region, customer_id, order_id, amount_cents, status) VALUES \
         ('us-east', 1001, 1, 3499, 'paid'), \
         ('us-west', 1002, 2, 1799, 'paid'), \
         ('us-east', 1003, 3, 2299, 'pending'), \
         ('eu-central', 1004, 4, 1299, 'paid'), \
         ('us-west', 1005, 5, 4599, 'refunded')",
    )
    .await
    .expect("insert")
    .collect()
    .await
    .expect("collect insert");

    let aggregate = ctx
        .sql(
            "SELECT region, COUNT(*) AS order_count, SUM(amount_cents) AS total_cents \
             FROM orders_kv \
             WHERE region = 'us-east' \
             GROUP BY region",
        )
        .await
        .expect("aggregate query")
        .collect()
        .await
        .expect("collect aggregate");
    let batch = &aggregate[0];
    let region = batch
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("region")
        .value(0);
    let count = ScalarValue::try_from_array(batch.column(1), 0).expect("count");
    let total = batch
        .column(2)
        .as_any()
        .downcast_ref::<Int64Array>()
        .expect("sum")
        .value(0);
    assert_eq!(region, "us-east");
    assert!(matches!(
        count,
        ScalarValue::Int64(Some(2)) | ScalarValue::UInt64(Some(2))
    ));
    assert_eq!(total, 3499 + 2299);

    let filtered = ctx
        .sql(
            "SELECT customer_id, order_id, amount_cents, status \
             FROM orders_kv \
             WHERE region = 'us-west' AND customer_id >= 1002 \
             ORDER BY customer_id, order_id",
        )
        .await
        .expect("filtered query")
        .collect()
        .await
        .expect("collect filtered");
    assert_eq!(collect_i64_pairs(&filtered, 0, 1), vec![(1002, 2), (1005, 5)]);
    assert_eq!(collect_i64_rows(&filtered, 2), vec![1799, 4599]);
    assert_eq!(
        collect_string_i64_rows(&filtered, 3, 1)
            .into_iter()
            .map(|(status, order_id)| (status, order_id))
            .collect::<Vec<_>>(),
        vec![("paid".to_string(), 2), ("refunded".to_string(), 5)]
    );
}

#[tokio::test]
async fn join_example_queries_work_end_to_end() {
    let (_dir, _server, client) = common::local_store_client().await;
    let ctx = SessionContext::new();

    KvSchema::new(client)
        .table(
            "customers",
            vec![
                TableColumnConfig::new("customer_id", DataType::Int64, false),
                TableColumnConfig::new("name", DataType::Utf8, false),
                TableColumnConfig::new("region", DataType::Utf8, false),
            ],
            vec!["customer_id".to_string()],
            vec![IndexSpec::lexicographic("region_idx", vec!["region".to_string()]).expect("index")],
        )
        .expect("customers schema")
        .table(
            "orders",
            vec![
                TableColumnConfig::new("order_id", DataType::Int64, false),
                TableColumnConfig::new("customer_id", DataType::Int64, false),
                TableColumnConfig::new("amount_cents", DataType::Int64, false),
                TableColumnConfig::new("status", DataType::Utf8, false),
            ],
            vec!["order_id".to_string()],
            vec![IndexSpec::lexicographic("customer_idx", vec!["customer_id".to_string()])
                .expect("index")],
        )
        .expect("orders schema")
        .register_all(&ctx)
        .expect("register");

    ctx.sql(
        "INSERT INTO customers (customer_id, name, region) VALUES \
         (1, 'Alice', 'us-east'), \
         (2, 'Bob', 'us-west'), \
         (3, 'Carol', 'eu-central'), \
         (4, 'Dave', 'us-east')",
    )
    .await
    .expect("insert customers")
    .collect()
    .await
    .expect("collect customers");

    ctx.sql(
        "INSERT INTO orders (order_id, customer_id, amount_cents, status) VALUES \
         (101, 1, 3499, 'paid'), \
         (102, 1, 1799, 'paid'), \
         (103, 2, 2299, 'pending'), \
         (104, 3, 1299, 'paid'), \
         (105, 2, 4599, 'refunded')",
    )
    .await
    .expect("insert orders")
    .collect()
    .await
    .expect("collect orders");

    let joined = ctx
        .sql(
            "SELECT c.name, o.order_id, o.amount_cents, o.status \
             FROM orders o \
             JOIN customers c ON o.customer_id = c.customer_id \
             ORDER BY c.name, o.order_id",
        )
        .await
        .expect("join query")
        .collect()
        .await
        .expect("collect join");
    assert_eq!(
        collect_string_i64_rows(&joined, 0, 1),
        vec![
            ("Alice".to_string(), 101),
            ("Alice".to_string(), 102),
            ("Bob".to_string(), 103),
            ("Bob".to_string(), 105),
            ("Carol".to_string(), 104),
        ]
    );
    assert_eq!(collect_i64_rows(&joined, 2), vec![3499, 1799, 2299, 4599, 1299]);

    let left_join = ctx
        .sql(
            "SELECT c.name, c.region \
             FROM customers c \
             LEFT JOIN orders o ON c.customer_id = o.customer_id \
             WHERE o.order_id IS NULL",
        )
        .await
        .expect("left join query")
        .collect()
        .await
        .expect("collect left join");
    assert_eq!(collect_two_strings(&left_join, 0, 1), vec![("Dave".to_string(), "us-east".to_string())]);
}

#[tokio::test]
async fn versioned_example_queries_work_end_to_end() {
    let (_dir, _server, client) = common::local_store_client().await;
    let ctx = SessionContext::new();
    let writer_client = client.clone();

    let schema = KvSchema::new(client)
        .table_versioned(
            "documents",
            vec![
                TableColumnConfig::new("doc_id", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("title", DataType::Utf8, false),
                TableColumnConfig::new("body", DataType::Utf8, true),
                TableColumnConfig::new("author", DataType::Utf8, true),
            ],
            "doc_id",
            "version",
            vec![],
        )
        .expect("documents schema");
    schema.register_all(&ctx).expect("register");

    let doc_id_hex = "d0c1aabbccddeeff0011223344556677";
    let doc_id = hex::decode(doc_id_hex).expect("doc_id hex");

    let mut batch = KvSchema::new(writer_client)
        .table_versioned(
            "documents",
            vec![
                TableColumnConfig::new("doc_id", DataType::FixedSizeBinary(16), false),
                TableColumnConfig::new("version", DataType::UInt64, false),
                TableColumnConfig::new("title", DataType::Utf8, false),
                TableColumnConfig::new("body", DataType::Utf8, true),
                TableColumnConfig::new("author", DataType::Utf8, true),
            ],
            "doc_id",
            "version",
            vec![],
        )
        .expect("documents writer schema")
        .batch_writer();

    for (version, title, body, author) in [
        (1u64, "Draft", "Initial content...", "Alice"),
        (2, "Review", "Revised content after review...", "Alice"),
        (3, "Approved", "Approved content.", "Bob"),
        (4, "Published", "Final published content.", "Bob"),
    ] {
        batch
            .insert(
                "documents",
                vec![
                    CellValue::FixedBinary(doc_id.clone()),
                    CellValue::UInt64(version),
                    CellValue::Utf8(title.to_string()),
                    CellValue::Utf8(body.to_string()),
                    CellValue::Utf8(author.to_string()),
                ],
            )
            .expect("insert document");
    }
    batch.flush().await.expect("flush versioned batch");

    let latest_leq_two = ctx
        .sql(&format!(
            "SELECT title, version FROM documents \
             WHERE doc_id = X'{}' AND version <= 2 \
             ORDER BY version DESC LIMIT 1",
            doc_id_hex.to_uppercase()
        ))
        .await
        .expect("latest <= 2 query")
        .collect()
        .await
        .expect("collect latest <= 2");
    let batch = &latest_leq_two[0];
    let title = batch
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("title")
        .value(0);
    let version = batch
        .column(1)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .expect("version")
        .value(0);
    assert_eq!(title, "Review");
    assert_eq!(version, 2);

    let exact = ctx
        .sql(&format!(
            "SELECT title, version FROM documents \
             WHERE doc_id = X'{}' AND version = 3",
            doc_id_hex.to_uppercase()
        ))
        .await
        .expect("exact version query")
        .collect()
        .await
        .expect("collect exact version query");
    let batch = &exact[0];
    let title = batch
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("title")
        .value(0);
    let version = batch
        .column(1)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .expect("version")
        .value(0);
    assert_eq!(title, "Approved");
    assert_eq!(version, 3);
}

#[tokio::test]
async fn fixed_binary_example_filters_work_end_to_end() {
    let (_dir, _server, client) = common::local_store_client().await;
    let ctx = SessionContext::new();
    let writer_client = client.clone();

    let schema = KvSchema::new(client)
        .table(
            "wallets",
            vec![
                TableColumnConfig::new("address", DataType::FixedSizeBinary(20), false),
                TableColumnConfig::new("label", DataType::Utf8, true),
                TableColumnConfig::new("balance_wei", DataType::UInt64, false),
            ],
            vec!["address".to_string()],
            vec![],
        )
        .expect("wallets schema")
        .table(
            "transfers",
            vec![
                TableColumnConfig::new("tx_hash", DataType::FixedSizeBinary(32), false),
                TableColumnConfig::new("from_addr", DataType::FixedSizeBinary(20), false),
                TableColumnConfig::new("to_addr", DataType::FixedSizeBinary(20), false),
                TableColumnConfig::new("amount", DataType::UInt64, false),
                TableColumnConfig::new("block_num", DataType::UInt64, false),
            ],
            vec!["tx_hash".to_string()],
            vec![IndexSpec::lexicographic("block_idx", vec!["block_num".to_string()]).expect("index")],
        )
        .expect("transfers schema");

    schema.register_all(&ctx).expect("register");

    let mut batch = KvSchema::new(writer_client)
        .table(
            "wallets",
            vec![
                TableColumnConfig::new("address", DataType::FixedSizeBinary(20), false),
                TableColumnConfig::new("label", DataType::Utf8, true),
                TableColumnConfig::new("balance_wei", DataType::UInt64, false),
            ],
            vec!["address".to_string()],
            vec![],
        )
        .expect("wallets writer schema")
        .table(
            "transfers",
            vec![
                TableColumnConfig::new("tx_hash", DataType::FixedSizeBinary(32), false),
                TableColumnConfig::new("from_addr", DataType::FixedSizeBinary(20), false),
                TableColumnConfig::new("to_addr", DataType::FixedSizeBinary(20), false),
                TableColumnConfig::new("amount", DataType::UInt64, false),
                TableColumnConfig::new("block_num", DataType::UInt64, false),
            ],
            vec!["tx_hash".to_string()],
            vec![IndexSpec::lexicographic("block_idx", vec!["block_num".to_string()]).expect("index")],
        )
        .expect("transfers writer schema")
        .batch_writer();
    let alice_addr = vec![0xAA; 20];
    let bob_addr = vec![0xBB; 20];
    batch
        .insert(
            "wallets",
            vec![
                CellValue::FixedBinary(alice_addr.clone()),
                CellValue::Utf8("Alice".to_string()),
                CellValue::UInt64(1_000),
            ],
        )
        .expect("insert alice");
    batch
        .insert(
            "wallets",
            vec![
                CellValue::FixedBinary(bob_addr.clone()),
                CellValue::Null,
                CellValue::UInt64(500),
            ],
        )
        .expect("insert bob");
    batch
        .insert(
            "transfers",
            vec![
                CellValue::FixedBinary(vec![0xDE; 32]),
                CellValue::FixedBinary(alice_addr.clone()),
                CellValue::FixedBinary(bob_addr),
                CellValue::UInt64(250),
                CellValue::UInt64(18_500_000),
            ],
        )
        .expect("insert transfer");
    batch.flush().await.expect("flush");

    ctx.sql(
        "INSERT INTO wallets (address, label, balance_wei) \
         VALUES (X'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC', 'Carol', 750)",
    )
    .await
    .expect("fixed-binary sql insert")
    .collect()
    .await
    .expect("collect fixed-binary insert");

    let alice_wallet = ctx
        .sql(
            "SELECT label, balance_wei FROM wallets \
             WHERE address = X'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'",
        )
        .await
        .expect("alice wallet query")
        .collect()
        .await
        .expect("collect alice wallet");
    let batch = &alice_wallet[0];
    let label = batch
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("label")
        .value(0);
    let balance = batch
        .column(1)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .expect("balance")
        .value(0);
    assert_eq!(label, "Alice");
    assert_eq!(balance, 1_000);

    let outgoing = ctx
        .sql(
            "SELECT amount, block_num FROM transfers \
             WHERE from_addr = X'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'",
        )
        .await
        .expect("transfer filter query")
        .collect()
        .await
        .expect("collect transfer filter");
    let batch = &outgoing[0];
    let amount = batch
        .column(0)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .expect("amount")
        .value(0);
    let block_num = batch
        .column(1)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .expect("block_num")
        .value(0);
    assert_eq!(amount, 250);
    assert_eq!(block_num, 18_500_000);

    let carol = ctx
        .sql(
            "SELECT label, balance_wei FROM wallets \
             WHERE address = X'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'",
        )
        .await
        .expect("carol query")
        .collect()
        .await
        .expect("collect carol query");
    let batch = &carol[0];
    let label = batch
        .column(0)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("label")
        .value(0);
    let balance = batch
        .column(1)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .expect("balance")
        .value(0);
    assert_eq!(label, "Carol");
    assert_eq!(balance, 750);
}
