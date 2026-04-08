use datafusion::arrow::datatypes::DataType;
use datafusion::arrow::util::pretty::print_batches;
use datafusion::common::Result as DataFusionResult;
use datafusion::prelude::SessionContext;
use exoware_sdk_rs::StoreClient;
use exoware_sql::{IndexSpec, KvSchema, TableColumnConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url =
        std::env::var("EXOWARE_URL").unwrap_or_else(|_| "http://localhost:10000".to_string());
    let client = StoreClient::new(&base_url);
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
            vec![IndexSpec::lexicographic(
                "region_idx",
                vec!["region".to_string()],
            )?],
        )?
        .table(
            "orders",
            vec![
                TableColumnConfig::new("order_id", DataType::Int64, false),
                TableColumnConfig::new("customer_id", DataType::Int64, false),
                TableColumnConfig::new("amount_cents", DataType::Int64, false),
                TableColumnConfig::new("status", DataType::Utf8, false),
            ],
            vec!["order_id".to_string()],
            vec![IndexSpec::lexicographic(
                "customer_idx",
                vec!["customer_id".to_string()],
            )?],
        )?
        .register_all(&ctx)?;

    seed_sample_data(&ctx).await?;

    println!("\n== All customers ==");
    let df = ctx
        .sql("SELECT * FROM customers ORDER BY customer_id")
        .await?;
    print_batches(&df.collect().await?)?;

    println!("\n== All orders ==");
    let df = ctx.sql("SELECT * FROM orders ORDER BY order_id").await?;
    print_batches(&df.collect().await?)?;

    println!("\n== JOIN: orders with customer names ==");
    let df = ctx
        .sql(
            "SELECT c.name, o.order_id, o.amount_cents, o.status \
             FROM orders o \
             JOIN customers c ON o.customer_id = c.customer_id \
             ORDER BY c.name, o.order_id",
        )
        .await?;
    print_batches(&df.collect().await?)?;

    println!("\n== Aggregate: total spend per customer ==");
    let df = ctx
        .sql(
            "SELECT c.name, c.region, COUNT(*) AS order_count, \
                    SUM(o.amount_cents) AS total_cents \
             FROM orders o \
             JOIN customers c ON o.customer_id = c.customer_id \
             GROUP BY c.name, c.region \
             ORDER BY total_cents DESC",
        )
        .await?;
    print_batches(&df.collect().await?)?;

    println!("\n== LEFT JOIN: customers with no orders ==");
    let df = ctx
        .sql(
            "SELECT c.name, c.region, o.order_id \
             FROM customers c \
             LEFT JOIN orders o ON c.customer_id = o.customer_id \
             WHERE o.order_id IS NULL",
        )
        .await?;
    print_batches(&df.collect().await?)?;

    Ok(())
}

async fn seed_sample_data(ctx: &SessionContext) -> DataFusionResult<()> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let cid_base = nonce.saturating_mul(10);
    let oid_base = nonce.saturating_mul(100);

    let customers_sql = format!(
        "INSERT INTO customers (customer_id, name, region) VALUES \
         ({}, 'Alice', 'us-east'), \
         ({}, 'Bob', 'us-west'), \
         ({}, 'Carol', 'eu-central'), \
         ({}, 'Dave', 'us-east')",
        cid_base + 1,
        cid_base + 2,
        cid_base + 3,
        cid_base + 4,
    );
    ctx.sql(&customers_sql).await?.collect().await?;

    let orders_sql = format!(
        "INSERT INTO orders (order_id, customer_id, amount_cents, status) VALUES \
         ({}, {}, 3499, 'paid'), \
         ({}, {}, 1799, 'paid'), \
         ({}, {}, 2299, 'pending'), \
         ({}, {}, 1299, 'paid'), \
         ({}, {}, 4599, 'refunded')",
        oid_base + 1,
        cid_base + 1,
        oid_base + 2,
        cid_base + 1,
        oid_base + 3,
        cid_base + 2,
        oid_base + 4,
        cid_base + 3,
        oid_base + 5,
        cid_base + 2,
    );
    ctx.sql(&orders_sql).await?.collect().await?;

    Ok(())
}
