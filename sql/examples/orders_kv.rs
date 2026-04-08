use datafusion::arrow::util::pretty::print_batches;
use datafusion::common::Result as DataFusionResult;
use datafusion::prelude::SessionContext;
use exoware_sdk_rs::StoreClient;
use exoware_sql::{default_orders_index_specs, KvSchema};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url =
        std::env::var("EXOWARE_URL").unwrap_or_else(|_| "http://localhost:10000".to_string());
    let client = StoreClient::new(&base_url);
    let ctx = SessionContext::new();
    let index_specs = default_orders_index_specs();

    KvSchema::new(client)
        .orders_table("orders_kv", index_specs)
        .map_err(datafusion::common::DataFusionError::Execution)?
        .register_all(&ctx)?;

    let seed_sample = std::env::var("EXOWARE_SEED_SAMPLE")
        .map(|v| v != "0")
        .unwrap_or(true);
    if seed_sample {
        seed_sample_orders_via_sql(&ctx).await?;
    }

    let df = ctx
        .sql(
            "SELECT region, COUNT(*) AS order_count, SUM(amount_cents) AS total_cents \
             FROM orders_kv \
             WHERE region = 'us-east' \
             GROUP BY region",
        )
        .await?;
    println!("\n== Region aggregate ==");
    print_batches(&df.collect().await?)?;

    let df = ctx
        .sql(
            "SELECT customer_id, order_id, amount_cents, status \
             FROM orders_kv \
             WHERE region = 'us-west' AND customer_id >= 1002 \
             ORDER BY customer_id, order_id",
        )
        .await?;
    println!("\n== Filtered rows ==");
    print_batches(&df.collect().await?)?;

    Ok(())
}

async fn seed_sample_orders_via_sql(ctx: &SessionContext) -> DataFusionResult<()> {
    let run_nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| datafusion::common::DataFusionError::Execution(format!("clock error: {e}")))?
        .as_secs() as i64;
    let base_order_id = run_nonce.saturating_mul(10);

    let sql = format!(
        "INSERT INTO orders_kv (region, customer_id, order_id, amount_cents, status) VALUES \
         ('us-east', 1001, {}, 3499, 'paid'), \
         ('us-west', 1002, {}, 1799, 'paid'), \
         ('us-east', 1003, {}, 2299, 'pending'), \
         ('eu-central', 1004, {}, 1299, 'paid'), \
         ('us-west', 1005, {}, 4599, 'refunded')",
        base_order_id + 1,
        base_order_id + 2,
        base_order_id + 3,
        base_order_id + 4,
        base_order_id + 5,
    );
    let insert_df = ctx.sql(&sql).await?;
    let insert_result = insert_df.collect().await?;
    println!("\n== SQL INSERT result ==");
    print_batches(&insert_result)?;
    Ok(())
}
