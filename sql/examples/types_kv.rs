use datafusion::arrow::datatypes::DataType;
use datafusion::arrow::util::pretty::print_batches;
use datafusion::prelude::SessionContext;
use exoware_sdk_rs::StoreClient;
use exoware_sql::{CellValue, IndexSpec, KvSchema, TableColumnConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url =
        std::env::var("EXOWARE_URL").unwrap_or_else(|_| "http://localhost:10000".to_string());
    let client = StoreClient::new(&base_url);
    let ctx = SessionContext::new();

    let schema = KvSchema::new(client)
        .table(
            "wallets",
            vec![
                // 20-byte Ethereum address as primary key
                TableColumnConfig::new("address", DataType::FixedSizeBinary(20), false),
                TableColumnConfig::new("label", DataType::Utf8, true),
                TableColumnConfig::new("balance_wei", DataType::UInt64, false),
            ],
            vec!["address".to_string()],
            vec![],
        )?
        .table(
            "transfers",
            vec![
                // 32-byte transaction hash as primary key
                TableColumnConfig::new("tx_hash", DataType::FixedSizeBinary(32), false),
                TableColumnConfig::new("from_addr", DataType::FixedSizeBinary(20), false),
                TableColumnConfig::new("to_addr", DataType::FixedSizeBinary(20), false),
                TableColumnConfig::new("amount", DataType::UInt64, false),
                TableColumnConfig::new("block_num", DataType::UInt64, false),
            ],
            vec!["tx_hash".to_string()],
            vec![IndexSpec::lexicographic(
                "block_idx",
                vec!["block_num".to_string()],
            )?],
        )?;

    // Register tables for SQL queries
    schema.register_all(&ctx)?;

    // Use BatchWriter to atomically insert across both tables
    demo_batch_writer_insert().await;

    // Demonstrate SQL INSERT with hex binary literals
    demo_sql_insert(&ctx).await?;

    Ok(())
}

async fn demo_batch_writer_insert() {
    println!("\n== BatchWriter: programmatic insert with FixedSizeBinary ==");

    let client = StoreClient::new("http://localhost:10000");
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
        .unwrap()
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
            vec![],
        )
        .unwrap();

    let mut batch = schema.batch_writer();

    // Insert a wallet with a 20-byte Ethereum address
    let alice_addr = vec![0xAA; 20];
    let bob_addr = vec![0xBB; 20];
    batch
        .insert(
            "wallets",
            vec![
                CellValue::FixedBinary(alice_addr.clone()),
                CellValue::Utf8("Alice".to_string()),
                CellValue::UInt64(1_000_000_000_000_000_000), // 1 ETH in wei
            ],
        )
        .unwrap();
    batch
        .insert(
            "wallets",
            vec![
                CellValue::FixedBinary(bob_addr.clone()),
                CellValue::Null, // no label
                CellValue::UInt64(500_000_000_000_000_000),
            ],
        )
        .unwrap();

    // Insert a transfer with a 32-byte transaction hash
    let tx_hash = vec![0xDE; 32];
    batch
        .insert(
            "transfers",
            vec![
                CellValue::FixedBinary(tx_hash),
                CellValue::FixedBinary(alice_addr),
                CellValue::FixedBinary(bob_addr),
                CellValue::UInt64(250_000_000_000_000_000),
                CellValue::UInt64(18_500_000),
            ],
        )
        .unwrap();

    println!(
        "  Queued {} KV entries across wallets + transfers (atomic batch)",
        batch.pending_count()
    );
    println!("  (skipping flush -- no server in this demo)");
}

async fn demo_sql_insert(ctx: &SessionContext) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n== SQL INSERT with hex binary literals ==");
    println!("  Example SQL (requires running KV server):");
    println!("    INSERT INTO wallets (address, label, balance_wei)");
    println!(
        "    VALUES (X'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'Alice', 1000000000000000000)"
    );

    println!("\n== SQL queries with FixedSizeBinary filters ==");
    let plan = ctx
        .sql(
            "SELECT label, balance_wei FROM wallets \
             WHERE address = X'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'",
        )
        .await;
    match plan {
        Ok(df) => {
            println!("  wallet filter query planned successfully");
            let _ = print_batches(&df.collect().await?);
        }
        Err(e) => println!("  (no data to query: {e})"),
    }

    let transfer_plan = ctx
        .sql(
            "SELECT amount, block_num FROM transfers \
             WHERE from_addr = X'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'",
        )
        .await;
    match transfer_plan {
        Ok(df) => {
            println!("  transfer filter query planned successfully");
            let _ = print_batches(&df.collect().await?);
        }
        Err(e) => println!("  (no data to query: {e})"),
    }

    Ok(())
}
