use datafusion::arrow::datatypes::DataType;
use datafusion::arrow::util::pretty::print_batches;
use datafusion::prelude::SessionContext;
use exoware_sdk_rs::StoreClient;
use exoware_sql::{CellValue, KvSchema, TableColumnConfig};

const DOC_ID_HEX: &str = "d0c1aabbccddeeff0011223344556677";

/// Demonstrates versioned primary keys using FixedSizeBinary(16) + UInt64.
///
/// The composite primary key `(doc_id, version)` lets SQL fetch either an exact
/// version or the latest version at or below some upper bound.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url =
        std::env::var("EXOWARE_URL").unwrap_or_else(|_| "http://localhost:10000".to_string());
    let client = StoreClient::new(&base_url);
    let ctx = SessionContext::new();

    // -- Define the versioned document table --
    let schema = build_schema(client)?;

    schema.register_all(&ctx)?;

    // -- Demonstrate programmatic inserts with BatchWriter --
    demo_batch_writer_insert().await;

    // -- Demonstrate SQL query patterns --
    demo_sql_queries(&ctx).await?;

    Ok(())
}

fn build_schema(client: StoreClient) -> Result<KvSchema, String> {
    KvSchema::new(client).table_versioned(
        "documents",
        vec![
            TableColumnConfig::new("doc_id", DataType::FixedSizeBinary(16), false),
            // Monotonically increasing version number
            TableColumnConfig::new("version", DataType::UInt64, false),
            // Document metadata
            TableColumnConfig::new("title", DataType::Utf8, false),
            TableColumnConfig::new("body", DataType::Utf8, true),
            TableColumnConfig::new("author", DataType::Utf8, true),
        ],
        "doc_id",
        "version", // version column (UInt64)
        vec![],
    )
}

async fn demo_batch_writer_insert() {
    println!("\n== BatchWriter: multiple document versions ==");

    let client = StoreClient::new("http://localhost:10000");
    let schema = build_schema(client).unwrap();

    let mut batch = schema.batch_writer();
    let doc_id = doc_id_bytes();

    batch
        .insert(
            "documents",
            vec![
                CellValue::FixedBinary(doc_id.clone()),
                CellValue::UInt64(1),
                CellValue::Utf8("Draft".to_string()),
                CellValue::Utf8("Initial content...".to_string()),
                CellValue::Utf8("Alice".to_string()),
            ],
        )
        .unwrap();

    batch
        .insert(
            "documents",
            vec![
                CellValue::FixedBinary(doc_id.clone()),
                CellValue::UInt64(2),
                CellValue::Utf8("Review".to_string()),
                CellValue::Utf8("Revised content after review...".to_string()),
                CellValue::Utf8("Alice".to_string()),
            ],
        )
        .unwrap();

    batch
        .insert(
            "documents",
            vec![
                CellValue::FixedBinary(doc_id.clone()),
                CellValue::UInt64(4),
                CellValue::Utf8("Published".to_string()),
                CellValue::Utf8("Final published content.".to_string()),
                CellValue::Utf8("Bob".to_string()),
            ],
        )
        .unwrap();

    batch
        .insert(
            "documents",
            vec![
                CellValue::FixedBinary(doc_id.clone()),
                CellValue::UInt64(5),
                CellValue::Utf8("Translated".to_string()),
                CellValue::Utf8("Localized content.".to_string()),
                CellValue::Utf8("Bob".to_string()),
            ],
        )
        .unwrap();

    batch
        .insert(
            "documents",
            vec![
                CellValue::FixedBinary(doc_id.clone()),
                CellValue::UInt64(3),
                CellValue::Utf8("Approved".to_string()),
                CellValue::Utf8("Approved content.".to_string()),
                CellValue::Utf8("Bob".to_string()),
            ],
        )
        .unwrap();

    println!("  Queued {} document-version rows", batch.pending_count());
    println!("  (skipping flush -- no server in this demo)");
}

async fn demo_sql_queries(ctx: &SessionContext) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n== SQL query patterns for versioned documents ==");
    let doc_id = format!("X'{}'", DOC_ID_HEX.to_uppercase());

    // Pattern 1: Get ALL versions of a document
    println!("\n  -- All versions of a document:");
    println!("  SELECT * FROM documents WHERE doc_id = '{doc_id}'");

    // Pattern 2: Get the latest version <= some number
    println!("\n  -- Latest version <= 2 (gets version 2, not 3):");
    println!(
        "  SELECT * FROM documents WHERE doc_id = '{doc_id}' AND version <= 2 \
         ORDER BY version DESC LIMIT 1"
    );

    // Pattern 3: Get a specific version
    println!("\n  -- Exact version lookup:");
    println!("  SELECT * FROM documents WHERE doc_id = '{doc_id}' AND version = 2");

    // Verify the plan compiles (no data since no server)
    let plan = ctx
        .sql(&format!(
            "SELECT title, version FROM documents \
             WHERE doc_id = {doc_id} \
             AND version <= 2 \
             ORDER BY version DESC LIMIT 1"
        ))
        .await;
    match plan {
        Ok(df) => {
            println!("\n  Query planned successfully");
            let _ = print_batches(&df.collect().await?);
        }
        Err(e) => println!("\n  (no data to query: {e})"),
    }

    Ok(())
}

fn doc_id_bytes() -> Vec<u8> {
    hex::decode(DOC_ID_HEX).expect("fixed example doc_id hex should decode")
}
