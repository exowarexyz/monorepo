# exoware-sql

`exoware-sql` provides tables and secondary indexes over Exoware Store, with SQL
queries planned by [DataFusion](https://datafusion.apache.org/). Rows and indexes
use ordered Store keys so key-range filters and supported aggregates can run in
the Store. Use `SqlContext` to query these tables from Rust, or expose them
through `SqlServer` for the [TypeScript client](../ts/README.md).

## Getting started

Add the crate and SDK along with DataFusion and Tokio:

```sh
cargo add exoware-sql exoware-sdk datafusion@55
cargo add tokio --features macros,rt-multi-thread
```

For local development, start the [simulator](../../examples/simulator/README.md):

```sh
cargo run -p exoware-simulator -- server run --port 8080
```

This example creates an `orders` table, writes two rows, and computes the total
for each status:

```rust
use datafusion::arrow::datatypes::DataType;
use exoware_sdk::{ReadSession, StoreClient};
use exoware_sql::{CellValue, IndexSpec, KvSchema, SqlContext, TableColumnConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let store = StoreClient::new("http://localhost:8080").unprefixed();
    let schema = KvSchema::new(store.clone()).table(
        "orders",
        vec![
            TableColumnConfig::new("order_id", DataType::Int64, false),
            TableColumnConfig::new("status", DataType::Utf8, false),
            TableColumnConfig::new("amount_cents", DataType::Int64, false),
        ],
        vec!["order_id".to_string()],
        vec![IndexSpec::lexicographic("status_idx", vec!["status".to_string()])?
            .with_cover_columns(vec!["amount_cents".to_string()])],
    )?;

    let mut writer = schema.batch_writer();
    for (id, status, cents) in [(1, "open", 1250), (2, "paid", 800)] {
        writer.insert(
            "orders",
            vec![CellValue::Int64(id), CellValue::Utf8(status.into()), CellValue::Int64(cents)],
        )?;
    }
    let sequence = writer.flush().await?;

    // Require the write's sequence so a lagging replica cannot answer the query.
    let ctx = SqlContext::builder(store.clone())
        .with_read_session(ReadSession::monotonic(store, sequence))
        .build();
    ctx.register_schema(schema)?;
    ctx.sql("SELECT status, SUM(amount_cents) AS total FROM orders GROUP BY status")
        .await?
        .show()
        .await?;
    Ok(())
}
```

Registering the schema makes its tables available to the DataFusion session
wrapped by `SqlContext`. You can then use JOINs, views, and other DataFusion SQL,
or call `ctx.datafusion()` for APIs that the context does not forward. The
[examples](#examples) build on this setup with joins, more column types, and
versioned keys.

## Designing tables

A `KvSchema` groups tables under one `PrefixedStoreClient`. It assigns each table
a key prefix in registration order, so every reader and writer must build the
schema with the same tables in the same order. A schema supports at most 16
tables, each with at most 15 secondary indexes. The
[key layout](../docs/query-planning.md#key-layout) explains these limits.

A table's name is exact and case-sensitive. In SQL, a double-quoted identifier
always names the table, as in `SELECT * FROM "Orders"`. The quotes are optional
for a lower-case identifier, because SQL folds unquoted identifiers to lower
case. The `Tables` and `Subscribe` RPCs use the name as declared.

When several SQL schemas, or SQL and [QMDB](../../qmdb/README.md), share a Store,
give each a disjoint SDK `StoreKeyPrefix`. SQL scans are bounded by the schema's
prefix, so overlapping prefixes can expose one tenant's keys in another's tables.

### Columns and keys

The supported column types below can all be stored as values. Primary keys and
index keys accept a smaller set of types:

| Arrow type | Primary key | Index key | Encoded key width |
|---|---|---|---|
| `Int64`, `UInt64` | yes | yes | 8 bytes |
| `Utf8`, `LargeUtf8`, `Utf8View` | yes | yes | variable |
| `FixedSizeBinary(n)` | yes | yes | `n` bytes |
| `Float64`, `Date64`, `Timestamp` | no | yes | 8 bytes |
| `Date32` | no | yes | 4 bytes |
| `Boolean` | no | yes | 1 byte |
| `Decimal128(p, s)` | no | yes | 16 bytes |
| `Decimal256(p, s)` | no | yes | 32 bytes |
| `Binary`, `LargeBinary`, `BinaryView` | no | no | |
| `List<T>`, `LargeList<T>` of `Int64`, `Float64`, `Boolean`, or `Utf8` | no | no | |

Text keys use an escaped, terminated encoding that preserves sort order,
including embedded NUL characters. The complete encoded key, with its prefixes,
must fit the Store key-length limit, and index key columns must be non-nullable.

Some types have a normalized representation in query results. Timestamp columns
use microsecond units and retain their timezone, and `LargeList` columns are
returned as `List`.

### Primary keys

A primary key identifies one immutable row, so give each row a unique key.
Writing the same primary key twice has undefined results, and neither write path
checks for it. To record changes to a logical entity, add a version column to its
primary key.

Pass several column names to `KvSchema::table` for a composite primary key. Keys
sort by their columns in order, so put the columns that queries constrain by
equality first. A range constraint on a later column narrows the scan only when
every earlier column has an equality constraint.

`KvSchema::versioned_table` declares an `(entity, version)` primary key. The
version column must be `UInt64` and distinct from the entity column, and other
layouts return a planning error. Versions sort numerically within each entity, so
the latest version at or below `V` is a short reverse range scan:

```rust
let schema = KvSchema::new(store).versioned_table(
    "documents",
    vec![
        TableColumnConfig::new("doc_id", DataType::FixedSizeBinary(16), false),
        TableColumnConfig::new("version", DataType::UInt64, false),
        TableColumnConfig::new("title", DataType::Utf8, false),
    ],
    "doc_id",
    "version",
    vec![],
)?;
```

```sql
SELECT * FROM documents
WHERE doc_id = X'AA000000000000000000000000000001' AND version <= 42
ORDER BY version DESC LIMIT 1
```

To prune old versions, build a Store prune policy from the schema and apply it
through the same `PrefixedStoreClient` that created the schema:

```rust
let policy = schema.keep_latest_versions_policy("documents", 1)?;
```

This policy requires an unindexed table whose primary key is exactly
`(entity, UInt64 version)`. Store pruning removes base rows but leaves their index
entries, so remove the policy before adding an index to the table. The schema
cannot check policies built directly with the SDK or schema changes made after
the policy was applied.

### Secondary indexes

Use secondary indexes to avoid scanning a whole table when a query filters
non-key columns. Each `IndexSpec` chooses key columns, a layout, and optional
cover columns:

- **Cover columns** copy non-key values into each index entry. A query whose
  projected and filtered columns are all available from the index reads only the
  index. Otherwise each matching entry needs a lookup of its base row. Primary-key
  columns are already available from the index key and cannot be listed as cover
  columns.
- **Layout** controls how key columns sort. The default lexicographic layout
  serves equality on leading columns followed by a range on the next one.
  `IndexSpec::z_order` interleaves fixed-width key columns so a box such as
  `x BETWEEN 100 AND 200 AND y BETWEEN 400 AND 500` maps to key ranges. Z-order
  ranges include false positives, and a residual check removes them.

```rust
let by_customer = IndexSpec::lexicographic(
    "customer_time",
    vec!["customer_id".to_string(), "created_at".to_string()],
)?
.with_cover_columns(vec!["total".to_string()]);
let by_point = IndexSpec::z_order("xy", vec!["x".to_string(), "y".to_string()])?;
```

Choose cover columns for the queries you need to serve, since each column adds
storage, write bandwidth, and compaction work to every index entry. An index that
covers an aggregate's filter, group, and input columns also lets the Store compute
that aggregate over the index's narrower key range, as described in the
[query planning guide](../docs/query-planning.md#aggregate-pushdown).

An index scan can only return rows with entries supplied by writers and
backfills. A missing or undecodable covering payload fails the query, and reads
do not repair it from the base row.

## Writing rows

Use `KvSchema::batch_writer` to write rows as `CellValue` vectors in column order.
The `BatchWriter` encodes each row's base entry and all of its index entries, and
`flush` uploads the pending rows across tables as one atomic Store batch. It
returns the batch's sequence number, or `None` when nothing was pending. If a flush
fails, the writer retains that batch and retries it alone on the next flush,
before uploading later rows.

To commit SQL rows atomically with other Store writes, prepare them with
`prepare_upload` and add them to an SDK `StoreWriteBatch` with the SDK's
`StoreWriteBatchUpload::stage_upload`. Call `mark_upload_persisted` after a
successful commit, or `mark_upload_failed` to retain the batch for retry.

SQL `INSERT` writes through the same schema, with each statement committed as one
atomic batch. It materializes Arrow batches first, so `BatchWriter` avoids that
work for application ingest. The Store's request-size limit bounds each batch,
and an oversized statement or flush returns the ingest error.

## Adding indexes to existing tables

When a schema gains an index, new writes include it but existing rows need a
backfill. Append new indexes to the list and preserve each existing index's
position, name, key columns, cover columns, and layout. Deploy the change in this
order so every row receives the new index entries:

1. Deploy every writer with the new index list.
2. Run the backfill, passing the index list that earlier rows were written with.
3. Enable the new indexes for reads after the backfill finishes.

Rows written by an old writer during or after the backfill are missing from the new
index.

Build `schema` with the new index list, then pass the original `IndexSpec` values
as `previous_index_specs` when backfilling:

```rust
let report = schema
    .backfill_added_indexes("orders", &previous_index_specs)
    .await?;
```

The backfill scans the table's primary keys and writes entries only for the added
indexes. If the index list has not changed, it writes nothing and reports zero
counts.

For a resumable backfill, use `backfill_added_indexes_with_options_and_progress`.
It sends each `Progress` event to the supplied Tokio `UnboundedSender` after
flushing the writes covered by that event, so you can persist its `next_cursor`
and pass it as `IndexBackfillOptions::start_cursor` when resuming. The options
also control the scan's response batch size.

## Read consistency

Store replicas can lag, so each response reports the sequence of the state used
for the read. A `ReadSession` carries an optional minimum acceptable sequence and
records the highest sequence observed. Choose how its minimum advances:

- A **monotonic** session raises its minimum as it observes newer Store sequences.
- A **fixed** session keeps its configured minimum.

Each Store read uses the minimum known when it starts. A session does not pin a
snapshot, so reads within one statement can observe different sequences at or
above that minimum.

`SqlContext::new` starts a monotonic session with no minimum and shares it across
the context's statements and clones. To read your own writes, start the session
at the sequence returned by `flush`, as in [Getting started](#getting-started).
You can also raise the minimum for a single query by deriving a context that
shares the catalog and observations:

```rust
let fresh = ctx.with_read_session(ctx.read_session().with_min_sequence_number(min_sequence_number));
fresh.sql("SELECT COUNT(*) FROM orders").await?.collect().await?;
let observed = ctx.read_session().evaluated_sequence();
```

All Store-backed tables in a context must read the same Store as its session. For
further configuration, `SqlContext::builder` accepts a `ReadSession`, a
DataFusion `SessionConfig` or `RuntimeEnv`, and other session state. If you supply
a custom DataFusion query planner, include `KvAggregateExtensionPlanner`.

## Query plans

Run [`EXPLAIN`](../docs/query-planning.md) to see how a query reaches the Store.
Its physical plan uses `KvScanExec` for row scans and `KvAggregateExec` for
aggregates computed in the Store. The plan identifies the chosen primary-key or
index access path, any remaining row checks, and whether the scan resembles a
full table scan.

## Serving SQL

To serve a schema over the `sql.v1` ConnectRPC API, create a `SqlServer` and mount
it on an axum router with `sql_stack`. The server registers the schema in
its own `SqlContext`:

```rust
use std::sync::Arc;
use exoware_sql::{sql_stack, SqlServer};

let server = Arc::new(SqlServer::new(schema)?);
let app = axum::Router::new().fallback_service(sql_stack(server));
```

`Query` runs one SQL statement and returns an Arrow IPC stream that Rust clients
can decode with Arrow's `StreamReader`. Its Store reads share a new monotonic
session starting at the request's optional minimum sequence. The response also
reports the highest Store sequence observed, omitting it when the statement read
nothing from the Store. A result whose encoded stream exceeds 256 MiB fails with
`RESOURCE_EXHAUSTED`.

`Query` accepts queries and `EXPLAIN`, `INSERT INTO` registered tables, `SET`
and `RESET` of options outside `datafusion.runtime` and `datafusion.catalog`,
`PREPARE`, `EXECUTE`, `DEALLOCATE`, `CREATE FUNCTION`, and `DROP FUNCTION`.
Session commands such as `SET`, `PREPARE`, and `CREATE FUNCTION` modify the
server's shared context, so their effects persist into later requests.
`CREATE FUNCTION` needs a function factory installed on the server's context.

`Query` rejects catalog DDL such as `CREATE TABLE`, `CREATE VIEW`, and
`DROP TABLE` because every caller shares the catalog. It rejects `COPY` and
`CREATE EXTERNAL TABLE` because they reach the server's files, and `DELETE`,
`UPDATE`, and other writes because `INSERT INTO` is the only write the service
offers. Register tables and views and set runtime options through
`server.context()`.

`Subscribe` streams rows from each Store batch that writes to a table and matches
a scalar SQL predicate. Predicates cannot use subqueries, aggregates, window
functions, or row-expanding expressions. Each frame is an independent Arrow IPC
stream with the batch's sequence number. To resume after a disconnect, set
`since_sequence_number` to the last frame's sequence plus one.

To discover the schema, use `Tables`. It lists each table's columns, primary key,
and indexes with their layout and cover columns.

## Examples

The examples connect to `EXOWARE_URL` (default `http://localhost:8080`):

```bash
cargo run -p exoware-sql --example orders_kv      # single-table inserts and queries
cargo run -p exoware-sql --example join_kv        # JOINs across tables
cargo run -p exoware-sql --example types_kv       # FixedSizeBinary and UInt64 keys
cargo run -p exoware-sql --example versioned_kv   # versioned primary keys
```

## Status

`exoware-sql` is **ALPHA** software and is not yet recommended for production use.
Developers should expect breaking changes and occasional instability.
