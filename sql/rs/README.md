# exoware-sql

Run SQL over tables stored in an Exoware Store. `exoware-sql` maps each table's rows
and secondary indexes onto ordered Store keys, plans queries with
[DataFusion](https://datafusion.apache.org/), and pushes key-range filters and
supported aggregates down to the Store. `SqlServer` exposes the same tables over the
`sql.v1` ConnectRPC API for the [TypeScript client](../ts/README.md).

## Getting started

Add the crate, the SDK, and the dependencies used by this example. Use the same
`datafusion` major version as [`exoware-sql`](Cargo.toml), because schema types such as
`DataType` come from DataFusion's Arrow re-export.

```sh
cargo add exoware-sql exoware-sdk datafusion@55
cargo add tokio --features macros,rt-multi-thread
```

For local development, start the [simulator](../../examples/simulator/README.md):

```sh
cargo run -p exoware-simulator -- server run --port 8080
```

Describe a table, write two rows, and query them:

```rust
use datafusion::arrow::datatypes::DataType;
use exoware_sdk::{ReadSession, StoreClient, StoreKeyPrefix};
use exoware_sql::{CellValue, IndexSpec, KvSchema, SqlContext, TableColumnConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = StoreClient::new("http://localhost:8080").prefixed(StoreKeyPrefix::identity());
    let schema = KvSchema::new(client.clone()).table(
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
    let ctx = SqlContext::builder(client.clone())
        .with_read_session(ReadSession::monotonic(client, Some(sequence)))
        .build();
    ctx.register_schema(schema)?;
    ctx.sql("SELECT status, SUM(amount_cents) AS total FROM orders GROUP BY status")
        .await?
        .show()
        .await?;
    Ok(())
}
```

`SqlContext` wraps a DataFusion session, so JOINs, views, and other DataFusion SQL work
once tables are registered. Use `ctx.datafusion()` for DataFusion APIs that the
context does not forward. The [examples](#examples) cover joins, more column types,
and versioned keys.

## Designing tables

A `KvSchema` is an ordered list of tables over one `PrefixedStoreClient`. It assigns
each table a key prefix in registration order, so every reader and writer must build
the schema with the same tables in the same order. One schema holds at most 16
tables, and each table holds at most 15 secondary indexes. The
[key layout](../docs/query-planning.md#key-layout) explains these limits.

To keep several SQL schemas, or SQL and [QMDB](../../qmdb/README.md), on one Store,
give each a distinct SDK `StoreKeyPrefix` that does not overlap another tenant's
prefix. SQL scans are bounded by the schema's prefix, so an overlapping tenant's keys
can appear in its tables.

### Columns and keys

Every supported column type can be stored as a value. Primary keys and index keys
accept a subset:

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

Text keys use an escaped, terminated encoding that preserves sort order, including
embedded NUL characters. The complete encoded key, with its prefixes, must fit the
Store key-length limit. Index key columns must be non-nullable. Timestamp columns are
exposed with microsecond units and keep their timezone, and `LargeList` columns are
exposed as `List`.

### Primary keys

A primary key identifies one immutable row. Writing the same primary key twice has
undefined results, and neither write path checks for it. To record changes to a
logical entity, add a version column to its primary key.

Pass several column names to `KvSchema::table` for a composite primary key. Keys sort
by their columns in order, so put the columns that queries constrain by equality
first. A range constraint on a later column narrows the scan only when every earlier
column has an equality constraint.

`KvSchema::table_versioned` declares an `(entity, version)` primary key. Use a
`UInt64` column for the version. Versions sort numerically within each entity, so
the latest version at or below `V` is a short reverse range scan:

```rust
let schema = KvSchema::new(client).table_versioned(
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

The policy requires a table whose primary key is exactly `(entity, UInt64 version)`
and that has no secondary indexes. Store pruning removes base rows but never their
index entries, so remove the policy before adding an index to the table. The schema
cannot check policies built directly with the SDK or schema changes made after the
policy was applied.

### Secondary indexes

Without a usable index, a filter on a non-key column scans the whole table. An
`IndexSpec` names its key columns and two optional properties:

- **Cover columns** copy non-key values into each index entry. A query whose
  projected and filtered columns are all available from the index reads only the
  index. Otherwise each matching entry needs a lookup of its base row. Primary-key
  columns are always available from the index key and cannot be listed as cover
  columns.
- **Layout** is lexicographic by default. A lexicographic index serves equality on
  leading key columns followed by a range on the next one. `IndexSpec::z_order`
  interleaves fixed-width key columns so a box such as
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

Every cover column adds storage, write bandwidth, and compaction work to each index
entry. Choose the columns that hot queries read. An index that covers an aggregate's
filter, group, and input columns also lets the Store
compute that aggregate over the index's narrower key range, as described in the
[query planning guide](../docs/query-planning.md#aggregate-pushdown).

A covering index entry with a missing or undecodable payload fails the query. Reads
never repair an index entry from its base row, so index results are only as complete
as the entries that writers and backfills emit.

## Writing rows

`KvSchema::batch_writer` returns a `BatchWriter` that encodes rows as `CellValue`
vectors in column order and writes each row's base entry and all of its index entries.
`flush` uploads the pending rows, across tables, as one atomic Store batch and returns
its sequence number, or `0` when nothing was pending. If a flush fails, the writer
keeps its rows, and the next flush retries that batch alone before later rows are
uploaded. To commit SQL rows atomically with other Store writes, stage them into an
SDK `StoreWriteBatch` with `prepare_flush` and `stage_flush`, then report the commit
result with `mark_flush_persisted` or `mark_flush_failed`.

SQL `INSERT` writes through the same schema, and each statement becomes one atomic
batch. It materializes Arrow batches first, so `BatchWriter` is the more efficient
path for application ingest. The Store's request-size limit bounds a single batch,
and an oversized statement or flush returns the ingest error.

## Adding indexes to existing tables

New writes include every index in the current schema, but rows written earlier need a
backfill. Index lists may only grow at the end: existing indexes must keep their
position, name, key columns, cover columns, and layout. Then:

1. Deploy every writer with the new index list.
2. Run the backfill, passing the index list that earlier rows were written with.
3. Enable the new indexes for reads after the backfill finishes.

Rows written by an old writer during or after the backfill are missing from the new
index.

With `schema` built from the new index list and `previous_indexes` containing the
original `IndexSpec` values:

```rust
let report = schema
    .backfill_added_indexes("orders", &previous_indexes)
    .await?;
```

The backfill scans the table's primary keys and writes only the added indexes'
entries. With no added indexes, it writes nothing and reports zero counts.

For resumable backfills, use `backfill_added_indexes_with_options_and_progress`.
Each `Progress` event is sent after the writes it covers are flushed. Persist its
`next_cursor` and pass that as `IndexBackfillOptions::start_from_primary_key` when
resuming. The options also control the scan's response batch size.

## Read consistency

Store replicas can lag, and each Store response reports the sequence it reflects. A
read session sends a minimum sequence with each read and records the highest sequence
observed:

- A **monotonic** session raises its minimum to the highest observed sequence, so a
  later read never reflects an older Store state than an earlier one.
- A **fixed** session keeps its configured minimum.

Neither policy pins a snapshot. Reads within one statement can observe different
sequences at or above the minimum.

`SqlContext::new` starts a monotonic session with no minimum, shared by every
statement run through the context and its clones. To read your own writes, start the
session at the sequence returned by `flush`, as in [Getting started](#getting-started).
To strengthen a single query, derive a context that shares the catalog and
observations:

```rust
let fresh = ctx.with_read_session(ctx.read_session().with_min_sequence_number(sequence));
fresh.sql("SELECT COUNT(*) FROM orders").await?.collect().await?;
let observed = ctx.read_session().evaluated_sequence();
```

All Store-backed tables in one context must read the same Store as its session. Use
`SqlContext::builder` to supply a `ReadSession`, a DataFusion `SessionConfig` or
`RuntimeEnv`, or other session state. A custom DataFusion query planner must include
`KvAggregateExtensionPlanner`.

## Query plans

Run `EXPLAIN` to see how a query reaches the Store. The physical plan shows a
`KvScanExec` for row scans or a `KvAggregateExec` for aggregates computed in the Store,
with the chosen primary-key or index access path, whether a residual row check
remains, and whether the scan resembles a full table scan. The
[query planning guide](../docs/query-planning.md) describes predicate and aggregate
pushdown and how to read these plans.

## Serving SQL

`SqlServer` registers a schema in its own `SqlContext` and implements the `sql.v1`
service. `sql_connect_stack` returns a Connect service to mount on an axum router:

```rust
use std::sync::Arc;
use exoware_sql::{sql_connect_stack, SqlServer};

let server = Arc::new(SqlServer::new(schema)?);
let app = axum::Router::new().fallback_service(sql_connect_stack(server));
```

The service has three RPCs:

- **Query** runs one SQL statement. Its reads share a new monotonic session that
  starts at the request's optional minimum sequence. The response holds the result as
  an Arrow IPC stream, decodable in Rust with Arrow's `StreamReader`. It also holds the
  highest Store sequence observed, absent when the statement read nothing from the
  Store. Session commands such as `SET`, `PREPARE`, and `CREATE FUNCTION` apply to
  the server's shared context and affect later requests.
- **Subscribe** streams rows from each Store batch that writes to a table and matches
  a scalar SQL predicate. Predicates cannot use subqueries, aggregates, window
  functions, or row-expanding expressions. Each frame is an independent Arrow IPC
  stream with the batch's sequence number, and `since_sequence_number` set to the last
  frame's sequence plus one resumes after a disconnect.
- **Tables** lists each table's columns, primary key, and indexes with their layout
  and cover columns.

The `sql` binary serves a demo `orders_kv` table on port 8082 and can seed it with
rows. The [sandbox](../../examples/sandbox/README.md#sql-panel) uses it:

```sh
cargo run -p exoware-sql --bin sql -- run --store-url http://127.0.0.1:8080
cargo run -p exoware-sql --bin sql -- seed --store-url http://127.0.0.1:8080
```

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
