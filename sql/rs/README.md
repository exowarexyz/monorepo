# exoware-sql

SQL engine backed by the Exoware API.

## Status

`exoware-sql` is **ALPHA** software and is not yet recommended for production use. Developers should expect breaking changes and occasional instability.

## Library usage

`exoware-sql` is library-first: register `KvSchema` tables against a [`StoreClient`](https://docs.rs/exoware-sdk), then run SQL.

All table registration goes through `KvSchema`, which auto-assigns each table
a one-byte key prefix (table id in the high nibble, key family in the low
nibble) so multiple tables can coexist on a single KV store. DataFusion
handles JOINs natively once tables are registered.

To run multiple independent SQL schemas, or SQL alongside QMDB, on one Store,
give each instance a distinct SDK `StoreKeyPrefix` and pass that prefixed
`StoreClient` to `KvSchema`.

```rust
use exoware_sdk::{StoreClient, StoreKeyPrefix};
use exoware_sql::{session_context, IndexSpec, KvSchema, TableColumnConfig};
use datafusion::arrow::datatypes::DataType;

let ctx = session_context();
let client = StoreClient::new("http://localhost:10000").prefixed(StoreKeyPrefix::identity());

KvSchema::new(client)
    .table("customers", vec![
        TableColumnConfig::new("customer_id", DataType::Int64, false),
        TableColumnConfig::new("name", DataType::Utf8, false),
    ], vec!["customer_id".to_string()], vec![])?
    .table("orders", vec![
        TableColumnConfig::new("order_id", DataType::Int64, false),
        TableColumnConfig::new("customer_id", DataType::Int64, false),
        TableColumnConfig::new("amount", DataType::Int64, false),
    ], vec!["order_id".to_string()], vec![
        IndexSpec::lexicographic("cust_idx", vec!["customer_id".to_string()])?
            .with_cover_columns(vec!["amount".to_string()]),
    ])?
    .register_all(&ctx)?;

// Standard SQL JOINs are supported:
// SELECT c.name, o.amount FROM orders o JOIN customers c ON ...
```

A convenience method `.orders_table(name, index_specs)` registers the
pre-defined orders schema (region, customer_id, order_id, amount_cents, status).

## SQL service results

`SqlServer` returns Query results and matching Subscribe batches as native Arrow
IPC streams. Each payload includes its result schema, including computed column
types, decimal scales and timestamp units. Query serializes DataFusion batches as
they arrive. Each subscription frame contains an independent IPC stream and the
underlying atomic ingest sequence number.

Rust consumers can decode the payload with Arrow `StreamReader`. The TypeScript
SQL client returns native Arrow `Table` objects. Schema-only empty results and
zero-column row counts are preserved. The Tables RPC separately describes the
Store-specific primary keys and indexes.

## Versioned tables (composite primary keys)

Tables can have composite primary keys for versioned entity patterns.
`table_versioned()` is a convenience for `(entity, version)` primary keys where:

- the entity column may be `Utf8`, `FixedSizeBinary`, `Int64`, or `UInt64`
- the version column is `UInt64`

The encoded primary-key payload is still ordered as `[entity bytes][version_be]`,
so the version lives in the trailing 8 bytes of the logical primary key even
when the entity value is variable-length:

```rust
let schema = KvSchema::new(client).table_versioned(
    "documents",
    vec![
        TableColumnConfig::new("doc_id", DataType::FixedSizeBinary(16), false),
        TableColumnConfig::new("version", DataType::UInt64, false),
        TableColumnConfig::new("title", DataType::Utf8, false),
        TableColumnConfig::new("body", DataType::Utf8, true),
    ],
    "doc_id",   // entity column
    "version",  // version column (UInt64)
    vec![],
)?;
```

UInt64 is encoded big-endian, so versions sort numerically. "Latest version
<= V" maps to a reverse range scan:

```sql
SELECT * FROM documents
WHERE doc_id = X'AA..AA' AND version <= 42
ORDER BY version DESC LIMIT 1
```

For compaction pruning of an unindexed versioned table, the schema builds the
policy from the table's assigned prefix and entity encoding:

```rust
let policy = schema.keep_latest_versions_policy("documents", 1)?;
```

The constructor requires exactly two primary key columns, `(entity, UInt64
version)`, and rejects tables with secondary indexes. Apply the returned SDK
`PrunePolicy` through the same `PrefixedStoreClient` used to create the schema.
Store pruning does not cascade to secondary indexes, so disable primary-row
retention before adding indexes. The constructor cannot validate policies
created directly through the SDK or later schema changes.

Any composite PK (not just versioned) can be created via `table()` with
multiple column names:

```rust
.table("events", columns, vec!["tenant_id".to_string(), "event_id".to_string()], specs)?
```

`BatchWriter` works with versioned tables too. A versioned table is still just
a table with a composite primary key, so programmatic inserts can write rows
directly without going through Arrow:

```rust
use exoware_sql::{CellValue, KvSchema, TableColumnConfig};
use datafusion::arrow::datatypes::DataType;

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

let mut batch = schema.batch_writer();
batch.insert(
    "documents",
    vec![
        CellValue::FixedBinary(vec![
            0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]),
        CellValue::UInt64(1),
        CellValue::Utf8("Draft".to_string()),
    ],
)?;
 let _sequence_number = batch.flush().await?;
```

See `examples/versioned_kv.rs` for a larger versioned insert/query example.

## Example programs

```bash
cargo run -p exoware-sql --example orders_kv      # single-table demo
cargo run -p exoware-sql --example join_kv         # multi-table JOIN demo
cargo run -p exoware-sql --example types_kv        # FixedSizeBinary, UInt64, BatchWriter
cargo run -p exoware-sql --example versioned_kv    # versioned composite PK demo
```

## Scan consistency

Store reads within one `Query` RPC share a `SerializableReadSession`.
The request can supply an initial minimum sequence. Each observed response
advances the floor for subsequent reads, including pagination, index lookups,
and aggregate reductions. This preserves monotonic freshness across query
workers behind a load balancer. It does not provide snapshot isolation.
Queries without Store reads return the requested floor, or zero if none was supplied.

Embedded DataFusion contexts share a request session when created with
`query_context_with_min_sequence`. Without a shared session in the context,
each scan or aggregate creates its own session.

Primary keys identify immutable rows. Inserting the same primary key more than
once has undefined behavior. The write path does not enforce uniqueness. Use a
version column in the primary key to represent changes to a logical entity.
Base rows and their secondary index entries are written in one atomic batch.

## Aggregate pushdown

`exoware-sql` sends supported single-table aggregates to Store's `Reduce` RPC.
Workers return aggregate states or distinct group keys instead of full input
rows. Supported built-in aggregates are `COUNT`, `SUM`, `MIN`, `MAX`, and numeric
`AVG` returning double (a pushed sum and count). Group-only queries and
`SELECT DISTINCT` use the same grouping path. A finite limit directly above a
group-only aggregate keeps it in DataFusion so its streaming and DISTINCT limit
optimizations remain available. `DISTINCT` inside an aggregate, such as
`COUNT(DISTINCT x)`, uses DataFusion's normal execution. Grouped `Float64` `MIN`
and `MAX` use Reduce, with native DataFusion aggregation at both the worker and
the SQL coordinator.

The adapter resolves column aliases and transparent projection chains. Supported
inputs include columns, literals, numeric `+`, `-`, `*`, `/`, `lower`, and
`date_trunc('day', ...)` for timestamps without timezone metadata. Tagged
timestamps retain DataFusion's checked calendar path. Casts retain their
semantics: identity casts, compatible string representations,
decimal precision widening without rescaling, and integer-to-double conversion
can be pushed. Integer-to-double `CAST` and `TRY_CAST` execute as native Store
casts. Narrowing casts, unsupported functions, and intervening row limits
stay in DataFusion.

Aggregate `FILTER` and equivalent `CASE` expressions can be pushed when every
original filter is exactly representable by the Store predicate compiler.
Grouped aggregates pass explicit `FILTER` predicates to native DataFusion
aggregates at the worker. Scalar aggregates filter before evaluating their
arguments, so their predicates also narrow the Store access path. `CASE` guards
filter input rows before evaluating their guarded expressions. Precomputed
arguments beneath scalar `FILTER` or `CASE` stay in DataFusion to preserve their
position before the guard. Grouped `FILTER` keeps computed projections eligible
for Reduce because native grouped aggregation evaluates arguments first. Every request applies its complete row predicate at
the worker, because raw range bounds can include rows that scan-time key checks
would exclude. A covering index reduces the scanned range when available. Primary-key ranges can
also use worker-side filtering on stored values, so unindexed predicates do not
require returning full rows. All filter, group, and aggregate inputs must be
available from the selected access path. Store key-field expressions use fixed
byte offsets. Variable-width SQL key fields and fields following them therefore
use stored index values when available, or fall back to native decoding.

Aggregates sharing ranges, grouping expressions, and a row filter share one
Reduce request, including grouped aggregates with different native filters.
Output columns retain their original order. Native filters retain every group,
even when none of its rows contribute to an aggregate. If every aggregate has a
`CASE` guard, a group-only request preserves groups outside those guards. A
group-only query itself uses one request per range.

Workers evaluate expressions with native DataFusion and Arrow. Integer addition,
subtraction, multiplication, and sums use the wrapping behavior of ordinary SQL
expressions. Integer division truncates and reports zero or overflow errors;
floating division follows IEEE behavior, including zero divisors. AVG converts
each integer input to double before accumulation.
NULLs retain SQL aggregate semantics. Floating-point results, including NaN
extrema, follow native partial/final execution and can depend on range partitioning
and merge order. Reduce returns query errors when required
payload decoding or expression evaluation fails. Requests without value-dependent
expressions do not decode payloads. Native base-row scans skip undecodable
payloads, so queries over corrupt data can behave differently across plans.
Requests use one read session with a shared minimum sequence number.
That freshness floor does not pin a snapshot.
Jobs execute in order, and range results merge in order. Once the first range has
established the read floor, later range requests can overlap up to the query's
DataFusion `target_partitions` setting.

Unsupported shapes use the normal streaming scan and DataFusion execution.
Reduce avoids transferring full input rows. Workers aggregate with DataFusion
and stream completed groups in batches. The SQL coordinator feeds those states
into DataFusion's final aggregate using the query's memory pool and spill
configuration. Both stages keep groups in memory by default. Workers configure
their native memory pool and spilling through `QueryState::with_runtime`.
Transport buffers and materialized query results have separate memory ownership.
A covering index is most useful when it contains the aggregate inputs and all
filter/group columns.

## Z-Order secondary indexes

`exoware-sql` now supports a Z-Order (Morton-order) secondary-index layout for
multi-column predicate boxes.

Declare one with `IndexSpec::z_order(...)`:

```rust
let schema = KvSchema::new(client).table(
    "points",
    vec![
        TableColumnConfig::new("x", DataType::Int64, false),
        TableColumnConfig::new("y", DataType::Int64, false),
        TableColumnConfig::new("id", DataType::Int64, false),
        TableColumnConfig::new("value", DataType::Int64, false),
    ],
    vec!["id".to_string()],
    vec![
        IndexSpec::z_order("xy_z", vec!["x".to_string(), "y".to_string()])?
            .with_cover_columns(vec!["value".to_string()]),
    ],
)?;
```

Use Z-Order when your hot queries look like:

```sql
SELECT id, value
FROM points
WHERE x BETWEEN 100 AND 200
  AND y BETWEEN 400 AND 500;
```

Behavior notes:

- use `IndexSpec::lexicographic(...)` for normal concatenated secondary indexes
- Z-Order scans use Morton bounding spans, so they may read false positives and
  then filter them locally
- `EXPLAIN` reports the layout in the access path, for example:
  - `mode=secondary_index(xy_z, z_order)`
- aggregate pushdown can also use Z-Order indexes now, but it relies on the
  coordinated shared reduction protocol / worker support in the query worker:
  - Z-Order-aware key extraction
  - worker-side residual predicate enforcement before reduction
- if an aggregate/filter/group expression cannot be represented safely in that
  pushed reduction protocol, exoware-sql falls back to the normal non-pushdown path

## Plan inspection

Use `EXPLAIN` (or `EXPLAIN ANALYZE`) to inspect exoware-sql's custom physical-plan
nodes before running an expensive query.

- `KvScanExec` now reports:
  - chosen access path (`primary_key` or `secondary_index(<name>, <layout>)`)
  - pushed predicate summary
  - whether the predicate is fully enforced by the chosen key/index path
  - whether a residual row recheck is still required
  - range count
  - whether the path is effectively `full_scan_like`
- `KvAggregateExec` reports the same access-path diagnostics for pushed
  reduction jobs

This is useful for spotting queries that lost pushdown or degenerated into a
full-row scan before you execute them.

Typical workflow:

```sql
EXPLAIN
SELECT id, status, amount_cents
FROM orders
WHERE status = 'open' AND amount_cents >= 5;
```

DataFusion returns `plan_type` / `plan` rows. The most useful row is usually
the `physical_plan` row containing the `KvScanExec` or `KvAggregateExec` text.

Things to look for in `KvScanExec`:

- `mode=primary_key`
  - the scan is using the table's primary-key space
- `mode=secondary_index(<name>, lexicographic)`
  - the scan is using a normal lexicographic secondary index
- `mode=secondary_index(<name>, z_order)`
  - the scan is using a Z-Order secondary index
- `exact=true`
  - the pushed predicate is fully enforced by the chosen key/index path
- `row_recheck=true`
  - exoware-sql still needs to decode candidate rows and apply residual filtering
- `full_scan_like=true`
  - the chosen path is effectively broad enough to resemble a full table scan
- `ranges=<N>`
  - how many key ranges are being scanned

### Example: broad / full-scan-like query

```sql
EXPLAIN
SELECT id, status
FROM orders;
```

Representative physical-plan output:

```text
 KvScanExec: fetch=None, direction=None, mode=primary_key, predicate=<none>, exact=true, row_recheck=false, ranges=1, full_scan_like=true, query_stats=streamed_range(detail.extra: server-defined metadata)
```

Interpretation:

- no predicate was pushed (`predicate=<none>`)
- exoware-sql is scanning the primary-key space directly
- there is no residual row filter, but the path is still broad
- `full_scan_like=true` is the warning sign that this is effectively a full row scan

### Example: indexed query with residual row filtering

```sql
EXPLAIN
SELECT id, status, amount_cents
FROM orders
WHERE status = 'open' AND amount_cents >= 5;
```

Representative physical-plan output:

```text
 KvScanExec: fetch=None, direction=None, mode=secondary_index(status_idx, lexicographic), predicate=status = 'open' AND amount_cents >= 5, exact=false, row_recheck=true, ranges=1, full_scan_like=false, constrained_prefix=1, query_stats=streamed_range(detail.extra: server-defined metadata)
```

Interpretation:

- exoware-sql chose `status_idx`
- the index narrowed the keyspace (`full_scan_like=false`)
- `status = 'open'` is enforced by the index key
- `amount_cents >= 5` still requires candidate-row rechecking
- `exact=false` plus `row_recheck=true` means pushdown helped, but not all filtering happened at the key/index level

### Example: indexed aggregate pushdown

```sql
EXPLAIN
SELECT status, SUM(amount_cents) AS total_cents
FROM orders
WHERE status = 'open'
GROUP BY status;
```

The Reduce source beneath DataFusion's final aggregate:

```text
 KvAggregateExec: grouped=true, seed_job=none, aggregate_jobs=[job0{mode=secondary_index(status_idx, lexicographic), predicate=status = 'open', exact=false, row_recheck=true, ranges=1, full_scan_like=false, constrained_prefix=1}], query_stats=range_reduce(detail.extra: server-defined metadata)
```

Interpretation:

- the aggregate stayed on the pushed reduction path (`KvAggregateExec`)
- DataFusion's final aggregate merges the returned states across ranges
- the worker-side reduction job is using `status_idx`
- the index narrows the scanned range
- the worker checks the complete predicate before updating aggregate states
- this is the kind of plan you usually want for selective grouped aggregates

### Example: what to do with the output

As a rough rule of thumb:

- good signs:
  - `mode=secondary_index(...)`
  - `exact=true`
  - `row_recheck=false`
  - `full_scan_like=false`
- warning signs:
  - `mode=primary_key` with `predicate=<none>`
  - `full_scan_like=true`
  - unexpectedly large `ranges=<N>`

If you see a warning-sign plan, consider:

- adding or using a more selective secondary index
- extending cover columns so the chosen index can satisfy the query exactly
- rewriting the predicate so more of it lands on PK/index-key columns
- using `EXPLAIN ANALYZE` to confirm the runtime behavior matches the expected plan

## Column type support

| Type | PK | Index key | Value | Key width |
|---|---|---|---|---|
| `Int64` | yes | yes | yes | 8 bytes |
| `UInt64` | yes | yes | yes | 8 bytes |
| `Float64` | -- | yes | yes | 8 bytes |
| `Boolean` | -- | yes | yes | 1 byte |
| `Utf8` / `LargeUtf8` / `Utf8View` | yes | yes | yes | escaped variable-width UTF-8 |
| `Date32` | -- | yes | yes | 4 bytes |
| `Date64` | -- | yes | yes | 8 bytes |
| `Timestamp` | -- | yes | yes | 8 bytes |
| `Decimal128(p, s)` | -- | yes | yes | 16 bytes |
| `Decimal256(p, s)` | -- | yes | yes | 32 bytes |
| `FixedSizeBinary(n)` | yes | yes | yes | n bytes |
| `Binary` / `LargeBinary` / `BinaryView` | -- | -- | yes | -- |
| `List<T>` / `LargeList<T>` | -- | -- | yes | -- |

PK-eligible types: `Int64`, `UInt64`, `Utf8`, `FixedSizeBinary`.
Composite PKs may combine any PK-eligible types. Text keys use escaped UTF-8
with a terminator, including embedded NUL characters. The complete encoded key
must fit the Store key-length limit. SQL keys must use this canonical encoding.

## Filter pushdown

DataFusion compiles and evaluates scalar predicates, including casts, functions,
and null handling. The adapter extracts supported constraints to prune Store key
ranges. The table below describes this range-pruning subset. Other predicates
still execute through DataFusion. Residuals are evaluated in batches before
projected payload columns are materialized.

| Column type | `=` | `<` `<=` `>` `>=` | `IN (...)` | `IS NULL` / `IS NOT NULL` |
|---|---|---|---|---|
| `Int64` | yes | yes | yes | yes |
| `UInt64` | yes | yes | yes | yes |
| `Float64` | yes | yes | -- | yes |
| `Boolean` | yes | -- | -- | yes |
| `Utf8` | yes | -- | yes | yes |
| `Date32` | yes | yes | -- | yes |
| `Date64` | yes | yes | -- | yes |
| `Timestamp` | yes | yes | -- | yes |
| `Decimal128` | yes | yes | -- | yes |
| `Decimal256` | yes | yes | -- | yes |
| `FixedSizeBinary` | yes | -- | yes | yes |
| `Binary` | -- | -- | -- | -- |
| `List` | -- | -- | -- | -- |

**Composite PK pushdown**: For composite primary keys, predicates are
evaluated left-to-right across PK columns. Equality constraints on leading
columns narrow the key range prefix; the first column with a range constraint
(or no constraint) determines the scan bounds. For example, with
PK = `(entity, version)`:

| Query pattern | Range produced |
|---|---|
| `entity = X AND version <= V` | `[entity, 0]` to `[entity, V]` |
| `entity = X` | `[entity, 0]` to `[entity, MAX]` |
| `entity IN (X, Y)` | two ranges: `[X, 0]..[X, MAX]`, `[Y, 0]..[Y, MAX]` |
| no PK constraint | full table scan |

**OR-to-IN folding**: Chains of `OR` equalities on the same column
(e.g., `region = 'us' OR region = 'eu'`) are automatically folded into
an `IN` list.

## Key layout

`exoware-sql` packs key kind metadata into a single bit-packed leading
byte.

Layout:

- Base row / primary key:
  - reserved prefix bits: `[table_id(4)][discriminator=0(4)]`
  - remaining bits: ordered primary-key payload bytes
- Secondary index:
  - reserved prefix bits: `[table_id(4)][index_id(4)]`
  - remaining bits: ordered index payload bytes, then ordered primary-key bytes

Logical structure:

- Base row: `[prefix_bits][pk_col_1][pk_col_2]...`
- Secondary index: `[prefix_bits][idx_cols...][pk_cols...]`

### Current codec limits

The current bit budget is intentionally compact and supports:

- up to 16 tables per `KvSchema`
- up to 15 secondary indexes per table

If you need a larger table or index budget, adjust the codec bit allocation in
`exoware-sql` rather than depending on the current raw prefix shape.

## Covering indexes (performance-critical)

`exoware-sql` supports per-index covered columns via:

```rust
IndexSpec::lexicographic("status_idx", vec!["status".to_string()])?
    .with_cover_columns(vec!["amount_cents".to_string(), "created_at".to_string()])
```

### Exact semantics of `cover_columns`

- `key_columns` are always covered by the index key.
- Primary key columns are always available from key bytes (implicit coverage).
- `cover_columns` are additional non-PK columns stored in the secondary index value.
- Covering a PK column is rejected at schema resolution time.
- Duplicate coverage is deduplicated (for example if a column appears in both key and cover lists).

### Planner behavior

Complete primary-key point sets use bounded GetMany requests, with results
restored to key order. Other candidates are ranked by constrained key columns,
coverage of all projected and predicate columns, layout, and range count.

A covering index returns rows without base lookups. A noncovering index first
checks available predicates and then fetches surviving primary keys in bounded
batches. The complete predicate is checked against each base row. Compatible
lexicographic covering indexes support native DataFusion sort and LIMIT pushdown,
including reverse traversal after a fixed equality prefix.

### No-fallback invariant

- Index scans require covering payloads in secondary index values.
- Missing/empty covering payload in an index entry is treated as execution error.
- In other words, index read correctness depends on index writer emitting covering values consistently.

### Performance vs storage/write tradeoff

- More covered columns:
  - faster index-only reads (fewer scanned base rows / no lookup fanout),
  - larger index values (more storage, write bandwidth, and compaction I/O).
- Fewer covered columns:
  - leaner writes and index footprint,
  - more queries require base-row lookups.

Tune `cover_columns` per index to match hot query shapes, not full table width.

### Practical design recipes

1. `WHERE status = 'open' SELECT id, amount_cents ...`
   - index key: `status`
   - cover: `amount_cents` (and any other selected/filter-only non-PK columns)
2. `WHERE customer_id = ? AND created_at >= ? SELECT total`
   - index key: `customer_id`, `created_at`
   - cover: `total`
3. Keep low-selectivity, rarely-read columns out of cover lists.
4. Start narrow, benchmark, then add only fields needed for index-only plans.

## Adding indexes after data already exists

`exoware-sql` now supports explicit index backfill for existing rows:

```rust
let previous_indexes = vec![]; // index list used when rows were originally written
let report = schema
    .backfill_added_indexes("orders", &previous_indexes)
    .await?;
println!(
    "backfilled {} rows into {} new indexes ({} entries)",
    report.scanned_rows, report.indexes_backfilled, report.index_entries_written
);
```

You can also tune the full-scan row page size:

```rust
use exoware_sql::IndexBackfillOptions;

let report = schema
    .backfill_added_indexes_with_options(
        "orders",
        &previous_indexes,
        IndexBackfillOptions {
            row_batch_size: 500,
            start_from_primary_key: None,
        },
    )
    .await?;
```

To monitor progress or resume later, subscribe to progress events via a channel:

```rust
use exoware_sql::{IndexBackfillEvent, IndexBackfillOptions};

let (progress_tx, mut progress_rx) = tokio::sync::mpsc::unbounded_channel();
let report = schema
    .backfill_added_indexes_with_options_and_progress(
        "orders",
        &previous_indexes,
        IndexBackfillOptions {
            row_batch_size: 500,
            start_from_primary_key: None,
        },
        Some(&progress_tx),
    )
    .await?;
drop(progress_tx);

while let Some(event) = progress_rx.recv().await {
    match event {
        IndexBackfillEvent::Progress { next_cursor, .. } => {
            // Store next_cursor somewhere durable if you want resumable backfill.
        }
        IndexBackfillEvent::Completed { report } => {
            println!("{report:?}");
        }
        _ => {}
    }
}
```

Behavior:

- Critical ordering: deploy writers that emit new index entries before starting
  backfill. Otherwise, rows written during the backfill window can be missed by
  the new index.
- Backfill performs a full primary-key scan for the table and writes only the newly added index entries.
- Default response batch size is 1000 (`backfill_added_indexes` wrapper).
- `backfill_added_indexes_with_options_and_progress(...)` emits `Started`,
  `Progress`, and `Completed` events to a caller-provided channel.
- To resume later, persist `Progress.next_cursor` and pass it back as
  `start_from_primary_key`.
- Index evolution must be append-only:
  - previously existing indexes must keep the same order and layout,
  - new indexes must be added only at the end of the index list.
- If there are no new indexes, backfill is a no-op and returns zero counts.

For large tables, run backfill as an operational task after deploying schema changes.

## Insert recommendations

For robust and efficient application writes, prefer:

- typed application row structs for each table
- conversion from those row structs into `Vec<CellValue>`
- `KvSchema::batch_writer()` / `BatchWriter::insert(...)` for ingestion

Why this is the recommended path:

- `BatchWriter` writes the base row and all registered secondary index rows for
  the target table automatically
- it supports atomic multi-row and multi-table ingest batches
- it avoids the SQL/DataFusion insert path's Arrow `RecordBatch` materialization
  and the extra row-to-owned-value copying that follows
- typed row structs reduce column-order mistakes and make nullable fields explicit

Typical pattern:

```rust
use exoware_sql::CellValue;

struct UserRow {
    user_id: u64,
    name: String,
    age: Option<u64>,
}

impl From<UserRow> for Vec<CellValue> {
    fn from(row: UserRow) -> Self {
        vec![
            CellValue::UInt64(row.user_id),
            CellValue::Utf8(row.name),
            match row.age {
                Some(v) => CellValue::UInt64(v),
                None => CellValue::Null,
            },
        ]
    }
}
```

Then write with:

```rust
let mut batch = schema.batch_writer();
batch.insert(
    "users",
    UserRow {
        user_id: 1,
        name: "Alice".to_string(),
        age: Some(30),
    }
    .into(),
)?;
 let _sequence_number = batch.flush().await?;
```

Use SQL `INSERT` when convenience matters more than raw write-path efficiency,
for example ad hoc loading, tests, demos, or when your input data already lives
in DataFusion.

`BatchWriter` and SQL `INSERT` share the same schema metadata, so both paths
write all secondary indexes registered on the table. If you add new index specs
after older rows already exist, new writes pick them up automatically, while
older rows still require backfill.

## Generic model (library)

- configure table schema via `KvSchema::table()` (`TableColumnConfig` list +
  primary key column names)
- configure secondary indexes via `IndexSpec`
- table key prefixes are auto-assigned by `KvSchema` (no manual tracking)
- insert model:
  - one SQL `INSERT` statement writes base + all index rows in one atomic ingest
    batch
  - `BatchWriter` enables programmatic multi-table atomic inserts without
    DataFusion/Arrow conversion
- oversized single-statement inserts rely on ingest API request-size enforcement
  and surface the upstream client error (for example HTTP 413)
- query model:
  - bounded primary-key point lookups or selective range/index scans
  - covering index reads avoid base-row lookups
  - noncovering indexes batch lookups after available predicate checks
- value serialization uses `commonware_codec`; `decode_base_row` uses
  `exoware_sdk::kv_codec::decode_stored_row`
