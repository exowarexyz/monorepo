# Query planning in exoware-sql

This guide explains how [`exoware-sql`](../rs/README.md) turns SQL into Store reads:
which predicates narrow key ranges, which aggregates the Store computes, and how to
read `EXPLAIN` output to check a plan before running an expensive query. Read the
crate README first for table, key, and index design.

## Access paths

DataFusion plans each query, and `exoware-sql` chooses how each table scan reads the
Store. A predicate that fixes every primary-key column to a finite set of values uses
bounded point lookups, with results restored to key order. The points enforce the
supported constraints on key columns, so rows are rechecked only when the query has
another predicate, such as one on a value column or an expression on a key column.
Without point lookups, the planner ranks the primary key and each secondary index by how
many leading key columns the predicate constrains, whether the index covers every
projected and filtered column, the index layout, and the number of key ranges.

A point lookup and a scan under a `LIMIT` report the most rows they can return as an
estimate to DataFusion. When the estimate is below DataFusion's row threshold for a
collected build side (`hash_join_single_partition_threshold_rows`), a hash join can
collect that scan and skip hash repartitioning of its inputs.

A covering index returns rows without touching base rows. A non-covering index first
applies the predicates it can check from the index entry, then fetches the surviving
base rows in bounded batches and checks the complete predicate against each one. When
the index key ranges enforce the whole predicate, a `LIMIT` sizes each request for index
entries and base rows by the rows still needed. A request that returns its full limit
without meeting the `LIMIT` ends that sizing, and the scan reads the rest of the range
without a limit and in full lookup batches. Compatible lexicographic covering indexes
also serve DataFusion's sort and `LIMIT` pushdown, including reverse traversal after a
fixed equality prefix. A scan with no filter also moves to such an index when the index
key order matches a requested order that the primary key cannot serve, so
`ORDER BY s LIMIT 7` over an index on `s` reads seven index entries. Equality on a
`Float64` zero matches both signed zeros, so it does not fix a prefix.

## Predicate pushdown

SQL predicates retain DataFusion semantics, including casts, functions, and null
handling. `exoware-sql` extracts the predicate forms below to prune key ranges on
primary-key and index key columns. Row scans evaluate remaining predicates on decoded
batches before materializing the other projected columns. Key-range pruning departs from
those semantics in one way. A row outside the pruned key ranges is never read, so an error
that a predicate would raise on that row, such as a division by zero in another conjunct,
does not occur.

| Column type | `=` | `<` `<=` `>` `>=` | `IN (...)` | `IS NULL`, `IS NOT NULL` |
|---|---|---|---|---|
| `Int64`, `UInt64` | yes | yes | yes | yes |
| `Utf8`, `FixedSizeBinary` | yes | no | yes | yes |
| `Float64`, `Date32`, `Date64`, `Timestamp`, `Decimal128`, `Decimal256` | yes | yes | no | yes |
| `Boolean` | yes | no | no | yes |

A chain of `OR` equalities on one column, such as `region = 'us' OR region = 'eu'`, is
treated as an `IN` list. A Boolean column used as a predicate, its negation, `IS TRUE`,
and `IS FALSE` count as equality on that column.

Composite keys are constrained left to right. Equality on leading columns fixes the
key prefix, and the first column with a range constraint, or with no constraint, sets
the scan bounds. With a primary key of `(entity, version)`:

| Predicate | Key ranges |
|---|---|
| `entity = X AND version <= V` | `[X, 0]` to `[X, V]` |
| `entity = X` | `[X, 0]` to `[X, MAX]` |
| `entity IN (X, Y)` | `[X, 0]` to `[X, MAX]` and `[Y, 0]` to `[Y, MAX]` |
| no primary-key constraint | the whole table |

A secondary index key continues with the primary-key columns, so the same rule runs
through both. In that suffix only an `Int64` or `UInt64` range narrows the key range.
`EXPLAIN` reports `exact=true` for an index scan only when the planner can show that
the range bounds enforce the whole predicate. It does not attempt this for a z-order
index. With `exact=false` the scan checks each entry itself and applies a `LIMIT` after
those checks, without passing it to the Store.

## Aggregate pushdown

Supported single-table aggregates run through the Store's `Reduce` RPC. Store workers
return partial aggregate states or distinct group keys instead of input rows, and
DataFusion's final aggregate merges them. Use `EXPLAIN` to confirm the plan contains a
`KvAggregateExec`. Any shape outside the rules below uses the normal scan and
DataFusion aggregation.

### Supported shapes

- **Aggregates:** `COUNT`, `SUM`, `MIN`, `MAX`, and numeric `AVG` returning a double
  (pushed as a sum and a count). Group-only queries and `SELECT DISTINCT` use the same
  grouping path. Aggregates with `DISTINCT`, such as `COUNT(DISTINCT x)`, run in
  DataFusion. A finite `LIMIT` that reaches a group-only aggregate, directly or through
  projections and subquery aliases, keeps it in DataFusion, where streaming and
  `DISTINCT` limit optimizations apply.
- **Expressions:** columns, literals, numeric `+`, `-`, `*`, `/`, negation of a signed
  64-bit integer expression, `lower`, and `date_trunc('day', ...)` on timestamps without
  a timezone. Aliases and transparent projection chains are resolved. Identity casts,
  compatible string representations, decimal precision widening without rescaling, and
  integer-to-double `CAST` and `TRY_CAST` are pushed. Narrowing casts, negation of a
  double, other functions, timezone-tagged timestamps, and row limits between the scan
  and the aggregate stay in DataFusion.
- **Filters:** aggregate `FILTER` clauses and equivalent `CASE` guards are pushed when
  every predicate is exactly representable by the Store predicate compiler. A scalar
  aggregate applies its filter before evaluating its argument, so the filter also
  narrows the access path. A grouped aggregate evaluates its argument before its
  filter, so precomputed grouped arguments remain eligible. A precomputed argument
  beneath a scalar `FILTER` or a `CASE` guard stays in DataFusion. Pushing it would
  evaluate it after the guard and could suppress an error it raises.
- **Access path:** every filter, group, and aggregate input must be available from the
  chosen primary-key range or index. Primary-key ranges can filter on stored values
  at the worker, so unindexed predicates do not require returning rows. A covering
  index narrows the scanned range. Variable-width key columns, and key columns after
  them, have no fixed byte offset, so they are read from stored index values when
  available and otherwise fall back to native decoding. A filter on such a column needs
  no worker check when the primary-key ranges enforce the whole predicate, as with
  `region = 'eu'` on a primary key of `(region, seq)`.

### Semantics

Workers apply each request's row predicate before updating aggregate state, because raw
range bounds can include rows that scan-time key checks would exclude. A request carries
no predicate when its primary-key ranges hold exactly the rows the filters accept.
Workers evaluate expressions with DataFusion and Arrow, so results follow ordinary
DataFusion semantics:

- Integer addition, subtraction, multiplication, negation, and sums wrap on overflow.
  Integer division truncates and reports division by zero and overflow as errors.
  Floating division follows IEEE rules, including zero divisors.
- `AVG` converts each integer input to a double before accumulating. NULLs follow SQL
  aggregate rules.
- Floating-point results, including `NaN` extrema, follow DataFusion's partial and
  final aggregation and can vary with range partitioning and merge order.
- A pushed aggregate reports payload decoding and expression errors as query errors.
  Requests without value-dependent expressions skip payload decoding. A plain base-row
  scan skips undecodable payloads, so queries over corrupt data can behave differently
  across plans.
- Aggregates with native `FILTER` clauses keep every group, even groups where no row
  passes a filter. When every aggregate has a `CASE` guard, the shared group-only
  request keeps groups that no guard selects.

### Execution

Aggregates that share ranges, grouping expressions, and a row filter share one
`Reduce` request, including grouped aggregates with different native filters. Output
columns keep their original order. A group-only query uses one request per range.

All requests for a query use its read session. Range requests run concurrently up to
the query's DataFusion `target_partitions` setting, each with the session's current
minimum sequence, and their results merge in range order. Workers stream completed
groups in batches, and the coordinator's final aggregate uses the query's memory pool
and spill configuration. Both stages keep groups in memory by default. Workers
configure their own memory pool and spilling through `QueryState::with_runtime_env` in
[`exoware-server`](../../server/README.md).

`EXPLAIN ANALYZE` reports metrics on each `KvAggregateExec`. Its `output_rows` counts the
partial-state rows it hands to the final aggregate, one per group in each `Reduce`
response, so the count can exceed the number of result rows. `store_requests` counts the
`Reduce` requests it started. `elapsed_compute` covers decoding their responses and
excludes time spent waiting for the Store.

`EXPLAIN FORMAT TREE` shows the fields of a `KvAggregateExec` one per line, with line
breaks in values escaped. A `jobs` line names its Reduce jobs. When there are several,
each field lists one value per job in that order, separated by semicolons. DataFusion's
tree renderer cuts a node off after 30 lines, so a node with many jobs loses its last
fields there. `EXPLAIN` without `FORMAT TREE` lists every job in full.

## Reading EXPLAIN output

`EXPLAIN` returns `plan_type` and `plan` rows. The `physical_plan` row contains a
`KvScanExec` for each row scan and a `KvAggregateExec` for each pushed aggregate. A
`KvAggregateExec` lists one access path per Reduce job. `EXPLAIN ANALYZE` runs the
query and adds runtime metrics. A `KvScanExec` reports `output_rows`, `elapsed_compute`
for the time it spent computing and not waiting on the Store, and `store_requests`.
`store_requests` counts the Store reads a node started. A retry that the SDK makes
inside one read is not counted.

| Field | Meaning |
|---|---|
| `mode=primary_key` | Scans the table's primary-key range. |
| `mode=primary_key_points` | Looks up the primary keys the predicate lists. |
| `mode=secondary_index(<name>, <layout>)` | Scans the named index with a `lexicographic` or `z_order` layout. |
| `predicate=...` | The predicate pushed to the scan, or `<none>`. |
| `exact=true` | The key ranges or points enforce the whole pushed predicate. |
| `row_recheck=true` | Candidate rows are decoded and checked against the residual predicate. |
| `ranges=<N>` | The number of key ranges read, or of keys looked up. |
| `full_scan_like=true` | The primary-key ranges are broad enough to resemble a full table scan. |
| `constrained_prefix=<N>` | The number of leading key columns the predicate constrains. |

`EXPLAIN FORMAT TREE` writes the same fields in the `KvScanExec` box, one per line, with
line breaks in values escaped. DataFusion wraps long values and cuts a box after 30
lines, so a long predicate can hide later fields. `EXPLAIN` without `FORMAT TREE` always
shows every field.

An indexed scan with a residual check, for `WHERE status = 'open' AND amount_cents >= 5`
over an index on `status`:

```text
KvScanExec: fetch=None, direction=None, mode=secondary_index(status_idx, lexicographic), predicate=status = 'open' AND amount_cents >= 5, exact=false, row_recheck=true, ranges=1, full_scan_like=false, constrained_prefix=1, query_stats=streamed_range(detail.extra: server-defined metadata)
```

The index enforces `status = 'open'` and narrows the key range, and each candidate row
is rechecked for `amount_cents >= 5`.

A pushed grouped aggregate, for
`SELECT status, SUM(amount_cents) ... WHERE status = 'open' GROUP BY status`:

```text
KvAggregateExec: grouped=true, seed_job=none, aggregate_jobs=[job0{mode=secondary_index(status_idx, lexicographic), predicate=status = 'open', exact=false, row_recheck=true, ranges=1, full_scan_like=false, constrained_prefix=1}], query_stats=range_reduce(detail.extra: server-defined metadata)
```

Here the worker reads only the `status_idx` range, checks the complete predicate, and
returns partial sums that DataFusion merges. This is the plan to aim for with
selective grouped aggregates.

`mode=primary_key` with `predicate=<none>` or `full_scan_like=true`, or an unexpectedly
large `ranges` count, signals a broad scan. So does a secondary index with
`constrained_prefix=0` and `fetch=None`, the plan for a sort that reads a whole index in
key order. To improve a broad scan, add or choose a more selective index, cover the
columns the query reads so the index can answer it alone, or rewrite the predicate so
more of it constrains leading key columns.

## Key layout

Each Store key starts with the schema's `StoreKeyPrefix`, followed by one family byte.
The high four bits of the family byte hold the table's position in the schema. The low
four bits are `0` for base rows and `1` through `15` for the table's secondary indexes
in declaration order. One byte therefore limits a schema to 16 tables and each table
to 15 indexes.

- Base row: `[family][primary key columns...]`
- Secondary index entry: `[family][index key columns...][primary key columns...]`

Key columns use order-preserving encodings, so Store key order matches SQL order on
those columns. Values are serialized with `commonware-codec` in the SDK's stored-row
format.
