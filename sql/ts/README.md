# @exowarexyz/sql

Use `SqlClient` to query an Exoware SQL server and subscribe to rows as they are
written. It connects to the `sql.v1` ConnectRPC API served by the Rust crate's
[`SqlServer`](../rs/README.md#serving-sql), returning query results and matching
rows as native [Apache Arrow](https://arrow.apache.org/docs/js/) `Table` objects.
The client works in Node and browsers and shares credentials, retry settings,
and other transport options with [`@exowarexyz/sdk`](../../sdk/ts/README.md).

## Getting started

```sh
npm install @exowarexyz/sql
```

Start the [simulator](../../examples/simulator/README.md) on port 8080, then
[run the SQL service and seed its demo table](../rs/README.md#serving-sql). This
example queries the demo `orders_kv` table on the SQL service's default port,
8082, and lists the available tables:

```ts
import { SqlClient } from '@exowarexyz/sql';

const client = new SqlClient('http://localhost:8082');

const { sequenceNumber, table } = await client.query(
  'SELECT status, SUM(amount_cents) AS total FROM orders_kv GROUP BY status',
);
console.log(sequenceNumber, table.schema.fields.map((field) => field.name));
for (const row of table) console.log(row.toJSON());

for (const info of await client.tables()) {
  console.log(info.name, info.primaryKeyColumns, info.indexes);
}
```

Pass the SDK's client options to the constructor, such as `{ token }` for a
deployment that requires a credential or `useBinaryFormat: false` to use JSON
instead of the default binary Connect encoding. Each method also accepts
Connect `CallOptions` for a request timeout or abort `signal`.

## Query results

`query` returns a `table` and a `sequenceNumber`. The Arrow table preserves the
result schema, column order, nulls, nested values, decimal scale, and timestamp
units and timezones.

Duplicate column names keep their positions, types, and values. Arrow JS 21.2 can
reject `Table.slice` and `Table.selectAt` when duplicate names have different types
([apache/arrow-js#288](https://github.com/apache/arrow-js/issues/288)), so give
columns unique SQL aliases before using those methods.

The accompanying `sequenceNumber` is the highest Store sequence observed by any
read in the query, represented as a `bigint`. It is `undefined` when the statement
read nothing from the Store. A requested minimum does not count as an
observation.

## Read consistency

Store replicas can lag, so queries can specify a minimum Store sequence and
require the server to read at or above it. Choose how the client sets that
minimum across queries:

- `new SqlClient(url, options)` and `SqlClient.monotonic(url, initialFloor, options)`
  raise the minimum to the highest sequence observed by completed queries,
  starting from the optional initial floor.
- `SqlClient.fixed(url, floor, options)` sends the same minimum with every query.

To read your own writes, use the sequence returned by the write as the floor.
You can also pass a minimum as `query`'s second argument to strengthen one query
without replacing the configured floor. Its response still advances a monotonic
client's observations. Inspect those observations with `evaluatedSequence()`, or
use `minSequenceNumber()` to see the minimum for the next query. Queries that
read nothing from the Store leave both unchanged.

Each query uses the minimum known when it starts. Neither policy pins a snapshot,
so reads within one query can observe different sequences at or above that
minimum.

## Subscriptions

To follow new writes, call `subscribe` with a table name and an optional `whereSql`
predicate. Each Store batch containing a matching row produces one frame with
the batch's `sequenceNumber` and an Arrow `table` of the matching rows:

```ts
for await (const frame of client.subscribe({ table: 'orders_kv', whereSql: "status = 'paid'" })) {
  console.log(frame.sequenceNumber, frame.table.numRows);
}
```

`whereSql` is a scalar boolean expression over the table's columns, written without
`WHERE`. An empty predicate matches every row. Subqueries, aggregates, window
functions, and row-expanding expressions are not supported. Stable time functions
such as `now()` use the subscription's start time, and volatile functions run for
each batch.

Omit `sinceSequenceNumber` to start with the next batch. To resume after a
disconnect, pass the last frame's `sequenceNumber + 1n`. The server replays
retained batches from that sequence and then continues live, or fails if the
requested batch has been evicted. Subscription frames do not change the client's
query floor or observations.
