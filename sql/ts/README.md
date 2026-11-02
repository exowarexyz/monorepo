# @exowarexyz/sql

Query an Exoware SQL server from TypeScript and subscribe to rows as they are written.
`SqlClient` talks to a server for the `sql.v1` ConnectRPC API, such as
[`SqlServer`](../rs/README.md#serving-sql) from the Rust crate. It runs SQL queries,
streams rows from new Store batches that match a predicate, and lists the server's
tables. Results arrive as native [Apache Arrow](https://arrow.apache.org/docs/js/)
`Table` objects. The client works in Node and browsers and shares transport setup,
including credentials and retries, with [`@exowarexyz/sdk`](../../sdk/ts/README.md).

## Getting started

```sh
npm install @exowarexyz/sql
```

For this example, start the [simulator](../../examples/simulator/README.md) on
port 8080, then
[run the SQL service and seed its demo table](../rs/README.md#serving-sql).
The client queries that `orders_kv` table on the SQL service's default port, 8082:

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

The constructor accepts the SDK's client options, such as `{ token }` for deployments
that require a credential. Requests use the binary Connect encoding unless
`useBinaryFormat: false` is passed. Each method also takes Connect `CallOptions`, such
as `{ timeoutMs: 5000 }` or an abort `signal`.

## Query results

`query` resolves to a `sequenceNumber` and a `table`. The table preserves the result
schema, column order, nulls, nested values, decimal scale, and timestamp units and
timezones. `sequenceNumber` is the highest Store sequence any read in the query
observed, as a `bigint`. It is `undefined` when the statement read nothing from the
Store, and a requested minimum never counts as an observation.

Duplicate column names keep their positions, types, and values. Arrow JS 21.2 can
reject `Table.slice` and `Table.selectAt` when duplicate names have different types
([apache/arrow-js#288](https://github.com/apache/arrow-js/issues/288)), so give
columns unique SQL aliases before using those methods.

## Read consistency

Store replicas can lag. Each query sends a minimum Store sequence, and the server
reads at or above it. A client chooses how that minimum changes across queries:

- `new SqlClient(url, options)` and `SqlClient.monotonic(url, initialFloor, options)`
  require the highest sequence observed by earlier completed queries, starting from
  the optional initial floor. Later queries never see an older Store state than
  earlier ones.
- `SqlClient.fixed(url, floor, options)` sends the same minimum with every query.

To read your own writes, use the sequence returned by the write as the floor. Pass a
minimum as `query`'s second argument to strengthen one query without replacing the
configured floor. Its response still advances a monotonic client's observations.
`minSequenceNumber()` reports the minimum for the next query, and
`evaluatedSequence()` reports the highest sequence observed so far. Queries that read
nothing from the Store leave both unchanged.

Neither policy pins a snapshot. Reads within one query can observe different
sequences at or above the minimum.

## Subscriptions

`subscribe` yields one frame for each Store batch that writes rows to a table and
contains at least one row matching `whereSql`. Each frame carries the batch's
`sequenceNumber` and a `table` of only the matching rows.

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

Without `sinceSequenceNumber`, a subscription starts with the next batch. To resume
after a disconnect, pass the last frame's `sequenceNumber + 1n`. The server replays
retained batches from that sequence and then continues live, or fails if that batch
has been evicted. Subscription frames do not change the client's query floor or
observations.
