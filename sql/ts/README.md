# @exowarexyz/sql

SQL client backed by the Exoware API.

This package exposes a TypeScript client for `sql.v1.Service` over Connect-Web.
It reuses `@exowarexyz/sdk` transport setup and owns its generated `sql.v1`
protobuf bindings.

Queries return `DecodedQueryResult` objects containing a native Apache Arrow
`table` and the highest Store `sequenceNumber` observed by the query. The
sequence number is `undefined` when the query does not read Store; a requested
minimum is not an observation. Subscription frames always contain a sequence
number. Arrow IPC preserves the result schema, field order,
nulls, nested values, decimal scale, and timestamp units/timezones. The client uses
binary Connect encoding by default.

Client reads are monotonic by default: each query requires the highest
Store sequence observed by earlier completed RPCs. `SqlClient.monotonic(url, initialFloor, options)` seeds
that minimum; `SqlClient.fixed(url, floor, options)` keeps it fixed across queries.
Neither policy pins an exact snapshot. The server uses monotonic reads within each query.

`minSequenceNumber()` reports the minimum for the next query, and
`evaluatedSequence()` reports the highest observation. An explicit minimum passed
to `query` can strengthen that request without changing the configured floor.
Queries without Store reads leave observations unchanged. Subscription frames
do not update query observations.

*Duplicate column names retain their positional types and values. Arrow JS 21.2
can reject `Table.slice` and `Table.selectAt` when duplicate names have different
types ([upstream issue](https://github.com/apache/arrow-js/issues/288)). Use unique
SQL aliases when applying those transformations.*

```ts
import { SqlClient } from '@exowarexyz/sql';

const client = new SqlClient('http://localhost:8080');
const result = await client.query('SELECT region, COUNT(*) FROM orders GROUP BY region');
console.log(result.sequenceNumber, result.table.schema.fields, result.table.numRows);
console.log(result.table.getChildAt(0)?.toArray());

const next = await client.query('SELECT * FROM orders', undefined, {
  timeoutMs: 5000,
});
console.log(next.sequenceNumber, next.table.numRows);

for await (const { sequenceNumber, table } of client.subscribe({ table: 'orders' })) {
  console.log(sequenceNumber, table.numRows);
}
```
