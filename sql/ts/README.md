# @exowarexyz/sql

SQL client backed by the Exoware API.

This package exposes a TypeScript client for `sql.v1.Service` over Connect-Web.
It reuses `@exowarexyz/sdk` transport setup and owns its generated `sql.v1`
protobuf bindings.

Queries return `DecodedQueryResult` objects containing the observed Store
`sequenceNumber` and a native Apache Arrow `table`. Queries without Store reads
return the requested floor, or `0n` if none was supplied. Subscription frames contain
the same fields. Arrow IPC preserves the result schema, field order,
nulls, nested values, decimal scale, and timestamp units/timezones. The client uses
binary Connect encoding by default.

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

const next = await client.query('SELECT * FROM orders', result.sequenceNumber, {
  timeoutMs: 5000,
});
console.log(next.sequenceNumber, next.table.numRows);

for await (const { sequenceNumber, table } of client.subscribe({ table: 'orders' })) {
  console.log(sequenceNumber, table.numRows);
}
```
