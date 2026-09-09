# @exowarexyz/sql

SQL client backed by the Exoware API.

This package exposes a TypeScript client for `sql.v1.Service` over Connect-Web.
It reuses `@exowarexyz/sdk` transport setup and owns its generated `sql.v1`
protobuf bindings.

Queries return native Apache Arrow `Table` objects. Subscription frames contain
`sequenceNumber` and `table`. Arrow IPC preserves the result schema, field order,
nulls, nested values, decimal scale, and timestamp units/timezones. The client uses
binary Connect encoding by default.

```ts
import { SqlClient } from '@exowarexyz/sql';

const client = new SqlClient('http://localhost:8080');
const result = await client.query('SELECT region, COUNT(*) FROM orders GROUP BY region');
console.log(result.schema.fields, result.numRows);
console.log(result.getChildAt(0)?.toArray());

for await (const { sequenceNumber, table } of client.subscribe({ table: 'orders' })) {
  console.log(sequenceNumber, table.numRows);
}
```
