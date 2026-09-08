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

Use positional columns when a query returns duplicate field names. Arrow's
JavaScript timestamp getters return milliseconds as `number`; use the timestamp
vector's `toArray()` and its field type for exact integer values. Date getters
also use JavaScript numbers. Reinterpret date chunks with native `Data.clone`
and `Vector` as `Int32` (days) or `Int64` (milliseconds) to read their full range.
Decimal getters return unscaled integer words and the field type provides the
scale. No eager row conversion is performed by this client.

Arrow JS 21.2 does not decode ListView, LargeListView, or RunEndEncoded outputs
from explicit `arrow_cast` expressions. Rust Arrow consumers can read those IPC
payloads. Native Arrow JS transformations such as `Table.slice()` can rebuild
duplicate field names incorrectly; access duplicate-name results by position
without reconstructing their schema. Its Decimal64/256 string helpers also have
signedness/width limitations. The column buffers preserve the complete integers.
