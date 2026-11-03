# exoware-sql

Define tables in Exoware Store and query them with SQL.

The [Rust crate](./rs/README.md) manages rows and indexes, runs queries with
DataFusion, and serves the `sql.v1` ConnectRPC API. The
[TypeScript client](./ts/README.md) queries that service and subscribes to new
rows, returning results as Apache Arrow tables.
