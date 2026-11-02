# exoware-sql

SQL engine backed by the Exoware API.

- [Rust](./rs/README.md): define tables and indexes over a Store, write rows, and
  run DataFusion SQL. Includes the server for the `sql.v1` ConnectRPC API.
- [TypeScript](./ts/README.md): query a `sql.v1` server and subscribe to matching
  rows, with results as Apache Arrow tables.
