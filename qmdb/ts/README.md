# exoware-qmdb-ts

Browser client for the ordered QMDB ConnectRPC proof API.

This package:

- calls `store.qmdb.v1.OrderedService` over Connect-Web
- verifies `get`, `getMany`, and `subscribe` proofs through a small WASM module
- supports `exact`, `prefix`, and `regex` subscription matchers

`get` and `getMany` remain root-driven: callers must supply the ordered current
or historical root they want the server to prove against.
