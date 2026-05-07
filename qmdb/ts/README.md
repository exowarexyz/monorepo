# @exowarexyz/qmdb

Browser client for the ordered QMDB ConnectRPC proof API.

This package:

- calls `qmdb.v1.OrderedService` over Connect-Web
- verifies `get`, `getMany`, and `subscribe` proofs for MMR or MMB through a small WASM module
- supports `exact`, `prefix`, and `regex` subscription matchers

`get` and `getMany` are root-driven: callers supply the ordered current root
they trust. The client is configured with a Merkle family (`mmr` by default)
and uses that for all proof decoding and verification.
