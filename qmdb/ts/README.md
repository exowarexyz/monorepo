# @exowarexyz/qmdb

Browser client for the ordered QMDB ConnectRPC proof API.

This package:

- calls `qmdb.v1.KeyLookupService`, `qmdb.v1.OrderedKeyRangeService`, and `qmdb.v1.RangeService` over Connect-Web
- verifies `get`, `getMany`, `getRange`, and `subscribe` proofs for MMR or MMB through a small WASM module
- supports `exact`, `prefix`, and `regex` subscription matchers

`get`, `getMany`, and `getRange` are root-driven: callers supply the ordered
current root they trust. The client is configured with a Merkle family (`mmr`
by default) and uses that for all proof decoding and verification.
