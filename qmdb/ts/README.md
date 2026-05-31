# @exowarexyz/qmdb

Browser client for the QMDB ConnectRPC proof API.

This package:

- calls `qmdb.v1.KeyLookupService`, `qmdb.v1.OrderedKeyRangeService`,
  `qmdb.v1.OperationLogService`, and `qmdb.v1.CurrentOperationService` over Connect-Web
- verifies `get`, `getMany`, `getRange`, `getOperationRange`,
  `getCurrentOperationRange`, and `subscribe` proofs for MMR or MMB through a small WASM module
- exposes `QmdbOperationLogClient` for backend-agnostic historical operation-log proofs,
  including fixed keyless appends and fixed unordered updates
- supports `exact`, `prefix`, and `regex` subscription matchers

Proof verification is root-driven: callers supply the current/global root for
current-boundary-backed services. Operation-log-only backends are a separate
contract and use a trusted operation-log root. The client is configured with a
Merkle family (`mmr` by default) and uses that for all proof decoding and
verification.
