# @exowarexyz/qmdb

Browser client for the QMDB ConnectRPC proof API.

This package:

- calls `qmdb.v1.KeyLookupService`, `qmdb.v1.OrderedKeyRangeService`,
  `qmdb.v1.OperationLogService`, and `qmdb.v1.CurrentOperationService` over Connect-Web
- verifies `get`, `getMany`, `getRange`, `getOperationRange`, `getOperations`,
  `getCurrentOperationRange`, and `subscribe` proofs for MMR or MMB through a small WASM module
- exposes `QmdbOperationLogClient` for backend-agnostic historical operation-log proofs,
  including fixed keyless appends and fixed unordered updates, singly or many per proof
- exposes `QmdbProofVerifier` for the same checks on proofs received through another transport
- supports `exact`, `prefix`, and `regex` subscription matchers

Proof verification is root-driven: callers supply the current/global root for
current-boundary-backed services. Operation-log-only backends are a separate
contract and use a trusted operation-log root. The client is configured with a
Merkle family (`mmr` by default) and uses that for all proof decoding and
verification.

Operation range verification binds the exact requested start, count, and tip.
Operations multi-proofs bind the exact requested tip and strictly ascending
locations.
Key ranges enforce linear ordering, bounds, and pagination. Absolute positions
use `bigint`. Batch limits and WASM byte-size arguments must fit their unsigned
32-bit representation.

All unary proof requests accept an optional `minSequenceNumber`: the minimum
Store sequence for checking publication of the requested watermark.

Subscription decoding checks internal proof consistency. Compare the returned
root with an independently trusted root for the frame tip before using its
operations. A server-provided root is not a trust anchor. `sha256` and `blake3`
provide cryptographic hashing. `crc32c` is a checksum mode for accidental
corruption and is unsuitable for authenticating an untrusted proof provider.

To verify proofs from an aggregate response, pass the raw `HistoricalOperationRangeProof`
or `HistoricalMultiProof` protobuf bytes, without the RPC response envelope:

```ts
import { initQmdbWasm, QmdbProofVerifier } from '@exowarexyz/qmdb';

const ready = initQmdbWasm();
const response = await fetchAggregate();
await ready;
const verifier = new QmdbProofVerifier({ merkleFamily: 'mmr', hashFamily: 'sha256' });
const account = await verifier.verifyFixedUnorderedUpdate(
  response.accountProof,
  { tip: stateTip, startLocation: accountLocation, maxLocations: 1 },
  stateRoot,
  accountLocation,
  accountKey,
  accountValueSize,
);
const transactions = await verifier.verifyFixedKeylessAppendMany(
  response.transactionProof,
  { tip: transactionTip },
  transactionRoot,
  expectedTransactions, // { location: bigint, value: Uint8Array }[]
);
```

Obtain roots and tips from authenticated application data, and bind the expected
keys, locations, and values to the requested account or transactions. An unordered
update proves historical membership, not that it is the latest update for its key.
`account.value` contains the authenticated value to decode. The verifier has no
Store freshness floor or transport options. The initializer is shared with network
clients and may also take WASM bytes or a compiled module. Supply a custom module
on the first initialization call. Later calls share that initialization, including
any failure.
