# @exowarexyz/qmdb

Query Exoware QMDB services and verify their proofs in the browser with WASM.
The package also verifies proofs received through an application's own transport.

## Choose an API

| API | Use |
| --- | --- |
| `QmdbOperationLogClient` | Fetch and verify raw log entries, consecutive or at selected locations |
| `OrderedQmdbClient` | Query current ordered keys and ranges, decode ordered log entries, and subscribe to updates |
| `QmdbProofVerifier` | Verify operation proofs without making RPC calls |

All three support MMR and MMB. Configure `merkleFamily` and `hashFamily` to match
the source database. They default to `mmr` and `sha256`. `blake3` is also
supported. `crc32c` detects accidental corruption and cannot authenticate an
untrusted proof provider.

## Query an operation log

```sh
npm install @exowarexyz/qmdb
```

Pass a trusted root and the tip and locations you want to read:

```ts
import {
  QmdbOperationLogClient,
  type OperationsContext,
} from '@exowarexyz/qmdb';

async function readOperations(
  endpoint: string,
  request: OperationsContext,
  trustedRoot: Uint8Array,
) {
  const client = new QmdbOperationLogClient(endpoint, {
    merkleFamily: 'mmr',
    hashFamily: 'sha256',
  });
  return client.getOperations(request, trustedRoot);
}
```

`request` contains a `tip: bigint` and nonempty, strictly ascending
`locations: bigint[]` at or below that tip. The RPC accepts up to 1,024 locations.
The result contains each location and its `encodedOperation: Uint8Array`.
`getOperationRange` instead takes `tip`, `startLocation`, and `maxLocations`, and
verifies the exact interval through `min(startLocation + maxLocations, tip + 1)`.

`QmdbOperationLogClient` and `OrderedQmdbClient` accept the
[SDK transport options](../../sdk/ts/README.md), including credentials. Unary
proof requests also accept `minSequenceNumber`, the minimum
Store sequence for checking publication of the requested tip. Locations and
sequences use `bigint`. Request counts and WASM byte sizes use unsigned 32-bit
numbers. Pass roots as digest bytes. String byte arguments are UTF-8 text, not
hex decoding.

## Supply the trust context

Obtain roots and tips from authenticated application data. A root returned by
the proof server is not itself trusted. For a database with current state,
supply its current root. The operation-root witness binds the log to it. For an
operation-log-only database, supply the operation-log root.

`OperationRangeProof` and `OperationMultiProof` establish membership in the log.
An included update need not still be active. `Current*` proofs additionally
authenticate activity at the requested batch boundary. That boundary can be
older than the latest published state.

`OrderedQmdbClient` supports variable-encoded ordered operations with byte keys
and values. Its current key lookups, exclusions, key ranges, and operation ranges
require the source's `currentChunkSize`, which defaults to 32 bytes. Key ranges
verify bounds and forward pagination over authenticated successor links.
Raw log verification works across other database kinds and encodings. It does
not decode them as ordered operations or supply generic current-state queries.

## Verify proofs from another transport

Use [`QmdbProofVerifier`](src/verification.ts) with the original request context
and trusted root. Its range methods accept `OperationRangeProof` protobuf bytes.
`verifyOperations` and the `*Many` methods accept `OperationMultiProof` bytes.
For example, this verifies a batch of expected fixed-size keyless appends:

```ts
import { QmdbProofVerifier } from '@exowarexyz/qmdb';

const verifier = new QmdbProofVerifier({ merkleFamily: 'mmr', hashFamily: 'sha256' });

async function verifyAppends(
  proofBytes: Uint8Array,
  tip: bigint,
  trustedRoot: Uint8Array,
  expected: { location: bigint; value: Uint8Array }[],
) {
  return verifier.verifyFixedKeylessAppendMany(
    proofBytes,
    { tip },
    trustedRoot,
    expected,
  );
}
```

The verifier checks the exact tip, locations, operation kinds, and expected
values. Fixed unordered-update methods check expected keys and return their
values. The native Rust prover and standalone verifier support larger proofs
than the RPC's request cap.

WASM initializes on first use. Call `initQmdbWasm` to preload it or supply a custom
module.

## Subscribe to ordered operations

`OrderedQmdbClient.subscribe` accepts exact, prefix, and regex filters built with
`matchExact`, `matchPrefix`, and `matchRegex`. Each frame contains a `tip`,
`resumeSequenceNumber`, and decoded proof. Decoding checks internal consistency.
Compare `frame.proof.root` with an independently trusted root for `frame.tip`
before using its operations.

Resume with `sinceSequenceNumber: frame.resumeSequenceNumber + 1n`. A frame may
contain only part of an uploaded range, and later frames can repeat operations
after upload retries. Consumers must tolerate at-least-once delivery.

See the [client methods](src/client.ts) for signatures and result types, and the
[Rust development guide](../rs/README.md#development) for tests and fixture
regeneration.
