# @exowarexyz/qmdb

Verify QMDB proofs in the browser with WASM. Proofs can come from your application
or an Exoware QMDB service, which the package's clients query directly.

```sh
npm install @exowarexyz/qmdb
```

## Choose an API

| API | Use |
| --- | --- |
| `QmdbProofVerifier` | Verify operation-log proofs supplied by your application |
| `QmdbLogClient` | Fetch and verify operation-log entries for any QMDB variant |
| `QmdbOrderedClient` | Read decoded log entries, query current state, and subscribe to an ordered QMDB |

All three support MMR and MMB with SHA-256 or BLAKE3. Match `merkleFamily` and
`hashFamily` to the source database, overriding the defaults of `mmr` and `sha256`
as needed.

## Query an operation log

To read selected log entries, pass their locations, the log's tip, and a trusted
root for that tip. The tip is the inclusive final operation location, and the
root is a hash commitment to the database state:

```ts
import {
  QmdbLogClient,
  type OperationsContext,
} from '@exowarexyz/qmdb';

async function readOperations(
  endpoint: string,
  request: OperationsContext,
  trustedRoot: Uint8Array,
) {
  const client = new QmdbLogClient(endpoint, {
    merkleFamily: 'mmr',
    hashFamily: 'sha256',
  });
  return client.getOperations(request, trustedRoot);
}
```

`request` contains a `tip: bigint` and nonempty, strictly ascending
`locations: bigint[]` at or below that tip. The RPC accepts up to 1,024 locations.
The result contains each location and its `encodedOperation: Uint8Array`. For
consecutive entries, use `getOperationRange` with `tip`, `startLocation`, and
`maxLocations`. It verifies the exact interval
`[startLocation, min(startLocation + maxLocations, tip + 1))`.

`QmdbLogClient` and `QmdbOrderedClient` accept the
[SDK transport options](../../sdk/ts/README.md), including credentials. Unary
proof requests also accept `minSequenceNumber` to set the minimum Store sequence
for checking publication of the requested tip.

Locations and sequences use `bigint`, while request counts and WASM byte sizes
use unsigned 32-bit numbers. Pass roots as digest bytes. For byte arguments that
accept strings, the string is interpreted as UTF-8 text, not decoded from hex.

## Supply the trust context

Obtain roots and tips from authenticated application data. For a database with
current state, supply its current root so the operation-root witness can bind
the log to it. For an operation-log-only database, supply the operation-log root.
A root returned by the proof server is not itself trusted.

`OperationRangeProof` and `OperationMultiProof` establish membership in the log,
so an included update need not still be active. `Current*` proofs additionally
authenticate activity at the requested batch boundary, the final commit
location of an applied batch. That boundary can be older than the latest
published state.

## Query current ordered state

`QmdbOrderedClient` supports variable-encoded ordered operations with byte keys
and values. Its current key lookups, exclusions, key ranges, and operation ranges
require the source's `currentChunkSize`, which defaults to 32 bytes. Key range
verification checks bounds and forward pagination over authenticated successor
links. For other database kinds and encodings, use raw log verification. It
verifies encoded operations without decoding them as ordered operations or
supplying generic current-state queries.

## Verify proofs from another transport

When your application transports proofs itself, pass the original request
context and trusted root to [`QmdbProofVerifier`](src/verification.ts). Its range
methods accept `OperationRangeProof` protobuf bytes, while `verifyOperations`
and the `*Many` methods accept `OperationMultiProof` bytes. For example, this
verifies a batch of expected fixed-size keyless appends:

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

For these appends, the verifier checks the exact tip, locations, operation kinds,
and expected values. The corresponding fixed unordered-update methods check
expected keys and return their values. The native Rust prover and standalone
verifier support larger proofs than the RPC's request cap.

WASM initializes on first use. Call `initQmdbWasm` to preload it or supply a custom
module.

## Subscribe to ordered operations

`QmdbOrderedClient.subscribe` accepts exact, prefix, and regex filters built with
`matchExact`, `matchPrefix`, and `matchRegex`. Each frame contains a `tip`,
`resumeSequenceNumber`, and decoded proof. Decoding checks internal consistency.
Compare `frame.proof.root` with an independently trusted root for `frame.tip`
before using its operations.

Resume with `sinceSequenceNumber: frame.resumeSequenceNumber + 1n`. A frame may
contain only part of an uploaded range, and later frames can repeat operations
after upload retries. Consumers must tolerate at-least-once delivery.
