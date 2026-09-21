# @exowarexyz/sdk

[![npm](https://img.shields.io/npm/v/@exowarexyz/sdk.svg)](https://www.npmjs.com/package/@exowarexyz/sdk)

Interact with the Exoware API in TypeScript.

## Status

`@exowarexyz/sdk` is **ALPHA** software and is not yet recommended for production use. Developers should expect breaking changes and occasional instability.

## Credentials

An auth token can be provided when constructing the client:

```ts
const client = new Client('https://query.<deployment>.<domain>', '<token>');
```

Or under Node the token may come from the `EXOWARE_API_KEY` environment variable instead, read when no token is passed to the client constructor.
Browsers have no environment, so a browser client must be given its token explicitly.

## Store Key Prefixes

Use `StoreKeyPrefix` when multiple logical QMDB, SQL, or raw KV instances share one Store database. The prefix is applied by the SDK, so higher-level clients keep using their normal logical keys:

```ts
import { Client, StoreKeyPrefix, StoreWriteBatch } from '@exowarexyz/sdk';

const base = new Client('http://localhost:10000').store();
const orders = base.withKeyPrefix(new StoreKeyPrefix(new Uint8Array([1])));
const accounts = base.withKeyPrefix(new StoreKeyPrefix(new Uint8Array([2])));

const batch = new StoreWriteBatch()
    .push(orders, orderKey, orderValue)
    .push(accounts, accountKey, accountValue);
const sequence = await batch.commit(base);
```

## Read Sessions

`ReadSession.monotonic(store, floor)` advances its minimum sequence as reads
observe newer responses. `ReadSession.fixed(store, floor)` keeps that minimum
unchanged. Both track the highest observed sequence; neither pins an exact snapshot.

```ts
import { ReadSession } from '@exowarexyz/sdk';

const session = ReadSession.monotonic(orders, 0n);
const reader = ReadSession.fixed(orders, publicationSequence);
```

`minSequenceNumber()` reports the effective read floor, and `evaluatedSequence()`
reports the highest observed sequence. `clone()` shares observations.
`withMinSequenceNumber(sequence)` derives a reader with a stronger floor when
needed, for either policy. It leaves the parent's configured floor unchanged and
does not count the requirement as an observation.

`createSession()` and `createSessionWithSequence(...)` create monotonic sessions.

## Generated TypeScript (`gen/ts`)

Protobuf-ES output lives under **`src/gen/ts/`** (mirrors the repo [`proto/`](../../proto/) tree, e.g. `proto/store/v1/query.proto` → `src/gen/ts/store/v1/query_pb.ts`). To regenerate after proto changes, run `../../gen.sh` from the repo root.

Integration tests spawn the Rust simulator via `jest.globalSetup.ts` (`cargo build --package exoware-simulator`).
