# @exowarexyz/sdk

[![npm](https://img.shields.io/npm/v/@exowarexyz/sdk.svg)](https://www.npmjs.com/package/@exowarexyz/sdk)

Interact with the Exoware API in TypeScript.

## Status

`@exowarexyz/sdk` is **ALPHA** software and is not yet recommended for production use. Developers should expect breaking changes and occasional instability.

## Put limits

`set`, `setMany`, and `StoreWriteBatch.commit` validate entry count, physical key
length, value length, and encoded request size before sending. Invalid batches
throw `RangeError`. Each call remains one atomic Put.

`StoreWriteBatch` provides `encodedLen(encoding)`, `validate(options)`, and
`split(options)`. Sizes include prefixed keys and the selected wire format.
The default encoding is JSON, matching the client transport. Pass
`store.putOptions` to match a client's encoding and limits:

```ts
const chunks = batch.split(store.putOptions);
for (const chunk of chunks) {
    await chunk.commit(store);
}
```

Splitting preserves order and shares payload buffers without changing the
original batch. An empty batch produces no chunks. An entry that cannot fit
alone throws. Each chunk is a separate write, so callers must handle partial
completion and any publication ordering they require.

Defaults use `MAX_PUT_ENTRIES`, `MAX_REQUEST_MESSAGE_BYTES`, `MAX_VALUE_LEN`, and
`MAX_KEY_LEN`. Configure `ClientOptions.putLimits` with `maxEntries`,
`maxEncodedBytes`, or `maxValueLen` to match a deployment. The same options can
be passed to `validate` and `split`. The byte budget is the logical batch size before stream envelopes.
See the [protocol contract](../../proto/README.md) for errors and portability.

## Streaming ingestion

Ingestion requires Node.js. The client uses the Connect Node HTTP/1.1 transport
for Put and keeps the fetch transport for other services.
`createTransport` creates a fetch transport for those other services. Both transports share
credentials and affinity cookies. Put failures are never retried automatically,
because an interrupted request may have committed.

Each Put sends one async stream of messages and returns one sequence number.
`PUT_CHUNK_TARGET_BYTES` is a 1 MiB soft target. A larger entry travels alone,
including supported 32 MiB values. `MAX_PUT_CHUNK_BYTES` caps each encoded message
at 64 MiB. These transport chunks preserve one atomic write.
`encodedLen` and aggregate validation describe the logical batch encoding and
exclude the five-byte stream envelopes. Explicit `split` calls still produce
separate writes.

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

const session = ReadSession.monotonic(orders);
const reader = ReadSession.fixed(orders, publicationSequence);
```

`minSequenceNumber()` reports the effective read floor, and `evaluatedSequence()`
reports the highest observed sequence. `clone()` shares observations.
Each request uses the floor known when it starts; overlapping reads proceed independently.
`undefined` means no requirement or observation; `0n` is an explicit sequence zero.
`withMinSequenceNumber(sequence)` derives a reader with a stronger floor when
needed, for either policy. It leaves the parent's configured floor unchanged and
does not count the requirement as an observation.

Successful `getBatch(...)` results and batches yielded by `subscribe(...)` are
observations. They advance subsequent query floors for monotonic sessions; fixed
sessions record them and retain their configured floor.

`createSession()` and `createSessionWithSequence(...)` create monotonic sessions.

## Generated TypeScript (`gen/ts`)

Protobuf-ES output lives under **`src/gen/ts/`** (mirrors the repo [`proto/`](../../proto/) tree, e.g. `proto/store/v1/query.proto` → `src/gen/ts/store/v1/query_pb.ts`). To regenerate after proto changes, run `../../gen.sh` from the repo root.

Integration tests spawn the Rust simulator via `jest.globalSetup.ts` (`cargo build --package exoware-simulator`).
