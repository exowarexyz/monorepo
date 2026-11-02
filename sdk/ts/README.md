# @exowarexyz/sdk

[![npm](https://img.shields.io/npm/v/@exowarexyz/sdk.svg)](https://www.npmjs.com/package/@exowarexyz/sdk)

Read and write Exoware's immutable key-value Store from TypeScript in Node or a
browser. The SDK also provides range queries, reductions, log subscriptions,
pruning, and log retention controls.

## Getting started

```sh
npm install @exowarexyz/sdk
```

For local development, start the
[simulator](../../examples/simulator/README.md) on port 10000. This example writes
a value and reads it at or after the returned sequence:

```ts
import { Client, StoreKeyPrefix } from '@exowarexyz/sdk';

const client = new Client('http://localhost:10000');
const encode = (text: string) => new TextEncoder().encode(text);
const store = client.store(new StoreKeyPrefix(encode('example/')));
const key = encode('greeting');

const sequence = await store.set(key, encode('hello'));
const reader = store.createSessionWithSequence(sequence);
const result = await reader.get(key);
console.log(result === null ? null : new TextDecoder().decode(result.value));
```

Sequences use `bigint`. Keys and values use `Uint8Array`. In Node, the client reads
`EXOWARE_API_KEY` unless you pass a token. Browser clients must receive a token
explicitly when the deployment requires one:

```ts
const client = new Client('https://query.example.com', { token: 'your-token' });
```

Use a credential issued for the deployment with the scopes your operations need.
`Client` uses one base URL for all services. Its service properties, such as
`query` and `ingest`, expose the generated RPC clients. `store()` provides the
higher-level key-value interface.

## Namespaces and atomic writes

`StoreKeyPrefix` adds a namespace to keys sent to the Store and removes it from
returned keys. Choose non-overlapping prefixes for logical stores that should be
independent. Prefix bytes count toward the physical key limit, so
`maxLogicalKeyLen()` reports the remaining capacity. The same mechanism lets
[QMDB](../../qmdb/README.md) and [SQL](../../sql/README.md) instances share a Store.

To write across namespaces atomically, stage each row through its owning store
and commit once:

```ts
import { StoreWriteBatch } from '@exowarexyz/sdk';

const base = client.store();
const orders = base.withKeyPrefix(new StoreKeyPrefix(encode('orders/')));
const accounts = base.withKeyPrefix(new StoreKeyPrefix(encode('accounts/')));
const batch = new StoreWriteBatch()
    .push(orders, encode('42'), encode('created'))
    .push(accounts, encode('7'), encode('active'));
const batchSequence = await batch.commit(base);
```

`set`, `setMany`, and batch commits each send one atomic Put. They validate sizes
before sending and throw `RangeError` for invalid batches. Set
`ClientOptions.putLimits` to configure entry, value, and encoded message limits for
your deployment.
`encodedLen()` reports a batch's uncompressed protobuf size, including prefixes.

For batches that need splitting, replace the single commit with:

```ts
for (const chunk of batch.split(base.putOptions)) {
    await chunk.commit(base);
}
```

Each chunk is a separate write. Handle partial completion and coordinate
publication yourself. Concurrent commits can be sequenced out of order. See the
[Put contract](../../proto/README.md) for limits, errors, and splitting constraints.

## Read consistency

A write's sequence is a minimum read position. Query replicas may lag, so pass
that sequence to `createSessionWithSequence` when a read depends on the write.
The resulting monotonic session raises its floor as it observes newer query
responses or log batches. `createSession()` starts without a floor.

`ReadSession.fixed(store, sequence)` keeps the configured floor unchanged. Neither
policy pins a historical snapshot: reads may observe a later sequence. Clones
share observations, and each request uses the floor known when it starts.
`withMinSequenceNumber(sequence)` derives a stronger reader without changing the
parent's configured floor. See [`ReadSession`](src/store.ts) for observation
tracking and log reads.

## Request options

The SDK sends uncompressed Connect requests. Put always uses binary protobuf.
`ClientOptions.useBinaryFormat` controls the other services. Custom ingest clients
created with `createTransport` must pass `{ useBinaryFormat: true }`. See the
[Put compatibility contract](../../proto/README.md#put-client-compatibility).

`ClientOptions.retry` controls retries. Put retries are limited to server
rejections that confirm the batch was never admitted. Generic errors, timeouts,
and lost responses are not automatically retried. Set `maxAttempts` to `1` to
disable retries. Direct `client.ingest.put(request, options)` calls accept a
`timeoutMs` or abort `signal` covering attempts and backoff. See the
[admission retry contract](../../proto/README.md#admission-retries) before adding
application retries.

The [client options](src/client.ts) and [Store API](src/store.ts) describe the
available calls. Generated protobuf types live in `src/gen/ts`. Regenerate them
with `./gen.sh` from the repository root after changing the schemas.

## Status

`@exowarexyz/sdk` is **ALPHA** software and is not yet recommended for production use.
Developers should expect breaking changes and occasional instability.
