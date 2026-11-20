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
[simulator](../../examples/simulator/README.md) on port 8080. Each Store write
returns a sequence number identifying its position in the Store's write order.
This example writes a value, then uses that sequence to read data at least as
recent as the write:

```ts
import { Client, StoreKeyPrefix } from '@exowarexyz/sdk';

const client = new Client('http://localhost:8080');
const encode = (text: string) => new TextEncoder().encode(text);
const store = client.store(new StoreKeyPrefix(encode('example/')));
const key = encode('greeting');

const sequence = await store.set(key, encode('hello'));
const reader = store.createSessionWithSequence(sequence);
const result = await reader.get(key);
console.log(result === null ? null : new TextDecoder().decode(result.value));
```

The SDK represents sequences as `bigint` and keys and values as `Uint8Array`.
To connect to a deployment that requires authentication, use a credential with
the scopes your operations need. In Node, the client reads `EXOWARE_API_KEY`
unless you pass a token. Browser clients must receive the token explicitly:

```ts
const client = new Client('https://query.example.com', { token: 'your-token' });
```

`Client` uses one base URL for all services. Use `store()` for the
higher-level key-value interface shown above, or access the generated RPC
clients through service properties such as `query` and `ingest`.

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

`set`, `setMany`, and batch commits each send one atomic Put. They validate
sizes before sending and throw `RangeError` for invalid batches. Configure
entry, value, and encoded message limits for your deployment with
`ClientOptions.putLimits`.

To plan a larger upload, use `encodedLen()` to find the batch's uncompressed
protobuf size, including prefixes. If it needs splitting, replace the single
commit with:

```ts
for (const chunk of batch.split(base.putOptions)) {
    await chunk.commit(base);
}
```

Each chunk is a separate write, so your application must handle partial
completion and coordinate publication. Concurrent commits can be sequenced out
of order.

## Read consistency

Query replicas may lag behind writes. A [`ReadSession`](src/store.ts)
sets a minimum sequence, or floor, that each query must satisfy. Pass a write's
sequence to `createSessionWithSequence` when a read depends on that write.
The session is monotonic: as it observes newer query responses or log batches,
it raises the floor for subsequent requests. `createSession()` starts
without a floor.

`ReadSession.fixed(store, sequence)` keeps the configured floor fixed as
responses arrive. A replica may already be ahead of the floor, so either
policy can return a later sequence. Neither pins a historical snapshot.

Clones share observations, and each query uses the floor known when it starts.
To require a higher minimum for one reader, use
`withMinSequenceNumber(sequence)`. The derived reader shares observations
with its parent but leaves the parent's configured floor unchanged.

## Subscriptions

`subscribe` streams each matching batch in sequence order. Set
`sinceSequenceNumber` to replay retained batches from that sequence first.
Without it, the subscription starts after the latest batch.

```ts
const selectors = [{ prefix: encode('orders/'), payloadRegex: '(?s-u).*' }];
for await (const batch of store.subscribe({ selectors })) {
    console.log(batch.sequenceNumber, batch.entries.length);
}
```

A subscription resumes on its own when the stream ends, the connection drops, or
the server is restarting. It reopens with the same filters from the next
sequence, so no batch is skipped or delivered twice. Errors that a retry cannot
fix are thrown instead. These include rejected credentials, invalid filters, and
an `OUT_OF_RANGE` error with reason `BATCH_EVICTED` when the requested batches
are no longer retained. A subscription without `sinceSequenceNumber` that fails
before its first response also throws, because it has no position to resume
from.

`ClientOptions.subscriptionRetry` configures this. An outage lasts from a
disconnect until the next response, and `outageBudgetMs` (60 seconds by
default, `Infinity` for no limit) bounds each outage. After that the last
error is thrown. Reconnects back off from `initialBackoffMs` up to
`maxBackoffMs` until a new batch arrives. An idle subscription has no time
limit. Set `enabled` to `false` to make a single attempt that ends with its
stream. Abort the call option `signal` or stop iterating to cancel the
subscription.

## Request options

The SDK defaults to uncompressed protobuf over Connect. To use JSON for
services other than Put, set `ClientOptions.useBinaryFormat` to `false`.

[Put requires binary protobuf](../../proto/README.md#put-client-compatibility).
When creating a custom ingest client with `createTransport`, leave
`useBinaryFormat` enabled.

`ClientOptions.retry` controls retries of other RPCs, and setting `maxAttempts`
to `1` disables them. Under the [admission retry contract](../../proto/README.md#admission-retries),
Put retries are limited to server rejections that confirm the batch was never
admitted. Generic errors, timeouts, and lost responses are not automatically
retried. Direct `client.ingest.put(request, options)` calls accept a `timeoutMs`
or abort `signal` covering attempts and backoff.

## Status

`@exowarexyz/sdk` is **ALPHA** software and is not yet recommended for production use.
Developers should expect breaking changes and occasional instability.
