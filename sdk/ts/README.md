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

## Request options

The SDK defaults to uncompressed protobuf over Connect. To use JSON for
services other than Put, set `ClientOptions.useBinaryFormat` to `false`.

[Put requires binary protobuf](../../proto/README.md#put-client-compatibility).
When creating a custom ingest client with `createTransport`, leave
`useBinaryFormat` enabled.

`ClientOptions.retry` controls retries, and setting `maxAttempts` to `1`
disables them. Under the [admission retry contract](../../proto/README.md#admission-retries),
Put retries are limited to server rejections that confirm the batch was never
admitted. Generic errors, timeouts, and lost responses are not automatically
retried. Direct `client.ingest.put(request, options)` calls accept a `timeoutMs`
or abort `signal` covering attempts and backoff.

## A Store in the browser

`@exowarexyz/sdk/indexeddb` keeps a Store in an IndexedDB database of the page's
origin and serves it in process. The same `Client` talks to it:

```ts
import { Client } from '@exowarexyz/sdk';
import { deleteIndexedDbStore, openIndexedDbStore } from '@exowarexyz/sdk/indexeddb';

const local = await openIndexedDbStore('my-app');
const client = new Client(local.transport);
const encode = (text: string) => new TextEncoder().encode(text);

const sequence = await client.store().set(encode('greeting'), encode('hello'));
const result = await client.store().createSessionWithSequence(sequence).get(encode('greeting'));

local.close();
await deleteIndexedDbStore('my-app');
```

`local.transport` is an in-process Connect transport that does not retry,
authenticate or compress. A `Client` built on a transport applies only its
`putLimits` option.

`local.routes` registers the same handlers on any Connect router, so an
application can serve the store over a channel of its own. The routes carry the
store's `maxRequestBytes`, so such a router refuses a larger request message
whatever its own options are. That limit counts bytes. A message within it can
still hold millions of empty Put entries or GetMany keys, and a router decodes
every one of them before a handler can count them. An application that passes
bytes from another page or peer to these routes must bound the number of
repeated elements before the bytes are decoded. It also decides who may call
Put, Prune and SetRetention.

The [database layout](../../indexeddb/README.md) is a contract shared with
other implementations. Pages and workers of one origin can open the same
database at the same time. Each operation is one IndexedDB transaction, so
every connection sees the same sequence of writes.

The store follows the Store API with these differences from a server:

- **Reduce is evaluated in the page.** It reads its range in one transaction,
  in batches of at most 4096 rows. `maxQueryBytes` bounds its aggregation state
  together with the results that the expressions of one batch compute, and a
  request that exceeds it fails with `RESOURCE_EXHAUSTED`.

  A group counts 48 bytes for each of its keys and reducers, plus the bytes of
  the text and binary values it keeps. Without `group_by` only those text and
  binary bytes count. For each value that an expression computes, a batch counts
  48 bytes plus the value's text or binary bytes. An expression computes one
  value per row, or one per batch when it is built from literals alone. Values
  read directly from a field are not counted. Without `group_by` a batch holds
  the computed values of one reducer at a time.

  `lower` follows the lowercase mapping of Unicode 18.0.0 on every JavaScript
  engine.

  Two kinds of expression answer `UNIMPLEMENTED`: `date_trunc_day` of a
  string, and arithmetic between a timestamp or a duration and a duration of
  another unit. A request nested deeper than 100 messages fails with
  `INVALID_ARGUMENT`, and so does a Date64 literal of the smallest value inside
  a larger expression. A request that the transport cannot decode, such as one
  nested thousands of messages deep, is answered by the transport with an error
  of its own.

  Groups arrive in the order of their first row. Arithmetic and sums pass on
  the sign and payload of a NaN operand. The NaN of an invalid operation such as
  0/0 and the result of an operation on two NaNs have no defined sign and
  payload, so a `MIN`, a `MAX` or a group key computed from one is unspecified.
  A NaN literal, range bound or result keeps its bits only where the JavaScript
  engine keeps them in a number.

- **A database can come back empty.** A browser may evict an origin's storage
  under disk pressure unless the page holds persistent storage
  (`navigator.storage.persist()`), and after a crash of the whole browser
  Chrome can find a database corrupt and delete it. Neither raises an error.
  `local.created` is `true` when the open created the database, so check it when
  you expected data. Sequence numbers then start again at 1, and a session that
  holds a floor from before the loss fails with `ABORTED` until the store
  reaches it.

- **Queries are bounded by memory.** IndexedDB cannot hold a snapshot open for a
  slow reader, so a Range or GetMany reads its whole answer before the first
  frame. An answer of Get, GetMany or Range above `maxQueryBytes` (64 MiB by
  default, counted as key and value bytes plus 64 bytes per row) fails with
  `RESOURCE_EXHAUSTED`, and the store stops reading at the first row that takes
  its answer above the limit. Read larger ranges in pages with `limit`. Pages
  are separate queries and may see different sequence numbers.

- **A Prune is bounded by the same limit.** It selects the keys of every policy
  before it deletes any. Meanwhile it holds each matched key with its order
  value, and the matcher of one pattern at a time. A request whose selection
  exceeds `maxQueryBytes` fails with `RESOURCE_EXHAUSTED` and deletes nothing.
  Prune a larger key family through narrower prefixes.

- **Requests are smaller.** One Put carries at most `maxRequestBytes` of encoded
  entries (64 MiB by default and at most the 256 MiB that a server accepts). Pass
  `putLimits: { maxEncodedBytes }` to `Client` so that batches are split to fit.
  `maxPutEntries` and `maxValueLen` default to the server's limits and cannot
  be set above them. A Prune request holds at most 256 policies.

- **Selector and filter regexes are a subset** of the Rust regex syntax, matched
  over bytes in linear time. The subset has the flags `s` and `u`, literals,
  `\xHH`, `.`, classes, `\d \s \w` without `u`, `^ $ \A \z`, groups, named
  groups, alternation, and greedy or lazy repetition of an expression that
  cannot match the empty string. A pattern has at most 1024 characters, groups
  nested 32 deep, repetition counts up to 1000 and a compiled size of 4096
  instructions. A pattern that a server accepts and that falls outside the
  subset answers `UNIMPLEMENTED`. An invalid pattern answers `INVALID_ARGUMENT`,
  except that these answer `UNIMPLEMENTED`: one longer than 1024 characters, one
  with the flag `x`, and one with an unknown Unicode property name in braces
  such as `\p{Bogus}`. A pattern that is invalid only because its compiled form
  is too large for the Rust regex crate may answer `UNIMPLEMENTED` too.

- **A subscription runs until its call is aborted or `local.close()` is
  called.** The `subscribe` methods of `client.store()` and its sessions abort
  their call when the consumer stops iterating. A direct
  `client.stream.subscribe` call stays open after its consumer leaves the loop,
  so pass a signal in its call options and abort it when you are done. Writes
  from other pages reach subscribers through a `BroadcastChannel` message that
  the writing page posts after each commit. The store does not poll, so if that
  page dies between its commit and the message, subscribers elsewhere receive
  the batch together with the next write or when they subscribe again.

- **Writes are ordered one at a time.** Every Put gets its own sequence number,
  applies the retention rule in the same transaction, and resolves after
  IndexedDB has reported the commit as durable. A Prune is one transaction as
  well. A long query delays writers in every page that has the database open,
  and a long write delays readers.

`openIndexedDbStore(name, options)` takes the limits `maxPutEntries`,
`maxValueLen`, `maxRequestBytes` and `maxQueryBytes`.

## Development

The lowercase mapping that `lower` follows in the browser store comes from
tables generated from the Rust standard library. The tables carry a digest of
the standard library's lowercase forms, and the tests of this package check on
every run that the store reproduces it. A test of the Rust SDK compares the
whole file of tables with the standard library whenever that library has the
tables' Unicode version. The tables move to another Unicode version only when
this command writes them anew, and the toolchain it runs with decides the
version. Run it inside the repository, then update the Unicode version named
above:

```sh
cargo test -p exoware-sdk --test lowercase_tables -- --ignored regenerate_lowercase_tables
```

## Status

`@exowarexyz/sdk` is **ALPHA** software and is not yet recommended for production use.
Developers should expect breaking changes and occasional instability.
