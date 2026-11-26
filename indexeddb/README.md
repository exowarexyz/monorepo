# Exoware Store on IndexedDB: database layout (version 1)

This document defines how an Exoware Store is laid out in an IndexedDB database. Every implementation that opens such a database MUST follow it. The TypeScript store in sdk/ts/src/indexeddb (published as @exowarexyz/sdk/indexeddb) is one such implementation. An implementation that follows this layout can open a database written by any other, in the same page or in another page of the same origin, at the same time.

The words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Browser behavior described below is that of Chrome 157 unless another browser is named.

## 1. Database

- The name is chosen by the application. The layout puts no meaning in the name.
- The IndexedDB version is 1.
- There are exactly three object stores, named kv, log and meta. Each is created with no key path, no key generator and no index (out-of-line keys).

### 1.1 Opening and upgrade

1. Open with indexedDB.open(name, 1).
2. In upgradeneeded with oldVersion 0, create the three object stores and nothing else. Version 1 defines no other upgrade step.
3. A VersionError from open means the database has a version this implementation does not know. The implementation MUST fail the open and MUST NOT delete or modify the database.
4. After a successful open, the implementation MUST check that objectStoreNames is exactly {kv, log, meta} and fail the open otherwise, without writing.
5. The implementation MUST handle the versionchange event on its connection by closing the connection, so that a delete or a later upgrade from another page is not blocked. Without the handler, deleteDatabase from another page stays blocked until the first page closes. With it, the delete proceeds as soon as the handler runs. A transaction on a closed connection throws InvalidStateError.
6. A later layout version N is opened with open(name, N) and defines its own steps from each older version. An implementation MUST refuse a version it does not implement.

### 1.2 A database can come back empty

Chrome deletes and recreates an IndexedDB database whose files it finds corrupt, and the page gets no error. open succeeds, upgradeneeded runs with oldVersion 0, and every committed row is gone. Chrome logs "IndexedDB recovering from a corrupted (and deleted) database". The loss needs a kill of the whole browser during Chrome's own background write after a commit, and it appears at an open in a later session. Apart from such a loss, a transaction that reported complete survives a kill that follows it, and a kill during a transaction leaves either all of it or none of it.

The layout cannot prevent this. Its consequences for every implementation are:

- An open that ran upgradeneeded from version 0 created the database. An implementation MUST be able to tell its caller that this happened (the TypeScript store reports created: true). The caller knows whether it expected data.
- The sequence number S of the last committed batch starts again at 0 after such a loss. Sequence numbers held by callers from before the loss are then above S, and a query that requires one of them fails its freshness check until S reaches it. Nothing in the layout distinguishes the old database from the new one.
- A browser may also evict an origin's storage under disk pressure unless the page was granted persistent storage (navigator.storage.persist()). Requesting it is the application's choice.

## 2. Types

### 2.1 Keys

Every key in every object store is an IndexedDB binary key. No other key type is used.

- A writer SHOULD pass each key as an ArrayBuffer of exactly the key's length. Chrome treats an ArrayBuffer and a Uint8Array with equal bytes as the same key. The fake-indexeddb 6.2.8 package that the TypeScript tests use rejects an empty Uint8Array key with DataError in put, get, delete and IDBKeyRange, and accepts an empty ArrayBuffer. A reader receives an ArrayBuffer.
- IndexedDB orders binary keys as unsigned bytes, and a key sorts before every longer key it prefixes. This is the Store's lexicographic key order, so no key transformation is applied. Chrome and fake-indexeddb 6.2.8 both order keys this way, including the empty key.
- The empty key (zero bytes) is a valid key.
- IDBKeyRange.bound throws DataError when lower is greater than upper, and when lower equals upper with an open bound. A reader MUST treat such a range as empty without building it.

### 2.2 Values

Every stored value is a byte string, stored as a Uint8Array or an ArrayBuffer. No other value type is stored (no bigint, number, string, Date, Map, array or object).

- A writer MUST store a value whose underlying buffer is exactly the value. That is either an ArrayBuffer, or a Uint8Array with byteOffset 0 and byteLength equal to its buffer's byteLength. IndexedDB serializes the whole underlying buffer of a view, so a view into a larger buffer (a decoded request, or WASM linear memory) stores the larger buffer in every row. A 10 byte view into a 4 MiB buffer reads back with the 4 MiB buffer.
- A reader MUST accept an ArrayBuffer and MUST accept a Uint8Array with any byteOffset, reading exactly byteLength bytes from byteOffset.

### 2.3 Integers

A u64 is encoded as 8 bytes, big endian. be64(n) names that encoding below.

### 2.4 Messages

Structured values are the repository's protobuf messages in protobuf binary encoding (proto/log/v1/stream.proto, proto/log/v1/retention.proto, proto/common/v1/kv.proto). Two encoders may produce different bytes for one message. A writer MUST NOT encode a group (wire types 3 and 4) and MUST encode each field that the messages define with that field's wire type. Within the limits of section 7, a reader MUST accept every valid encoding that keeps these two rules, including fields in any order, a field that repeats and fields it does not know. A reader MUST NOT compare encodings. A reader MAY treat a value that breaks either rule as corruption.

## 3. Object stores

Each subsection says what a row of its object store holds and what makes a row corrupt. An implementation MUST fail the operation that reads a corrupt row and MUST NOT repair it silently.

### 3.1 kv (current rows)

- Key: the Store key, 0 to 254 bytes. A longer key is corruption.
- Value: the row's value bytes (may be empty).

### 3.2 log (retained batches)

- Key: be64(sequence number), always 8 bytes, never be64(0). A key that is not 8 bytes, or that encodes 0 or a number above S, is corruption.
- Value: one encoded log.stream.v1.GetResponse with sequence_number equal to the key's sequence number and entries holding every common.kv.v1.Entry of the batch, in the order the Put carried them, with duplicates kept. An entry key is 0 to 254 bytes. A value is corruption when it does not decode, carries another sequence number than its key, has no entry, or has an entry key longer than 254 bytes.

### 3.3 meta (two optional rows)

Keys are the ASCII bytes of the names below.

| Key (ASCII) | Key bytes (hex) | Value | Absent means |
| --- | --- | --- | --- |
| sequence | 73 65 71 75 65 6e 63 65 | be64(S), the sequence number of the last committed batch | S = 0, nothing was ever written |
| retention | 72 65 74 65 6e 74 69 6f 6e | one encoded log.retention.v1.RetentionPolicy with kind set (keep_latest count greater than 0) | no retention rule is installed |

An implementation MUST NOT write any other row to meta. A retention row is at most 1024 bytes. A writer MUST NOT store a longer one, and a reader MUST accept every valid encoding of a rule (section 2.4) up to that length. A sequence row that is not 8 bytes is corruption, and so is a retention row that is longer than 1024 bytes, does not decode or fails validation. A reader MUST check the length of a retention row before it copies or decodes the row.

## 4. Invariants

These hold whenever no readwrite transaction is live. S is the value of meta.sequence (0 when absent).

- I1. S never decreases. Sequence numbers start at 1 and each committed batch has the next one.
- I2. log holds no key above be64(S).
- I3. The keys of log are be64(L) to be64(S) with no gap for some L of at least 1, or log is empty. Eviction only ever removes the lowest keys.
- I4. kv is the result of applying batches 1 to S in order (entries in batch order, a later entry for the same key wins), followed by any prune deletions. Prune deletions are not sequenced.
- I5. Every log value decodes, carries the sequence number of its key and has at least one entry.
- I6. If a retention rule is installed, log holds no key below be64(cutoff(rule, S)) (section 5.3).

## 5. Transactions

Each operation uses exactly one IndexedDB transaction with the scope, mode and durability below. An implementation MUST NOT split one operation over several transactions. It MUST NOT keep in memory, across transactions, any value it then writes back, because another connection may have changed it. The sequence number and the retention rule are read inside the transaction that uses them. A read followed by a write of one row in a readwrite transaction is serialized across connections and across pages.

| Operation | Scope | Mode | Durability |
| --- | --- | --- | --- |
| Put (one batch) | kv, log, meta | readwrite | strict |
| Get, GetMany, Range, Reduce | kv, meta | readonly | default |
| Prune | kv | readwrite | strict |
| Read one batch (log Get, each Subscribe step), oldest retained | log, meta | readonly | default |
| SetRetention | log, meta | readwrite | strict |

### 5.0 Rules for every write transaction

IndexedDB commits whatever requests were placed when a transaction is left with none pending. A task that places one put and returns leaves that row committed, and the same task with abort() leaves nothing. Therefore:

- W1. A writer MUST read and validate every row its operation depends on (meta.sequence, meta.retention) before it places its first write, and SHOULD finish all other work that can fail (copying keys and values, encoding the log row) before that point.
- W2. A writer MUST call abort() on the transaction when it cannot place every request of the operation (an exception, an early return, a failed call).
- W3. A cancellation that arrives after the first write was placed does not stop the placement. The operation either places everything or aborts.

Success is reported to the caller only after the transaction's complete event. With durability strict the browser reports complete only after the changes reached persistent storage. In Chrome a transaction that reported complete survives a kill of the browser right after it. A loss of power was not tested. Section 1.2 describes the loss that strict durability does not protect against.

An aborted transaction changes nothing. A transaction whose complete event the writer did not observe, because the browser was killed or the page went away, has an unknown outcome. The database then holds either all of that transaction or none of it, and a writer that repeats the operation may find the first attempt applied. A transaction over quota aborts at commit with QuotaExceededError after every put reported success, and leaves no change.

### 5.1 Put

Inside one transaction:

1. Read meta.sequence as S and meta.retention as the rule. Validate both (section 3.3). Fail without writing if either is malformed or if S is 2^64 - 1.
2. Let N = S + 1.
3. For each entry in request order, put the value under the key in kv. A later entry for the same key overwrites an earlier one.
4. Put the encoded GetResponse { sequence_number: N, entries } under be64(N) in log.
5. Put be64(N) under sequence in meta.
6. If a rule is present, delete from log every key below be64(cutoff(rule, N)). A writer MAY skip step 4 when that delete would remove the row it is about to write.

Step 1 is the only step that can fail by inspection of the database, and it precedes every write (W1).

The batch has sequence number N once the transaction completes. A writer that combines several requests into one transaction MUST give them one batch (one N, one log row with all entries in arrival order) or repeat steps 1 to 6 per batch in order.

After the complete event the writer MUST post the notification of section 6.

### 5.2 Queries

A query reads meta.sequence and its rows from kv in the same readonly transaction and reports that sequence number with every part of its answer. IndexedDB keeps the data seen by a live readonly transaction constant, so the rows are exactly the state at that sequence number. A live readonly transaction makes an overlapping writer wait until it finishes, whether the writer is in the same page or another page.

A transaction finishes as soon as it has no pending request when control returns to the event loop, so every read of one query MUST be issued from the transaction's own callbacks or their microtasks. A request placed after awaiting microtasks succeeds, and a request placed after setTimeout(0) throws TransactionInactiveError.

A long transaction delays every later transaction whose scope overlaps it with a writer on either side. An implementation SHOULD bound the work of one transaction.

### 5.3 Retention

cutoff(rule, S) is the lowest sequence number the rule keeps, limited to S + 1:

| Rule | Lowest kept sequence number |
| --- | --- |
| keep_latest { count } | max(S - count, 0) + 1 |
| greater_than { threshold } | min(threshold + 1, 2^64 - 1) |
| greater_than_or_equal { threshold } | threshold |
| drop_all | S + 1 |

cutoff = min(lowest kept, S + 1), with S + 1 saturating at 2^64 - 1. This is retention_floor in examples/simulator/src/rocks.rs, capped at S + 1 as that file does when it prunes the log.

SetRetention runs inside one transaction. It reads meta.sequence as S and the lowest key of log that will remain, and validates both before it places a write (W1). That key is the lowest key of log when the rule is cleared or cutoff(rule, S) is 1 or less, and otherwise the lowest key at or above be64(cutoff(rule, S)). If that key is corrupt (section 3.2), the call fails without a write. It then puts the encoded rule under retention in meta, or deletes that row to clear the rule, and if a rule was installed it deletes from log every key below be64(cutoff(rule, S)). SetRetention answers with the key it read as the oldest retained sequence number, or with none when log holds no such key.

Clearing the rule restores nothing.

### 5.4 Prune

Inside one transaction over kv, delete the selected rows. Prune does not read or write meta or log and does not change S.

### 5.5 Reading the log

Read log[be64(n)] and meta.sequence in one transaction. A present row is batch n. An absent row with n greater than S was never written. An absent row with n at most S (including n = 0) was evicted, and the lowest key of log read in the same transaction is the oldest retained batch.

## 6. Notification of writes

IndexedDB has no change events. Writers announce committed batches on a BroadcastChannel so that other connections (other pages, workers, or another implementation in the same page) can wake subscribers and refresh any frontier they cache.

- Channel name: the string exoware-store: followed by the database name.
- Message: a Uint8Array of exactly 8 bytes, be64(N), where N is a sequence number the sender committed. A sender MAY skip a message when it immediately sends a higher one.
- A sender MUST post after every committed Put transaction, after the complete event.
- A receiver MUST treat a message only as a hint that meta.sequence is now at least N. It MUST read the database for the truth, MUST ignore any message that is not 8 bytes, and MUST NOT assume delivery. A receiver MAY ignore the payload altogether and treat every well formed message as "read again". A page that dies between the commit and the post sends nothing, and a receiver then learns of the batch from the next message or the next time it reads.
- A BroadcastChannel object does not receive its own messages, but other BroadcastChannel objects with the same name in the same page do. Messages arrive in another page in order. An implementation wakes its own waiters directly.
- No message is sent for Prune or SetRetention. Neither changes S, and the retention rule is read inside every Put transaction.

## 7. Limits and what an implementation chooses

- An implementation sets its own limits on the largest value, the entries of a batch and the encoded entries of a batch, up to the limits of sdk/rs/src/limits.rs (254 byte keys, 32 MiB values, 2,000,000 entries and 256 MiB of encoded entries per batch). A reader MUST be able to read any row that those limits allow, with one exception. A reader MAY refuse a log value that holds more than 1,000,000 fields it does not know, counted over the value and its entries together. A writer MUST NOT store a value longer than 32 MiB, a batch of more than 2,000,000 entries, or a log value longer than 268,435,467 bytes, which is 256 MiB of encoded entries and 11 bytes for the sequence number field in its shortest encoding. A reader MAY refuse a row beyond these limits and MAY accept it.
- The TypeScript store defaults to the limits of sdk/rs/src/limits.rs except for the encoded entries of a batch (the sum that put_encoded_len in sdk/rs/src/limits.rs computes), where its default is 64 MiB. Its limits on a value, on the entries of a batch and on the encoded entries of a batch can be lowered and cannot be set above those of sdk/rs/src/limits.rs. A Put writes its payload twice in one transaction (kv rows and the log row), and Chrome fails a transaction holding about 500 MiB of values with DataError "Failed to write blobs (InvalidBlob)" while 400 MiB commits.
- A query reads all of its rows inside one transaction (section 5.2), so the TypeScript store holds the answer of a Get, GetMany or Range in memory, by default at most 64 MiB. It counts key bytes plus value bytes plus 64 bytes per row, and it bounds the keys that one Prune selects before it deletes by the same limit.
- How an implementation counts and bounds the memory of a large query, schedules subscriptions, or matches selectors is not part of the layout.
- Deleting a store is indexedDB.deleteDatabase(name).
