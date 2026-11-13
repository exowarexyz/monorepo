/**
 * IndexedDB plumbing shared by the store's handlers. It defines the names and encodings of the
 * database layout, copies keys and values into exact buffers, and runs the one transaction of each
 * operation. The layout is specified in indexeddb/README.md at the repository root.
 */

import { ConnectError } from '@connectrpc/connect';
import { MAX_KEY_LEN } from '../limits.js';
import { dataCorrupt, domExceptionName, metadataCorrupt, storeClosed } from './errors.js';

/** Object store of the current rows, keyed by the Store key. */
export const KV = 'kv';

/** Object store of the retained batches, keyed by the encoded sequence number. */
export const LOG = 'log';

/** Object store of the sequence number and the retention rule. */
export const META = 'meta';

/** Version of the database layout, used as the IndexedDB database version. */
export const LAYOUT_VERSION = 1;

/** The highest sequence number, the largest unsigned 64-bit integer. */
export const MAX_SEQUENCE = (1n << 64n) - 1n;

/**
 * Number of writes a handler issues before it waits for one of them. A large batch is placed in
 * chunks so that it does not queue every request in one task.
 */
export const REQUEST_CHUNK = 1024;

/** Copies bytes into a buffer of exactly their length. Keys and values are stored in this form. */
export function exactBuffer(bytes: Uint8Array): ArrayBuffer {
    const copy = new Uint8Array(bytes.byteLength);
    copy.set(bytes);
    return copy.buffer;
}

/** The ArrayBuffer behind `bytes` when it holds exactly those bytes, otherwise an exact copy. */
export function ownedBuffer(bytes: Uint8Array): ArrayBuffer {
    const { buffer } = bytes;
    const exact = bytes.byteOffset === 0 && bytes.byteLength === buffer.byteLength;
    return exact && tagOf(buffer) === 'ArrayBuffer' ? (buffer as ArrayBuffer) : exactBuffer(bytes);
}

/** The 8 byte big endian form of a sequence number. */
export function be64(value: bigint): ArrayBuffer {
    const buffer = new ArrayBuffer(8);
    new DataView(buffer).setBigUint64(0, value);
    return buffer;
}

function readBe64(bytes: Uint8Array): bigint {
    return new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0);
}

function asciiKey(name: string): ArrayBuffer {
    return exactBuffer(new TextEncoder().encode(name));
}

// Keys of the meta rows that hold the sequence number and the retention rule.
export const SEQUENCE_KEY = asciiKey('sequence');
export const RETENTION_KEY = asciiKey('retention');

// Values and keys can come from another JavaScript realm, where instanceof does not hold.
function tagOf(value: unknown): string {
    return Object.prototype.toString.call(value).slice(8, -1);
}

/**
 * Reads a stored byte string of at most `maxBytes`. A value that has neither form the layout
 * allows, or that is longer, fails with the error that `corrupt` builds. The form and the length
 * are read from the stored object and checked before any byte is copied.
 *
 * The result always covers its whole buffer. A stored view of part of a buffer is copied, so that
 * what a reader keeps is as large as the bytes it counts and the rest of the buffer can be freed.
 */
function boundedBytes(stored: unknown, maxBytes: number, corrupt: () => ConnectError): Uint8Array {
    const tag = tagOf(stored);
    if (tag !== 'ArrayBuffer' && tag !== 'Uint8Array') throw corrupt();
    if ((stored as ArrayBuffer | Uint8Array).byteLength > maxBytes) throw corrupt();
    return tag === 'ArrayBuffer'
        ? new Uint8Array(stored as ArrayBuffer)
        : new Uint8Array(ownedBuffer(stored as Uint8Array));
}

/**
 * The bytes of a stored row value or batch. A value of another form or longer than `maxBytes` is
 * corrupt data.
 */
export function storedBytes(stored: unknown, maxBytes: number = Infinity): Uint8Array {
    return boundedBytes(stored, maxBytes, dataCorrupt);
}

/**
 * The bytes of a stored meta row. A row of another form or longer than `maxBytes` is corrupt
 * metadata.
 */
export function storedMetaBytes(stored: unknown, maxBytes: number): Uint8Array {
    return boundedBytes(stored, maxBytes, metadataCorrupt);
}

function binaryKey(key: IDBValidKey): Uint8Array {
    if (tagOf(key) !== 'ArrayBuffer') throw dataCorrupt();
    return new Uint8Array(key as ArrayBuffer);
}

/** Fails for a stored Store key that is longer than any Put can have written. */
export function checkStoredKey(key: Uint8Array): void {
    if (key.byteLength > MAX_KEY_LEN) throw dataCorrupt();
}

/** The Store key of a row that a cursor returned. */
export function rowKey(key: IDBValidKey): Uint8Array {
    const bytes = binaryKey(key);
    checkStoredKey(bytes);
    return bytes;
}

/** The sequence number that a key of the log encodes. */
export function sequenceOfKey(key: IDBValidKey): bigint {
    const bytes = binaryKey(key);
    if (bytes.byteLength !== 8) throw dataCorrupt();
    return readBe64(bytes);
}

/** Resolves with the result of one request of a live transaction. */
export function settle<T>(request: IDBRequest<T>): Promise<T> {
    return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

/**
 * Reads the sequence number of the last committed batch, or 0 for a store that was never
 * written. Each operation that uses it reads it inside its own transaction, because another
 * connection may have advanced it since this one last looked.
 */
export async function readSequence(meta: IDBObjectStore): Promise<bigint> {
    const stored = await settle(meta.get(SEQUENCE_KEY));
    if (stored === undefined) return 0n;
    const bytes = storedMetaBytes(stored, 8);
    if (bytes.byteLength !== 8) throw metadataCorrupt();
    return readBe64(bytes);
}

/**
 * The lowest sequence number in the log at or above `from`, undefined when there is none.
 * `sequenceNumber` is the store's sequence number, read in the same transaction. No Put writes a
 * key of 0 or a key above `sequenceNumber`, so finding one is corrupt data.
 */
export async function oldestRetained(
    log: IDBObjectStore,
    sequenceNumber: bigint,
    from: bigint = 0n,
): Promise<bigint | undefined> {
    const keys = from > 1n ? IDBKeyRange.lowerBound(be64(from)) : undefined;
    const cursor = await settle(log.openKeyCursor(keys));
    if (cursor === null) return undefined;
    const oldest = sequenceOfKey(cursor.key);
    if (oldest === 0n || oldest > sequenceNumber) throw dataCorrupt();
    return oldest;
}

/** The range of log keys below `floor`, undefined when no key can be below it. */
export function logKeysBelow(floor: bigint): IDBKeyRange | undefined {
    return floor > 1n ? IDBKeyRange.upperBound(be64(floor), true) : undefined;
}

/**
 * Visits the rows of a cursor in order until `visit` returns false. A row arrives per event, so
 * the visitor can bound what a scan reads. A visitor that throws ends the scan with its error.
 */
export function walk<C extends IDBCursor>(
    opened: IDBRequest<C | null>,
    visit: (cursor: C) => boolean,
): Promise<void> {
    return new Promise((resolve, reject) => {
        opened.onerror = () => reject(opened.error);
        opened.onsuccess = () => {
            const cursor = opened.result;
            try {
                if (cursor === null || !visit(cursor)) {
                    resolve();
                } else {
                    cursor.continue();
                }
            } catch (error) {
                reject(error);
            }
        };
    });
}

type Scope = readonly string[];

// Scope of each operation's transaction.
export const PUT_SCOPE: Scope = [KV, LOG, META];
export const QUERY_SCOPE: Scope = [KV, META];
export const PRUNE_SCOPE: Scope = [KV];
export const LOG_SCOPE: Scope = [LOG, META];
export const RETENTION_SCOPE: Scope = [LOG, META];

/**
 * Runs one transaction and resolves after its complete event with what `body` returned.
 *
 * `body` may only wait for requests of the transaction. Each pending request keeps the
 * transaction alive, so it stays open until `body` returns. IndexedDB commits whatever was placed
 * once a transaction has no pending request, so when `body` throws, the transaction is aborted
 * before that can happen and nothing it placed remains.
 *
 * `committed` runs inside the complete event and must not throw. A caller uses it for work that
 * must follow a commit even when nobody awaits the returned promise.
 */
async function transact<T>(
    db: IDBDatabase,
    scope: Scope,
    mode: IDBTransactionMode,
    body: (tx: IDBTransaction) => Promise<T>,
    committed?: (result: T) => void,
): Promise<T> {
    let tx: IDBTransaction;
    try {
        tx = mode === 'readwrite'
            ? db.transaction(scope as string[], mode, { durability: 'strict' })
            : db.transaction(scope as string[], mode);
    } catch (error) {
        // A closed connection refuses new transactions with InvalidStateError.
        throw domExceptionName(error) === 'InvalidStateError' ? storeClosed() : error;
    }
    let result: { value: T } | undefined;

    // Resolves with 'complete', or with the transaction's error (null for an explicit abort).
    const ended = new Promise<'complete' | DOMException | null>((resolve) => {
        tx.oncomplete = () => {
            if (result !== undefined) committed?.(result.value);
            resolve('complete');
        };
        tx.onabort = () => resolve(tx.error);
    });
    try {
        result = { value: await body(tx) };
    } catch (error) {
        try {
            tx.abort();
        } catch {
            // The transaction has already ended, and `ended` reports how.
        }
        const end = await ended;

        // A request that fails because the transaction aborted hides the cause. The transaction
        // carries it.
        throw error instanceof ConnectError || end === 'complete' || end === null ? error : end;
    }
    const end = await ended;
    if (end !== 'complete') throw end ?? new DOMException('transaction aborted', 'AbortError');
    return result.value;
}

/** Runs a readonly transaction. It sees one state of the stores in its scope. */
export function read<T>(
    db: IDBDatabase,
    scope: Scope,
    body: (tx: IDBTransaction) => Promise<T>,
): Promise<T> {
    return transact(db, scope, 'readonly', body);
}

/**
 * Runs a readwrite transaction with strict durability, so the returned promise resolves only
 * after the browser has reported the changes as persisted.
 */
export function write<T>(
    db: IDBDatabase,
    scope: Scope,
    body: (tx: IDBTransaction) => Promise<T>,
    committed?: (result: T) => void,
): Promise<T> {
    return transact(db, scope, 'readwrite', body, committed);
}
