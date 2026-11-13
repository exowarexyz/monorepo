/**
 * Get, GetMany and Range. A query reads the sequence number and its whole answer in one readonly
 * transaction, so every frame of the answer is the state of the store at that sequence number.
 *
 * IndexedDB has no snapshot outside a live transaction, and a transaction ends as soon as it has
 * no pending request. A streamed answer therefore cannot keep reading while its consumer is slow.
 * Each query, a Get included, reads its whole answer into memory and charges every row it holds
 * to a byte budget.
 *
 * A Range or a GetMany whose call is canceled while it reads ends its transaction at the next row
 * or key.
 */

import type { MessageInitShape } from '@bufbuild/protobuf';
import { Code, ConnectError, type HandlerContext } from '@connectrpc/connect';
import {
    TraversalMode,
    type DetailSchema,
    type GetManyFrameSchema,
    type GetManyRequest,
    type GetRequest,
    type GetResponseSchema,
    type RangeFrameSchema,
    type RangeRequest,
} from '../gen/ts/store/v1/query_pb.js';
import { canceled, checkKeyLength, consistencyNotReady, fieldError } from './errors.js';
import {
    KV,
    META,
    QUERY_SCOPE,
    exactBuffer,
    read,
    readSequence,
    rowKey,
    settle,
    storedBytes,
    walk,
} from './idb.js';

/** Domain of the ErrorInfo details that query failures carry. */
const DOMAIN = 'store.query';

/** Maximum number of rows in one frame of a streamed answer. */
const MAX_FRAME_ROWS = 4096;

/** Bytes charged per buffered row on top of its key and value, for the objects that hold it. */
export const ROW_OVERHEAD_BYTES = 64;

/**
 * The memory one query may hold. Charging past the limit fails the query with
 * RESOURCE_EXHAUSTED.
 */
export class QueryBudget {
    private used = 0;

    constructor(private readonly limit: number, private readonly subject: string) {}

    charge(bytes: number): void {
        this.used += bytes;
        if (this.used > this.limit) throw this.exceeded();
    }

    /** Gives back memory that a charge counted and the query has freed. */
    release(bytes: number): void {
        this.used -= bytes;
    }

    exceeded(): ConnectError {
        return new ConnectError(
            `${this.subject} exceeds the store's query memory limit of ${this.limit} bytes`,
            Code.ResourceExhausted,
        );
    }
}

/**
 * Runs `body` in the query transaction after checking that the store has reached
 * `minSequenceNumber`. `body` gets the object store of rows and may only wait for requests of that
 * transaction. The result comes with the sequence number whose state `body` read.
 */
export function snapshot<T>(
    db: IDBDatabase,
    minSequenceNumber: bigint | undefined,
    body: (kv: IDBObjectStore) => Promise<T>,
): Promise<{ sequenceNumber: bigint; result: T }> {
    return read(db, QUERY_SCOPE, async (tx) => {
        const sequenceNumber = await readSequence(tx.objectStore(META));
        if (minSequenceNumber !== undefined && sequenceNumber < minSequenceNumber) {
            throw consistencyNotReady(minSequenceNumber, sequenceNumber);
        }
        return { sequenceNumber, result: await body(tx.objectStore(KV)) };
    });
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
    const shared = Math.min(a.byteLength, b.byteLength);
    for (let i = 0; i < shared; i++) {
        if (a[i] !== b[i]) return a[i] - b[i];
    }
    return a.byteLength - b.byteLength;
}

/**
 * The keys from `start` to `end`, both included. An empty `end` means no upper bound. Returns
 * undefined when `start` is above `end`. Such a range holds no key, and IndexedDB refuses to
 * build it.
 */
export function keyRange(start: Uint8Array, end: Uint8Array): IDBKeyRange | undefined {
    if (end.byteLength === 0) return IDBKeyRange.lowerBound(exactBuffer(start));
    if (compareBytes(start, end) > 0) return undefined;
    return IDBKeyRange.bound(exactBuffer(start), exactBuffer(end));
}

/**
 * Visits the rows of `keys` in key order, or in reverse, until `visit` returns false. Must run
 * inside the transaction of `kv`.
 */
export function scanRows(
    kv: IDBObjectStore,
    keys: IDBKeyRange,
    direction: 'next' | 'prev',
    visit: (key: Uint8Array, value: Uint8Array) => boolean,
): Promise<void> {
    return walk(kv.openCursor(keys, direction), (cursor) =>
        visit(rowKey(cursor.key), storedBytes(cursor.value)));
}

/** The detail that every frame of one answer carries. */
export function queryDetail(sequenceNumber: bigint): MessageInitShape<typeof DetailSchema> {
    return { sequenceNumber, extra: {} };
}

/** Cuts an answer into frames. An empty answer is one empty frame. */
function* frames<T>(items: readonly T[], batchSize: number): Generator<T[]> {
    const size = Math.min(batchSize, MAX_FRAME_ROWS);
    if (items.length === 0) yield [];
    for (let start = 0; start < items.length; start += size) yield items.slice(start, start + size);
}

function checkBatchSize(batchSize: number, rpc: string): void {
    if (batchSize === 0) {
        throw fieldError(
            DOMAIN,
            'batch_size',
            'batch_size must be greater than 0',
            'INVALID_BATCH_SIZE',
            `${rpc} batch_size must be positive`,
        );
    }
}

export function getHandler(db: IDBDatabase, maxQueryBytes: number) {
    return async (request: GetRequest): Promise<MessageInitShape<typeof GetResponseSchema>> => {
        checkKeyLength(DOMAIN, 'key', request.key);
        const key = exactBuffer(request.key);
        const { sequenceNumber, result } = await snapshot(db, request.minSequenceNumber, async (kv) => {
            const stored = await settle(kv.get(key));
            const value = stored === undefined ? undefined : storedBytes(stored);
            new QueryBudget(maxQueryBytes, 'get result')
                .charge(key.byteLength + (value?.byteLength ?? 0) + ROW_OVERHEAD_BYTES);
            return value;
        });
        return { value: result, detail: queryDetail(sequenceNumber) };
    };
}

type FoundEntry = { key: Uint8Array; value?: Uint8Array };

export function getManyHandler(db: IDBDatabase, maxQueryBytes: number) {
    return async function* (
        request: GetManyRequest,
        context: HandlerContext,
    ): AsyncGenerator<MessageInitShape<typeof GetManyFrameSchema>> {
        const { keys } = request;
        const { signal } = context;
        if (keys.length === 0) {
            throw fieldError(
                DOMAIN,
                'keys',
                'at least one key is required',
                'INVALID_BATCH',
                'get_many request must contain at least one key',
            );
        }
        for (const [index, key] of keys.entries()) checkKeyLength(DOMAIN, `keys[${index}]`, key);
        checkBatchSize(request.batchSize, 'get_many');

        // Every key yields an entry of the answer, found or not, so the number of keys alone can
        // exceed the budget.
        const budget = new QueryBudget(maxQueryBytes, 'get_many result');
        if (keys.length > Math.floor(maxQueryBytes / ROW_OVERHEAD_BYTES)) throw budget.exceeded();

        const { sequenceNumber, result } = await snapshot(db, request.minSequenceNumber, async (kv) => {
            const entries: FoundEntry[] = [];

            // A value is charged before the next one is read, so the answer exceeds the budget by
            // at most one value when the query fails.
            for (const key of keys) {
                if (signal.aborted) throw canceled(signal);
                const stored = await settle(kv.get(exactBuffer(key)));
                const value = stored === undefined ? undefined : storedBytes(stored);
                budget.charge(key.byteLength + (value?.byteLength ?? 0) + ROW_OVERHEAD_BYTES);
                entries.push({ key, value });
            }
            return entries;
        });
        const detail = queryDetail(sequenceNumber);
        for (const results of frames(result, request.batchSize)) yield { results, detail };
    };
}

export function rangeHandler(db: IDBDatabase, maxQueryBytes: number) {
    return async function* (
        request: RangeRequest,
        context: HandlerContext,
    ): AsyncGenerator<MessageInitShape<typeof RangeFrameSchema>> {
        checkKeyLength(DOMAIN, 'start', request.start);
        checkKeyLength(DOMAIN, 'end', request.end);
        checkBatchSize(request.batchSize, 'range');
        const mode: number = request.mode;
        if (mode !== TraversalMode.FORWARD && mode !== TraversalMode.REVERSE) {
            throw fieldError(
                DOMAIN,
                'mode',
                `unknown TraversalMode enum value ${mode}`,
                'INVALID_TRAVERSAL_MODE',
                'range mode must be TRAVERSAL_MODE_FORWARD (0) or TRAVERSAL_MODE_REVERSE (1)',
            );
        }
        const limit = request.limit ?? Infinity;
        const keys = limit === 0 ? undefined : keyRange(request.start, request.end);
        const { signal } = context;

        const { sequenceNumber, result } = await snapshot(db, request.minSequenceNumber, async (kv) => {
            const rows: { key: Uint8Array; value: Uint8Array }[] = [];
            if (keys === undefined) return rows;
            const budget = new QueryBudget(maxQueryBytes, 'range result');
            const direction = mode === TraversalMode.REVERSE ? 'prev' : 'next';
            await scanRows(kv, keys, direction, (key, value) => {
                if (signal.aborted) throw canceled(signal);
                budget.charge(key.byteLength + value.byteLength + ROW_OVERHEAD_BYTES);
                rows.push({ key, value });
                return rows.length < limit;
            });
            return rows;
        });
        const detail = queryDetail(sequenceNumber);
        for (const results of frames(result, request.batchSize)) yield { results, detail };
    };
}
