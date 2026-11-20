/** The Put handler. It writes one batch of rows atomically under the next sequence number. */

import { create, toBinary, type MessageInitShape } from '@bufbuild/protobuf';
import { Code, ConnectError, type HandlerContext } from '@connectrpc/connect';
import type { PutRequest, PutResponseSchema } from '../gen/ts/log/v1/ingest_pb.js';
import { GetResponseSchema } from '../gen/ts/log/v1/stream_pb.js';
import { MAX_KEY_LEN, putEntryEncodedLen } from '../limits.js';
import { canceled, checkKeyLength, fieldError } from './errors.js';
import {
    KV,
    LOG,
    MAX_SEQUENCE,
    META,
    PUT_SCOPE,
    REQUEST_CHUNK,
    SEQUENCE_KEY,
    be64,
    exactBuffer,
    logKeysBelow,
    ownedBuffer,
    readSequence,
    settle,
    write,
} from './idb.js';
import { readRetentionRule, retentionCutoff } from './retention.js';

/** Domain of the ErrorInfo details that Put failures carry. */
const DOMAIN = 'log.ingest';

/** The limits on one Put, as `IndexedDbStoreOptions` sets them. */
export interface PutLimits {
    readonly maxPutEntries: number;
    readonly maxValueLen: number;
    readonly maxRequestBytes: number;
}

type BatchEntry = { key: Uint8Array; value: Uint8Array };

function validate(request: PutRequest, limits: PutLimits): void {
    const count = request.kvs.length;
    if (count === 0) {
        throw fieldError(
            DOMAIN,
            'kvs',
            'at least one key-value pair is required',
            'INVALID_BATCH',
            'put request must contain at least one key-value pair',
        );
    }
    if (count > limits.maxPutEntries) {
        throw fieldError(
            DOMAIN,
            'kvs',
            `put has ${count} entries, exceeding the limit of ${limits.maxPutEntries}`,
            'PUT_TOO_LARGE',
            'put request exceeds size limits',
            { entries: String(count), max_entries: String(limits.maxPutEntries) },
        );
    }
    let encodedBytes = 0;
    for (const [index, entry] of request.kvs.entries()) {
        if (entry.key.byteLength > MAX_KEY_LEN) checkKeyLength(DOMAIN, `kvs[${index}].key`, entry.key);
        if (entry.value.byteLength > limits.maxValueLen) {
            const field = `kvs[${index}].value`;
            throw fieldError(
                DOMAIN,
                field,
                `value length ${entry.value.byteLength} exceeds maximum ${limits.maxValueLen}`,
                'INVALID_VALUE_LENGTH',
                `${field} value length is outside store limits`,
                { max_value_len: String(limits.maxValueLen) },
            );
        }

        // Checking the sum after every entry keeps it within one entry of the limit, far below
        // 2^53, so it stays an exact integer.
        encodedBytes += putEntryEncodedLen(entry);
        if (encodedBytes > limits.maxRequestBytes) {
            throw new ConnectError('put exceeds the request message size limit', Code.ResourceExhausted);
        }
    }
}

function varintLength(value: bigint): number {
    let length = 1;
    for (; value >= 0x80n; value >>= 7n) length++;
    return length;
}

function encodeBatch(sequenceNumber: bigint, entries: readonly BatchEntry[]): ArrayBuffer {
    const batch = create(GetResponseSchema, { sequenceNumber, entries: entries as BatchEntry[] });
    return ownedBuffer(toBinary(GetResponseSchema, batch));
}

/**
 * The log row of a batch, encoded before the batch's sequence number is known.
 *
 * The Put's transaction reads the number and should not wait for a large batch to encode. The row
 * is encoded ahead with an expected number, and the real number is written over it in place when
 * both numbers take the same number of bytes on the wire. Otherwise the row is encoded again.
 */
class LogRow {
    private readonly width: number;
    private readonly encoded: ArrayBuffer;

    constructor(private readonly entries: readonly BatchEntry[], expected: bigint) {
        this.width = varintLength(expected);
        this.encoded = encodeBatch(expected, entries);
    }

    /** The encoded batch carrying `sequenceNumber`. The number must be at least 1. */
    withSequence(sequenceNumber: bigint): ArrayBuffer {
        if (varintLength(sequenceNumber) !== this.width) return encodeBatch(sequenceNumber, this.entries);

        // The message starts with the tag of field 1 followed by the number as a varint.
        const bytes = new Uint8Array(this.encoded);
        let offset = 1;
        let rest = sequenceNumber;
        for (; rest >= 0x80n; rest >>= 7n) bytes[offset++] = Number(rest & 0x7fn) | 0x80;
        bytes[offset] = Number(rest);
        return this.encoded;
    }
}

interface PreparedBatch {
    readonly keys: ArrayBuffer[];
    readonly values: ArrayBuffer[];
    readonly row: LogRow;
}

/**
 * Builds everything the transaction will store. Request fields are views into the request
 * message, and IndexedDB stores the whole buffer behind a view, so every key and value is copied
 * to a buffer of its own. The log row keeps every entry in request order, duplicates included.
 */
function prepare(request: PutRequest, expectedSequence: bigint): PreparedBatch {
    const keys: ArrayBuffer[] = [];
    const values: ArrayBuffer[] = [];
    const entries: BatchEntry[] = [];
    for (const { key, value } of request.kvs) {
        keys.push(exactBuffer(key));
        values.push(exactBuffer(value));
        entries.push({ key, value });
    }
    return { keys, values, row: new LogRow(entries, expectedSequence) };
}

/**
 * Places the batch. Everything that can refuse the batch is read and checked before the first
 * write. From there on the function only places requests, and a failure aborts the transaction.
 */
async function place(tx: IDBTransaction, batch: PreparedBatch): Promise<bigint> {
    const meta = tx.objectStore(META);
    const sequence = await readSequence(meta);
    const rule = await readRetentionRule(meta);
    if (sequence === MAX_SEQUENCE) {
        throw new ConnectError('store sequence numbers are exhausted', Code.Internal);
    }
    const next = sequence + 1n;
    const cutoff = rule === undefined ? 0n : retentionCutoff(rule, next);

    // A rule that evicts the new batch at once leaves no row to write.
    const row = cutoff > next ? undefined : batch.row.withSequence(next);

    // Store the rows in request order, so a later entry for the same key wins. Each chunk waits for
    // its last request before the next chunk is placed.
    const kv = tx.objectStore(KV);
    for (let start = 0; start < batch.keys.length; start += REQUEST_CHUNK) {
        const end = Math.min(start + REQUEST_CHUNK, batch.keys.length);
        let last: IDBRequest | undefined;
        for (let i = start; i < end; i++) last = kv.put(batch.values[i], batch.keys[i]);
        await settle(last!);
    }

    // Record the batch in the log, advance the sequence number and evict what the rule no longer
    // keeps. Requests of one transaction complete in order, so the last one settles after the
    // others.
    const log = tx.objectStore(LOG);
    if (row !== undefined) log.put(row, be64(next));
    let last: IDBRequest = meta.put(be64(next), SEQUENCE_KEY);
    const evicted = logKeysBelow(cutoff);
    if (evicted !== undefined) last = log.delete(evicted);
    await settle(last);
    return next;
}

/**
 * The Put handler. `expectedSequence` guesses the number the batch will get, and the guess only
 * sizes the log row. `committed` runs inside the transaction's complete event with the batch's
 * number, so that subscribers hear of a batch even when the caller has stopped waiting for the
 * answer.
 */
export function putHandler(
    db: IDBDatabase,
    limits: PutLimits,
    expectedSequence: () => bigint,
    committed: (sequenceNumber: bigint) => void,
) {
    return async (
        request: PutRequest,
        context: HandlerContext,
    ): Promise<MessageInitShape<typeof PutResponseSchema>> => {
        validate(request, limits);
        if (context.signal.aborted) throw canceled(context.signal);
        const batch = prepare(request, expectedSequence());
        const sequenceNumber = await write(db, PUT_SCOPE, (tx) => place(tx, batch), committed);
        return { sequenceNumber };
    };
}
