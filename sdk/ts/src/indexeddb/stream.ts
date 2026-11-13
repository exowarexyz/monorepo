/** The log handlers: Get of one batch, and Subscribe. */

import type { MessageInitShape } from '@bufbuild/protobuf';
import type { HandlerContext } from '@connectrpc/connect';
import type { Entry } from '../gen/ts/common/v1/kv_pb.js';
import type {
    GetRequest,
    GetResponse,
    SubscribeRequest,
    SubscribeResponseSchema,
} from '../gen/ts/log/v1/stream_pb.js';
import { MAX_PUT_ENTRIES, MAX_REQUEST_MESSAGE_BYTES } from '../limits.js';
import {
    batchEvicted,
    batchNotFound,
    canceled,
    dataCorrupt,
    invalidArgument,
    storeClosed,
} from './errors.js';
import {
    LOG,
    LOG_SCOPE,
    MAX_SEQUENCE,
    META,
    be64,
    checkStoredKey,
    oldestRetained,
    read,
    readSequence,
    settle,
    storedBytes,
} from './idb.js';
import type { Notifier } from './notifier.js';
import { KeySelector, Pacer, ValueFilters, checkSelectorPrefix, isBlankPattern } from './selector.js';

// Maximum numbers of selectors and of value filters in one subscription.
const MAX_SELECTORS = 16;
const MAX_VALUE_FILTERS = 16;

/** What one read of the log found for a sequence number. */
interface LogRead {
    /** The store's sequence number in the same transaction. */
    sequenceNumber: bigint;
    /** The batch, undefined when the log holds no row for the number. */
    batch?: GetResponse;
    /** The lowest retained number, read only when the batch was evicted. */
    oldest?: bigint;
}

/** The largest stored batch that a read decodes. */
export interface LogBounds {
    /** Longest log row in bytes. */
    maxRowBytes: number;
    /** Maximum number of entries in one log row. */
    maxEntries: number;
}

/**
 * Most bytes that the sequence number field of a batch takes in its shortest encoding, a tag of
 * one byte and a varint of ten.
 */
const SEQUENCE_FIELD_BYTES = 11;

/**
 * The largest batch that the database layout lets a writer store, and so the largest that a read
 * decodes. Its row is at most as long as the encoded entries of the largest Put with the sequence
 * number field in its shortest encoding, and holds at most as many entries as one Put.
 */
export const LOG_BOUNDS: LogBounds = {
    maxRowBytes: MAX_REQUEST_MESSAGE_BYTES + SEQUENCE_FIELD_BYTES,
    maxEntries: MAX_PUT_ENTRIES,
};

// Wire types of the protobuf encoding.
const VARINT = 0;
const FIXED64 = 1;
const LENGTH_DELIMITED = 2;
const FIXED32 = 5;

const NO_BYTES = new Uint8Array(0);

/**
 * A position in an encoded batch. Every read takes the end of the message that encloses it and
 * fails with corrupt data when it would pass that end, so nothing is read across the boundary of
 * an entry or of the row.
 */
class Cursor {
    offset = 0;

    constructor(readonly bytes: Uint8Array) {}

    // A varint ends within 10 bytes, and the tenth byte may only hold bit 63.
    private varintByte(index: number, end: number): number {
        if (this.offset >= end) throw dataCorrupt();
        const byte = this.bytes[this.offset++];
        if (index === 9 && byte > 1) throw dataCorrupt();
        return byte;
    }

    /** Reads a varint that fits 32 bits, as a tag and a length must. */
    uint32(end: number): number {
        let value = 0;
        let scale = 1;
        for (let index = 0; index < 10; index++) {
            const byte = this.varintByte(index, end);
            value += (byte & 0x7f) * scale;
            if (byte < 0x80) {
                if (value > 0xffffffff) throw dataCorrupt();
                return value;
            }
            scale *= 128;
        }
        throw dataCorrupt();
    }

    /** Reads a varint that fits 64 bits. */
    uint64(end: number): bigint {
        let value = 0n;
        for (let index = 0; index < 10; index++) {
            const byte = this.varintByte(index, end);
            value |= BigInt(byte & 0x7f) << BigInt(7 * index);
            if (byte < 0x80) return value;
        }
        throw dataCorrupt();
    }

    /** Reads the length of a length delimited field and returns the offset where the field ends. */
    fieldEnd(end: number): number {
        const length = this.uint32(end);
        if (length > end - this.offset) throw dataCorrupt();
        return this.offset + length;
    }

    /** Skips the value of a field that the messages do not define. A group is corrupt data. */
    skip(wireType: number, end: number): void {
        switch (wireType) {
            case VARINT: {
                let index = 0;
                while (this.varintByte(index, end) >= 0x80) index++;
                return;
            }
            case LENGTH_DELIMITED:
                this.offset = this.fieldEnd(end);
                return;
            case FIXED64:
            case FIXED32: {
                const width = wireType === FIXED64 ? 8 : 4;
                if (width > end - this.offset) throw dataCorrupt();
                this.offset += width;
                return;
            }
            default:
                throw dataCorrupt();
        }
    }
}

/**
 * Reads one common.kv.v1.Entry, which has the bytes fields key (1) and value (2). The key and the
 * value are views of the row. A key longer than any Put can have written is corrupt data.
 */
function readEntry(cursor: Cursor, end: number): Entry {
    let key = NO_BYTES;
    let value = NO_BYTES;
    while (cursor.offset < end) {
        const tag = cursor.uint32(end);
        const field = tag >>> 3;
        if (field === 0) throw dataCorrupt();
        if (field > 2) {
            cursor.skip(tag & 7, end);
            continue;
        }
        if ((tag & 7) !== LENGTH_DELIMITED) throw dataCorrupt();
        const fieldEnd = cursor.fieldEnd(end);
        const bytes = cursor.bytes.subarray(cursor.offset, fieldEnd);
        cursor.offset = fieldEnd;
        if (field === 1) {
            key = bytes;
        } else {
            value = bytes;
        }
    }
    checkStoredKey(key);
    return { $typeName: 'common.kv.v1.Entry', key, value };
}

/**
 * Reads a stored batch and checks that it is one a Put can have written under `sequenceNumber`.
 *
 * The row is a log.stream.v1.GetResponse, which has the fields sequence_number (1, a varint) and
 * entries (2, repeated messages). One pass over the row validates each field and builds what it
 * holds, so the reader never creates more entries than `bounds` allows. `bounds` defaults to the
 * largest batch a writer may store.
 *
 * The reader accepts every encoding that the database layout obliges a reader to accept. Fields
 * may come in any order, a later sequence number, key or value replaces an earlier one, and a
 * field that the messages do not define is passed over and not kept. The layout forbids a writer
 * two things, a group and a defined field under another wire type than its own, and the reader
 * treats both as corrupt data.
 *
 * Corrupt data is also a row longer than the bounds allow, more entries than they allow, a field
 * that runs past the message around it, a field number 0, and a varint that does not end or does
 * not fit its type.
 *
 * The result is the message itself with its entries, so the router serializes it without
 * building the entries again. Keys and values are views of the one buffer that holds the row.
 */
export function decodeBatch(stored: unknown, sequenceNumber: bigint, bounds = LOG_BOUNDS): GetResponse {
    const cursor = new Cursor(storedBytes(stored, bounds.maxRowBytes));
    const end = cursor.bytes.byteLength;
    let storedSequenceNumber = 0n;
    const entries: Entry[] = [];
    while (cursor.offset < end) {
        const tag = cursor.uint32(end);
        const wireType = tag & 7;
        switch (tag >>> 3) {
            case 0:
                throw dataCorrupt();
            case 1:
                if (wireType !== VARINT) throw dataCorrupt();
                storedSequenceNumber = cursor.uint64(end);
                break;
            case 2: {
                if (wireType !== LENGTH_DELIMITED) throw dataCorrupt();
                const entryEnd = cursor.fieldEnd(end);
                if (entries.length >= bounds.maxEntries) throw dataCorrupt();
                entries.push(readEntry(cursor, entryEnd));
                break;
            }
            default:
                cursor.skip(wireType, end);
        }
    }
    if (storedSequenceNumber !== sequenceNumber || entries.length === 0) throw dataCorrupt();
    return { $typeName: 'log.stream.v1.GetResponse', sequenceNumber, entries };
}

/**
 * Reads batch `n` and the sequence number in one transaction. A missing row with `n` above the
 * sequence number was never written. A missing row at or below it was evicted. No Put writes
 * batch 0 or a batch above the sequence number, so a row found for either is corrupt data.
 */
function readLog(db: IDBDatabase, n: bigint): Promise<LogRead> {
    return read(db, LOG_SCOPE, async (tx) => {
        const log = tx.objectStore(LOG);
        const stored = await settle(log.get(be64(n)));
        const sequenceNumber = await readSequence(tx.objectStore(META));
        if (stored !== undefined) {
            if (n === 0n || n > sequenceNumber) throw dataCorrupt();
            return { sequenceNumber, batch: decodeBatch(stored, n) };
        }
        if (n > sequenceNumber) return { sequenceNumber };
        return { sequenceNumber, oldest: await oldestRetained(log, sequenceNumber) };
    });
}

export function getBatchHandler(db: IDBDatabase) {
    return async (request: GetRequest): Promise<GetResponse> => {
        const found = await readLog(db, request.sequenceNumber);
        if (found.batch !== undefined) return found.batch;
        if (request.sequenceNumber > found.sequenceNumber) throw batchNotFound();
        throw batchEvicted(found.oldest);
    };
}

interface Matchers {
    selectors: KeySelector[];
    values: ValueFilters | undefined;
}

/** Validates and compiles the filter of a subscription, in the order the Rust server checks it. */
function compileMatchers(request: SubscribeRequest): Matchers {
    const { selectors, valueFilters } = request;
    if (valueFilters.some((filter) => filter.kind.case === undefined)) {
        throw invalidArgument('each value_filter must set exactly one of exact, prefix, or regex');
    }
    if (selectors.length === 0) {
        throw invalidArgument('stream filter must contain at least one selector');
    }
    if (selectors.length > MAX_SELECTORS) {
        throw invalidArgument(`stream filter capped at ${MAX_SELECTORS} selectors`);
    }
    if (valueFilters.length > MAX_VALUE_FILTERS) {
        throw invalidArgument(`stream filter capped at ${MAX_VALUE_FILTERS} value_filters`);
    }
    for (const selector of selectors) {
        checkSelectorPrefix(selector.prefix, (reason) => `invalid selector prefix: ${reason}`);
        if (isBlankPattern(selector.payloadRegex)) {
            throw invalidArgument('selector payload_regex must not be empty');
        }
    }
    for (const { kind } of valueFilters) {
        if (kind.case === 'regex' && isBlankPattern(kind.value)) {
            throw invalidArgument('value_filter regex must not be empty');
        }
    }
    return {
        selectors: selectors.map((selector) => new KeySelector(selector)),
        values: valueFilters.length === 0 ? undefined : new ValueFilters(valueFilters),
    };
}

/**
 * The entries of a batch that the subscription delivers, in batch order. An entry passes when
 * some selector accepts its key and, if there are value filters, some filter accepts its value.
 * `alive` throws once the subscription has ended. It runs whenever the matching yields.
 */
async function matchingEntries(
    entries: readonly Entry[],
    matchers: Matchers,
    alive: () => void,
): Promise<Entry[]> {
    const pacer = new Pacer(alive);
    const matched: Entry[] = [];
    for (const entry of entries) {
        if (pacer.due()) await pacer.turn();
        if (!matchers.selectors.some((selector) => selector.matches(entry.key))) continue;
        if (matchers.values !== undefined && !(await matchers.values.matches(entry.value, pacer))) continue;
        matched.push(entry);
    }
    return matched;
}

/**
 * The Subscribe handler. It delivers the matching entries of each batch in order, from a starting
 * sequence number on. It reads one batch per transaction and holds one batch at a time.
 *
 * The stream ends normally once no sequence number is left to deliver. It fails with CANCELED
 * when the call's signal aborts, or with the Connect error that the signal carries, with
 * UNAVAILABLE when the store closes, and with OUT_OF_RANGE when the batch it has to read was
 * evicted.
 *
 * Closing the store fails the stream at its next check. The check also runs while a batch is
 * matched and right before each frame, so no frame follows the close. A consumer that stops
 * reading after a frame without aborting leaves the handler suspended at a yield, where it holds
 * no waiter and reads nothing.
 */
export function subscribeHandler(db: IDBDatabase, notifier: Notifier, isOpen: () => boolean) {
    return async function* (
        request: SubscribeRequest,
        context: HandlerContext,
    ): AsyncGenerator<MessageInitShape<typeof SubscribeResponseSchema>> {
        const matchers = compileMatchers(request);
        const { signal } = context;
        const alive = () => {
            if (signal.aborted) throw canceled(signal);
            if (!isOpen()) throw storeClosed();
        };
        const since = request.sinceSequenceNumber ?? 0n;

        // The mark is taken before each read, so a batch committed after the read wakes the wait
        // that follows it.
        let mark = notifier.mark();
        let found = await readLog(db, since);
        let n = since;
        if (since === 0n) {
            // Without `sinceSequenceNumber`, or with 0, the stream starts at the batch after the
            // store's sequence number. The read ran before that batch was written, so the loop
            // waits for a wake before reading it. A store at the highest sequence number has no
            // next batch.
            if (found.sequenceNumber === MAX_SEQUENCE) return;
            n = found.sequenceNumber + 1n;
            found = { sequenceNumber: found.sequenceNumber };
        }
        for (;;) {
            alive();
            if (found.batch !== undefined) {
                const entries = await matchingEntries(found.batch.entries, matchers, alive);
                alive();
                if (entries.length > 0) yield { sequenceNumber: n, entries };
                if (n === MAX_SEQUENCE) return;
                n++;
            } else if (n <= found.sequenceNumber) {
                throw batchEvicted(found.oldest);
            } else {
                await notifier.after(mark, signal);
            }
            mark = notifier.mark();
            found = await readLog(db, n);
        }
    };
}
