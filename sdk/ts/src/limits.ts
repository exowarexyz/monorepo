export const MAX_PUT_ENTRIES = 2_000_000;
export const MAX_REQUEST_MESSAGE_BYTES = 256 * 1024 * 1024;
export const MAX_VALUE_LEN = 32 * 1024 * 1024;
export const MAX_KEY_LEN = 254;

export type PutEncoding = 'binary' | 'json';

export interface PutLimits {
    maxEntries?: number;
    maxEncodedBytes?: number;
    maxValueLen?: number;
}

export interface PutBatchOptions extends PutLimits {
    encoding?: PutEncoding;
}

type PutEntry = { key: Uint8Array; value: Uint8Array };

export function normalizePutOptions(options: PutBatchOptions = {}): Required<PutBatchOptions> {
    const limits = {
        maxEntries: options.maxEntries ?? MAX_PUT_ENTRIES,
        maxEncodedBytes: options.maxEncodedBytes ?? MAX_REQUEST_MESSAGE_BYTES,
        maxValueLen: options.maxValueLen ?? MAX_VALUE_LEN,
    };
    for (const [name, value] of Object.entries(limits)) {
        if (!Number.isSafeInteger(value) || value < (name === 'maxValueLen' ? 0 : 1)) {
            throw new RangeError(`${name} must be a ${name === 'maxValueLen' ? 'nonnegative' : 'positive'} safe integer`);
        }
    }
    return { ...limits, encoding: options.encoding ?? 'json' };
}

function varintLen(value: number): number {
    let length = 1;
    while (value >= 128) {
        value = Math.floor(value / 128);
        length++;
    }
    return length;
}

export function putEntryEncodedLen(entry: PutEntry, encoding: PutEncoding): number {
    const key = entry.key.byteLength;
    const value = entry.value.byteLength;
    if (encoding === 'binary') {
        const length = (key === 0 ? 0 : 1 + varintLen(key) + key)
            + (value === 0 ? 0 : 1 + varintLen(value) + value);
        return 1 + varintLen(length) + length;
    }

    // ProtoJSON omits empty byte fields and uses padded base64 for the others.
    return 2 + (key === 0 ? 0 : 8 + 4 * Math.ceil(key / 3))
        + (value === 0 ? 0 : 10 + 4 * Math.ceil(value / 3))
        + (key !== 0 && value !== 0 ? 1 : 0);
}

export function putMessageEncodedLen(entryBytes: number, count: number, encoding: PutEncoding): number {
    if (encoding === 'binary') return entryBytes;
    return count === 0 ? 2 : 9 + count + entryBytes;
}

export function putEncodedLen(entries: readonly PutEntry[], encoding: PutEncoding = 'json'): number {
    let entryBytes = 0;
    for (const entry of entries) entryBytes += putEntryEncodedLen(entry, encoding);
    return putMessageEncodedLen(entryBytes, entries.length, encoding);
}

export function validatePutEntry(entry: PutEntry, index: number, maxValueLen: number): void {
    if (entry.key.byteLength > MAX_KEY_LEN) {
        throw new RangeError(`Put entry ${index} key length ${entry.key.byteLength} exceeds ${MAX_KEY_LEN}`);
    }
    if (entry.value.byteLength > maxValueLen) {
        throw new RangeError(`Put entry ${index} value length ${entry.value.byteLength} exceeds ${maxValueLen}`);
    }
}

export function validatePut(entries: readonly PutEntry[], options: PutBatchOptions = {}): void {
    const limits = normalizePutOptions(options);
    if (entries.length === 0 || entries.length > limits.maxEntries) {
        throw new RangeError(`Put requires between 1 and ${limits.maxEntries} entries, got ${entries.length}`);
    }
    let entryBytes = 0;
    for (const [index, entry] of entries.entries()) {
        validatePutEntry(entry, index, limits.maxValueLen);
        entryBytes += putEntryEncodedLen(entry, limits.encoding);
    }
    const length = putMessageEncodedLen(entryBytes, entries.length, limits.encoding);
    if (length > limits.maxEncodedBytes) {
        throw new RangeError(`Put encoded size ${length} exceeds ${limits.maxEncodedBytes}`);
    }
}
