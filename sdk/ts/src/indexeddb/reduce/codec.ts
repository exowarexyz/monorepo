import { KvFieldKind, type KvFieldRef } from '../../gen/ts/store/v1/query_pb.js';
import { toBits } from './float.js';
import { failedPrecondition, invalidParams, type Field, type Value } from './types.js';

/** The unsigned integer of big endian bytes. */
export function readBigEndian(bytes: Uint8Array): bigint {
    let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    return value;
}

/** The unsigned integer of little endian bytes. */
export function readLittleEndian(bytes: Uint8Array): bigint {
    let value = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) value = (value << 8n) | BigInt(bytes[i]);
    return value;
}

/** The low bytes of a two's complement integer, most significant byte first. */
export function writeBigEndian(value: bigint, length: number): Uint8Array {
    const bytes = new Uint8Array(length);
    let rest = BigInt.asUintN(length * 8, value);
    for (let i = length - 1; i >= 0; i--) {
        bytes[i] = Number(rest & 0xffn);
        rest >>= 8n;
    }
    return bytes;
}

/** The byte length of a string in UTF-8. The string must hold no lone surrogate. */
export function utf8Length(text: string): number {
    let length = 0;
    for (let i = 0; i < text.length; i++) {
        const unit = text.charCodeAt(i);
        if (unit < 0x80) length += 1;
        else if (unit < 0x800) length += 2;
        else if (unit >= 0xd800 && unit < 0xdc00) {
            length += 4;
            i++;
        } else length += 3;
    }
    return length;
}

/** One value of a stored row. A list carries no value because no field kind can read one. */
export interface Stored {
    readonly tag: number;
    readonly value: bigint | boolean | string | Uint8Array | undefined;
}

// Tags of the values of a stored row.
const TAG_INT64 = 0;
const TAG_UINT64 = 1;
const TAG_FLOAT64 = 2;
const TAG_BOOLEAN = 3;
const TAG_UTF8 = 4;
const TAG_BYTES = 5;
const TAG_LIST = 6;

const strictUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

class Reader {
    private offset = 0;
    private readonly view: DataView;

    constructor(private readonly bytes: Uint8Array) {
        this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    }

    private need(count: number): void {
        if (this.bytes.length - this.offset < count) {
            throw failedPrecondition('Unexpected End-of-Buffer: Not enough bytes remaining to read data');
        }
    }

    u8(): number {
        this.need(1);
        return this.bytes[this.offset++];
    }

    u64(): bigint {
        this.need(8);
        const value = this.view.getBigUint64(this.offset);
        this.offset += 8;
        return value;
    }

    bool(): boolean {
        const byte = this.u8();
        if (byte > 1) throw failedPrecondition('Invalid Bool: Expected 0 or 1, found different value');
        return byte === 1;
    }

    take(count: number): Uint8Array {
        this.need(count);
        const taken = this.bytes.subarray(this.offset, this.offset + count);
        this.offset += count;
        return taken;
    }

    /**
     * Reads a length in the canonical LEB128 form of a 32 bit unsigned integer. A form that ends in
     * a zero byte after its first byte is malformed. So is a fifth byte above 15, and a form has at
     * most five bytes.
     */
    length(): number {
        let byte = this.u8();
        if ((byte & 0x80) === 0) return byte;
        let result = 0;
        for (let bits = 0; ; bits += 7) {
            if (byte === 0 && bits > 0) throw failedPrecondition('Invalid 4-byte varint');
            if (bits === 28 && byte > 0x0f) throw failedPrecondition('Invalid 4-byte varint');
            result += (byte & 0x7f) * 2 ** bits;
            if ((byte & 0x80) === 0) return result;
            byte = this.u8();
        }
    }
}

function readScalar(reader: Reader, tag: number): Stored {
    switch (tag) {
        case TAG_INT64: return { tag, value: BigInt.asIntN(64, reader.u64()) };
        case TAG_UINT64: return { tag, value: reader.u64() };
        case TAG_FLOAT64: return { tag, value: reader.u64() };
        case TAG_BOOLEAN: return { tag, value: reader.bool() };
        case TAG_UTF8: {
            const bytes = reader.take(reader.length());
            try {
                return { tag, value: strictUtf8.decode(bytes) };
            } catch {
                throw failedPrecondition('Validation Error: Context(Utf8), Message(invalid utf8)');
            }
        }
        case TAG_BYTES: return { tag, value: reader.take(reader.length()) };
        default: throw failedPrecondition('Invalid Enum: Expected a valid enum variant, found ' + tag);
    }
}

/**
 * Reads one value. The items of a list are validated and dropped. Nested lists are walked with
 * an explicit stack of remaining item counts, so the depth of a stored list cannot exhaust the
 * call stack.
 */
function readValue(reader: Reader): Stored {
    const tag = reader.u8();
    if (tag !== TAG_LIST) return readScalar(reader, tag);
    const remaining = [reader.length()];
    while (remaining.length > 0) {
        const top = remaining.length - 1;
        if (remaining[top] === 0) {
            remaining.pop();
            continue;
        }
        remaining[top]--;
        const item = reader.u8();
        if (item === TAG_LIST) remaining.push(reader.length());
        else readScalar(reader, item);
    }
    return { tag, value: undefined };
}

/** The highest column index that a field reference can name. */
const MAX_COLUMN_INDEX = 65535;

/**
 * Decodes a stored row. A row is a count followed, for each column, by a presence byte and, when
 * present, a tagged value. Every column is validated, whether or not a field refers to it. No field
 * reference can name a column past MAX_COLUMN_INDEX, so the result drops those columns and a row of
 * many columns allocates a bounded number of entries. Bytes after the last column are ignored. Byte
 * values are views into the input.
 */
export function decodeStoredRow(bytes: Uint8Array): (Stored | null)[] {
    const reader = new Reader(bytes);
    const count = reader.length();
    const row: (Stored | null)[] = [];
    for (let column = 0; column < count; column++) {
        const value = reader.bool() ? readValue(reader) : null;
        if (column <= MAX_COLUMN_INDEX) row.push(value);
    }
    return row;
}

function convertKind(kind: KvFieldKind, fixedSizeBinaryLen: number): { kind: KvFieldKind; len: number } {
    if (!(kind in KvFieldKind)) throw invalidParams('unsupported KvFieldKind');
    if (kind !== KvFieldKind.FIXED_SIZE_BINARY) return { kind, len: 0 };
    if (fixedSizeBinaryLen > 255) {
        throw invalidParams('fixed_size_binary_len ' + fixedSizeBinaryLen + ' does not fit in u8');
    }
    return { kind, len: fixedSizeBinaryLen };
}

/**
 * Converts a field reference of a request. Throws INVALID_ARGUMENT for a missing reference, an
 * unknown kind, or an offset, position, index, width or length that does not fit its wire type.
 */
export function convertField(message: KvFieldRef): Field {
    const ref = message.field;
    switch (ref.case) {
        case 'key': {
            const { byteOffset } = ref.value;
            if (byteOffset > 65535) throw invalidParams('byte_offset ' + byteOffset + ' does not fit in u16');
            return { src: 'key', byteOffset, ...convertKind(ref.value.kind, ref.value.fixedSizeBinaryLen) };
        }
        case 'zOrderKey': {
            const { bitOffset, fieldPosition, fieldWidths } = ref.value;
            if (bitOffset > 65535) throw invalidParams('bit_offset ' + bitOffset + ' does not fit in u16');
            if (fieldPosition > 255) throw invalidParams('field_position ' + fieldPosition + ' does not fit in u8');
            let totalBytes = 0;
            for (const width of fieldWidths) {
                if (width > 255) throw invalidParams('field width ' + width + ' does not fit in u8');
                totalBytes += width;
            }
            return {
                src: 'zorder',
                bitOffset,
                position: fieldPosition,
                widths: fieldWidths,
                totalBytes,
                ...convertKind(ref.value.kind, ref.value.fixedSizeBinaryLen),
            };
        }
        case 'value': {
            const { index, nullable } = ref.value;
            if (index > MAX_COLUMN_INDEX) throw invalidParams('index ' + index + ' does not fit in u16');
            return { src: 'value', index, nullable, ...convertKind(ref.value.kind, ref.value.fixedSizeBinaryLen) };
        }
        default: throw invalidParams('missing field ref');
    }
}

/** The bytes a key field of a kind occupies. */
function keyWidth(kind: KvFieldKind, len: number): number {
    switch (kind) {
        case KvFieldKind.BOOLEAN: return 1;
        case KvFieldKind.DATE32: return 4;
        case KvFieldKind.UTF8:
        case KvFieldKind.DECIMAL128: return 16;
        case KvFieldKind.DECIMAL256: return 32;
        case KvFieldKind.FIXED_SIZE_BINARY: return len;
        default: return 8;
    }
}

/**
 * Decodes the order preserving encoding of a key field. Signed kinds are stored with the sign bit
 * flipped. A float whose sign bit is clear is stored with that bit set, and any other float with
 * all bits flipped. Text is padded with zero bytes and ends at the first one. Returns undefined for
 * bytes that are not a value of the kind.
 */
function decodeOrdered(bytes: Uint8Array, kind: KvFieldKind, len: number): Value | undefined {
    switch (kind) {
        case KvFieldKind.INT64:
        case KvFieldKind.DATE64:
        case KvFieldKind.TIMESTAMP:
            return bytes.length === 8 ? BigInt.asIntN(64, readBigEndian(bytes) ^ (1n << 63n)) : undefined;
        case KvFieldKind.UINT64:
            return bytes.length === 8 ? readBigEndian(bytes) : undefined;
        case KvFieldKind.FLOAT64: {
            if (bytes.length !== 8) return undefined;
            const bits = readBigEndian(bytes);
            return (bits >> 63n) !== 0n ? bits ^ (1n << 63n) : BigInt.asUintN(64, ~bits);
        }
        case KvFieldKind.BOOLEAN:
            return bytes.length >= 1 ? bytes[0] !== 0 : undefined;
        case KvFieldKind.UTF8: {
            const end = bytes.indexOf(0);
            try {
                return strictUtf8.decode(end < 0 ? bytes : bytes.subarray(0, end));
            } catch {
                return undefined;
            }
        }
        case KvFieldKind.DATE32:
            return bytes.length === 4 ? BigInt.asIntN(32, readBigEndian(bytes) ^ (1n << 31n)) : undefined;
        case KvFieldKind.DECIMAL128:
            return bytes.length === 16 ? BigInt.asIntN(128, readBigEndian(bytes) ^ (1n << 127n)) : undefined;
        case KvFieldKind.DECIMAL256:
            return bytes.length === 32 ? BigInt.asIntN(256, readBigEndian(bytes) ^ (1n << 255n)) : undefined;
        case KvFieldKind.FIXED_SIZE_BINARY:
            return bytes.length === len ? bytes.slice() : undefined;
    }
}

// Scratch counts of extractZOrder, cleared on every call. For each width narrower than the
// referenced field, they count the fields of a block with that width, among all fields and among
// the fields before the referenced one.
const ended = new Int32Array(256);
const endedBefore = new Int32Array(256);

/**
 * Reads one field out of a Z-order block of a key. Returns undefined when the position names no
 * field or the block does not lie inside the key.
 *
 * The block is a sequence of rounds, and round b holds bit b of every field that has one, in field
 * order, counting bits from the most significant. A field of w bytes has 8w bits, so the fields of
 * width w leave the rounds after round 8w - 1. Counting the fields of each width locates every bit
 * of the referenced field in steps bounded by the number of fields plus its bits.
 */
function extractZOrder(key: Uint8Array, field: Extract<Field, { src: 'zorder' }>): Value | undefined {
    const { position, widths } = field;
    if (position >= widths.length || field.bitOffset + field.totalBytes * 8 > key.length * 8) return undefined;
    const bytes = new Uint8Array(widths[position]);
    ended.fill(0, 0, bytes.length);
    endedBefore.fill(0, 0, bytes.length);
    for (let f = 0; f < widths.length; f++) {
        if (widths[f] >= bytes.length) continue;
        ended[widths[f]]++;
        if (f < position) endedBefore[widths[f]]++;
    }

    // `at` is the first bit of the current round. A round holds one bit of each field still in
    // it, and `before` of those bits belong to fields ahead of the referenced one.
    let [at, fields, before] = [field.bitOffset, widths.length, position];
    for (let byte = 0; byte < bytes.length; byte++) {
        fields -= ended[byte];
        before -= endedBefore[byte];
        for (let bit = 0; bit < 8; bit++) {
            const from = at + before;
            if (((key[from >> 3] >> (7 - (from & 7))) & 1) !== 0) bytes[byte] |= 0x80 >> bit;
            at += fields;
        }
    }
    return decodeOrdered(bytes, field.kind, field.len);
}

/**
 * Reads a value field from its stored value. A Float64 field also reads an Int64 value, and a
 * Date32 field the low 32 bits of one. A tag or byte width that does not fit the field kind fails
 * the request.
 */
function extractStored(stored: Stored, field: Extract<Field, { src: 'value' }>): Value {
    const { tag, value } = stored;
    switch (field.kind) {
        case KvFieldKind.INT64:
        case KvFieldKind.DATE64:
        case KvFieldKind.TIMESTAMP:
            if (tag === TAG_INT64) return value as bigint;
            break;
        case KvFieldKind.UINT64:
            if (tag === TAG_UINT64) return value as bigint;
            break;
        case KvFieldKind.FLOAT64:
            if (tag === TAG_FLOAT64) return value as bigint;
            if (tag === TAG_INT64) return toBits(Number(value as bigint));
            break;
        case KvFieldKind.BOOLEAN:
            if (tag === TAG_BOOLEAN) return value as boolean;
            break;
        case KvFieldKind.UTF8:
            if (tag === TAG_UTF8) return value as string;
            break;
        case KvFieldKind.DATE32:
            if (tag === TAG_INT64) return BigInt.asIntN(32, value as bigint);
            break;
        case KvFieldKind.DECIMAL128:
        case KvFieldKind.DECIMAL256: {
            if (tag !== TAG_BYTES) break;
            const wide = field.kind === KvFieldKind.DECIMAL256;
            const bytes = value as Uint8Array;
            if (bytes.length !== (wide ? 32 : 16)) {
                throw failedPrecondition('invalid Decimal' + (wide ? 256 : 128) + ' byte width');
            }
            return BigInt.asIntN(wide ? 256 : 128, readLittleEndian(bytes));
        }
        case KvFieldKind.FIXED_SIZE_BINARY: {
            if (tag !== TAG_BYTES) break;
            const bytes = value as Uint8Array;
            if (bytes.length !== field.len) throw failedPrecondition('invalid FixedSizeBinary byte width');
            return bytes.slice();
        }
    }
    throw failedPrecondition('stored field type mismatch');
}

/**
 * Reads a field of one row. A key field is never NULL. A value field is NULL only when the
 * column holds no value and the reference declares it nullable. Everything else that does not
 * fit the reference fails the request with FAILED_PRECONDITION.
 */
export function extractField(key: Uint8Array, row: readonly (Stored | null)[] | null, field: Field): Value | null {
    if (field.src === 'key') {
        const end = field.byteOffset + keyWidth(field.kind, field.len);
        const bytes = end <= key.length ? key.subarray(field.byteOffset, end) : undefined;
        const value = bytes === undefined ? undefined : decodeOrdered(bytes, field.kind, field.len);
        if (value === undefined) throw failedPrecondition('invalid key field');
        return value;
    }
    if (field.src === 'zorder') {
        const value = extractZOrder(key, field);
        if (value === undefined) throw failedPrecondition('invalid z-order key field');
        return value;
    }
    if (row === null) throw failedPrecondition('value field requires stored row');
    if (field.index >= row.length) throw failedPrecondition('stored row index out of bounds');
    const stored = row[field.index];
    if (stored === null) {
        if (field.nullable) return null;
        throw failedPrecondition('non-nullable field stored as null');
    }
    return extractStored(stored, field);
}
