/**
 * Builders and seeded generators for Reduce tests. They cover stored rows, ordered keys, request
 * messages, and random schemas, rows and requests.
 *
 * The random requests stay clear of the limits that only the IndexedDB store sets. Their
 * expressions nest a few levels deep. Only a chain of date_trunc_day can go deeper, and each
 * further level of it is drawn at 8 percent, so none comes near the store's limit of 100
 * messages. No literal is the smallest Date64, because the store refuses that literal inside a
 * larger expression.
 */
import type { MessageInitShape } from '@bufbuild/protobuf';
import {
    KvFieldKind,
    RangeReduceOp,
    type KvExprSchema,
    type KvFieldRefSchema,
    type KvPredicateConstraintSchema,
    type KvPredicateSchema,
    type KvReducedValueSchema,
    type RangeReducerSpecSchema,
    type ReduceParamsSchema,
} from '../../src/gen/ts/store/v1/query_pb';
import { concat, utf8, type Row } from './contract';

export type ExprInit = MessageInitShape<typeof KvExprSchema>;
export type FieldInit = MessageInitShape<typeof KvFieldRefSchema>;
export type ValueInit = MessageInitShape<typeof KvReducedValueSchema>;
export type ConstraintInit = MessageInitShape<typeof KvPredicateConstraintSchema>;
export type PredicateInit = MessageInitShape<typeof KvPredicateSchema>;
export type ReducerInit = MessageInitShape<typeof RangeReducerSpecSchema>;
export type ParamsInit = MessageInitShape<typeof ReduceParamsSchema>;

/** The low bytes of an integer, most significant first. Negative values are two's complement. */
export function be(value: bigint | number, bytes: number): Uint8Array {
    const out = new Uint8Array(bytes);
    let rest = BigInt.asUintN(bytes * 8, BigInt(value));
    for (let i = bytes - 1; i >= 0; i--) {
        out[i] = Number(rest & 0xffn);
        rest >>= 8n;
    }
    return out;
}

export const le = (value: bigint | number, bytes: number): Uint8Array => be(value, bytes).reverse();

export function floatBits(value: number): bigint {
    const view = new DataView(new ArrayBuffer(8));
    view.setFloat64(0, value);
    return view.getBigUint64(0);
}

export function floatOfBits(bits: bigint): number {
    const view = new DataView(new ArrayBuffer(8));
    view.setBigUint64(0, BigInt.asUintN(64, bits));
    return view.getFloat64(0);
}

export function varint(value: number): Uint8Array {
    const out: number[] = [];
    let rest = value >>> 0;
    while (rest >= 0x80) {
        out.push((rest & 0x7f) | 0x80);
        rest >>>= 7;
    }
    out.push(rest);
    return Uint8Array.from(out);
}

/** Encoders of stored values. Each writes a tag byte followed by the payload. */
export const SV = {
    i64: (value: bigint | number) => concat([0], be(value, 8)),
    u64: (value: bigint | number) => concat([1], be(value, 8)),
    f64: (value: number) => concat([2], be(floatBits(value), 8)),
    f64bits: (bits: bigint) => concat([2], be(bits, 8)),
    bool: (value: boolean) => Uint8Array.from([3, value ? 1 : 0]),
    str: (value: string) => SV.rawStr(utf8(value)),
    rawStr: (bytes: Uint8Array) => concat([4], varint(bytes.length), bytes),
    bytes: (bytes: Uint8Array) => concat([5], varint(bytes.length), bytes),
    list: (items: Uint8Array[]) => concat([6], varint(items.length), ...items),
    d128: (value: bigint | number) => SV.bytes(le(value, 16)),
    d256: (value: bigint | number) => SV.bytes(le(value, 32)),
};

/**
 * Encodes a stored row as the column count, then for each column a presence byte followed by the
 * value when it is present.
 */
export function encodeRow(values: (Uint8Array | null)[]): Uint8Array {
    return concat(varint(values.length), ...values.map((value) => (value === null ? [0] : concat([1], value))));
}

/** The order preserving encodings of key fields. */
export const KEY = {
    i64: (value: bigint | number) => be(BigInt.asUintN(64, BigInt(value)) ^ (1n << 63n), 8),
    u64: (value: bigint | number) => be(value, 8),
    f64bits: (bits: bigint) => be((bits >> 63n) !== 0n ? ~bits : bits ^ (1n << 63n), 8),
    i32: (value: bigint | number) => be(BigInt.asUintN(32, BigInt(value)) ^ (1n << 31n), 4),
    d128: (value: bigint) => be(BigInt.asUintN(128, value) ^ (1n << 127n), 16),
    d256: (value: bigint) => be(BigInt.asUintN(256, value) ^ (1n << 255n), 32),
    text16: (text: string) => {
        const out = new Uint8Array(16);
        out.set(utf8(text));
        return out;
    },
};

/** Interleaves fields bit by bit, the first bit of every field first. */
export function interleave(fields: Uint8Array[]): Uint8Array {
    const out = new Uint8Array(fields.reduce((bytes, field) => bytes + field.length, 0));
    const maxBits = Math.max(0, ...fields.map((field) => field.length * 8));
    let at = 0;
    for (let bit = 0; bit < maxBits; bit++) {
        for (const field of fields) {
            if (bit >= field.length * 8) continue;
            if (((field[bit >> 3] >> (7 - (bit & 7))) & 1) !== 0) out[at >> 3] |= 0x80 >> (at & 7);
            at++;
        }
    }
    return out;
}

/** A field kind, or the byte length of a FIXED_SIZE_BINARY field. */
export type KindArg = KvFieldKind | { fsb: number };

const kindArgs = (kind: KindArg) => (typeof kind === 'object'
    ? { kind: KvFieldKind.FIXED_SIZE_BINARY, fixedSizeBinaryLen: kind.fsb }
    : { kind });

/** Field references to a value column, an ordered key field or a field of a Z-order block. */
export const F = {
    value: (index: number, kind: KindArg, nullable = true): FieldInit =>
        ({ field: { case: 'value', value: { index, nullable, ...kindArgs(kind) } } }),
    key: (byteOffset: number, kind: KindArg): FieldInit =>
        ({ field: { case: 'key', value: { byteOffset, ...kindArgs(kind) } } }),
    zorder: (bitOffset: number, fieldPosition: number, fieldWidths: number[], kind: KindArg): FieldInit =>
        ({ field: { case: 'zOrderKey', value: { bitOffset, fieldPosition, fieldWidths, ...kindArgs(kind) } } }),
};

/** Literals. Decimal128 is big endian and Decimal256 little endian on the wire. */
export const V = {
    i64: (value: bigint | number): ValueInit => ({ value: { case: 'int64Value', value: BigInt(value) } }),
    u64: (value: bigint | number): ValueInit => ({ value: { case: 'uint64Value', value: BigInt(value) } }),
    f64: (value: number): ValueInit => ({ value: { case: 'float64Value', value } }),
    bool: (value: boolean): ValueInit => ({ value: { case: 'booleanValue', value } }),
    str: (value: string): ValueInit => ({ value: { case: 'utf8Value', value } }),
    date32: (value: number): ValueInit => ({ value: { case: 'date32Value', value } }),
    date64: (value: bigint | number): ValueInit => ({ value: { case: 'date64Value', value: BigInt(value) } }),
    ts: (value: bigint | number): ValueInit => ({ value: { case: 'timestampValue', value: BigInt(value) } }),
    d128: (value: bigint | number): ValueInit => ({ value: { case: 'decimal128Value', value: be(value, 16) } }),
    d128raw: (bytes: Uint8Array): ValueInit => ({ value: { case: 'decimal128Value', value: bytes } }),
    d256: (value: bigint | number): ValueInit => ({ value: { case: 'decimal256Value', value: le(value, 32) } }),
    d256raw: (bytes: Uint8Array): ValueInit => ({ value: { case: 'decimal256Value', value: bytes } }),
    fsb: (bytes: Uint8Array): ValueInit => ({ value: { case: 'fixedSizeBinaryValue', value: bytes } }),
};

/** Expressions. */
export const X = {
    f: (ref: FieldInit): ExprInit => ({ expr: { case: 'field', value: ref } }),
    v: (index: number, kind: KindArg, nullable = true): ExprInit => X.f(F.value(index, kind, nullable)),
    k: (byteOffset: number, kind: KindArg): ExprInit => X.f(F.key(byteOffset, kind)),
    lit: (value: ValueInit): ExprInit => ({ expr: { case: 'literal', value } }),
    add: (left: ExprInit, right: ExprInit): ExprInit => ({ expr: { case: 'add', value: { left, right } } }),
    sub: (left: ExprInit, right: ExprInit): ExprInit => ({ expr: { case: 'sub', value: { left, right } } }),
    mul: (left: ExprInit, right: ExprInit): ExprInit => ({ expr: { case: 'mul', value: { left, right } } }),
    div: (left: ExprInit, right: ExprInit): ExprInit => ({ expr: { case: 'div', value: { left, right } } }),
    lower: (inner: ExprInit): ExprInit => ({ expr: { case: 'lower', value: inner } }),
    trunc: (inner: ExprInit): ExprInit => ({ expr: { case: 'dateTruncDay', value: inner } }),
    cast: (inner: ExprInit): ExprInit => ({ expr: { case: 'castFloat64', value: inner } }),
};

type Bound = bigint | number | null | undefined;
const bounds = <T>(min: T | null | undefined, max: T | null | undefined) =>
    ({ ...(min == null ? {} : { min }), ...(max == null ? {} : { max }) });
const big = (value: Bound) => (value == null ? value : BigInt(value));

/** Predicate constraints. */
export const C = {
    strEq: (value: string): ConstraintInit => ({ constraint: { case: 'stringEq', value } }),
    boolEq: (value: boolean): ConstraintInit => ({ constraint: { case: 'boolEq', value } }),
    fsbEq: (value: Uint8Array): ConstraintInit => ({ constraint: { case: 'fixedSizeBinaryEq', value } }),
    intRange: (min?: Bound, max?: Bound): ConstraintInit => ({ constraint: { case: 'intRange', value: bounds(big(min), big(max)) } }),
    u64Range: (min?: Bound, max?: Bound): ConstraintInit => ({ constraint: { case: 'uint64Range', value: bounds(big(min), big(max)) } }),
    /** Each bound is the value and whether it is inclusive. */
    floatRange: (min?: [number, boolean] | null, max?: [number, boolean] | null): ConstraintInit => {
        const bound = (b: [number, boolean] | null | undefined) => (b == null ? b : { value: b[0], inclusive: b[1] });
        return { constraint: { case: 'floatRange', value: bounds(bound(min), bound(max)) } };
    },
    d128Range: (min?: bigint | Uint8Array | null, max?: bigint | Uint8Array | null): ConstraintInit => {
        const bound = (b: bigint | Uint8Array | null | undefined) => (typeof b === 'bigint' ? be(b, 16) : b);
        return { constraint: { case: 'decimal128Range', value: bounds(bound(min), bound(max)) } };
    },
    d256Range: (min?: bigint | Uint8Array | null, max?: bigint | Uint8Array | null): ConstraintInit => {
        const bound = (b: bigint | Uint8Array | null | undefined) => (typeof b === 'bigint' ? le(b, 32) : b);
        return { constraint: { case: 'decimal256Range', value: bounds(bound(min), bound(max)) } };
    },
    isNull: (value = true): ConstraintInit => ({ constraint: { case: 'isNull', value } }),
    isNotNull: (value = true): ConstraintInit => ({ constraint: { case: 'isNotNull', value } }),
    strIn: (values: string[]): ConstraintInit => ({ constraint: { case: 'stringIn', value: { values } } }),
    intIn: (values: (bigint | number)[]): ConstraintInit => ({ constraint: { case: 'intIn', value: { values: values.map(BigInt) } } }),
    u64In: (values: (bigint | number)[]): ConstraintInit => ({ constraint: { case: 'uint64In', value: { values: values.map(BigInt) } } }),
    fsbIn: (values: Uint8Array[]): ConstraintInit => ({ constraint: { case: 'fixedSizeBinaryIn', value: { values } } }),
};

export const pred = (checks: [FieldInit, ConstraintInit][], contradiction = false): PredicateInit =>
    ({ checks: checks.map(([field, constraint]) => ({ field, constraint })), contradiction });

const reducer = (op: RangeReduceOp) => (expr: ExprInit, filter?: PredicateInit): ReducerInit =>
    ({ op, expr, ...(filter === undefined ? {} : { filter }) });

/** Reducers, each with an optional FILTER. */
export const R = {
    countAll: (filter?: PredicateInit): ReducerInit => ({ op: RangeReduceOp.COUNT_ALL, ...(filter === undefined ? {} : { filter }) }),
    count: reducer(RangeReduceOp.COUNT_FIELD),
    sum: reducer(RangeReduceOp.SUM_FIELD),
    min: reducer(RangeReduceOp.MIN_FIELD),
    max: reducer(RangeReduceOp.MAX_FIELD),
};

/** A small deterministic generator (mulberry32), so a case is reproduced by its seed. */
export interface Rng {
    next(): number;
    int(n: number): number;
    chance(p: number): boolean;
    pick<T>(list: readonly T[]): T;
    big(bits: number): bigint;
}

export function rng(seed: number): Rng {
    let state = seed >>> 0;
    const next = () => {
        state = (state + 0x6d2b79f5) >>> 0;
        let t = state;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    return {
        next,
        int: (n) => Math.floor(next() * n),
        chance: (p) => next() < p,
        pick: (list) => list[Math.floor(next() * list.length)],
        big: (bits) => {
            let value = 0n;
            for (let i = 0; i < bits; i += 16) value = (value << 16n) | BigInt(Math.floor(next() * 65536));
            return BigInt.asUintN(bits, value);
        },
    };
}

const I64_MAX = (1n << 63n) - 1n;
const I64_MIN = -(1n << 63n);
const U64_MAX = (1n << 64n) - 1n;
const I128_MAX = (1n << 127n) - 1n;
const I128_MIN = -(1n << 127n);
const I256_MAX = (1n << 255n) - 1n;
const I256_MIN = -(1n << 255n);
const DAY = 86_400_000n;

/** Date64 values of stored rows and literals. Only stored rows also use the smallest Date64. */
const DATE64_VALUES = [0n, 1n, -1n, DAY, -DAY, DAY - 1n, -DAY - 1n, DAY * 3n + 5n, 1700000000000n, 9223372036854n, -9223372036854n,
    9223286400000n, -9223286400000n, 9223372036855n, I64_MAX, I64_MIN + 1n];

const pools = {
    i64: (r: Rng) => r.pick([0n, 1n, -1n, 2n, 7n, -7n, 100n, I64_MAX, I64_MIN, I64_MAX - 1n, I64_MIN + 1n, (1n << 53n) + 1n,
        -(1n << 53n) - 1n, 3037000500n, BigInt(r.int(20) - 10), BigInt.asIntN(64, r.big(64))]),
    u64: (r: Rng) => r.pick([0n, 1n, 2n, 3n, 7n, U64_MAX, U64_MAX - 1n, 1n << 63n, (1n << 53n) + 1n, (1n << 63n) + 1025n,
        BigInt(r.int(20)), r.big(64)]),
    // Zeros and ones of both signs, 0.1, 1e16 of both signs, 1e-3, infinities, quiet NaNs of both
    // signs, a signaling NaN, the smallest subnormal, the largest finite values of both signs,
    // 2.5, 3.5, 1/3, random bits, and either 2 plus up to 999 ulps or a negative NaN with a random
    // payload.
    f64bits: (r: Rng) => r.pick([0n, 0x8000000000000000n, 0x3ff0000000000000n, 0xbff0000000000000n, 0x3fb999999999999an,
        0x4341c37937e08000n, 0xc341c37937e08000n, 0x3f50624dd2f1a9fcn, 0x7ff0000000000000n, 0xfff0000000000000n,
        0x7ff8000000000000n, 0x7ff8000000000001n, 0xfff8000000000001n, 0x7ff0000000000001n, 0x0000000000000001n,
        0x7fefffffffffffffn, 0xffefffffffffffffn, 0x4004000000000000n, 0x400c000000000000n, 0x3fd5555555555555n, r.big(64),
        BigInt.asUintN(64, BigInt(Math.floor((r.next() - 0.5) * 2000))) | 0x4000000000000000n]),
    str: (r: Rng) => r.pick(['', 'a', 'A', 'b', '\u00c9', '\u00e9', '\u039f\u03a3', '\u0130', '\u01c5', '3.25', ' 7 ', '-0.5', 'nan',
        '-NaN', 'inf', '1e5', '1e400', '.5', '5.', '0x10', 'x', '\u0391\u03a3 \u0392\u03a3', '\u{1f600}', '\u00df', 'MiXeD Case',
        '2020-01-02', String(r.int(5))]),
    date32: (r: Rng) => r.pick([0n, 1n, -1n, 10n, 19000n, -19000n, 106751n, -106751n, 106752n, -106752n, 2147483647n, -2147483648n,
        95026236n, 95026237n, 1n << 32n, BigInt(r.int(2000) - 1000)]),
    date64: (r: Rng) => r.pick([...DATE64_VALUES, I64_MIN, BigInt(r.int(2000) - 1000) * DAY + BigInt(r.int(1000))]),
    date64Literal: (r: Rng) => r.pick([...DATE64_VALUES, I64_MIN + 2n, BigInt(r.int(2000) - 1000) * DAY + BigInt(r.int(1000))]),
    ts: (r: Rng) => r.pick([0n, 1n, -1n, 86400000000n, -86400000000n, 86399999999n, -86400000001n, 1700000000000000n, I64_MAX,
        I64_MIN, -9223372022400000000n, -9223372022400000001n, 9223372036854775n, -9223372036854775n, 9223372036854776n,
        BigInt(r.int(2000) - 1000) * 86400000000n + BigInt(r.int(1000000))]),
    d128: (r: Rng) => r.pick([0n, 1n, -1n, 2n, 7n, -7n, 3n, 10n ** 18n, 10n ** 37n, -(10n ** 37n), 10n ** 38n - 1n, I128_MAX,
        I128_MIN, I128_MAX / 10000n, I128_MAX / 10000n + 1n, (1n << 53n) + 1n, 9007199254740000n, BigInt(r.int(200) - 100),
        BigInt.asIntN(128, r.big(128)), BigInt.asIntN(70, r.big(70))]),
    d256: (r: Rng) => r.pick([0n, 1n, -1n, 2n, 7n, -7n, 3n, 10n ** 38n, 10n ** 75n, -(10n ** 75n), 10n ** 76n - 1n, I256_MAX,
        I256_MIN, I256_MAX / 10000n, 9223372036854776833n, -18446744073709557757n, BigInt(r.int(200) - 100),
        BigInt.asIntN(256, r.big(256)), BigInt.asIntN(130, r.big(130))]),
};

const KINDS = ['i64', 'u64', 'f64', 'bool', 'utf8', 'date32', 'date64', 'ts', 'd128', 'd256', 'fsb'] as const;
type Kind = typeof KINDS[number];

interface Column {
    /** The kind of the column's values. */
    kind: Kind;
    /** Byte length of an fsb column. */
    len: number;
    /** Probability that a row stores NULL in the column. */
    nullProb: number;
    /** A column of few distinct values, useful as a group key. */
    lowCard: boolean;
}

export interface Schema {
    /** Value columns in row order, the six grouping columns last. */
    columns: Column[];
    /** Ordered key fields after the dataset prefix. The Z-order block and a row counter follow. */
    keyFields: Column[];
    /** Fields of the Z-order block, empty when the keys have none. */
    z: Column[];
}

const PROTO_KINDS: Record<Exclude<Kind, 'fsb'>, KvFieldKind> = {
    i64: KvFieldKind.INT64,
    u64: KvFieldKind.UINT64,
    f64: KvFieldKind.FLOAT64,
    bool: KvFieldKind.BOOLEAN,
    utf8: KvFieldKind.UTF8,
    date32: KvFieldKind.DATE32,
    date64: KvFieldKind.DATE64,
    ts: KvFieldKind.TIMESTAMP,
    d128: KvFieldKind.DECIMAL128,
    d256: KvFieldKind.DECIMAL256,
};
const protoKind = (column: { kind: Kind; len: number }): KindArg => (column.kind === 'fsb' ? { fsb: column.len } : PROTO_KINDS[column.kind]);

const smallBytes = (r: Rng, length: number): Uint8Array => Uint8Array.from({ length }, () => r.int(3));

/**
 * A stored value of the column's kind. A FLOAT64 field also reads a stored Int64, so an f64
 * column stores one in 5 percent of rows.
 */
function storedValue(r: Rng, column: Column): Uint8Array {
    switch (column.kind) {
        case 'i64': return SV.i64(pools.i64(r));
        case 'u64': return SV.u64(pools.u64(r));
        case 'f64': return r.chance(0.05) ? SV.i64(pools.i64(r)) : SV.f64bits(pools.f64bits(r));
        case 'bool': return SV.bool(r.chance(0.5));
        case 'utf8': return SV.str(pools.str(r));
        case 'date32': return SV.i64(pools.date32(r));
        case 'date64': return SV.i64(pools.date64(r));
        case 'ts': return SV.i64(pools.ts(r));
        case 'd128': return SV.d128(pools.d128(r));
        case 'd256': return SV.d256(pools.d256(r));
        case 'fsb': return SV.bytes(smallBytes(r, column.len));
    }
}

function literal(r: Rng, kind: Kind): ValueInit {
    switch (kind) {
        case 'i64': return V.i64(pools.i64(r));
        case 'u64': return V.u64(pools.u64(r));
        case 'f64': return V.f64(floatOfBits(pools.f64bits(r)));
        case 'bool': return V.bool(r.chance(0.5));
        case 'utf8': return V.str(pools.str(r));
        case 'date32': return V.date32(Number(BigInt.asIntN(32, pools.date32(r))));
        case 'date64': return V.date64(pools.date64Literal(r));
        case 'ts': return V.ts(pools.ts(r));
        case 'd128': return V.d128(pools.d128(r));
        case 'd256': return V.d256(pools.d256(r));
        case 'fsb': return V.fsb(smallBytes(r, r.int(3)));
    }
}

function keyField(r: Rng, column: Column): Uint8Array {
    switch (column.kind) {
        case 'i64': return KEY.i64(pools.i64(r));
        case 'u64': return KEY.u64(pools.u64(r));
        case 'f64': return KEY.f64bits(pools.f64bits(r));
        case 'bool': return Uint8Array.from([r.pick([0, 1, 1, 2])]);
        case 'utf8': return KEY.text16(r.pick(['', 'west', 'east', '\u00c9', 'north']));
        case 'date32': return KEY.i32(BigInt.asIntN(32, pools.date32(r)));
        case 'date64': return KEY.i64(pools.date64(r));
        case 'ts': return KEY.i64(pools.ts(r));
        case 'd128': return KEY.d128(pools.d128(r));
        case 'd256': return KEY.d256(pools.d256(r));
        case 'fsb': return smallBytes(r, column.len);
    }
}

const KEY_WIDTHS: Record<Exclude<Kind, 'fsb'>, number> = { i64: 8, u64: 8, f64: 8, bool: 1, utf8: 16, date32: 4, date64: 8, ts: 8, d128: 16, d256: 32 };
const keyWidth = (column: Column): number => (column.kind === 'fsb' ? column.len : KEY_WIDTHS[column.kind]);

/**
 * Draws a schema of 3 to 9 value columns of random kinds and NULL rates, six columns of few
 * distinct values for grouping, up to two ordered key fields and, in 30 percent of schemas, a
 * Z-order block of one to three fields.
 */
export function genSchema(r: Rng): Schema {
    const column = (nullProb = 0): Column => {
        const kind = r.pick(KINDS);
        return { kind, len: kind === 'fsb' ? r.int(4) : 0, nullProb, lowCard: false };
    };
    const columns = Array.from({ length: 3 + r.int(7) }, () => {
        const made = column();
        made.nullProb = r.pick([0, 0, 0.1, 0.3, 0.9]);
        return made;
    });
    for (const [kind, nullProb] of [['i64', 0.4], ['utf8', 0.4], ['i64', 0.4], ['utf8', 0.4], ['i64', 0.1], ['utf8', 0.1]] as const) {
        columns.push({ kind, len: 0, nullProb, lowCard: true });
    }
    const emptyBinary = (c: Column) => c.kind === 'fsb' && c.len === 0;
    const keyFields = Array.from({ length: r.int(3) }, () => column()).filter((c) => !emptyBinary(c));
    const z = r.chance(0.3)
        ? Array.from({ length: 1 + r.int(3) }, () => {
            let made = column();
            while (made.kind === 'utf8' || made.kind === 'd256' || emptyBinary(made)) made = column();
            return made;
        })
        : [];
    return { columns, keyFields, z };
}

/** Rows of a schema with keys relative to the dataset prefix. The row counter keeps keys unique. */
export function genRows(r: Rng, schema: Schema, count: number): Row[] {
    const rows: Row[] = [];
    for (let i = 0; i < count; i++) {
        const key = concat(
            ...schema.keyFields.map((c) => keyField(r, c)),
            schema.z.length > 0 ? interleave(schema.z.map((c) => keyField(r, c))) : [],
            be(i, 4),
        );
        const values = schema.columns.map((c) => {
            if (r.chance(c.nullProb)) return null;
            if (!c.lowCard) return storedValue(r, c);
            return c.kind === 'i64' ? SV.i64(r.int(4)) : SV.str(r.pick(['x', 'y', 'z']));
        });
        rows.push([key, encodeRow(values)]);
    }
    return rows;
}

/** What a request generator needs to know about a dataset. */
export interface Context {
    schema: Schema;
    /** Length of the key prefix in front of the schema's key fields. */
    prefixLength: number;
}

/**
 * A reference to a random field of the wanted kinds, or undefined when the schema has none. With
 * small probability the reference declares another kind, an index beyond the row, a nullable
 * column as not nullable, or a key offset beyond the key.
 */
function fieldRef(r: Rng, ctx: Context, wanted: readonly Kind[] | null): { ref: FieldInit; kind: Kind } | undefined {
    const { schema } = ctx;
    const fits = (c: Column) => wanted === null || wanted.includes(c.kind);
    const candidates: (() => { ref: FieldInit; kind: Kind })[] = [];
    schema.columns.forEach((c, index) => {
        if (!fits(c)) return;
        candidates.push(() => {
            const lie = r.next();
            const declared = lie < 0.01 ? { kind: r.pick(KINDS), len: 1 } : c;
            const at = lie > 0.995 ? schema.columns.length + 2 : index;
            const nullable = c.nullProb > 0 ? !r.chance(0.02) : r.chance(0.5);
            return { ref: F.value(at, protoKind(declared), nullable), kind: declared.kind };
        });
    });
    let offset = ctx.prefixLength;
    for (const c of schema.keyFields) {
        const at = offset;
        if (fits(c)) candidates.push(() => ({ ref: F.key(r.chance(0.01) ? at + 200 : at, protoKind(c)), kind: c.kind }));
        offset += keyWidth(c);
    }
    schema.z.forEach((c, position) => {
        const bitOffset = offset * 8;
        if (fits(c)) candidates.push(() => ({ ref: F.zorder(bitOffset, position, schema.z.map(keyWidth), protoKind(c)), kind: c.kind }));
    });
    return candidates.length === 0 ? undefined : r.pick(candidates)();
}

const NUMERIC: readonly Kind[] = ['i64', 'u64', 'f64', 'd128', 'd256'];

/** Kinds drawn together so that most arithmetic over them is well typed. */
const FAMILIES: readonly (readonly Kind[])[] = [['i64'], ['u64'], ['f64'], ['i64', 'f64'], ['u64', 'f64'], ['i64', 'u64'], ['d128'],
    ['d128', 'i64'], ['d128', 'u64'], ['d256'], ['d256', 'i64'], ['d128', 'd256'], ['d128', 'f64'], NUMERIC];

const ARITHMETIC = [X.add, X.sub, X.mul, X.div];

/** A field of one of the kinds, or a literal of one when none fits and in a quarter of draws. */
function leaf(r: Rng, ctx: Context, kinds: readonly Kind[]): ExprInit {
    if (r.chance(0.75)) {
        const field = fieldRef(r, ctx, kinds);
        if (field !== undefined) return X.f(field.ref);
    }
    return X.lit(literal(r, r.pick(kinds)));
}

/**
 * An expression over a family of numeric kinds. Most of its operations are arithmetic within the
 * family, and the rest are cast_float64 or a difference of dates.
 */
function numeric(r: Rng, ctx: Context, depth: number, family: readonly Kind[]): ExprInit {
    if (depth <= 0 || r.chance(0.3)) return leaf(r, ctx, family);
    const roll = r.next();
    if (roll < 0.75) {
        const op = r.pick(ARITHMETIC);
        const left = numeric(r, ctx, depth - 1, family);
        return op(left, numeric(r, ctx, depth - 1, family));
    }
    if (roll < 0.87) return X.cast(anyExpr(r, ctx, depth - 1));
    if (roll < 0.93) {
        const kind = r.pick(['date32', 'date64'] as const);
        const left = leaf(r, ctx, [kind]);
        return X.sub(left, leaf(r, ctx, r.chance(0.8) ? [kind] : ['date32', 'date64']));
    }
    return X.cast(numeric(r, ctx, depth - 1, r.pick(FAMILIES)));
}

const TEMPORAL = ['ts', 'date32', 'date64'] as const;

/**
 * An expression over dates and timestamps: date_trunc_day, days added to or subtracted from a
 * date, a difference of timestamps, a timestamp plus such a difference, or a difference of any
 * two temporal kinds.
 */
function temporal(r: Rng, ctx: Context, depth: number): ExprInit {
    const roll = r.next();
    if (roll < 0.35) return X.trunc(leaf(r, ctx, [r.pick(TEMPORAL)]));
    if (roll < 0.6) {
        const date = leaf(r, ctx, [r.pick(['date32', 'date64'] as const)]);
        const days = r.chance(0.6)
            ? X.lit(V.i64(r.pick([0n, 1n, -1n, 7n, 365n, 106751n, 106752n, -106752n])))
            : leaf(r, ctx, ['i64', 'u64']);
        return r.chance(0.5) ? X.add(date, days) : r.chance(0.5) ? X.sub(date, days) : X.add(days, date);
    }
    if (roll < 0.75) {
        const left = leaf(r, ctx, ['ts']);
        return X.sub(left, leaf(r, ctx, ['ts']));
    }
    if (roll < 0.85) {
        const base = leaf(r, ctx, ['ts']);
        const left = leaf(r, ctx, ['ts']);
        return X.add(base, X.sub(left, leaf(r, ctx, ['ts'])));
    }
    if (roll < 0.92) {
        const left = leaf(r, ctx, [r.pick(TEMPORAL)]);
        return X.sub(left, leaf(r, ctx, [r.pick(TEMPORAL)]));
    }
    return X.trunc(temporal(r, ctx, depth - 1));
}

/**
 * An expression of any kind: numeric, temporal, lower over text, a lone field or literal, or an
 * operation on operands of unrelated kinds.
 */
function anyExpr(r: Rng, ctx: Context, depth: number): ExprInit {
    const roll = r.next();
    if (roll < 0.5) return numeric(r, ctx, depth, r.pick(FAMILIES));
    if (roll < 0.62) return temporal(r, ctx, depth);
    if (roll < 0.72) return r.chance(0.7) ? X.lower(leaf(r, ctx, ['utf8'])) : X.lower(X.lower(leaf(r, ctx, ['utf8'])));
    if (roll < 0.92) return leaf(r, ctx, [r.pick(KINDS)]);

    // Operands of unrelated kinds, mostly rejected when the request is planned.
    const a = leaf(r, ctx, [r.pick(KINDS)]);
    const b = leaf(r, ctx, [r.pick(KINDS)]);
    return r.pick([() => X.add(a, b), () => X.sub(a, b), () => X.mul(a, b), () => X.div(a, b), () => X.lower(a), () => X.trunc(a),
        () => X.cast(a)])();
}

/** A random constraint made for a kind. */
function constraintFor(r: Rng, kind: Kind): ConstraintInit {
    const opt = <T>(make: () => T): T | null => (r.chance(0.3) ? null : make());
    const list = <T>(make: () => T): T[] => Array.from({ length: r.int(4) }, make);
    switch (kind) {
        case 'i64': return r.chance(0.7) ? C.intRange(opt(() => pools.i64(r)), opt(() => pools.i64(r))) : C.intIn(list(() => pools.i64(r)));
        case 'date32': return C.intRange(opt(() => BigInt.asIntN(32, pools.date32(r))), opt(() => pools.date32(r)));
        case 'date64': return C.intRange(opt(() => pools.date64(r)), opt(() => pools.date64(r)));
        case 'ts': return C.intRange(opt(() => pools.ts(r)), opt(() => pools.ts(r)));
        case 'u64': return r.chance(0.7) ? C.u64Range(opt(() => pools.u64(r)), opt(() => pools.u64(r))) : C.u64In(list(() => pools.u64(r)));
        case 'f64': {
            const bound = (): [number, boolean] => [floatOfBits(pools.f64bits(r)), r.chance(0.5)];
            return C.floatRange(opt(bound), opt(bound));
        }
        case 'bool': return C.boolEq(r.chance(0.5));
        case 'utf8': return r.chance(0.6) ? C.strEq(pools.str(r)) : C.strIn(list(() => r.pick(['x', 'y', 'z', 'a', ''])));
        case 'd128': return C.d128Range(opt(() => pools.d128(r)), opt(() => pools.d128(r)));
        case 'd256': return C.d256Range(opt(() => pools.d256(r)), opt(() => pools.d256(r)));
        case 'fsb': return r.chance(0.6) ? C.fsbEq(smallBytes(r, r.int(3))) : C.fsbIn([smallBytes(r, r.int(3))]);
    }
}

/**
 * A predicate of up to three checks over random fields, marked as a contradiction in 4 percent
 * of draws. Most checks get a constraint made for the kind of their field.
 */
function predicate(r: Rng, ctx: Context): PredicateInit {
    const checks: [FieldInit, ConstraintInit][] = [];
    const count = r.pick([0, 1, 1, 1, 2, 3]);
    for (let i = 0; i < count; i++) {
        const field = fieldRef(r, ctx, null) as { ref: FieldInit; kind: Kind };
        const roll = r.next();
        const constraint = roll < 0.15 ? C.isNull(r.chance(0.5))
            : roll < 0.3 ? C.isNotNull(r.chance(0.5))
                : constraintFor(r, roll < 0.93 ? field.kind : r.pick(KINDS));
        checks.push([field.ref, constraint]);
    }
    return pred(checks, r.chance(0.04));
}

/**
 * Draws the params of a request over a dataset. A request has up to four reducers, each with a
 * FILTER at 30 percent and SUM drawn twice as often as each other op. It groups at 45 percent and
 * whenever it has no reducer, and it carries a request filter at 40 percent. With largeLiteral,
 * 30 percent of requests also count a literal of 4 to 20 KiB. Every row of a batch charges that
 * literal to the byte budget, so batches end at the budget before the 4096 rows of a chunk.
 */
export function genRequest(r: Rng, ctx: Context, options: { largeLiteral?: boolean } = {}): ParamsInit {
    const reducers: ReducerInit[] = [];
    const count = r.pick([0, 1, 1, 2, 3, 4]);
    for (let i = 0; i < count; i++) {
        const filter = r.chance(0.3) ? predicate(r, ctx) : undefined;
        const op = r.pick(['countAll', 'count', 'sum', 'sum', 'min', 'max'] as const);
        if (op === 'countAll') reducers.push(R.countAll(filter));
        else if (op === 'sum') reducers.push(R.sum(r.chance(0.85) ? numeric(r, ctx, 2, r.pick(FAMILIES)) : anyExpr(r, ctx, 2), filter));
        else reducers.push(R[op](anyExpr(r, ctx, 2), filter));
    }
    const groupBy: ExprInit[] = [];
    if (r.chance(0.45) || reducers.length === 0) {
        const keys = r.pick([1, 1, 2, 3, 3, 4, 5]);
        const columns = ctx.schema.columns;
        for (let i = 0; i < keys; i++) {
            if (r.chance(0.65)) {
                const index = columns.length - 1 - r.int(6);
                groupBy.push(X.v(index, columns[index].kind === 'i64' ? KvFieldKind.INT64 : KvFieldKind.UTF8));
            } else groupBy.push(anyExpr(r, ctx, 1));
        }
    }
    const params: ParamsInit = { reducers, groupBy };
    if (r.chance(0.4)) params.filter = predicate(r, ctx);
    if (options.largeLiteral && r.chance(0.3)) reducers.push(R.count(X.lit(V.str('X'.repeat(4096 + r.int(16384))))));
    return params;
}

/** Row counts of a random case. */
export const SIZES = [0, 1, 1, 2, 3, 5, 8, 17, 40, 100, 257];

/** Row counts of a big case, around the 4096 rows of a scan chunk and its multiples. */
export const BIG_SIZES = [4095, 4096, 4097, 5000, 8192, 8193, 9000];
