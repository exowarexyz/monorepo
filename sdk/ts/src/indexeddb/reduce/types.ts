import { Code, ConnectError } from '@connectrpc/connect';
import { KvFieldKind } from '../../gen/ts/store/v1/query_pb.js';
import { fieldError } from '../errors.js';

/**
 * A non-NULL value inside the evaluator. An integer, date, timestamp, duration, interval or
 * decimal is a bigint holding the raw word. A Float64 is a bigint holding its 64 bit pattern, so
 * that a NaN keeps its bits and the two zeros stay apart wherever the service tells them apart.
 * A Boolean is a boolean, text is a string and binary is a Uint8Array.
 */
export type Value = bigint | boolean | string | Uint8Array;

/** The result of an expression over one batch. A scalar stands for the same value in every row. */
export type Datum =
    | { readonly scalar: true; readonly value: Value | null }
    | { readonly scalar: false; readonly values: readonly (Value | null)[] };

export type Unit = 'us' | 'ns';

/**
 * The type of an expression. It is finer than KvFieldKind because the precision and scale of a
 * decimal and the unit of a timestamp decide results, although the wire drops them.
 */
export type Type =
    | { readonly t: 'i64' | 'u64' | 'f64' | 'bool' | 'utf8' | 'bin' | 'date32' | 'date64' | 'interval' }
    | { readonly t: 'ts' | 'dur'; readonly unit: Unit }
    | { readonly t: 'dec'; readonly w: 128 | 256; readonly p: number; readonly s: number };

export type DecimalType = Extract<Type, { t: 'dec' }>;

export const INT64: Type = { t: 'i64' };
export const UINT64: Type = { t: 'u64' };
export const FLOAT64: Type = { t: 'f64' };
export const BOOLEAN: Type = { t: 'bool' };
export const UTF8: Type = { t: 'utf8' };
export const BINARY: Type = { t: 'bin' };
export const DATE32: Type = { t: 'date32' };
export const DATE64: Type = { t: 'date64' };
export const INTERVAL: Type = { t: 'interval' };
export const timestamp = (unit: Unit): Type => ({ t: 'ts', unit });
export const duration = (unit: Unit): Type => ({ t: 'dur', unit });
export const decimal = (w: 128 | 256, p: number, s: number): DecimalType => ({ t: 'dec', w, p, s });

/** The largest precision and scale of each decimal width. */
const MAX_DECIMAL_DIGITS = { 128: 38, 256: 76 } as const;

export function sameType(a: Type, b: Type): boolean {
    if (a.t === 'dec') return b.t === 'dec' && a.w === b.w && a.p === b.p && a.s === b.s;
    if (a.t === 'ts' || a.t === 'dur') return b.t === a.t && b.unit === a.unit;
    return a.t === b.t;
}

const UNIT_NAMES = { us: '\u00b5s', ns: 'ns' } as const;

/** The name of a type as it appears in error descriptions. */
export function typeName(type: Type): string {
    switch (type.t) {
        case 'i64': return 'Int64';
        case 'u64': return 'UInt64';
        case 'f64': return 'Float64';
        case 'bool': return 'Boolean';
        case 'utf8': return 'Utf8';
        case 'bin': return 'Binary';
        case 'date32': return 'Date32';
        case 'date64': return 'Date64';
        case 'interval': return 'Interval(MonthDayNano)';
        case 'ts': return 'Timestamp(' + UNIT_NAMES[type.unit] + ')';
        case 'dur': return 'Duration(' + UNIT_NAMES[type.unit] + ')';
        case 'dec': return 'Decimal' + type.w + '(' + type.p + ', ' + type.s + ')';
    }
}

/** The type of a field or literal of a kind. */
export function kindType(kind: KvFieldKind): Type {
    switch (kind) {
        case KvFieldKind.INT64: return INT64;
        case KvFieldKind.UINT64: return UINT64;
        case KvFieldKind.FLOAT64: return FLOAT64;
        case KvFieldKind.BOOLEAN: return BOOLEAN;
        case KvFieldKind.UTF8: return UTF8;
        case KvFieldKind.DATE32: return DATE32;
        case KvFieldKind.DATE64: return DATE64;
        case KvFieldKind.TIMESTAMP: return timestamp('us');
        case KvFieldKind.DECIMAL128: return decimal(128, 38, 0);
        case KvFieldKind.DECIMAL256: return decimal(256, 76, 0);
        case KvFieldKind.FIXED_SIZE_BINARY: return BINARY;
    }
}

/**
 * A field reference after conversion. len is the byte length of a FIXED_SIZE_BINARY field and 0
 * for every other kind, so that two references are equal exactly when all their properties are.
 */
export type Field =
    | { readonly src: 'key'; readonly kind: KvFieldKind; readonly len: number; readonly byteOffset: number }
    | {
        readonly src: 'zorder';
        readonly kind: KvFieldKind;
        readonly len: number;
        readonly bitOffset: number;
        /** The position of the referenced field among the interleaved ones, as sent. */
        readonly position: number;
        /** The byte widths of the interleaved fields in the request's own array. */
        readonly widths: readonly number[];
        /** The byte width of all interleaved fields together. */
        readonly totalBytes: number;
    }
    | {
        readonly src: 'value';
        readonly kind: KvFieldKind;
        readonly len: number;
        readonly index: number;
        readonly nullable: boolean;
    };

/** A string that is equal for two field references exactly when the references are equal. */
export function fieldIdentity(field: Field): string {
    const kind = field.kind + '/' + field.len;
    switch (field.src) {
        case 'key': return 'k:' + field.byteOffset + ':' + kind;
        case 'zorder': return 'z:' + field.bitOffset + ':' + kind + ':' + field.position + ':' + field.widths.join(',');
        case 'value': return 'v:' + field.index + ':' + kind + ':' + (field.nullable ? 1 : 0);
    }
}

export type Op = 'add' | 'sub' | 'mul' | 'div';

export const OP_SYMBOLS = { add: '+', sub: '-', mul: '*', div: '/' } as const;

export const I64_MIN = -(1n << 63n);
export const I64_MAX = (1n << 63n) - 1n;

export const QUERY_DOMAIN = 'store.query';
export const INVALID_REDUCE_PARAMS = 'INVALID_REDUCE_PARAMS';

/** The error of a request whose params cannot be converted or planned. */
export function invalidParams(description: string): ConnectError {
    return fieldError(QUERY_DOMAIN, 'params', description, INVALID_REDUCE_PARAMS, 'reduce params are invalid');
}

export const planError = (text: string): ConnectError => invalidParams('Error during planning: ' + text);

/** The error of a request that is valid but fails on the stored rows or on a computed value. */
export const failedPrecondition = (message: string): ConnectError => new ConnectError(message, Code.FailedPrecondition);

export const arrowError = (text: string): ConnectError => failedPrecondition('Arrow error: ' + text);

export const executionError = (text: string): ConnectError => failedPrecondition('Execution error: ' + text);

/** The text that ends the message of every INTERNAL error. */
const INTERNAL_SUFFIX = ".\nThis issue was likely caused by a bug in DataFusion's code. Please help us to resolve this "
    + 'by filing a bug report in our issue tracker: https://github.com/apache/datafusion/issues';

/** An INTERNAL error with the message text the service uses for it. */
export function internalError(text: string): ConnectError {
    return new ConnectError('Internal error: ' + text + INTERNAL_SUFFIX, Code.Internal);
}

/** The error of a request the service defines and this evaluator does not compute. */
export const unimplemented = (message: string): ConnectError => new ConnectError(message, Code.Unimplemented);

/** The kernel has no rule for a pair of operand types. The text goes into a plan error. */
class KernelError {
    constructor(readonly text: string) {}
}

const isInteger = (type: Type): boolean => type.t === 'i64' || type.t === 'u64';
const isDate = (type: Type): boolean => type.t === 'date32' || type.t === 'date64';
const isNumeric = (type: Type): boolean => isInteger(type) || type.t === 'f64' || type.t === 'dec';

/** Whether an operator over two operand types is the subtraction of two dates of one type. */
const isDateDifference = (left: Type, op: Op, right: Type): boolean => op === 'sub' && isDate(left) && left.t === right.t;

/** The result type of an arithmetic kernel over two operand types that are used as they are. */
function kernelType(left: Type, op: Op, right: Type): Type | KernelError {
    const pair = typeName(left) + ' ' + OP_SYMBOLS[op] + ' ' + typeName(right);
    const invalid = (what: string) =>
        new KernelError('Invalid argument error: Invalid ' + what + 'arithmetic operation: ' + pair);
    const additive = op === 'add' || op === 'sub';
    if (left.t === right.t && (left.t === 'i64' || left.t === 'u64' || left.t === 'f64')) return left;
    if (left.t === 'ts') {
        if (op === 'sub' && right.t === 'ts' && right.unit === left.unit) return duration(left.unit);
        if (additive && right.t === 'dur' && right.unit === left.unit) return left;
        if (additive && right.t === 'interval') return left;
        return invalid('timestamp ');
    }
    if (left.t === 'dur' && right.t === 'dur' && left.unit === right.unit) return additive ? left : invalid('duration ');
    if (left.t === 'interval' && right.t === 'interval') return additive ? left : invalid('interval ');
    if (isDate(left)) return additive && right.t === 'interval' ? left : invalid('date ');
    if (left.t === 'dec' && right.t === 'dec' && left.w === right.w) {
        const max = MAX_DECIMAL_DIGITS[left.w];
        if (additive) {
            const scale = Math.max(left.s, right.s);
            return decimal(left.w, Math.min(max, scale + Math.max(left.p - left.s, right.p - right.s) + 1), scale);
        }
        if (op === 'mul') {
            const scale = left.s + right.s;
            if (scale > max) {
                return new KernelError('Invalid argument error: Output scale of ' + typeName(left) + ' * ' + typeName(right)
                    + ' would exceed max scale of ' + max);
            }
            return decimal(left.w, Math.min(max, left.p + right.p + 1), scale);
        }
        const scale = Math.min(left.s + 4, max);
        const shift = scale - left.s + right.s;
        if (shift > max) return new KernelError('Arithmetic overflow: Overflow happened on: 10 ^ ' + shift);
        return decimal(left.w, Math.min(max, shift + left.p), scale);
    }
    if ((left.t === 'dur' || left.t === 'interval') && (isDate(right) || right.t === 'ts') && op === 'add') {
        return kernelType(right, op, left);
    }
    return new KernelError('Invalid argument error: Invalid arithmetic operation: ' + pair);
}

/** The result type of an operator over operand types that need no further conversion. */
function resultType(left: Type, op: Op, right: Type): Type | KernelError {
    return isDateDifference(left, op, right) ? INT64 : kernelType(left, op, right);
}

/**
 * The types both operands of an arithmetic operator are converted to and the type of the result, by
 * the first rule that applies: a date difference or a pair the kernel accepts as it is, temporal
 * arithmetic with a number or a span, a common temporal type, decimals, then plain numbers. Throws
 * the plan error of a pair that no rule accepts.
 */
export function coerceBinary(left: Type, op: Op, right: Type): { left: Type; right: Type; result: Type } {
    const symbol = OP_SYMBOLS[op];
    const direct = resultType(left, op, right);
    if (!(direct instanceof KernelError)) return { left, right, result: direct };
    const checked = (targets: [Type, Type], what: string, shown: [Type, Type]) => {
        const result = resultType(targets[0], op, targets[1]);
        if (result instanceof KernelError) {
            throw planError('Cannot get result type for ' + what + ' operation ' + typeName(shown[0]) + ' ' + symbol + ' '
                + typeName(shown[1]) + ': ' + result.text);
        }
        return { left: targets[0], right: targets[1], result };
    };

    // Temporal arithmetic with a number or a span: a date with an integer number of days, a
    // timestamp with a duration of another unit, and an interval with an integer or a float.
    let temporal: [Type, Type] | undefined;
    if (isDate(left) && isInteger(right)) temporal = [left, INTERVAL];
    else if (isInteger(left) && isDate(right)) temporal = [INTERVAL, right];
    else if (left.t === 'ts' && right.t === 'dur') temporal = [left, duration(left.unit)];
    else if (left.t === 'dur' && right.t === 'ts') temporal = [duration(right.unit), right];
    else if ((left.t === 'interval' && (isInteger(right) || right.t === 'f64'))
        || ((isInteger(left) || left.t === 'f64') && right.t === 'interval')) temporal = [INTERVAL, INTERVAL];
    if (temporal !== undefined) return checked(temporal, 'temporal', [left, right]);

    // Two temporal operands meet at a common type.
    const isSpan = (type: Type) => type.t === 'dur' || type.t === 'interval';
    let common: Type | undefined;
    if (left.t === 'ts' && right.t === 'ts') common = timestamp(left.unit === 'ns' || right.unit === 'ns' ? 'ns' : 'us');
    else if (isSpan(left) && isSpan(right)) common = INTERVAL;
    else if (isDate(left) && isDate(right) && left.t !== right.t) common = DATE64;
    else if ((left.t === 'ts' && isDate(right)) || (isDate(left) && right.t === 'ts')) common = timestamp('ns');
    if (common !== undefined) return checked([common, common], 'temporal', [common, common]);

    // Decimals of two widths meet in the wide one. An integer next to a decimal has 20 digits.
    let decimals: [Type, Type] | undefined;
    if (left.t === 'dec' && right.t === 'dec') {
        if (left.w === right.w) decimals = [left, right];
        else {
            const scale = Math.max(left.s, right.s);
            const precision = Math.max(left.p - left.s, right.p - right.s) + scale;
            const wide = decimal(256, precision, scale);
            if (precision <= MAX_DECIMAL_DIGITS[256]) decimals = [wide, wide];
        }
    } else if (left.t === 'dec' && isInteger(right)) decimals = [left, decimal(left.w, 20, 0)];
    else if (isInteger(left) && right.t === 'dec') decimals = [decimal(right.w, 20, 0), right];
    if (decimals !== undefined) return checked(decimals, 'decimal', [left, right]);

    // A float next to any number makes both floats. A signed and an unsigned integer both become
    // Decimal128(20, 0).
    if (isNumeric(left) && isNumeric(right)) {
        if (left.t === 'f64' || right.t === 'f64') return { left: FLOAT64, right: FLOAT64, result: FLOAT64 };
        if (isInteger(left) && isInteger(right)) {
            return checked([decimal(128, 20, 0), decimal(128, 20, 0)], 'decimal', [left, right]);
        }
    }
    throw planError('Cannot coerce arithmetic expression ' + typeName(left) + ' ' + symbol + ' ' + typeName(right)
        + ' to valid types');
}
