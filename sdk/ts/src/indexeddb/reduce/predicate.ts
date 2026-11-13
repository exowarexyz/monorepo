import { KvFieldKind, type KvPredicate, type KvPredicateConstraint } from '../../gen/ts/store/v1/query_pb.js';
import { convertField, extractField, readBigEndian, readLittleEndian, type Stored } from './codec.js';
import { toBits, totalOrderKey } from './float.js';
import { invalidParams, type Field, type Value } from './types.js';

interface FloatBound {
    /** The totalOrderKey of the bound. */
    readonly key: bigint;
    readonly inclusive: boolean;
}

type Constraint =
    | { readonly c: 'isNull' | 'isNotNull' }
    | { readonly c: 'equals'; readonly kind: KvFieldKind; readonly value: string | boolean | Uint8Array }
    | {
        readonly c: 'range';
        readonly kinds: readonly KvFieldKind[];
        readonly min: bigint | undefined;
        readonly max: bigint | undefined;
    }
    | { readonly c: 'floatRange'; readonly min: FloatBound | undefined; readonly max: FloatBound | undefined }
    | { readonly c: 'in'; readonly kind: KvFieldKind; readonly values: ReadonlySet<string | bigint> }
    | { readonly c: 'binaryIn'; readonly values: readonly Uint8Array[] };

interface Check {
    readonly field: Field;
    readonly constraint: Constraint;
}

/** A conjunction of checks over fields of one row. */
export interface Predicate {
    readonly checks: readonly Check[];
    readonly contradiction: boolean;
}

const SIGNED_RANGE_KINDS = [KvFieldKind.INT64, KvFieldKind.DATE32, KvFieldKind.DATE64, KvFieldKind.TIMESTAMP];

/**
 * Converts a decimal bound of a range. It must be exactly the word size, big endian for Decimal128
 * and little endian for Decimal256.
 */
function decimalBound(bytes: Uint8Array | undefined, bits: 128 | 256, which: string): bigint | undefined {
    if (bytes === undefined) return undefined;
    if (bytes.length !== bits / 8) {
        throw invalidParams('decimal' + bits + ' ' + which + ' must be exactly ' + bits / 8 + ' bytes');
    }
    return BigInt.asIntN(bits, bits === 128 ? readBigEndian(bytes) : readLittleEndian(bytes));
}

function convertConstraint(message: KvPredicateConstraint): Constraint {
    const c = message.constraint;
    switch (c.case) {
        // is_null and is_not_null apply whenever they are set, whatever bool they carry.
        case 'isNull': return { c: 'isNull' };
        case 'isNotNull': return { c: 'isNotNull' };
        case 'stringEq': return { c: 'equals', kind: KvFieldKind.UTF8, value: c.value };
        case 'boolEq': return { c: 'equals', kind: KvFieldKind.BOOLEAN, value: c.value };
        case 'fixedSizeBinaryEq': return { c: 'equals', kind: KvFieldKind.FIXED_SIZE_BINARY, value: c.value };
        case 'intRange': return { c: 'range', kinds: SIGNED_RANGE_KINDS, min: c.value.min, max: c.value.max };
        case 'uint64Range': return { c: 'range', kinds: [KvFieldKind.UINT64], min: c.value.min, max: c.value.max };
        case 'floatRange': {
            const bound = (b: { value: number; inclusive: boolean } | undefined): FloatBound | undefined =>
                (b === undefined ? undefined : { key: totalOrderKey(toBits(b.value)), inclusive: b.inclusive });
            return { c: 'floatRange', min: bound(c.value.min), max: bound(c.value.max) };
        }
        case 'decimal128Range': {
            const min = decimalBound(c.value.min, 128, 'min');
            return { c: 'range', kinds: [KvFieldKind.DECIMAL128], min, max: decimalBound(c.value.max, 128, 'max') };
        }
        case 'decimal256Range': {
            const min = decimalBound(c.value.min, 256, 'min');
            return { c: 'range', kinds: [KvFieldKind.DECIMAL256], min, max: decimalBound(c.value.max, 256, 'max') };
        }
        case 'stringIn': return { c: 'in', kind: KvFieldKind.UTF8, values: new Set(c.value.values) };
        case 'intIn': return { c: 'in', kind: KvFieldKind.INT64, values: new Set(c.value.values) };
        case 'uint64In': return { c: 'in', kind: KvFieldKind.UINT64, values: new Set(c.value.values) };
        case 'fixedSizeBinaryIn': return { c: 'binaryIn', values: c.value.values };
        default: throw invalidParams('missing predicate constraint');
    }
}

/**
 * Converts a predicate of a request. Checks are converted in order, the field of a check before its
 * constraint. A predicate marked as a contradiction is still converted and validated.
 */
export function convertPredicate(message: KvPredicate): Predicate {
    const checks = message.checks.map((check): Check => {
        if (check.field === undefined) throw invalidParams('missing predicate field');
        const field = convertField(check.field);
        if (check.constraint === undefined) throw invalidParams('missing predicate constraint');
        return { field, constraint: convertConstraint(check.constraint) };
    });
    return { checks, contradiction: message.contradiction };
}

/** Whether evaluating the predicate reads the stored row. */
export function predicateNeedsValue(predicate: Predicate): boolean {
    return predicate.checks.some((check) => check.field.src === 'value');
}

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((byte, i) => byte === b[i]);

/**
 * Whether a field value satisfies a constraint. NULL satisfies only is_null. A constraint over a
 * kind other than the field's is false and does not fail the request.
 */
function matches(value: Value | null, kind: KvFieldKind, constraint: Constraint): boolean {
    if (constraint.c === 'isNull') return value === null;
    if (constraint.c === 'isNotNull') return value !== null;
    if (value === null) return false;
    switch (constraint.c) {
        case 'equals':
            if (kind !== constraint.kind) return false;
            return kind === KvFieldKind.FIXED_SIZE_BINARY
                ? sameBytes(value as Uint8Array, constraint.value as Uint8Array)
                : value === constraint.value;
        case 'range':
            return constraint.kinds.includes(kind)
                && (constraint.min === undefined || (value as bigint) >= constraint.min)
                && (constraint.max === undefined || (value as bigint) <= constraint.max);
        case 'floatRange': {
            if (kind !== KvFieldKind.FLOAT64) return false;
            const key = totalOrderKey(value as bigint);
            const { min, max } = constraint;
            return (min === undefined || key > min.key || (min.inclusive && key === min.key))
                && (max === undefined || key < max.key || (max.inclusive && key === max.key));
        }
        case 'in':
            return kind === constraint.kind && constraint.values.has(value as string | bigint);
        case 'binaryIn':
            return kind === KvFieldKind.FIXED_SIZE_BINARY
                && constraint.values.some((bytes) => sameBytes(value as Uint8Array, bytes));
    }
}

/**
 * Evaluates a predicate on one row. A contradiction is false without reading a field. Checks run
 * in order and the first false check ends the evaluation, so a later check cannot fail the
 * request through its field.
 */
export function evalPredicate(key: Uint8Array, row: readonly (Stored | null)[] | null, predicate: Predicate): boolean {
    if (predicate.contradiction) return false;
    for (const check of predicate.checks) {
        const value = extractField(key, row, check.field);
        if (!matches(value, check.field.kind, check.constraint)) return false;
    }
    return true;
}
