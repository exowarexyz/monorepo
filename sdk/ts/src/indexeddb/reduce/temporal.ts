import {
    arrowError,
    executionError,
    I64_MAX,
    I64_MIN,
    internalError,
    typeName,
    type Datum,
    type Op,
    type Type,
    type Unit,
    type Value,
} from './types.js';

const DAY_MILLIS = 86_400_000n;
const DAY_MICROS = 86_400_000_000n;
const DAY_NANOS = 86_400_000_000_000n;

// The days since the Unix epoch of -262143-01-01 and +262142-12-31, the range of date arithmetic.
const MIN_DAY = -96_465_292n;
const MAX_DAY = 95_026_236n;

const fitsI64 = (value: bigint): boolean => value >= I64_MIN && value <= I64_MAX;

const floorDiv = (a: bigint, b: bigint): bigint => {
    const quotient = a / b;
    return a % b !== 0n && (a < 0n) !== (b < 0n) ? quotient - 1n : quotient;
};

/** Adds or subtracts two signed 64 bit counts and fails when the result does not fit 64 bits. */
export function checkedCounts(op: Op): (l: bigint, r: bigint) => bigint {
    const symbol = op === 'add' ? ' + ' : ' - ';
    return (l, r) => {
        const result = op === 'add' ? l + r : l - r;
        if (!fitsI64(result)) throw arrowError('Arithmetic overflow: Overflow happened on: ' + l + symbol + r);
        return result;
    };
}

/**
 * Whole days between two Date64 values. The subtraction wraps and the quotient truncates toward
 * zero.
 */
export const date64Difference = (l: bigint, r: bigint): bigint => BigInt.asIntN(64, l - r) / DAY_MILLIS;

/**
 * A date plus or minus an interval of nanoseconds. A Date64 is first truncated toward zero to whole
 * days, and the interval counts only its whole days, also truncated toward zero. The request fails
 * when the date or the result lies outside the supported range of days.
 */
export function dateWithInterval(op: Op, isDate64: boolean): (date: bigint, nanos: bigint) => bigint {
    const symbol = op === 'add' ? '+' : '-';
    return (date, nanos) => {
        const fail = () => arrowError('Compute error: Date arithmetic overflow: ' + date + ' ' + symbol
            + ' IntervalMonthDayNano { months: 0, days: 0, nanoseconds: ' + nanos + ' }');
        if (isDate64 && date === I64_MIN) throw fail();
        const day = isDate64 ? date / DAY_MILLIS : date;
        if (day < MIN_DAY || day > MAX_DAY) throw fail();
        const delta = nanos / DAY_NANOS;
        const result = op === 'add' ? day + delta : day - delta;
        if (result < MIN_DAY || result > MAX_DAY) throw fail();
        return isDate64 ? result * DAY_MILLIS : result;
    };
}

/**
 * An integer number of days as an interval of nanoseconds. The seconds wrap at 64 bits and the
 * nanoseconds must fit 64 bits.
 */
export function daysToInterval(days: bigint): bigint {
    const seconds = BigInt.asIntN(64, days * 86_400n);
    const nanos = seconds * 1_000_000_000n;
    if (!fitsI64(nanos)) {
        throw arrowError('Compute error: Cannot cast to Interval(MonthDayNano). Overflowing on ' + seconds);
    }
    return nanos;
}

/** The days of an unsigned integer. A value above the signed range fails the request. */
export function unsignedDays(value: bigint): bigint {
    if (value > I64_MAX) throw arrowError("Cast error: Can't cast value " + value + ' to type Int64');
    return value;
}

const mapDatum = (datum: Datum, f: (value: bigint) => bigint): Datum => (datum.scalar
    ? { scalar: true, value: datum.value === null ? null : f(datum.value as bigint) }
    : { scalar: false, values: datum.values.map((value) => (value === null ? null : f(value as bigint))) });

/**
 * Converts dates or microsecond timestamps to nanosecond timestamps. The conversion fails when a
 * value leaves 64 bits. Over a column the smallest value is checked first and then the largest,
 * so the error names an extreme value.
 */
export function toNanoTimestamps(datum: Datum, from: Type): Datum {
    const factor = from.t === 'date32' ? DAY_NANOS : from.t === 'date64' ? 1_000_000n : 1_000n;
    const check = (value: bigint) => {
        if (!fitsI64(value * factor)) {
            throw executionError('Cannot cast ' + typeName(from) + ' value ' + value
                + ' to Timestamp(ns): converted value exceeds the representable i64 range');
        }
    };
    if (datum.scalar) {
        if (datum.value !== null) check(datum.value as bigint);
    } else {
        let min: bigint | undefined;
        let max: bigint | undefined;
        for (const value of datum.values as readonly (bigint | null)[]) {
            if (value === null) continue;
            if (min === undefined || value < min) min = value;
            if (max === undefined || value > max) max = value;
        }
        if (min !== undefined && max !== undefined) {
            check(min);
            check(max);
        }
    }
    return mapDatum(datum, (value) => value * factor);
}

/**
 * date_trunc_day of timestamps in the given unit: the start of the UTC day, rounding toward
 * negative infinity. A scalar is truncated in nanoseconds and fails when the value or the start of
 * its day does not fit a nanosecond timestamp. A column value whose day starts below the smallest
 * timestamp fails the request with INTERNAL.
 */
export function truncateToDay(datum: Datum, unit: Unit): Datum {
    const day = unit === 'us' ? DAY_MICROS : DAY_NANOS;
    if (!datum.scalar) {
        return mapDatum(datum, (value) => {
            const start = floorDiv(value, day) * day;
            if (start < I64_MIN) throw internalError('native Reduce execution panicked');
            return start;
        });
    }
    if (datum.value === null) return datum;
    const value = datum.value as bigint;
    const perUnit = unit === 'us' ? 1_000n : 1n;
    const nanos = value * perUnit;
    if (!fitsI64(nanos)) throw executionError('Timestamp ' + value + ' out of range');
    const start = floorDiv(nanos, DAY_NANOS) * DAY_NANOS;
    if (!fitsI64(start)) throw executionError('Timestamp ' + nanos + ' out of range after truncating to day');
    return { scalar: true, value: (start / perUnit) as Value };
}
