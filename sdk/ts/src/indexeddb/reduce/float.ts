/**
 * Float64 arithmetic on 64 bit patterns.
 *
 * A Float64 is held as its bits, so a NaN keeps its sign and payload from the stored row or key
 * it was read from to the result. A literal, a bound of a range and a result cross the wire as
 * JavaScript numbers, where a NaN keeps its bits only if the engine keeps them.
 *
 * Arithmetic passes on a NaN operand with its sign and payload and with the quiet bit set. Two
 * results have no sign and payload that the service defines: the NaN of an invalid operation such
 * as 0/0, and the NaN of an operation on two NaNs. This module gives the first as QUIET_NAN and the
 * second as its left operand with the quiet bit set, and counts both.
 */

const view = new DataView(new ArrayBuffer(8));

export function toBits(value: number): bigint {
    view.setFloat64(0, value);
    return view.getBigUint64(0);
}

export function fromBits(bits: bigint): number {
    view.setBigUint64(0, bits);
    return view.getFloat64(0);
}

const SIGN = 1n << 63n;
const EXPONENT = 0x7ff0000000000000n;
const MANTISSA = 0x000fffffffffffffn;

const QUIET = 0x0008000000000000n;
const QUIET_NAN = 0x7ff8000000000000n;
const NEGATIVE_QUIET_NAN = 0xfff8000000000000n;
export const NEGATIVE_ZERO = SIGN;

// The largest and the smallest finite value.
export const F64_MAX = 0x7fefffffffffffffn;
export const F64_MIN = 0xffefffffffffffffn;

export const isNaNBits = (bits: bigint): boolean => (bits & EXPONENT) === EXPONENT && (bits & MANTISSA) !== 0n;

let unspecified = 0;

/**
 * The number of NaNs that arithmetic has produced so far without a sign and payload that the
 * service defines. A caller reads it before and after an evaluation to learn whether the evaluation
 * produced one.
 */
export const unspecifiedNaNs = (): number => unspecified;

function arithmetic(a: bigint, b: bigint, f: (x: number, y: number) => number): bigint {
    const [aIsNaN, bIsNaN] = [isNaNBits(a), isNaNBits(b)];
    if (aIsNaN || bIsNaN) {
        if (aIsNaN && bIsNaN) unspecified++;
        return (aIsNaN ? a : b) | QUIET;
    }
    const result = f(fromBits(a), fromBits(b));
    if (!Number.isNaN(result)) return toBits(result);
    unspecified++;
    return QUIET_NAN;
}

export const add = (a: bigint, b: bigint): bigint => arithmetic(a, b, (x, y) => x + y);
export const sub = (a: bigint, b: bigint): bigint => arithmetic(a, b, (x, y) => x - y);
export const mul = (a: bigint, b: bigint): bigint => arithmetic(a, b, (x, y) => x * y);
export const div = (a: bigint, b: bigint): bigint => arithmetic(a, b, (x, y) => x / y);

/**
 * A key whose unsigned order is the IEEE 754 total order of the values: negative NaNs, negative
 * infinity, negative numbers, -0, +0, positive numbers, positive infinity, positive NaNs.
 */
export const totalOrderKey = (bits: bigint): bigint => ((bits & SIGN) !== 0n ? BigInt.asUintN(64, ~bits) : bits | SIGN);

// The lane counts of the sum over one input batch of a request without group_by. The service adds
// the values of a batch in interleaved lanes, and in fewer lanes when the batch holds a NULL.
// Float64 addition is not associative, so the lane counts are part of the result of a SUM.
const LANES = 4;
const LANES_WITH_NULLS = 2;

/**
 * The sum of the non-NULL values of one batch, or null when there is none. Value j goes to lane j
 * modulo the lane count. The lanes are then folded in halves until one is left, and a fold of w
 * lanes adds lane i + w/2 into lane i.
 */
export function sumBatch(values: readonly (bigint | null)[]): bigint | null {
    let valid = 0;
    for (const value of values) if (value !== null) valid++;
    if (valid === 0) return null;
    const lanes = valid === values.length ? LANES : LANES_WITH_NULLS;
    const sums = new Array<bigint>(lanes).fill(0n);
    for (let j = 0; j < values.length; j++) {
        const value = values[j];
        if (value !== null) sums[j % lanes] = add(sums[j % lanes], value);
    }
    for (let width = lanes; width >= 2; width >>= 1) {
        for (let i = 0; i < width >> 1; i++) sums[i] = add(sums[i], sums[i + (width >> 1)]);
    }
    return sums[0];
}

const isWhitespace = (code: number): boolean => code === 9 || code === 10 || code === 12 || code === 13 || code === 32;

const DECIMAL_NUMBER = /^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?/;

function parseExact(text: string): bigint | undefined {
    switch (text.toLowerCase()) {
        case 'nan': case '+nan': return QUIET_NAN;
        case '-nan': return NEGATIVE_QUIET_NAN;
        case 'inf': case '+inf': case 'infinity': case '+infinity': return toBits(Infinity);
        case '-inf': case '-infinity': return toBits(-Infinity);
    }
    const match = DECIMAL_NUMBER.exec(text);
    return match !== null && match[0].length === text.length ? toBits(Number(text)) : undefined;
}

/**
 * Parses the text of a number as cast_float64 does: an optional sign followed by decimal digits
 * with an optional fraction and exponent, or by nan, inf or infinity in any letter case. The text
 * is tried as it is and then without leading and trailing tab, line feed, form feed, carriage
 * return and space. Returns undefined when neither parses.
 */
export function parseFloat64(text: string): bigint | undefined {
    const exact = parseExact(text);
    if (exact !== undefined) return exact;
    let begin = 0;
    let end = text.length;
    while (begin < end && isWhitespace(text.charCodeAt(begin))) begin++;
    while (end > begin && isWhitespace(text.charCodeAt(end - 1))) end--;
    return parseExact(text.slice(begin, end));
}
