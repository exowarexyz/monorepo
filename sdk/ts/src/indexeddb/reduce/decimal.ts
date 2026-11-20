import { arrowError, type DecimalType, type Op } from './types.js';
import { toBits } from './float.js';

export const pow10 = (exponent: number): bigint => 10n ** BigInt(exponent);

/** Whether a value fits a two's complement word of the given width. */
const fitsWord = (value: bigint, bits: number): boolean => BigInt.asIntN(bits, value) === value;

const overflow = (left: bigint, symbol: string, right: bigint) =>
    arrowError('Arithmetic overflow: Overflow happened on: ' + left + ' ' + symbol + ' ' + right);

/**
 * Arithmetic over the raw words of two decimals of one width and the given scales. Each step fails
 * when its result overflows the word, and no step checks the decimal precision. Division scales the
 * dividend so that the quotient has the result scale, and truncates toward zero.
 */
export function decimalKernel(
    op: Op,
    left: DecimalType,
    right: DecimalType,
    result: DecimalType,
): (l: bigint, r: bigint) => bigint {
    const bits = left.w;
    const multiply = (a: bigint, b: bigint): bigint => {
        const product = a * b;
        if (!fitsWord(product, bits)) throw overflow(a, '*', b);
        return product;
    };
    if (op === 'mul') return multiply;
    if (op === 'div') {
        const scaleUp = pow10(result.s - left.s + right.s);
        const wordMin = -(1n << BigInt(bits - 1));
        return (l, r) => {
            const dividend = multiply(l, scaleUp);
            if (r === 0n) throw arrowError('Divide by zero error');
            if (dividend === wordMin && r === -1n) throw overflow(dividend, '/', r);
            return dividend / r;
        };
    }
    const symbol = op === 'add' ? '+' : '-';
    const combine = (a: bigint, b: bigint): bigint => {
        const sum = op === 'add' ? a + b : a - b;
        if (!fitsWord(sum, bits)) throw overflow(a, symbol, b);
        return sum;
    };
    if (left.s === right.s) return combine;
    const leftUp = pow10(result.s - left.s);
    const rightUp = pow10(result.s - right.s);
    return (l, r) => {
        const a = multiply(l, leftUp);
        return combine(a, multiply(r, rightUp));
    };
}

/**
 * The Float64 of a 256 bit integer as the service computes it. The value is shifted to keep one
 * sign bit, and its top 64 bits are converted and scaled by a power of two. The bits below them are
 * dropped without rounding.
 */
function wideToFloat(value: bigint): number {
    if (value === -(1n << 255n)) return -(2 ** 255);
    if (value === 0n || value === 1n) return Number(value);
    const magnitude = value < 0n ? ~value : value;
    const redundantSignBits = 255 - (magnitude === 0n ? 0 : magnitude.toString(2).length);
    return Number((value << BigInt(redundantSignBits)) >> 192n) * 2 ** (192 - redundantSignBits);
}

/** Ten to a power by repeated squaring, with one rounding per multiplication. */
function powi10(exponent: number): number {
    let base = 10;
    let result = 1;
    let n = exponent;
    for (;;) {
        if (n % 2 !== 0) result *= base;
        n = Math.floor(n / 2);
        if (n === 0) return result;
        base *= base;
    }
}

/** cast_float64 of a decimal: the word as a Float64 divided by the power of ten of its scale. */
export function decimalToFloat(type: DecimalType): (word: bigint) => bigint {
    const divisor = powi10(type.s);
    return type.w === 128 ? (word) => toBits(Number(word) / divisor) : (word) => toBits(wideToFloat(word) / divisor);
}
