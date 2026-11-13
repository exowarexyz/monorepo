/**
 * The lowercase form of text as the service computes it for lower.
 *
 * The mapping comes from the tables of lowercase-tables.ts, so every JavaScript engine gives the
 * same lowercase form whatever Unicode data it has.
 */

import { CASE_IGNORABLE, CASED, LOWERCASE_EXPANSIONS, LOWERCASE_RUNS } from './lowercase-tables.js';

/** The capital sigma. Its lowercase form depends on the scalar values around it. */
const CAPITAL_SIGMA = 0x3a3;

// The two lowercase forms of the capital sigma.
const SMALL_SIGMA = '\u03c3';
const FINAL_SIGMA = '\u03c2';

/** The map of lowercaseForms, built on first use. */
let forms: Map<number, string> | undefined;

/** The lowercase form of every scalar value that lowering changes, read from the tables once. */
function lowercaseForms(): Map<number, string> {
    if (forms !== undefined) return forms;
    forms = new Map();
    for (let i = 0; i < LOWERCASE_RUNS.length; i += 4) {
        const [first, last, step, distance] = LOWERCASE_RUNS.slice(i, i + 4);
        for (let scalar = first; scalar <= last; scalar += step) forms.set(scalar, String.fromCodePoint(scalar + distance));
    }
    for (let i = 0; i < LOWERCASE_EXPANSIONS.length; i += 3) {
        forms.set(LOWERCASE_EXPANSIONS[i], String.fromCodePoint(LOWERCASE_EXPANSIONS[i + 1], LOWERCASE_EXPANSIONS[i + 2]));
    }
    return forms;
}

/**
 * Whether a scalar value lies in one of the ranges. The ranges are sorted pairs of a first and a
 * last value.
 */
function inRanges(ranges: readonly number[], scalar: number): boolean {
    let low = 0;
    let high = ranges.length / 2;
    while (low < high) {
        const middle = (low + high) >> 1;
        if (scalar > ranges[2 * middle + 1]) low = middle + 1;
        else high = middle;
    }
    return low < ranges.length / 2 && scalar >= ranges[2 * low];
}

/**
 * Whether the nearest scalar value that is not case ignorable, walking from index `at` in the
 * given direction, is a cased letter. Reaching the end of the text counts as no cased letter.
 */
function casedNeighbor(text: string, at: number, direction: 1 | -1): boolean {
    for (let i = at; i >= 0 && i < text.length; ) {
        // A scalar value above the basic plane is two units. Walking back meets its second one.
        const pair = direction < 0 && i > 0 && (text.charCodeAt(i) & 0xfc00) === 0xdc00;
        const scalar = text.codePointAt(pair ? i - 1 : i) as number;
        if (!inRanges(CASE_IGNORABLE, scalar)) return inRanges(CASED, scalar);
        i += direction * (scalar > 0xffff ? 2 : 1);
    }
    return false;
}

/**
 * The lowercase form of the whole text. Every scalar value takes its form from the tables, and a
 * form can be two scalar values. A capital sigma becomes the final sigma when a cased letter
 * stands before it and none stands after it, with case ignorable scalar values in between
 * skipped. Otherwise it becomes the small sigma. The text must hold no lone surrogate.
 */
export function toLowercase(text: string): string {
    const lowercase = lowercaseForms();
    const parts: string[] = [];

    // `parts` holds the output for the units before `unchanged`. The units from `unchanged` up
    // to `i` are unchanged so far and are copied from the text when a change or the end comes.
    let unchanged = 0;
    for (let i = 0; i < text.length; ) {
        const scalar = text.codePointAt(i) as number;
        const units = scalar > 0xffff ? 2 : 1;
        const lower = scalar !== CAPITAL_SIGMA ? lowercase.get(scalar)
            : casedNeighbor(text, i - 1, -1) && !casedNeighbor(text, i + 1, 1) ? FINAL_SIGMA : SMALL_SIGMA;
        if (lower !== undefined) {
            parts.push(text.slice(unchanged, i), lower);
            unchanged = i + units;
        }
        i += units;
    }
    if (unchanged === 0) return text;
    parts.push(text.slice(unchanged));
    return parts.join('');
}
