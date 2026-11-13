/**
 * Compiled key selectors, shared by Subscribe and Prune, and the value filters of Subscribe.
 * Patterns compile with the store's own regex engine, which accepts a subset of the Rust regex
 * syntax and matches in linear time.
 */

import { Code, ConnectError } from '@connectrpc/connect';
import type { Filter } from '../gen/ts/common/v1/kv_pb.js';
import { MAX_KEY_LEN } from '../limits.js';
import { invalidArgument, quoted } from './errors.js';
import { exactBuffer } from './idb.js';
import { MAX_INSTRUCTIONS, Regex, RegexSyntaxError } from './regex.js';

/**
 * Time in milliseconds after which matching yields to the event loop. The clock is read between
 * pieces of work, so a slice runs over by at most one piece.
 */
const SLICE_MS = 8;

/** Machine steps of a sliced search between two looks at the clock. */
const SEARCH_STEPS = 1 << 16;

/** Bytes of a long value filter that are compared between two looks at the clock. */
const COMPARE_BYTES = SEARCH_STEPS;

/**
 * Longest input matched in one call. One search costs up to the input length times the size of
 * the compiled pattern, so this is the longest input that the largest pattern matches within
 * `SEARCH_STEPS`. A longer input is searched in slices.
 */
const DIRECT_MATCH_BYTES = SEARCH_STEPS / MAX_INSTRUCTIONS;

// The characters that the Rust server trims before it decides that a pattern is empty.
const BLANK = /^[\t-\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*$/;

/**
 * Whether a pattern is empty or only white space. The payload regex of a selector and the regex of
 * a value filter must be neither.
 */
export function isBlankPattern(pattern: string): boolean {
    return BLANK.test(pattern);
}

/**
 * Compiles a pattern from a request. A pattern that is valid for the Rust server and outside the
 * supported subset is UNIMPLEMENTED. A pattern that is not valid is INVALID_ARGUMENT with the
 * message that `invalid` builds from the engine's reason.
 */
function compilePattern(pattern: string, field: string, invalid: (reason: string) => string): Regex {
    try {
        return Regex.compile(pattern);
    } catch (error) {
        if (!(error instanceof RegexSyntaxError)) throw error;
        if (error.unsupported) {
            throw new ConnectError(
                `${field} uses regex syntax that this store does not support: ${error.message}`,
                Code.Unimplemented,
            );
        }
        throw invalidArgument(invalid(error.message));
    }
}

/**
 * Rejects a selector prefix longer than a key. `message` turns the reason into the error message.
 */
export function checkSelectorPrefix(prefix: Uint8Array, message: (reason: string) => string): void {
    if (prefix.byteLength > MAX_KEY_LEN) {
        throw invalidArgument(message(`prefix length ${prefix.byteLength} exceeds max ${MAX_KEY_LEN}`));
    }
}

/** Compiles the payload regex of a selector. An empty or blank regex is INVALID_ARGUMENT. */
export function compilePayloadRegex(pattern: string): Regex {
    if (isBlankPattern(pattern)) throw invalidArgument('selector payload_regex must not be empty');
    return compilePattern(
        pattern,
        'selector payload_regex',
        () => `invalid selector payload_regex ${quoted(pattern)}`,
    );
}

function startsWith(bytes: Uint8Array, prefix: Uint8Array): boolean {
    if (bytes.byteLength < prefix.byteLength) return false;
    for (let i = 0; i < prefix.byteLength; i++) {
        if (bytes[i] !== prefix[i]) return false;
    }
    return true;
}

/**
 * Whether `bytes` starts with `prefix`. A prefix of at most `COMPARE_BYTES` is compared at once and
 * answers without a promise. A longer one is compared in pieces of that length, with the pacer
 * asked before each piece.
 */
function startsWithPaced(bytes: Uint8Array, prefix: Uint8Array, pacer: Pacer): boolean | Promise<boolean> {
    if (bytes.byteLength < prefix.byteLength) return false;
    if (prefix.byteLength <= COMPARE_BYTES) return startsWith(bytes, prefix);
    return (async () => {
        for (let start = 0; start < prefix.byteLength; start += COMPARE_BYTES) {
            if (pacer.due()) await pacer.turn();
            const end = Math.min(start + COMPARE_BYTES, prefix.byteLength);
            if (!startsWith(bytes.subarray(start, end), prefix.subarray(start, end))) return false;
        }
        return true;
    })();
}

/**
 * A selector that accepts a key when the key starts with the prefix and the regex matches the
 * rest.
 */
export class KeySelector {
    readonly prefix: Uint8Array;
    readonly regex: Regex;

    constructor(selector: { prefix: Uint8Array; payloadRegex: string }) {
        this.prefix = new Uint8Array(exactBuffer(selector.prefix));
        this.regex = compilePayloadRegex(selector.payloadRegex);
    }

    /** The bytes of `key` after the prefix, undefined when the key is outside the prefix. */
    payload(key: Uint8Array): Uint8Array | undefined {
        return startsWith(key, this.prefix) ? key.subarray(this.prefix.byteLength) : undefined;
    }

    matches(key: Uint8Array): boolean {
        const payload = this.payload(key);
        return payload !== undefined && this.regex.isMatch(payload);
    }
}

/**
 * Bounds how long a computation holds the event loop. The computation asks `due` between small
 * pieces of work and awaits `turn` when its slice is used up. `check` runs after every turn and
 * throws when the computation must stop, such as when its call was canceled.
 */
export class Pacer {
    private sliceStart = performance.now();

    constructor(private readonly check: () => void) {}

    /** Whether the current slice is used up. */
    due(): boolean {
        return performance.now() - this.sliceStart >= SLICE_MS;
    }

    /** Lets other tasks run, then runs `check`. */
    async turn(): Promise<void> {
        await new Promise<void>((resolve) => setTimeout(resolve, 0));
        this.check();
        this.sliceStart = performance.now();
    }
}

/** The value filters of a subscription. A value passes when any one filter accepts it. */
export class ValueFilters {
    private readonly exacts: Uint8Array[] = [];
    private readonly prefixes: Uint8Array[] = [];
    private readonly regexes: Regex[] = [];

    /**
     * Compiles the filters. The caller has checked that each filter has a kind and that each regex
     * is not blank.
     */
    constructor(filters: readonly Filter[]) {
        for (const { kind } of filters) {
            if (kind.case === 'exact') {
                this.exacts.push(new Uint8Array(exactBuffer(kind.value)));
            } else if (kind.case === 'prefix') {
                this.prefixes.push(new Uint8Array(exactBuffer(kind.value)));
            } else if (kind.case === 'regex') {
                const pattern = kind.value;
                this.regexes.push(compilePattern(
                    pattern,
                    'value_filter regex',
                    (reason) => 'invalid value_filter: invalid regex `' + pattern + '`: ' + reason,
                ));
            }
        }
    }

    /**
     * Whether some filter accepts the value. The pacer is asked before every filter and inside
     * the work of a long one, so neither many filters nor one large filter hold the event loop.
     */
    async matches(value: Uint8Array, pacer: Pacer): Promise<boolean> {
        for (const exact of this.exacts) {
            if (pacer.due()) await pacer.turn();
            if (value.byteLength !== exact.byteLength) continue;
            const equal = startsWithPaced(value, exact, pacer);
            if (typeof equal === 'boolean' ? equal : await equal) return true;
        }
        for (const prefix of this.prefixes) {
            if (pacer.due()) await pacer.turn();
            const starts = startsWithPaced(value, prefix, pacer);
            if (typeof starts === 'boolean' ? starts : await starts) return true;
        }
        for (const regex of this.regexes) {
            if (pacer.due()) await pacer.turn();
            if (value.byteLength <= DIRECT_MATCH_BYTES) {
                if (regex.isMatch(value)) return true;
                continue;
            }
            const search = regex.search(value);
            let found = search.step(SEARCH_STEPS);
            while (found === undefined) {
                if (pacer.due()) await pacer.turn();
                found = search.step(SEARCH_STEPS);
            }
            if (found) return true;
        }
        return false;
    }
}
