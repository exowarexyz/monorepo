import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
    MAX_GROUP_DEPTH,
    MAX_INSTRUCTIONS,
    MAX_PATTERN_CHARS,
    MAX_REPEAT_COUNT,
    RUST_NEST_LIMIT,
    Regex,
    RegexSyntaxError,
} from '../src/indexeddb/regex';

type Status = 'OK' | 'UNSUPPORTED' | 'ERR';

interface FixtureCase {
    pattern: string;
    status: Status;
    /**
     * What this engine answers. It equals the status except for an ERR UNSUPPORTED row, a pattern
     * that the Rust crate rejects and this engine reports as unsupported.
     */
    outcome: Status;
    /** Names of all groups, group 0 first, empty for unnamed groups. */
    names: string[];
    /** One result per input, as written by the fixture. */
    results: string[];
}

/** OK patterns that no input can match. */
const UNSATISFIABLE = new Set(['$a', 'a^']);

const unhex = (hex: string): Uint8Array => Uint8Array.from(hex.match(/../g) ?? [], (byte) => parseInt(byte, 16));
const bytes = (text: string): Uint8Array => new TextEncoder().encode(text);

/** Reads the fixture. Its header describes the records. */
function loadFixture(): { inputs: Uint8Array[]; cases: FixtureCase[] } {
    const text = readFileSync(join(__dirname, 'fixtures', 'selector-regex.txt'), 'utf8');
    const records = text
        .split('\n')
        .filter((line) => line !== '' && !line.startsWith('#'))
        .map((line) => {
            const space = line.indexOf(' ');
            return space < 0 ? [line, ''] : [line.slice(0, space), line.slice(space + 1)];
        });
    const inputs: Uint8Array[] = [];
    const cases: FixtureCase[] = [];
    for (let i = 0; i < records.length; i++) {
        const [tag, payload] = records[i];
        if (tag === 'H') {
            inputs.push(unhex(payload));
            continue;
        }
        if (tag !== 'P') throw new Error('unexpected record ' + tag);
        const [status, names] = records[++i] as [Status, string];
        if (!['OK', 'UNSUPPORTED', 'ERR'].includes(status)) throw new Error('unexpected status ' + status);
        if (status === 'ERR' && names !== '' && names !== 'UNSUPPORTED') throw new Error('unexpected ERR ' + names);
        const pattern = new TextDecoder().decode(unhex(payload));
        let results: string[] = [];
        if (status === 'OK') {
            const [resultTag, line] = records[++i] ?? [];
            results = line?.split(' ') ?? [];
            if (resultTag !== 'R' || results.length !== inputs.length) {
                throw new Error(`pattern ${JSON.stringify(pattern)} must have an R record with ${inputs.length} results`);
            }
        }
        const outcome = status === 'ERR' && names === 'UNSUPPORTED' ? 'UNSUPPORTED' : status;
        cases.push({ pattern, status, outcome, names: names.split(','), results });
    }
    return { inputs, cases };
}

/** Describes a match in the fixture's result format. */
function describeMatch(regex: Regex, groups: number, input: Uint8Array): string {
    const captures = regex.captures(input);
    if (captures === null) return 'N';
    const spans = Array.from({ length: groups }, (_, index) => captures.span(index)?.join('-') ?? 'x');
    return 'M' + spans.join(',');
}

/**
 * Runs a search one call of step(budget) at a time and returns its result and the number of
 * calls.
 */
function searchInSlices(regex: Regex, input: Uint8Array, budget: number): { result: boolean; slices: number } {
    const search = regex.search(input);
    for (let slices = 1; ; slices++) {
        const result = search.step(budget);
        if (result !== undefined) return { result, slices };
    }
}

function syntaxError(pattern: string): RegexSyntaxError | undefined {
    try {
        Regex.compile(pattern);
        return undefined;
    } catch (error) {
        if (error instanceof RegexSyntaxError) return error;
        throw error;
    }
}

/** Expects the pattern to be refused as unsupported, or as invalid when unsupported is false. */
function expectRejected(pattern: string, unsupported: boolean): void {
    expect(syntaxError(pattern)?.unsupported).toBe(unsupported);
}

const nested = (depth: number): string => '(?:'.repeat(depth) + 'a' + ')'.repeat(depth);

/**
 * The distinct buffers of the typed arrays reachable from `root` through object properties, array
 * items and map entries.
 */
function buffersReachableFrom(root: unknown): Set<ArrayBufferLike> {
    const buffers = new Set<ArrayBufferLike>();
    const seen = new Set<object>();
    const stack: unknown[] = [root];
    while (stack.length > 0) {
        const value = stack.pop();
        if (typeof value !== 'object' || value === null || seen.has(value)) continue;
        seen.add(value);
        if (ArrayBuffer.isView(value)) {
            buffers.add(value.buffer);
        } else if (value instanceof Map) {
            stack.push(...value.keys(), ...value.values());
        } else {
            stack.push(...Object.values(value));
        }
    }
    return buffers;
}

describe('regex fixture recorded from the Rust regex crate', () => {
    const { inputs, cases } = loadFixture();
    const supported = cases.filter((c) => c.status === 'OK');
    const compiled = new Map(supported.map((c) => [c, Regex.compile(c.pattern)]));

    test('covers every status', () => {
        expect(inputs.length).toBeGreaterThan(50);
        for (const status of ['OK', 'UNSUPPORTED', 'ERR']) {
            expect(cases.filter((c) => c.status === status).length).toBeGreaterThan(40);
        }
    });

    test('every pattern that can match matches one of the inputs', () => {
        const silent = supported.filter((c) => !UNSATISFIABLE.has(c.pattern) && c.results.every((r) => r === 'N'));
        expect(silent.map((c) => c.pattern)).toEqual([]);
    });

    test('compiles exactly the supported patterns and rejects the others with their kind', () => {
        const wrong = cases.flatMap((c) => {
            const error = syntaxError(c.pattern);
            const outcome = error === undefined ? 'OK' : error.unsupported ? 'UNSUPPORTED' : 'ERR';
            return outcome === c.outcome ? [] : [{ pattern: c.pattern, expected: c.outcome, outcome }];
        });
        expect(wrong).toEqual([]);
    });

    test('reports the recorded group names', () => {
        const wrong = supported.flatMap((c) => {
            const regex = compiled.get(c)!;
            const named = c.names.filter((name) => name !== '');
            const ok = JSON.stringify(regex.groupNames) === JSON.stringify(named) && named.every((n) => regex.hasGroup(n));
            return ok ? [] : [{ pattern: c.pattern, expected: named, actual: regex.groupNames }];
        });
        expect(wrong).toEqual([]);
    });

    test('matches every input with the recorded result and capture spans', () => {
        const wrong = supported.flatMap((c) => {
            const regex = compiled.get(c)!;
            const named = c.names.filter((name) => name !== '');
            const capturer = regex.capturer(named);
            return inputs.flatMap((input, i) => {
                const actual = describeMatch(regex, c.names.length, input);
                const expected = c.results[i];
                const captures = regex.captures(input);
                const recorded = capturer.captures(input);
                const consistent =
                    regex.isMatch(input) === (expected !== 'N') &&
                    (recorded === null) === (captures === null) &&
                    (captures === null || captures.span(c.names.length) === undefined) &&
                    c.names.every((name, index) => {
                        if (name === '') return true;
                        const span = captures?.span(index);
                        const named = captures?.named(name);
                        const bytes = span === undefined ? undefined : input.subarray(...span).join();
                        return named?.join() === bytes && recorded?.named(name)?.join() === bytes;
                    });
                return actual === expected && consistent
                    ? []
                    : [{ pattern: c.pattern, input: Buffer.from(input).toString('hex'), expected, actual, consistent }];
            });
        });
        expect(wrong.slice(0, 20)).toEqual([]);
    });

    test('a search run in small slices finds the recorded result', () => {
        const wrong = supported.flatMap((c) => {
            const regex = compiled.get(c)!;
            return inputs.flatMap((input, i) =>
                searchInSlices(regex, input, 3).result === (c.results[i] !== 'N') ? [] : [{ pattern: c.pattern, i }],
            );
        });
        expect(wrong.slice(0, 20)).toEqual([]);
    });
});

describe('regex limits', () => {
    test('accept a pattern at the length limit and refuse a longer one as unsupported', () => {
        expect(() => Regex.compile('a'.repeat(MAX_PATTERN_CHARS))).not.toThrow();
        expectRejected('a'.repeat(MAX_PATTERN_CHARS + 1), true);
    });

    test('accept groups nested to the limit and refuse deeper nesting as unsupported', () => {
        expect(Regex.compile(nested(MAX_GROUP_DEPTH)).isMatch(bytes('a'))).toBe(true);
        expectRejected(nested(MAX_GROUP_DEPTH + 1), true);
    });

    test('accept a syntax tree as deep as the Rust crate does and refuse a deeper one as invalid', () => {
        const stacked = (count: number): string => 'a' + '+'.repeat(count);
        expect(Regex.compile(stacked(RUST_NEST_LIMIT)).isMatch(bytes('a'))).toBe(true);
        expectRejected(stacked(RUST_NEST_LIMIT + 1), false);
        expectRejected(nested(RUST_NEST_LIMIT), true);
        expectRejected(nested(RUST_NEST_LIMIT + 1), false);
    });

    test('accept the largest repetition count and refuse a larger one as unsupported', () => {
        expect(Regex.compile('^a{' + MAX_REPEAT_COUNT + '}$').isMatch(new Uint8Array(MAX_REPEAT_COUNT).fill(0x61))).toBe(true);
        for (const count of ['{N}', '{0,N}', '{N,}']) {
            expectRejected('a' + count.replace('N', String(MAX_REPEAT_COUNT + 1)), true);
        }
    });

    test('accept a program at the size limit and refuse a larger one as unsupported', () => {
        // A SAVE before the body and a SAVE and a MATCH after it make three instructions, and each
        // `.` that the repetitions below expand to is one more.
        const program = (body: number): string =>
            '(?s-u)' + '.{1000}'.repeat(Math.floor(body / 1000)) + '.{' + (body % 1000) + '}';
        expect(() => Regex.compile(program(MAX_INSTRUCTIONS - 3))).not.toThrow();
        expectRejected(program(MAX_INSTRUCTIONS - 2), true);
    });
});

describe('regex captures', () => {
    const prune = Regex.compile('(?s-u)^prune-test-(?P<group>[a-z]+)\\x00\\x00(?P<version>.{8})$');
    const key = Uint8Array.from([...bytes('prune-test-alpha'), 0, 0, 0, 0, 0, 0, 0, 0, 0, 7]);

    test('named groups are views of the input', () => {
        expect(prune.groupNames).toEqual(['group', 'version']);
        expect(prune.hasGroup('group')).toBe(true);
        expect(prune.hasGroup('other')).toBe(false);
        const captures = prune.captures(key)!;
        expect(captures.span(0)).toEqual([0, key.length]);
        expect(captures.span(1)).toEqual([11, 16]);
        expect(captures.span(2)).toEqual([18, 26]);
        expect(captures.span(3)).toBeUndefined();
        expect(captures.span(-1)).toBeUndefined();
        const version = captures.named('version')!;
        expect(Array.from(version)).toEqual([0, 0, 0, 0, 0, 0, 0, 7]);
        expect(version.buffer).toBe(key.buffer);
        expect(version.byteOffset).toBe(18);
        expect(captures.named('other')).toBeUndefined();
        expect(prune.captures(key.subarray(1))).toBeNull();
    });

    test('a group that took no part has neither span nor bytes', () => {
        const captures = Regex.compile('(?P<x>x)|(?P<y>y)').captures(bytes('-y'))!;
        expect(captures.span(1)).toBeUndefined();
        expect(captures.named('x')).toBeUndefined();
        expect(captures.span(2)).toEqual([1, 2]);
        expect(captures.named('y')).toEqual(bytes('y'));
    });
});

describe('regex capture memory', () => {
    // 4,085 instructions, 3,081 of which a thread can wait on, and 502 groups. Each waiting
    // thread holds two slots for every group the matcher records, so recording every group would
    // take megabytes.
    const regex = Regex.compile('()'.repeat(500) + '(?P<g>a{770}{4})');
    const input = new Uint8Array(3080).fill(0x61);

    test('a capturer holds memory for the groups it records only', () => {
        const capturer = regex.capturer(['g']);
        const captures = capturer.captures(input);
        expect(capturer.bytes).toBeLessThanOrEqual(128 * 1024);
        expect(captures?.named('g')).toHaveLength(3080);
        expect(captures?.span(1)).toBeUndefined();
        expect(regex.capturer([]).captures(input)).not.toBeNull();
        expect(() => regex.capturer(['other'])).toThrow('no group named other');
    });

    test('a capturer holds the memory it reports before and after matches', () => {
        // The matcher owns the arrays it allocates for itself. The compiled program and the other
        // state of the Regex are shared with every matcher of the pattern, and the input belongs to
        // the caller, so buffers reachable from either are left out.
        const pattern = Regex.compile('(?P<a>a+)(?P<b>b+)(?P<c>c+)(?P<d>d*)');
        const capturer = pattern.capturer(['a', 'b', 'c', 'd']);
        const owned = (input: Uint8Array) => {
            const shared = buffersReachableFrom([pattern, input]);
            return [...buffersReachableFrom(capturer)].filter((buffer) => !shared.has(buffer));
        };
        const total = (buffers: ArrayBufferLike[]) => buffers.reduce((sum, buffer) => sum + buffer.byteLength, 0);

        const before = owned(new Uint8Array(0));
        expect(total(before)).toBe(capturer.bytes);
        for (const text of ['xaabbc', 'abbbccdd']) {
            const input = bytes(text);
            expect(capturer.captures(input)?.named('c')).toEqual(bytes(text.includes('cc') ? 'cc' : 'c'));
            const after = owned(input);
            expect(after.length === before.length && after.every((buffer) => before.includes(buffer))).toBe(true);
            expect(total(after)).toBe(capturer.bytes);
        }
    });
});

describe('regex syntax errors', () => {
    test('carry their kind', () => {
        expect(syntaxError('(')).toBeInstanceOf(RegexSyntaxError);
        expect(syntaxError('(')?.name).toBe('RegexSyntaxError');
        expectRejected('(', false);
        expectRejected('\\b', true);
        expectRejected('\ud800', false);
    });
});

describe('regex running time', () => {
    test('a pattern that backtracks exponentially in RegExp stays linear', () => {
        const regex = Regex.compile('(?:a+)+b');
        const input = new Uint8Array(254).fill(0x61);
        const started = performance.now();
        expect(regex.isMatch(input)).toBe(false);
        expect(regex.captures(input)).toBeNull();
        expect(performance.now() - started).toBeLessThan(250);
    });

    test('search over 1 MiB returns between slices', () => {
        const regex = Regex.compile('(?s-u)needle');
        const value = new Uint8Array(1 << 20).fill(0x61);
        const missing = searchInSlices(regex, value, 1 << 16);
        expect(missing.result).toBe(false);
        expect(missing.slices).toBeGreaterThan(16);
        value.set(bytes('needle'), value.length - 10);
        const found = searchInSlices(regex, value, 1 << 16);
        expect(found.result).toBe(true);
        expect(found.slices).toBeGreaterThan(16);
        expect(regex.isMatch(value)).toBe(true);
    });

    test('a finished search keeps its result and a budget below 1 is refused', () => {
        const search = Regex.compile('b').search(bytes('ab'));
        expect(() => search.step(0)).toThrow(RangeError);
        expect(search.step(Infinity)).toBe(true);
        expect(search.step(1)).toBe(true);
    });
});
