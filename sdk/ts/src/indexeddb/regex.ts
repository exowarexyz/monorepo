/**
 * A linear time regular expression engine over bytes for a subset of the syntax of the Rust
 * regex crate, used for key selectors and value filters.
 *
 * Within its subset the engine gives the same results as `regex::bytes::Regex` of that crate, with
 * the same unanchored search, leftmost-first match and capture spans, and with Unicode mode on by
 * default. The subset has the flags `s` and `u`, literals, `\xHH` and the single byte escapes, `.`,
 * classes, the ASCII Perl classes without `u`, `^ $ \A \z`, groups (plain, non-capturing and
 * named), alternation, and greedy or lazy repetition of an expression that cannot match the empty
 * string.
 *
 * Compilation fails with a `RegexSyntaxError`. Its `unsupported` field is true for syntax that the
 * Rust crate accepts and that lies outside the subset or its limits, and false for a pattern that
 * the Rust crate rejects as well. The parser reads on past most unsupported constructs, including a
 * class that holds a nested class or a set operation, so an invalid part anywhere in the pattern
 * makes the pattern invalid.
 *
 * Three cases are unsupported although the Rust crate rejects them. A pattern longer than
 * `MAX_PATTERN_CHARS` and the flag `x` stop the parser, so it does not see a later invalid part. A
 * Unicode class named in braces is unsupported whatever its name, because the engine holds no table
 * of Unicode property names. A pattern that the Rust crate rejects only because its compiled form
 * is too large can be unsupported here.
 *
 * Nesting has two limits. A pattern whose syntax tree is deeper than `RUST_NEST_LIMIT` is invalid,
 * with depth counted over groups, repetitions, alternations, concatenations and classes as the Rust
 * crate counts it. In a pattern within that limit, groups nested deeper than `MAX_GROUP_DEPTH` are
 * unsupported.
 *
 * Matching simulates the compiled program on all threads at once and never backtracks. The work per
 * input byte is bounded by the program size, times the number of capture slots when the match
 * records any.
 */

/** The longest pattern, in Unicode scalar values. It bounds parsing time. */
export const MAX_PATTERN_CHARS = 1024;

/** Deepest nesting of groups this engine supports. */
export const MAX_GROUP_DEPTH = 32;

/**
 * Deepest syntax tree the Rust regex crate accepts by default. It also bounds the recursion of
 * the parser and the compiler.
 */
export const RUST_NEST_LIMIT = 250;

/** The largest count this engine supports in a counted repetition such as `x{n,m}`. */
export const MAX_REPEAT_COUNT = 1000;

/**
 * Largest compiled program. With the number of groups it bounds the work per input byte and the
 * memory of a match.
 */
export const MAX_INSTRUCTIONS = 4096;

/** A pattern that does not compile. */
export class RegexSyntaxError extends Error {
    /** True for syntax the Rust regex crate accepts and this engine does not. */
    readonly unsupported: boolean;

    constructor(message: string, unsupported: boolean) {
        super(message);
        this.name = 'RegexSyntaxError';
        this.unsupported = unsupported;
    }
}

const invalid = (message: string): RegexSyntaxError => new RegexSyntaxError(message, false);
const unsupported = (message: string): RegexSyntaxError => new RegexSyntaxError(message, true);

/** The capture groups of a match. */
export interface RegexCaptures {
    /** Byte offsets of group `index` (0 is the whole match), undefined when it took no part. */
    span(index: number): readonly [number, number] | undefined;
    /** The bytes of the named group as a view of the input, undefined when it took no part. */
    named(name: string): Uint8Array | undefined;
}

/** A search that runs in slices so a long input does not hold the event loop. */
export interface RegexSearch {
    /**
     * Runs the search until it ends or has spent at least `budget` steps. A step is one
     * instruction the machine follows or one thread it holds at an input position. The budget is
     * checked between input positions, so a call can pass it by the work of one position. Returns
     * undefined until the search ends, and then whether the pattern matched.
     */
    step(budget: number): boolean | undefined;
}

/** A matcher that records the spans of chosen named groups and keeps its memory between calls. */
export interface RegexCapturer {
    /** Bytes of working memory the matcher holds. */
    readonly bytes: number;
    /**
     * The leftmost-first match, or null. Only the chosen groups have spans, and every other group
     * reads as taking no part. The spans live in the matcher's memory, so a result holds until the
     * next call.
     */
    captures(haystack: Uint8Array): RegexCaptures | null;
}

type Range = readonly [number, number];

// Well formed UTF-8 sequences of two to four bytes as ranges per byte (Unicode table 3-7).
const UTF8_MULTI_BYTE: readonly (readonly Range[])[] = [
    [[0xc2, 0xdf], [0x80, 0xbf]],
    [[0xe0, 0xe0], [0xa0, 0xbf], [0x80, 0xbf]],
    [[0xe1, 0xec], [0x80, 0xbf], [0x80, 0xbf]],
    [[0xed, 0xed], [0x80, 0x9f], [0x80, 0xbf]],
    [[0xee, 0xef], [0x80, 0xbf], [0x80, 0xbf]],
    [[0xf0, 0xf0], [0x90, 0xbf], [0x80, 0xbf], [0x80, 0xbf]],
    [[0xf1, 0xf3], [0x80, 0xbf], [0x80, 0xbf], [0x80, 0xbf]],
    [[0xf4, 0xf4], [0x80, 0x8f], [0x80, 0xbf], [0x80, 0xbf]],
];

const ESCAPED_BYTES: ReadonlyMap<string, number> = new Map([
    ['n', 0x0a],
    ['r', 0x0d],
    ['t', 0x09],
    ['f', 0x0c],
    ['v', 0x0b],
    ['a', 0x07],
]);

const DIGIT: readonly Range[] = [[0x30, 0x39]];
const SPACE: readonly Range[] = [[0x09, 0x0d], [0x20, 0x20]];
const WORD: readonly Range[] = [[0x30, 0x39], [0x41, 0x5a], [0x5f, 0x5f], [0x61, 0x7a]];
const PERL_CLASSES: ReadonlyMap<string, { ranges: readonly Range[]; negate: boolean }> = new Map([
    ['d', { ranges: DIGIT, negate: false }],
    ['D', { ranges: DIGIT, negate: true }],
    ['s', { ranges: SPACE, negate: false }],
    ['S', { ranges: SPACE, negate: true }],
    ['w', { ranges: WORD, negate: false }],
    ['W', { ranges: WORD, negate: true }],
]);

// Escapes and flags of Rust syntax outside the subset. The parser reads on past a word boundary
// assertion, a Unicode class, a code point escape and every such flag except x, because x changes
// how the rest of the pattern reads. A Unicode class named by one letter must name a general
// category.
const WORD_BOUNDARIES = new Set(['b', 'B', '<', '>']);
const UNICODE_CLASSES = new Set(['p', 'P']);
const ONE_LETTER_CATEGORIES = /^[CLMNPSZclmnpsz]$/;
const SPECIAL_WORD_BOUNDARIES = new Set(['start', 'end', 'start-half', 'end-half']);
const ASCII_CLASSES = new Set([
    'alnum',
    'alpha',
    'ascii',
    'blank',
    'cntrl',
    'digit',
    'graph',
    'lower',
    'print',
    'punct',
    'space',
    'upper',
    'word',
    'xdigit',
]);
const OTHER_FLAGS = new Set(['i', 'm', 'R', 'U']);

// The number of hex digits of a code point escape without braces.
const CODE_POINT_DIGITS: ReadonlyMap<string, number> = new Map([
    ['x', 2],
    ['u', 4],
    ['U', 8],
]);

// The characters that Rust's char::is_whitespace accepts. The Rust crate skips them around the
// numbers of a counted repetition.
const RUST_WHITE_SPACE = /^[\t-\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]$/;

const ASCII_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const RUST_NAME_START = /^[_\p{Alphabetic}]$/u;
const RUST_NAME_REST = /^[_.[\]\p{Alphabetic}\p{N}]$/u;

const NO_INPUT = new Uint8Array(0);
const NO_SLOTS = new Int32Array(0);

function tableOf(ranges: readonly Range[], negate: boolean): Uint8Array {
    const table = new Uint8Array(256);
    for (const [lo, hi] of ranges) table.fill(1, lo, hi + 1);
    if (negate) for (let i = 0; i < 256; i++) table[i] ^= 1;
    return table;
}

function utf8(cp: number): number[] {
    if (cp < 0x80) return [cp];
    if (cp < 0x800) return [0xc0 | (cp >> 6), 0x80 | (cp & 63)];
    if (cp < 0x10000) return [0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63)];
    return [0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63)];
}

type Node =
    | { readonly kind: 'empty' }
    | { readonly kind: 'start' }
    | { readonly kind: 'end' }
    | { readonly kind: 'set'; readonly table: Uint8Array }
    | { readonly kind: 'cat'; readonly items: readonly Node[] }
    | { readonly kind: 'alt'; readonly items: readonly Node[] }
    | { readonly kind: 'group'; readonly sub: Node; readonly index: number }
    | { readonly kind: 'repeat'; readonly sub: Node; readonly min: number; readonly max: number; readonly greedy: boolean };

type Repetition = { min: number; max: number; greedy: boolean };

const EMPTY: Node = { kind: 'empty' };
const START: Node = { kind: 'start' };
const END: Node = { kind: 'end' };

const setNode = (table: Uint8Array): Node => ({ kind: 'set', table });
const byteNode = (byte: number): Node => setNode(tableOf([[byte, byte]], false));
const bytesNode = (bytes: readonly number[]): Node =>
    bytes.length === 1 ? byteNode(bytes[0]) : { kind: 'cat', items: bytes.map(byteNode) };

/** A node for one Unicode scalar value as UTF-8. Its single byte form must be a byte of `ascii`. */
function scalarNode(ascii: Uint8Array): Node {
    const multi = UTF8_MULTI_BYTE.map(
        (seq): Node => ({ kind: 'cat', items: seq.map((range) => setNode(tableOf([range], false))) }),
    );
    return { kind: 'alt', items: [setNode(ascii), ...multi] };
}

function nullable(node: Node): boolean {
    switch (node.kind) {
        case 'empty':
        case 'start':
        case 'end':
            return true;
        case 'set':
            return false;
        case 'cat':
            return node.items.every(nullable);
        case 'alt':
            return node.items.some(nullable);
        case 'repeat':
            return node.min === 0 || nullable(node.sub);
        case 'group':
            return nullable(node.sub);
    }
}

/** A single escape, decoded for the caller to place in or outside a class. */
type EscapeItem =
    | { readonly kind: 'hex'; readonly value: number }
    | { readonly kind: 'codePoint'; readonly value: number }
    | { readonly kind: 'byte'; readonly value: number }
    | { readonly kind: 'perl'; readonly table: Uint8Array }
    | { readonly kind: 'node'; readonly node: Node };

/**
 * A parsed expression with its height in the syntax tree of the Rust crate. A literal, an escape,
 * `.` and an assertion are leaves of height 0.
 */
interface Parsed {
    readonly node: Node;
    readonly height: number;
}

class Parser {
    private readonly chars: string[];
    private pos = 0;
    /** The number of groups open at `pos`. */
    private depth = 0;
    /** The flags in effect at `pos`. */
    private flags = { s: false, u: true };
    /** The first unsupported construct read past. `parse` reports it at the end. */
    private unsupportedFound: string | null = null;
    /** The number of capturing groups read so far, group 0 included. */
    groups = 1;
    /** The group index of each named group. */
    readonly names = new Map<string, number>();

    constructor(chars: string[]) {
        this.chars = chars;
    }

    private eof(): boolean {
        return this.pos >= this.chars.length;
    }

    private peek(offset = 0): string | undefined {
        return this.chars[this.pos + offset];
    }

    private eat(c: string): boolean {
        if (this.peek() !== c) return false;
        this.pos++;
        return true;
    }

    parse(): Node {
        const { node } = this.alternation();
        if (!this.eof()) throw invalid('unopened group');
        if (this.unsupportedFound !== null) throw unsupported(this.unsupportedFound);
        return node;
    }

    private defer(message: string): void {
        this.unsupportedFound ??= message;
    }

    /**
     * Checks a height against the Rust nest limit and returns it. `child` is the height of the
     * tallest of `count` items. A concatenation or alternation is a node of the Rust tree only
     * when it has more than one item, and then it adds one level.
     */
    private height(child: number, count: number): number {
        const height = count > 1 ? child + 1 : child;
        if (height > RUST_NEST_LIMIT) throw invalid('pattern nested deeper than ' + RUST_NEST_LIMIT);
        return height;
    }

    private alternation(): Parsed {
        const branches = [this.concat()];
        while (this.eat('|')) branches.push(this.concat());
        const height = this.height(Math.max(...branches.map((branch) => branch.height)), branches.length);
        if (branches.length === 1) return { node: branches[0].node, height };
        return { node: { kind: 'alt', items: branches.map((branch) => branch.node) }, height };
    }

    private concat(): Parsed {
        const items: Node[] = [];
        let count = 0;
        let tallest = 0;
        while (!this.eof() && this.peek() !== '|' && this.peek() !== ')') {
            // A null atom is a flag group such as "(?s)". It has nothing to repeat but still counts
            // as an item of the Rust concatenation.
            const parsed = this.atom();
            let atom = parsed?.node ?? null;
            let height = parsed?.height ?? 0;
            count++;
            for (;;) {
                const repetition = this.quantifier();
                if (repetition === null) break;
                if (atom === null) throw invalid('repetition operator missing expression');
                height = this.height(height + 1, 1);
                if (nullable(atom)) this.defer('repetition of an expression that can match the empty string');
                atom = { kind: 'repeat', sub: atom, ...repetition };
            }
            tallest = Math.max(tallest, height);
            if (atom !== null) items.push(atom);
        }
        const height = this.height(tallest, count);
        if (items.length === 0) return { node: EMPTY, height };
        return { node: items.length === 1 ? items[0] : { kind: 'cat', items }, height };
    }

    private quantifier(): Repetition | null {
        let min: number;
        let max: number;
        if (this.eat('*')) {
            min = 0;
            max = Infinity;
        } else if (this.eat('+')) {
            min = 1;
            max = Infinity;
        } else if (this.eat('?')) {
            min = 0;
            max = 1;
        } else if (this.eat('{')) {
            // White space may stand before and after each number, but not between the comma and
            // the brace of "{n,}".
            const first = this.decimal();
            if (this.eat(',')) {
                if (first === null) throw invalid('repetition quantifier expects a valid decimal');
                min = first;
                if (this.peek() === '}') {
                    max = Infinity;
                } else {
                    const second = this.decimal();
                    if (second === null) throw invalid('repetition quantifier expects a valid decimal');
                    max = second;
                }
            } else {
                if (first === null) throw invalid('repetition quantifier expects a valid decimal');
                min = first;
                max = first;
            }
            if (!this.eat('}')) throw invalid('unclosed counted repetition');
            if (max < min) throw invalid('invalid repetition count range');
            if (min > MAX_REPEAT_COUNT || (max !== Infinity && max > MAX_REPEAT_COUNT)) {
                this.defer('repetition count too large');
            }
        } else {
            return null;
        }
        return { min, max, greedy: !this.eat('?') };
    }

    private skipSpace(): void {
        while (RUST_WHITE_SPACE.test(this.peek() ?? '')) {
            this.pos++;
            this.defer('white space in a counted repetition');
        }
    }

    /** Reads a count with the white space around it. Returns null when there are no digits. */
    private decimal(): number | null {
        this.skipSpace();
        let digits = '';
        for (let c = this.peek(); c !== undefined && c >= '0' && c <= '9'; c = this.peek()) {
            digits += c;
            this.pos++;
        }
        this.skipSpace();
        if (digits === '') return null;
        const value = Number(digits);
        if (value > 0xffffffff) throw invalid('repetition quantifier expects a valid decimal');
        return value;
    }

    private atom(): Parsed | null {
        const c = this.chars[this.pos++];
        switch (c) {
            case '(':
                return this.group();
            case '[':
                return this.klass();
            case '.':
                return { node: this.dot(), height: 0 };
            case '^':
                return { node: START, height: 0 };
            case '$':
                return { node: END, height: 0 };
            case '\\':
                return { node: this.escape(), height: 0 };
            case '*':
            case '+':
            case '?':
            case '{':
                throw invalid('repetition operator missing expression');
            default:
                return { node: bytesNode(utf8(c.codePointAt(0)!)), height: 0 };
        }
    }

    private dot(): Node {
        const { s, u } = this.flags;
        if (!u) return setNode(tableOf(s ? [[0, 0xff]] : [[0, 0x09], [0x0b, 0xff]], false));
        return scalarNode(tableOf(s ? [[0, 0x7f]] : [[0, 0x09], [0x0b, 0x7f]], false));
    }

    private group(): Parsed | null {
        const saved = { ...this.flags };
        let index: number | null = null;
        if (this.eat('?')) {
            if (this.eat(':')) {
                // A non-capturing group.
            } else if (this.peek() === 'P' && this.peek(1) === '<') {
                this.pos += 2;
                index = this.name();
            } else if (this.peek() === '<' && this.peek(1) !== '=' && this.peek(1) !== '!') {
                this.pos += 1;
                index = this.name();
            } else if (this.peek() === '=' || this.peek() === '!' || this.peek() === '<') {
                throw invalid('look-around is not supported');
            } else if (!this.flagItems()) {
                // "(?flags)" applies to the rest of the enclosing group.
                return null;
            }
        } else {
            index = this.groups++;
        }
        if (++this.depth > RUST_NEST_LIMIT) throw invalid('pattern nested deeper than ' + RUST_NEST_LIMIT);
        if (this.depth > MAX_GROUP_DEPTH) this.defer('groups nested deeper than ' + MAX_GROUP_DEPTH);
        const sub = this.alternation();
        if (!this.eat(')')) throw invalid('unclosed group');
        this.flags = saved;
        this.depth--;
        const height = this.height(sub.height + 1, 1);
        return { node: index === null ? sub.node : { kind: 'group', sub: sub.node, index }, height };
    }

    private name(): number {
        const start = this.pos;
        while (!this.eof() && this.peek() !== '>') this.pos++;
        const chars = this.chars.slice(start, this.pos);
        if (!this.eat('>')) throw invalid('unclosed capture group name');
        if (chars.length === 0) throw invalid('empty capture group name');
        if (!chars.every((c, i) => (i === 0 ? RUST_NAME_START : RUST_NAME_REST).test(c))) {
            throw invalid('invalid capture group character');
        }
        const name = chars.join('');
        if (this.names.has(name)) throw invalid('duplicate capture group name');
        if (!ASCII_NAME.test(name)) this.defer('capture group name outside [A-Za-z_][A-Za-z0-9_]*');
        const index = this.groups++;
        this.names.set(name, index);
        return index;
    }

    /** Parses the flags after "(?". Returns true for "(?flags:" and false for "(?flags)". */
    private flagItems(): boolean {
        let negate = false;
        let afterDash = false;
        let count = 0;
        const seen = new Set<string>();
        for (;;) {
            if (this.eof()) throw invalid('unclosed flags');
            const c = this.chars[this.pos++];
            if (c === ')' || c === ':') {
                if (count === 0 && !negate) throw invalid('missing flags');
                if (afterDash) throw invalid('dangling flag negation operator');
                return c === ':';
            }
            if (c === '-') {
                if (negate) throw invalid('flag negation operator repeated');
                negate = true;
                afterDash = true;
                continue;
            }
            afterDash = false;
            if (c === 's' || c === 'u') {
                if (seen.has(c)) throw invalid('duplicate flag');
                seen.add(c);
                this.flags[c] = !negate;
                count++;
            } else if (OTHER_FLAGS.has(c)) {
                if (seen.has(c)) throw invalid('duplicate flag');
                seen.add(c);
                count++;
                this.defer('flag ' + c + ' is not supported');
            } else if (c === 'x') {
                throw unsupported('flag x is not supported');
            } else {
                throw invalid('unrecognized flag');
            }
        }
    }

    private escapeItem(inClass: boolean): EscapeItem {
        if (this.eof()) throw invalid('incomplete escape sequence');
        const c = this.chars[this.pos++];
        const digits = CODE_POINT_DIGITS.get(c);
        if (digits !== undefined) {
            if (c === 'x' && this.peek() !== '{') return { kind: 'hex', value: this.hexDigits(digits) };
            const value = this.eat('{') ? this.bracedHex() : this.hexDigits(digits);
            if (value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) {
                throw invalid('hexadecimal literal is not a Unicode scalar value');
            }
            this.defer('code point escapes other than \\xHH are not supported');
            return { kind: 'codePoint', value };
        }
        const escaped = ESCAPED_BYTES.get(c);
        if (escaped !== undefined) return { kind: 'byte', value: escaped };
        const perl = PERL_CLASSES.get(c);
        if (perl !== undefined) {
            if (this.flags.u) this.defer('Unicode Perl classes are not supported, use (?-u)');
            return { kind: 'perl', table: tableOf(perl.ranges, perl.negate) };
        }
        if (!inClass && c === 'A') return { kind: 'node', node: START };
        if (!inClass && c === 'z') return { kind: 'node', node: END };
        if (WORD_BOUNDARIES.has(c)) {
            if (inClass) throw invalid('an assertion is not allowed in a class');
            if (c === 'b' && this.peek() === '{') this.specialWordBoundary();
            this.defer('word boundaries are not supported');
            return { kind: 'node', node: EMPTY };
        }
        if (UNICODE_CLASSES.has(c)) {
            if (!this.flags.u) throw invalid('Unicode classes are not allowed without the u flag');
            this.unicodeClassName();
            this.defer('Unicode classes are not supported');
            return { kind: 'perl', table: new Uint8Array(256) };
        }
        const cp = c.codePointAt(0)!;
        if (cp < 0x80 && !/[0-9A-Za-z]/.test(c)) return { kind: 'byte', value: cp };
        throw invalid('unrecognized escape sequence');
    }

    private hexDigits(count: number): number {
        let value = 0;
        for (let i = 0; i < count; i++) {
            if (this.eof()) throw invalid('incomplete escape sequence');
            const digit = parseInt(this.chars[this.pos++], 16);
            if (Number.isNaN(digit)) throw invalid('invalid hexadecimal digit');
            value = value * 16 + digit;
        }
        return value;
    }

    /**
     * Reads any number of hex digits up to a closing brace. The caller rejects a value above the
     * largest code point.
     */
    private bracedHex(): number {
        let value = 0;
        let count = 0;
        for (;;) {
            if (this.eof()) throw invalid('incomplete escape sequence');
            const c = this.chars[this.pos++];
            if (c === '}') break;
            const digit = parseInt(c, 16);
            if (Number.isNaN(digit)) throw invalid('invalid hexadecimal digit');
            value = value * 16 + digit;
            count++;
        }
        if (count === 0) throw invalid('hexadecimal literal empty');
        return value;
    }

    /**
     * Reads the name of a word boundary such as `\b{start}` after `\b`. Braces that do not start
     * with a letter or - are a counted repetition of `\b`, so this method leaves them for the
     * quantifier to read.
     */
    private specialWordBoundary(): void {
        if (this.peek(1) === undefined) throw invalid('incomplete escape sequence');
        if (!/^[A-Za-z-]$/.test(this.peek(1)!)) return;
        this.pos++;
        const name = this.pos;
        while (!this.eof() && /^[A-Za-z-]$/.test(this.peek()!)) this.pos++;
        const word = this.chars.slice(name, this.pos).join('');
        if (!this.eat('}')) throw invalid('unclosed special word boundary');
        if (!SPECIAL_WORD_BOUNDARIES.has(word)) throw invalid('unrecognized special word boundary');
    }

    /** Reads the name after `\p` or `\P`: one letter, or a name in braces. */
    private unicodeClassName(): void {
        if (this.eof()) throw invalid('incomplete escape sequence');
        if (!this.eat('{')) {
            if (!ONE_LETTER_CATEGORIES.test(this.chars[this.pos++])) throw invalid('unknown Unicode class');
            return;
        }
        if (this.eat('}')) throw invalid('unknown Unicode class');
        while (!this.eof() && this.peek() !== '}') this.pos++;
        if (!this.eat('}')) throw invalid('unclosed Unicode class name');
    }

    private escape(): Node {
        const item = this.escapeItem(false);
        switch (item.kind) {
            case 'node':
                return item.node;
            case 'perl':
                return setNode(item.table);
            case 'hex':
                // "\xHH" is the byte HH without the u flag and the code point U+00HH with it.
                return this.flags.u ? bytesNode(utf8(item.value)) : byteNode(item.value);
            case 'codePoint':
                return bytesNode(utf8(item.value));
            case 'byte':
                return byteNode(item.value);
        }
    }

    /** Reads one class member. Returns its byte, or null after adding a Perl class to `table`. */
    private classMember(table: Uint8Array): number | null {
        const limit = this.flags.u ? 0x7f : 0xff;
        const c = this.chars[this.pos++];
        if (c === '\\') {
            const item = this.escapeItem(true);
            if (item.kind === 'perl') {
                for (let i = 0; i < 256; i++) table[i] |= item.table[i];
                return null;
            }
            if (item.kind === 'node') throw invalid('unrecognized escape sequence');
            if (item.kind === 'codePoint' && !this.flags.u && item.value > 0x7f) {
                throw invalid('Unicode not allowed here');
            }
            if (item.value > limit) this.defer('a class member above 0x7F needs (?-u)');
            return item.value;
        }
        const cp = c.codePointAt(0)!;
        if (cp > 0x7f && !this.flags.u) throw invalid('Unicode not allowed here');
        if (cp > 0x7f) this.defer('a class member above 0x7F is not supported');
        return cp;
    }

    /**
     * This engine does not match a class that holds a nested class or a set operation. This method
     * reads such a class from `start` with the grammar of the Rust crate, checks what the Rust
     * parser checks and measures the class as the Rust nest limiter does. It records the class as
     * unsupported and returns, so the parser still reads the rest of the pattern.
     */
    private setClass(start: number, message: string): Parsed {
        // Each open class holds the heights of the items of its current union and, after a set
        // operation, the height of the left operand. A union of one item is that item, and an
        // operation or a union of more items adds a level.
        interface Open {
            items: number[];
            left: number | null;
        }
        const union = ({ items }: Open) => (items.length > 1 ? 1 + Math.max(...items) : (items[0] ?? 0));
        const set = (open: Open) => (open.left === null ? union(open) : 1 + Math.max(open.left, union(open)));
        const unclosed = () => invalid('unclosed character class');
        const ignored = new Uint8Array(256);
        const stack: Open[] = [];

        // A class opens with an optional ^, then takes any leading - and a leading ] as literals.
        const open = () => {
            const opened: Open = { items: [], left: null };
            this.pos++;
            this.eat('^');
            while (this.eat('-')) opened.items.push(0);
            if (opened.items.length === 0 && this.eat(']')) opened.items.push(0);
            stack.push(opened);
        };

        this.pos = start;
        open();
        for (;;) {
            if (this.eof()) throw unclosed();
            const top = stack[stack.length - 1];
            const c = this.peek();
            if (c === '[' && this.asciiClass()) {
                top.items.push(0);
            } else if (c === '[') {
                open();
            } else if (c === ']') {
                this.pos++;
                stack.pop();
                const height = this.height(1 + set(top), 1);
                if (stack.length === 0) {
                    this.defer(message);
                    return { node: setNode(new Uint8Array(256)), height };
                }
                stack[stack.length - 1].items.push(height);
            } else if ((c === '&' || c === '-' || c === '~') && this.peek(1) === c) {
                this.pos += 2;
                top.left = set(top);
                top.items = [];
            } else {
                // One item, or a range of two literals unless the - closes the class or starts
                // a set difference.
                const lo = this.classMember(ignored);
                if (this.eof()) throw unclosed();
                if (this.peek() === '-' && this.peek(1) !== ']' && this.peek(1) !== '-') {
                    this.pos++;
                    if (this.eof()) throw unclosed();
                    const hi = this.classMember(ignored);
                    if (lo === null || hi === null) throw invalid('invalid class range');
                    if (hi < lo) throw invalid('invalid character class range');
                }
                top.items.push(0);
            }
        }
    }

    /** Reads a POSIX class such as "[:alpha:]" in a class, or reads nothing and returns false. */
    private asciiClass(): boolean {
        const start = this.pos;
        this.pos++;
        if (this.eat(':')) {
            this.eat('^');
            const name = this.pos;
            while (!this.eof() && this.peek() !== ':') this.pos++;
            if (ASCII_CLASSES.has(this.chars.slice(name, this.pos).join('')) && this.eat(':') && this.eat(']')) {
                return true;
            }
        }
        this.pos = start;
        return false;
    }

    private klass(): Parsed {
        const start = this.pos - 1;
        const negate = this.eat('^');
        const table = new Uint8Array(256);
        let first = true;
        let members = 0;
        for (;;) {
            if (this.eof()) throw invalid('unclosed character class');
            const c = this.peek();
            if (c === ']' && !first) {
                this.pos++;
                break;
            }

            // A ] at the start of a class is a member and never starts a range.
            if (c === ']') {
                this.pos++;
                table[0x5d] = 1;
                first = false;
                members++;
                continue;
            }
            if (c === '[') return this.setClass(start, 'nested and POSIX classes are not supported');
            if ((c === '&' || c === '~' || c === '-') && this.peek(1) === c) {
                return this.setClass(start, 'class set operations are not supported');
            }
            if (c === '-' && !first && this.peek(1) !== ']') {
                this.defer('an unescaped - inside a class must be first or last');
            }
            first = false;
            members++;
            const lo = this.classMember(table);
            if (lo === null) {
                if (this.peek() === '-' && this.peek(1) === '-') {
                    return this.setClass(start, 'class set operations are not supported');
                }
                if (this.peek() === '-' && this.peek(1) !== ']') throw invalid('invalid class range');
                continue;
            }
            if (this.peek() === '-' && this.peek(1) !== ']' && this.peek(1) !== undefined) {
                this.pos++;
                if (this.peek() === '-') return this.setClass(start, 'class set operations are not supported');
                const hi = this.classMember(table);
                if (hi === null) throw invalid('invalid class range');
                if (hi < lo) throw invalid('invalid character class range');
                table.fill(1, lo, hi + 1);
            } else {
                table[lo] = 1;
            }
        }

        // The Rust tree holds the class and, for more than one member, their union.
        const height = members > 1 ? 2 : 1;
        if (!this.flags.u) {
            if (negate) for (let i = 0; i < 256; i++) table[i] ^= 1;
            return { node: setNode(table), height };
        }
        if (!negate) return { node: setNode(table), height };

        // A negated class in Unicode mode matches every scalar value outside its ASCII members.
        const ascii = new Uint8Array(256);
        for (let i = 0; i < 0x80; i++) ascii[i] = table[i] ^ 1;
        return { node: scalarNode(ascii), height };
    }
}

// The instructions of a program. BYTE and SET consume one byte, MATCH ends a thread, and the rest
// are followed without consuming input. SPLIT prefers its first target.
const BYTE = 0;
const SET = 1;
const SPLIT = 2;
const JUMP = 3;
const SAVE = 4;
const ASSERT_START = 5;
const ASSERT_END = 6;
const MATCH = 7;

interface Program {
    /** The instruction at each program counter. */
    readonly op: Uint8Array;
    /**
     * The byte of BYTE, the index in `tables` of SET, the first target of SPLIT and JUMP, and the
     * slot of SAVE.
     */
    readonly x: Int32Array;
    /** The second target of SPLIT. */
    readonly y: Int32Array;
    /** The byte tables of the SET instructions, 1 for each byte that matches. */
    readonly tables: readonly Uint8Array[];
    /** The number of capture slots, two per group including group 0. */
    readonly slots: number;
    /** The number of instructions a thread can wait on. A list holds at most this many threads. */
    readonly waits: number;
    /** True when no thread can start after the first position. */
    readonly anchored: boolean;
}

class Compiler {
    readonly op: number[] = [];
    readonly x: number[] = [];
    readonly y: number[] = [];
    readonly tables: Uint8Array[] = [];

    emit(op: number, x = 0, y = 0): number {
        if (this.op.length >= MAX_INSTRUCTIONS) throw unsupported('pattern compiles to too many instructions');
        this.op.push(op);
        this.x.push(x);
        this.y.push(y);
        return this.op.length - 1;
    }

    private patchSplit(pc: number, greedy: boolean, body: number, exit: number): void {
        this.x[pc] = greedy ? body : exit;
        this.y[pc] = greedy ? exit : body;
    }

    node(node: Node): void {
        switch (node.kind) {
            case 'empty':
                return;
            case 'start':
                this.emit(ASSERT_START);
                return;
            case 'end':
                this.emit(ASSERT_END);
                return;
            case 'set': {
                let count = 0;
                let only = 0;
                for (let i = 0; i < 256; i++) {
                    if (node.table[i]) {
                        count++;
                        only = i;
                    }
                }
                if (count === 1) {
                    this.emit(BYTE, only);
                } else {
                    this.emit(SET, this.tables.length);
                    this.tables.push(node.table);
                }
                return;
            }
            case 'cat':
                for (const item of node.items) this.node(item);
                return;
            case 'alt': {
                const jumps: number[] = [];
                const last = node.items.length - 1;
                for (let i = 0; i < last; i++) {
                    const split = this.emit(SPLIT, this.op.length + 1);
                    this.node(node.items[i]);
                    jumps.push(this.emit(JUMP));
                    this.y[split] = this.op.length;
                }
                this.node(node.items[last]);
                for (const jump of jumps) this.x[jump] = this.op.length;
                return;
            }
            case 'group':
                this.emit(SAVE, 2 * node.index);
                this.node(node.sub);
                this.emit(SAVE, 2 * node.index + 1);
                return;
            case 'repeat':
                this.repeat(node.sub, node.min, node.max, node.greedy);
                return;
        }
    }

    private repeat(sub: Node, min: number, max: number, greedy: boolean): void {
        if (max === Infinity && min === 0) {
            const split = this.emit(SPLIT);
            this.node(sub);
            this.emit(JUMP, split);
            this.patchSplit(split, greedy, split + 1, this.op.length);
            return;
        }
        if (max === Infinity) {
            for (let i = 0; i < min - 1; i++) this.node(sub);
            const body = this.op.length;
            this.node(sub);
            const split = this.emit(SPLIT);
            this.patchSplit(split, greedy, body, split + 1);
            return;
        }
        for (let i = 0; i < min; i++) this.node(sub);
        const optional: number[] = [];
        for (let i = min; i < max; i++) {
            optional.push(this.emit(SPLIT));
            this.node(sub);
        }
        for (const split of optional) this.patchSplit(split, greedy, split + 1, this.op.length);
    }
}

/**
 * Whether every path from the first instruction passes ASSERT_START before it can wait or match.
 */
function isAnchored(op: Uint8Array, x: Int32Array, y: Int32Array): boolean {
    const seen = new Uint8Array(op.length);
    const stack = [0];
    while (stack.length > 0) {
        const pc = stack.pop()!;
        if (seen[pc]) continue;
        seen[pc] = 1;
        switch (op[pc]) {
            case ASSERT_START:
                break;
            case JUMP:
                stack.push(x[pc]);
                break;
            case SPLIT:
                stack.push(x[pc], y[pc]);
                break;
            case SAVE:
            case ASSERT_END:
                stack.push(pc + 1);
                break;
            default:
                return false;
        }
    }
    return true;
}

/**
 * A Pike VM. It keeps one thread per instruction in priority order, advances every thread over each
 * input byte, and drops a thread that reaches an instruction already taken by a thread of higher
 * priority. The work per byte is bounded by the program size, and every thread that moves copies
 * the capture slots the machine records.
 */
class Machine {
    private readonly program: Program;
    /** For each capture slot of the program, its index among the recorded slots, or -1. */
    private readonly slotOf: Int32Array;
    /** Capture slots recorded per thread, 0 when only whether the pattern matches is wanted. */
    private readonly slots: number;

    // The thread list of the current position and the list built for the next one. A list holds the
    // program counter of each thread in `pcs` and `slots` recorded slots per thread in `caps`.
    private pcs: Int32Array;
    private nextPcs: Int32Array;
    private caps: Int32Array;
    private nextCaps: Int32Array;

    /** `mark[pc] === generation` when pc was reached while building the current list. */
    private readonly mark: Int32Array;
    /** The pending instructions and slot restores of `add`. */
    private readonly stack: Int32Array;
    /** The recorded slots of the thread that `add` follows. */
    private readonly scratch: Int32Array;
    /** The recorded capture slots of the winning thread, copied when it reaches MATCH. */
    private readonly saved: Int32Array;
    private haystack = NO_INPUT;
    /** The input position of the current list. */
    private pos = 0;
    /** The number of threads in the current list. */
    private count = 0;
    /** Numbers each list built, so `mark` needs no clearing between lists. */
    private generation = 0;
    /**
     * The steps spent so far, the unit of a `run` budget. A step is one entry that `add` takes from
     * its stack or one thread of the list at an input position.
     */
    private steps = 0;
    /** Whether the search has ended. */
    done = false;
    /** Whether the pattern matched. */
    found = false;
    /** `saved` once a match was found and the machine records slots, otherwise null. */
    matched: Int32Array | null = null;

    constructor(program: Program, slotOf: Int32Array, slots: number) {
        const n = program.op.length;
        this.program = program;
        this.slotOf = slotOf;
        this.slots = slots;
        this.pcs = new Int32Array(program.waits);
        this.nextPcs = new Int32Array(program.waits);
        this.caps = new Int32Array(program.waits * slots);
        this.nextCaps = new Int32Array(program.waits * slots);
        this.mark = new Int32Array(n);
        this.scratch = new Int32Array(slots);
        this.saved = new Int32Array(slots);

        // Each instruction is followed at most once per list, and following one pops an entry and
        // pushes at most three, so the stack never holds more than 2n + 2 entries.
        this.stack = new Int32Array(2 * n + 2);
    }

    /**
     * Bytes of the arrays that a machine recording `slots` slots of `program` allocates, with the
     * slot map of its capturer.
     */
    static bytes(program: Program, slots: number): number {
        const n = program.op.length;
        return 4 * (2 * program.waits * (1 + slots) + n + (2 * n + 2) + 2 * slots + program.slots);
    }

    reset(haystack: Uint8Array): void {
        this.haystack = haystack;
        this.pos = 0;
        this.count = 0;
        this.generation = 0;
        this.mark.fill(-1);
        this.done = false;
        this.found = false;
        this.matched = null;
    }

    /** Ends the search and lets go of the input. */
    private finish(): void {
        this.done = true;
        this.haystack = NO_INPUT;
    }

    /**
     * Adds the thread at `start` with the captures in `scratch` to a list, following every
     * instruction that does not consume input, in priority order. Returns the new list length.
     */
    private add(pcs: Int32Array, caps: Int32Array, count: number, start: number, pos: number): number {
        const { op, x, y } = this.program;
        const { mark, stack, scratch, slotOf, slots, generation } = this;

        // A negative entry -(slot + 1) restores the slot to the value below it on the stack.
        let sp = 0;
        stack[sp++] = start;
        while (sp > 0) {
            const pc = stack[--sp];
            this.steps++;
            if (pc < 0) {
                scratch[-pc - 1] = stack[--sp];
                continue;
            }
            if (mark[pc] === generation) continue;
            mark[pc] = generation;
            switch (op[pc]) {
                case JUMP:
                    stack[sp++] = x[pc];
                    break;
                case SPLIT:
                    stack[sp++] = y[pc];
                    stack[sp++] = x[pc];
                    break;
                case SAVE: {
                    const slot = slotOf[x[pc]];
                    if (slot >= 0) {
                        stack[sp++] = scratch[slot];
                        stack[sp++] = -slot - 1;
                        scratch[slot] = pos;
                    }
                    stack[sp++] = pc + 1;
                    break;
                }
                case ASSERT_START:
                    if (pos === 0) stack[sp++] = pc + 1;
                    break;
                case ASSERT_END:
                    if (pos === this.haystack.length) stack[sp++] = pc + 1;
                    break;
                default:
                    pcs[count] = pc;
                    if (slots !== 0) caps.set(scratch, count * slots);
                    count++;
            }
        }
        return count;
    }

    /**
     * Advances over the input until the search ends or at least `budget` steps were spent. The
     * budget is checked between input positions, so a call can pass it by the work of one position.
     */
    run(budget: number): void {
        const { op, x, tables, anchored } = this.program;
        const { haystack, slots } = this;
        const length = haystack.length;
        const limit = this.steps + budget;
        while (!this.done && this.steps < limit) {
            const pos = this.pos;

            // A thread starts at every position until a match is found, or only at the first
            // position of an anchored program. The list for this position was built with the
            // current generation, so the new thread is dropped wherever the list already holds one
            // of higher priority.
            if (this.matched === null && (pos === 0 || !anchored)) {
                this.scratch.fill(-1);
                this.count = this.add(this.pcs, this.caps, this.count, 0, pos);
            }
            if (this.count === 0) {
                if (this.matched !== null || anchored || pos === length) {
                    this.finish();
                    return;
                }
                this.pos++;
                this.generation++;
                continue;
            }
            this.generation++;
            const byte = pos < length ? haystack[pos] : -1;
            let next = 0;
            for (let i = 0; i < this.count; i++) {
                const pc = this.pcs[i];
                const code = op[pc];
                if (code === MATCH) {
                    this.found = true;
                    if (slots === 0) {
                        this.finish();
                        return;
                    }

                    // Threads after this one have lower priority and cannot win.
                    this.saved.set(this.caps.subarray(i * slots, (i + 1) * slots));
                    this.matched = this.saved;
                    break;
                }
                if (byte >= 0 && (code === BYTE ? x[pc] === byte : tables[x[pc]][byte] === 1)) {
                    if (slots !== 0) this.scratch.set(this.caps.subarray(i * slots, (i + 1) * slots));
                    next = this.add(this.nextPcs, this.nextCaps, next, pc + 1, pos + 1);
                }
            }
            this.steps += this.count;
            [this.pcs, this.nextPcs] = [this.nextPcs, this.pcs];
            [this.caps, this.nextCaps] = [this.nextCaps, this.caps];
            this.count = next;
            this.pos = pos + 1;
            if (this.pos > length) this.finish();
        }
    }
}

class Captures implements RegexCaptures {
    constructor(
        private readonly haystack: Uint8Array,
        /** The recorded slots of the match. */
        private readonly slots: Int32Array,
        private readonly slotOf: Int32Array,
        private readonly names: ReadonlyMap<string, number>,
    ) {}

    span(index: number): readonly [number, number] | undefined {
        if (!Number.isInteger(index) || index < 0 || 2 * index >= this.slotOf.length) return undefined;
        const slot = this.slotOf[2 * index];
        const start = slot < 0 ? -1 : this.slots[slot];
        return start < 0 ? undefined : [start, this.slots[this.slotOf[2 * index + 1]]];
    }

    named(name: string): Uint8Array | undefined {
        const index = this.names.get(name);
        const span = index === undefined ? undefined : this.span(index);
        return span === undefined ? undefined : this.haystack.subarray(span[0], span[1]);
    }
}

class Search implements RegexSearch {
    constructor(private readonly machine: Machine) {}

    step(budget: number): boolean | undefined {
        if (!(budget >= 1)) throw new RangeError('budget must be at least 1');
        if (!this.machine.done) this.machine.run(budget);
        return this.machine.done ? this.machine.found : undefined;
    }
}

class Capturer implements RegexCapturer {
    readonly bytes: number;
    private readonly machine: Machine;

    constructor(
        program: Program,
        private readonly slotOf: Int32Array,
        slots: number,
        private readonly names: ReadonlyMap<string, number>,
    ) {
        this.bytes = Machine.bytes(program, slots);
        this.machine = new Machine(program, slotOf, slots);
    }

    captures(haystack: Uint8Array): RegexCaptures | null {
        const { machine } = this;
        machine.reset(haystack);
        machine.run(Infinity);
        if (!machine.found) return null;
        return new Captures(haystack, machine.matched ?? NO_SLOTS, this.slotOf, this.names);
    }
}

/** A compiled pattern. */
export class Regex {
    /** Names of the named groups in order of appearance. */
    readonly groupNames: readonly string[];
    private readonly program: Program;
    /** The group index of each named group. */
    private readonly names: ReadonlyMap<string, number>;
    /** A slot map with -1 for every capture slot, for machines that record no slot. */
    private readonly noSlot: Int32Array;
    /** The machine of `isMatch`, created on first use and reused. */
    private matcher: Machine | undefined;

    private constructor(program: Program, names: ReadonlyMap<string, number>) {
        this.program = program;
        this.names = names;
        this.noSlot = new Int32Array(program.slots).fill(-1);
        this.groupNames = Object.freeze([...names.keys()]);
    }

    /** Compiles a pattern, or throws a `RegexSyntaxError`. */
    static compile(pattern: string): Regex {
        if (typeof pattern !== 'string') throw invalid('pattern must be a string');
        if (pattern.length > 2 * MAX_PATTERN_CHARS) throw unsupported('pattern too long');
        const chars = Array.from(pattern);
        if (chars.length > MAX_PATTERN_CHARS) throw unsupported('pattern too long');
        if (chars.some((c) => c.length === 1 && c >= '\ud800' && c <= '\udfff')) {
            throw invalid('pattern is not well formed Unicode');
        }
        const parser = new Parser(chars);
        const ast = parser.parse();
        const compiler = new Compiler();
        compiler.emit(SAVE, 0);
        compiler.node(ast);
        compiler.emit(SAVE, 1);
        compiler.emit(MATCH);
        const op = Uint8Array.from(compiler.op);
        const x = Int32Array.from(compiler.x);
        const y = Int32Array.from(compiler.y);
        const waits = op.filter((code) => code === BYTE || code === SET || code === MATCH).length;
        const program: Program = {
            op,
            x,
            y,
            tables: compiler.tables,
            slots: 2 * parser.groups,
            waits,
            anchored: isAnchored(op, x, y),
        };
        return new Regex(program, parser.names);
    }

    /** Whether the pattern has a named group `name`. */
    hasGroup(name: string): boolean {
        return this.names.has(name);
    }

    /** Whether the pattern matches anywhere in `haystack`. */
    isMatch(haystack: Uint8Array): boolean {
        const machine = (this.matcher ??= new Machine(this.program, this.noSlot, 0));
        machine.reset(haystack);
        machine.run(Infinity);
        return machine.found;
    }

    /**
     * The leftmost-first match and all its groups, or null. Each call builds a machine that
     * records every group. Use `capturer` to match many inputs.
     */
    captures(haystack: Uint8Array): RegexCaptures | null {
        const every = Int32Array.from(this.noSlot, (_, slot) => slot);
        return new Capturer(this.program, every, every.length, this.names).captures(haystack);
    }

    /**
     * A matcher that records only the named groups in `names`. Its memory, reported by `bytes`,
     * grows with the program size times the number of groups it records. Throws for a name that
     * is not a group of the pattern.
     */
    capturer(names: readonly string[]): RegexCapturer {
        const { slotOf, slots } = this.recorded(names);
        return new Capturer(this.program, slotOf, slots, this.names);
    }

    /** The `bytes` of `capturer(names)`, known without building it. */
    capturerBytes(names: readonly string[]): number {
        return Machine.bytes(this.program, this.recorded(names).slots);
    }

    /** The slot map and the number of slots of a matcher that records the groups in `names`. */
    private recorded(names: readonly string[]): { slotOf: Int32Array; slots: number } {
        const slotOf = this.noSlot.slice();
        let slots = 0;
        for (const name of names) {
            const index = this.names.get(name);
            if (index === undefined) throw new Error('the pattern has no group named ' + name);
            if (slotOf[2 * index] < 0) {
                slotOf[2 * index] = slots++;
                slotOf[2 * index + 1] = slots++;
            }
        }
        return { slotOf, slots };
    }

    /** The search of `isMatch` run in slices. The haystack must not change until it finishes. */
    search(haystack: Uint8Array): RegexSearch {
        const machine = new Machine(this.program, this.noSlot, 0);
        machine.reset(haystack);
        return new Search(machine);
    }
}
