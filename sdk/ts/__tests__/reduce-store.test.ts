/**
 * Reduce through the store, on the isolated simulator and on the IndexedDB store.
 *
 * A case of the first suite writes its rows to both stores, runs each request on both through a
 * Client and compares the answers (support/reduce-compare.ts states what is compared). Where a
 * case names values, the answer of the IndexedDB store must also equal them. The second suite
 * tests what the IndexedDB store does on its own terms, such as its limits, on that store alone.
 * The last suite tests the comparison itself.
 */
import { create, toBinary } from '@bufbuild/protobuf';
import { Code, ConnectError, createConnectRouter } from '@connectrpc/connect';
import { readFileSync } from 'fs';
import * as path from 'path';
import { Client } from '../src/client';
import {
    KvFieldKind,
    RangeReduceGroupSchema,
    RangeReduceOp,
    ReduceRequestSchema,
    ReduceResponseSchema,
    type ReduceRequest,
} from '../src/gen/ts/store/v1/query_pb';
import { deleteIndexedDbStore, openIndexedDbStore, type IndexedDbStore } from '../src/indexeddb';
import { planReduce, validateReduceEnvelope } from '../src/indexeddb/reduce';
import { decodeStoredRow } from '../src/indexeddb/reduce/codec';
import * as lowercase from '../src/indexeddb/reduce/lowercase';
import { LOWERCASE_DIGEST, UNICODE_VERSION } from '../src/indexeddb/reduce/lowercase-tables';
import { MAX_KEY_LEN } from '../src/limits';
import { freshDatabaseName } from './support/backends';
import { abortCall, collect, failure, put, until, utf8, type Row } from './support/contract';
import {
    answer,
    compare,
    describeError,
    renderKeys,
    renderResults,
    showError,
    type ErrorDescription,
    type Outcome,
} from './support/reduce-compare';
import {
    be,
    C,
    encodeRow,
    F,
    floatBits,
    floatOfBits,
    interleave,
    KEY,
    pred,
    R,
    rng,
    SV,
    V,
    varint,
    X,
    type ConstraintInit,
    type ExprInit,
    type ParamsInit,
    type ValueInit,
} from './support/reduce-gen';
import { evaluate, rangeRequest, ReducePair, Tally, type Checked, type Dataset } from './support/reduce-pair';

const K = KvFieldKind;
const I64_MAX = (1n << 63n) - 1n;
const I64_MIN = -(1n << 63n);
const MIB = 1024 * 1024;
const { toLowercase } = lowercase;

/** Rows of the given column values under increasing keys. */
const table = (...rows: (Uint8Array | null)[][]): Row[] => rows.map((values, i): Row => [be(i, 8), encodeRow(values)]);

const i64 = (index: number, nullable = true): ExprInit => X.v(index, K.INT64, nullable);
const f64 = (index: number): ExprInit => X.v(index, K.FLOAT64);
const text = (index: number): ExprInit => X.v(index, K.UTF8);
const int = (value: bigint | number): ExprInit => X.lit(V.i64(value));
const atLeast = (index: number, min: number, nullable = true) => pred([[F.value(index, K.INT64, nullable), C.intRange(min)]]);
const ints = (...values: (bigint | number | null)[]): Row[] => table(...values.map((value) => [value === null ? null : SV.i64(value)]));
const floats = (...bits: (bigint | null)[]): Row[] => table(...bits.map((value) => [value === null ? null : SV.f64bits(value)]));

/** One line per group, "keys => results", sorted. */
const groupLines = (outcome: Outcome): string[] => outcome.frames.flatMap((frame) => frame.groups)
    .map((group) => renderKeys(group).join(' | ') + ' => ' + renderResults(group.results).join(', '))
    .sort();

describe('Reduce on the isolated simulator and on the IndexedDB store', () => {
    let pair: ReducePair;

    beforeAll(async () => {
        pair = await ReducePair.open();
    });

    afterEach(() => pair.release());

    afterAll(() => pair.close());

    /** What a case expects of the answer, in the text form of support/reduce-compare.ts. */
    interface Want {
        /** The results of a request without group_by. */
        results?: string[];
        /** One line per group, "keys => results", in any order. */
        groups?: string[];
        /**
         * The code and the text of the error. The text is the field description of an
         * INVALID_ARGUMENT and the message of any other error.
         */
        error?: [string, string];
    }

    /**
     * Expects both stores to agree, error text included, and the IndexedDB store to answer what
     * `want` names.
     */
    async function expectAnswer(dataset: Dataset, params: ParamsInit, want: Want = {}): Promise<Checked> {
        const checked = await pair.check(dataset, params);
        expect(checked.comparison).toEqual(expect.objectContaining({ status: 'identical', detail: '' }));
        const { actual } = checked;
        if (want.error !== undefined) {
            expect(actual.error).toBeDefined();
            const { code, message, description } = describeError(actual.error as ConnectError);
            expect([code, description ?? message]).toEqual(want.error);
        } else if (want.results !== undefined || want.groups !== undefined) {
            expect(actual.error === undefined ? 'success' : showError(actual.error)).toBe('success');
        }
        if (want.results !== undefined) expect(renderResults(actual.frames[0].results)).toEqual(want.results);
        if (want.groups !== undefined) expect(groupLines(actual)).toEqual([...want.groups].sort());
        return checked;
    }

    const invalidArgument = (description: string): Want => ({ error: ['InvalidArgument', description] });
    const failedPrecondition = (message: string): Want => ({ error: ['FailedPrecondition', message] });

    describe('reducers', () => {
        test('counts, sums and takes the extrema of a range', async () => {
            const dataset = await pair.store(ints(10, 20, null, -5));
            await expectAnswer(dataset, { reducers: [R.countAll(), R.count(i64(0)), R.sum(i64(0)), R.min(i64(0)), R.max(i64(0))] },
                { results: ['u64:4', 'u64:3', 'i64:25', 'i64:-5', 'i64:20'] });
        });

        test('rows without columns are counted', async () => {
            await expectAnswer(await pair.store(table([], [], [])), { reducers: [R.countAll()] }, { results: ['u64:3'] });
        });

        test('an empty range counts zero and has no sum or extremum', async () => {
            const dataset = await pair.store([]);
            await expectAnswer(dataset, { reducers: [R.countAll(), R.count(i64(0)), R.sum(i64(0)), R.min(i64(0)), R.max(i64(0))] },
                { results: ['u64:0', 'u64:0', 'NULL', 'NULL', 'NULL'] });
            await expectAnswer(dataset, { reducers: Array.from({ length: 65536 }, (_, index) => R.count(i64(index))) },
                { results: new Array<string>(65536).fill('u64:0') });
        });

        test('sums floats', async () => {
            const dataset = await pair.store(table([SV.f64(1.5)], [SV.f64(2.5)]));
            await expectAnswer(dataset, { reducers: [R.sum(f64(0))] }, { results: ['f64:4/4010000000000000'] });
        });

        test('integer sums and arithmetic wrap', async () => {
            const dataset = await pair.store(ints(I64_MAX, 2));
            await expectAnswer(dataset, { reducers: [R.countAll(), R.sum(i64(0)), R.sum(X.add(i64(0), int(1)))] },
                { results: ['u64:2', 'i64:' + (I64_MIN + 1n), 'i64:' + (I64_MIN + 3n)] });
        });

        test('arithmetic over literals wraps and does not read the stored row', async () => {
            const dataset = await pair.store([[be(0, 8), utf8('invalid row')]]);
            await expectAnswer(dataset, {
                reducers: [
                    R.min(X.add(int(I64_MAX), int(1))),
                    R.min(X.sub(X.lit(V.u64(0)), X.lit(V.u64(1)))),
                    R.min(X.mul(int(I64_MAX), int(2))),
                ],
            }, { results: ['i64:' + I64_MIN, 'u64:' + ((1n << 64n) - 1n), 'i64:-2'] });
        });

        test('expressions keep their types and values', async () => {
            const [i, u, f] = [i64(0), X.v(1, K.UINT64), f64(2)];
            const dataset = await pair.store(table(
                [SV.i64(7), SV.u64(7), SV.f64(2), SV.i64(-1), SV.i64(-1), SV.i64(-1)],
                [null, null, null, null, null, null],
            ));
            const cases: [ExprInit, string][] = [
                [X.add(i, int(2)), 'i64:9'],
                [X.sub(u, X.lit(V.u64(9))), 'u64:18446744073709551614'],
                [X.mul(i, i), 'i64:49'],
                [X.div(i, int(2)), 'i64:3'],
                [X.div(u, X.lit(V.u64(2))), 'u64:3'],
                [X.div(i, f), 'f64:3.5/400c000000000000'],
                [X.trunc(X.v(3, K.TIMESTAMP)), 'ts:-86400000000'],
                [X.trunc(X.v(4, K.DATE32)), 'ts:-86400000000'],
                [X.trunc(X.v(5, K.DATE64)), 'ts:-86400000000'],
                [X.add(i, u), 'd128:14'],
                [X.div(u, i), 'd128:10000'],
                [X.mul(u, f), 'f64:14/402c000000000000'],
                [X.cast(i), 'f64:7/401c000000000000'],
                [X.cast(u), 'f64:7/401c000000000000'],
                [X.cast(f), 'f64:2/4000000000000000'],
                [X.sub(X.mul(X.add(i, int(10)), int(2)), int(5)), 'i64:29'],
            ];
            await expectAnswer(dataset, { reducers: cases.map(([expr]) => R.min(expr)) }, { results: cases.map(([, want]) => want) });
        });

        test('lower follows the Unicode lowercase mapping of the whole string', async () => {
            const dataset = await pair.store(table([SV.str('\u039f\u03a3 \u0130 MIXED')], [null]));
            await expectAnswer(dataset, { reducers: [R.min(X.lower(text(0))), R.count(X.lower(text(0)))] },
                { results: ['utf8:"\u03bf\u03c2 i\u0307 mixed"', 'u64:1'] });
        });

        test('integers and decimals of both widths meet in a decimal', async () => {
            const dataset = await pair.store(table([SV.i64(7), SV.u64(2), SV.d128(3), SV.d256(11)]));
            const [i, u, d128, d256] = [i64(0), X.v(1, K.UINT64), X.v(2, K.DECIMAL128), X.v(3, K.DECIMAL256)];
            const cases: [ExprInit, string][] = [
                // Division adds four digits of scale and truncates.
                [X.div(i, u), 'd128:35000'],
                [X.div(d128, X.lit(V.d128(-2))), 'd128:-15000'],
                [X.mul(X.div(d128, d128), d128), 'd128:30000'],
                [X.add(d128, d256), 'd256:14'],
                [X.div(i, d256), 'd256:6363'],
                [X.sub(d256, X.div(i, d256)), 'd256:103637'],
                // Scales 4 and 8 meet at 8.
                [X.add(X.div(i, d256), X.div(X.div(d128, d128), d128)), 'd256:96963333'],
                [X.cast(X.div(X.div(d128, d128), d128)), 'f64:0.33333333/3fd5555551c112da'],
            ];
            await expectAnswer(dataset, { reducers: cases.map(([expr]) => R.max(expr)) }, { results: cases.map(([, want]) => want) });
        });

        test('float division by a signed zero gives NaN for a zero dividend and a signed infinity otherwise', async () => {
            const dataset = await pair.store(table(
                [SV.i64(0), SV.f64(0), SV.f64(-0)],
                [SV.i64(1), SV.f64(1), SV.f64(-0)],
                [SV.i64(2), SV.f64(0), SV.f64(0)],
                [SV.i64(3), SV.f64(1), SV.f64(0)],
            ));
            const quotients = ['f64:NaN', 'f64:-Infinity/fff0000000000000', 'f64:NaN', 'f64:Infinity/7ff0000000000000'];
            for (const [row, quotient] of quotients.entries()) {
                await expectAnswer(dataset, {
                    reducers: [R.sum(X.div(f64(1), f64(2)))],
                    filter: pred([[F.value(0, K.INT64), C.intRange(row, row)]]),
                }, { results: [quotient] });
            }
        });

        test('cast_float64 rounds integers to the nearest double and keeps NULL', async () => {
            const columns: [KvFieldKind, (Uint8Array | null)[]][] = [
                [K.INT64, [null, I64_MIN, -(1n << 53n) - 1n, 0n, (1n << 53n) + 1n, I64_MAX].map((v) => (v === null ? null : SV.i64(v)))],
                [K.UINT64, [null, 0n, (1n << 53n) - 1n, 1n << 53n, (1n << 53n) + 1n, (1n << 64n) - 1n].map((v) => (v === null ? null : SV.u64(v)))],
                [K.BOOLEAN, [null, SV.bool(false), SV.bool(true)]],
                [K.UTF8, [null, SV.str('3.25'), SV.str('-0.5')]],
            ];
            const wanted = [
                ['NULL', 'f64:-9223372036854776000/c3e0000000000000', 'f64:-9007199254740992/c340000000000000', 'f64:0/0',
                    'f64:9007199254740992/4340000000000000', 'f64:9223372036854776000/43e0000000000000'],
                ['NULL', 'f64:0/0', 'f64:9007199254740991/433fffffffffffff', 'f64:9007199254740992/4340000000000000',
                    'f64:9007199254740992/4340000000000000', 'f64:18446744073709552000/43f0000000000000'],
                ['NULL', 'f64:0/0', 'f64:1/3ff0000000000000'],
                ['NULL', 'f64:3.25/400a000000000000', 'f64:-0.5/bfe0000000000000'],
            ];
            for (const [column, [kind, values]] of columns.entries()) {
                const dataset = await pair.store(table(...values.map((value, row) => [SV.i64(row), value])));
                for (const row of values.keys()) {
                    await expectAnswer(dataset, {
                        reducers: [R.min(X.cast(X.v(1, kind)))],
                        filter: pred([[F.value(0, K.INT64), C.intRange(row, row)]]),
                    }, { results: [wanted[column][row]] });
                }
            }
        });

        test('expressions over key fields share a column and do not read the stored row', async () => {
            const dataset = await pair.store([[KEY.i64(3), utf8('not a stored row')]]);
            const doubled = X.add(X.k(dataset.prefix.length, K.INT64), X.k(dataset.prefix.length, K.INT64));
            await expectAnswer(dataset, { groupBy: [doubled], reducers: [R.sum(doubled), R.countAll(), R.sum(X.cast(doubled))] },
                { groups: ['i64:6 => i64:6, u64:1, f64:6/4018000000000000'] });
        });

        test('the request filter decides which rows exist', async () => {
            const dataset = await pair.store(ints(10, 20, 30));
            await expectAnswer(dataset, { reducers: [R.sum(i64(0))], filter: atLeast(0, 15, false) }, { results: ['i64:50'] });
            await expectAnswer(dataset, { reducers: [R.countAll()], filter: atLeast(0, 20, false) }, { results: ['u64:2'] });
        });

        test('a reducer FILTER is applied before its argument without group_by and after it with group_by', async () => {
            const dataset = await pair.store(ints(1, 2, 3, 4));
            const division = X.div(i64(0), X.sub(i64(0), int(1)));
            for (const [expr, sum] of [[division, 'i64:4'], [X.cast(division), 'f64:4/4010000000000000']] as const) {
                const reducers = [R.countAll(), R.sum(expr, atLeast(0, 2))];
                await expectAnswer(dataset, { reducers }, { results: ['u64:4', sum] });
                await expectAnswer(dataset, { reducers, groupBy: [int(0)] }, failedPrecondition('Arrow error: Divide by zero error'));
                await expectAnswer(dataset, { reducers, groupBy: [int(0)], filter: atLeast(0, 2) }, { groups: ['i64:0 => u64:3, ' + sum] });
            }
        });

        test('a reducer FILTER keeps the groups of the rows it rejects', async () => {
            const dataset = await pair.store(ints(1, null, 3));
            const reducers = [R.countAll(atLeast(0, 2)), R.countAll()];
            await expectAnswer(dataset, { reducers }, { results: ['u64:1', 'u64:3'] });
            await expectAnswer(dataset, { reducers, groupBy: [i64(0)] },
                { groups: ['i64:1 => u64:0, u64:1', 'NULL => u64:0, u64:1', 'i64:3 => u64:1, u64:1'] });
            await expectAnswer(await pair.store([[be(0, 8), utf8('bad row')]]), { reducers },
                failedPrecondition('Invalid Bool: Expected 0 or 1, found different value'));
        });

        test('a reducer FILTER over a key field does not read the stored row', async () => {
            const dataset = await pair.store([[KEY.i64(1), utf8('bad row')], [KEY.i64(2), utf8('bad row')]]);
            const filter = pred([[F.key(dataset.prefix.length, K.INT64), C.intRange(2)]]);
            await expectAnswer(dataset, { reducers: [R.countAll(filter), R.countAll()] }, { results: ['u64:1', 'u64:2'] });
        });

        test('MIN and MAX of text follow the UTF-8 bytes', async () => {
            const dataset = await pair.store(table([SV.str('\uffff')], [SV.str('\u{1f600}')], [SV.str('a')], [SV.str('ab')]));
            await expectAnswer(dataset, { reducers: [R.min(text(0)), R.max(text(0))] }, { results: ['utf8:"a"', 'utf8:"\u{1f600}"'] });
        });
    });

    describe('grouping', () => {
        test('counts and sums per group', async () => {
            const dataset = await pair.store(table(
                [SV.str('west'), SV.i64(10)],
                [SV.str('east'), SV.i64(20)],
                [SV.str('west'), SV.i64(30)],
            ));
            await expectAnswer(dataset, { reducers: [R.countAll(), R.sum(i64(1))], groupBy: [text(0)] },
                { groups: ['utf8:"east" => u64:1, i64:20', 'utf8:"west" => u64:2, i64:40'] });
            await expectAnswer(dataset, { groupBy: [text(0)] }, { groups: ['utf8:"east" => ', 'utf8:"west" => '] });
        });

        test('groups by a key field of fixed size binary', async () => {
            const dataset = await pair.store([[utf8('a\u0001'), encodeRow([SV.i64(1)])], [utf8('a\u0002'), encodeRow([SV.i64(2)])],
                [utf8('b\u0001'), encodeRow([SV.i64(3)])]]);
            await expectAnswer(dataset, { reducers: [R.countAll()], groupBy: [X.k(dataset.prefix.length, { fsb: 1 })] },
                { groups: ['fsb:61 => u64:2', 'fsb:62 => u64:1'] });
        });

        test('keys of several columns are told apart', async () => {
            const pairs: [string | null, string | null][] = [['1', null], [null, '1'], ['', 'N'], ['N', ''], ['a|sb', 'c'], ['a', 'b|sc'],
                ['a', 'b'], ['a', 'b'], [null, null], ['\u00e9', 'e\u0301']];
            const dataset = await pair.store(table(...pairs.map((pair) => pair.map((value) => (value === null ? null : SV.str(value))))));
            const { actual } = await expectAnswer(dataset, { reducers: [R.countAll()], groupBy: [text(0), text(1)] });
            expect(groupLines(actual)).toHaveLength(9);
            expect(groupLines(actual)).toContain('utf8:"a" | utf8:"b" => u64:2');
        });

        test('reads Z-order fields of uneven widths at a bit offset inside a byte', async () => {
            const widths = [1, 0, 2, 3, 1, 8, 2, 0, 4];
            const noise = rng(2);
            const rows = Array.from({ length: 6 }, (_, row): Row => {
                const block = interleave(widths.map((width) => Uint8Array.from({ length: width }, () => noise.int(256))));

                // A counter byte keeps keys unique, and the block starts 3 bits after it.
                const key = new Uint8Array(block.length + 2);
                key[0] = row;
                block.forEach((byte, i) => {
                    key[i + 1] |= byte >> 3;
                    key[i + 2] |= (byte << 5) & 0xff;
                });
                return [key, encodeRow([])];
            });
            const dataset = await pair.store(rows);
            const field = (position: number, kind: Parameters<typeof F.zorder>[3]) =>
                X.f(F.zorder((dataset.prefix.length + 1) * 8 + 3, position, widths, kind));
            const fields = [...widths.map((width, position) => field(position, { fsb: width })), field(5, K.INT64), field(5, K.FLOAT64),
                field(3, K.UTF8), field(0, K.BOOLEAN)];
            await expectAnswer(dataset, { reducers: fields.flatMap((expr) => [R.min(expr), R.max(expr)]) });
            const { actual } = await expectAnswer(dataset, { reducers: [R.countAll()], groupBy: [field(2, { fsb: 2 }), field(6, { fsb: 2 })] });
            expect(groupLines(actual)).toHaveLength(6);
            await expectAnswer(dataset, { reducers: [R.min(field(9, { fsb: 0 }))] }, failedPrecondition('invalid z-order key field'));
            await expectAnswer(dataset, { reducers: [R.min(field(5, K.DATE32))] }, failedPrecondition('invalid z-order key field'));
        });

        test('NULL is a key, the two zeros are one key and NaNs of different bits are different keys', async () => {
            const dataset = await pair.store(floats(null, 0x8000000000000000n, 0n, 0x7ff8000000000001n, 0x7ff8000000000001n, 0x7ff8000000000002n));
            await expectAnswer(dataset, { reducers: [R.countAll()], groupBy: [f64(0)] },
                { groups: ['NULL => u64:1', 'f64:0/0 => u64:2', 'f64:NaN => u64:2', 'f64:NaN => u64:1'] });
        });

        test('takes float extrema with and without group_by', async () => {
            const [inf, negInf, nan, negNan] = [0x7ff0000000000000n, 0xfff0000000000000n, 0x7ff8000000000001n, 0xfff8000000000001n];
            const zero = 0n;
            const negZero = 0x8000000000000000n;
            const one = 0x3ff0000000000000n;
            const two = 0x4000000000000000n;
            const inputs = [[], [null], [inf], [negInf], [nan, zero], [zero, nan], [negNan, negInf], [negInf, negNan], [nan, negNan],
                [negNan, nan], [zero, negZero], [negZero, zero], [null, one, nan, two, null]];

            // With group_by the first of two zeros wins, a NaN replaces the value before it and
            // is replaced by the value after it, and a group of one infinity keeps the finite
            // starting value.
            const grouped: Record<number, string> = {
                2: 'f64:1.7976931348623157e+308/7fefffffffffffff, f64:Infinity/7ff0000000000000, u64:1',
                3: 'f64:-Infinity/fff0000000000000, f64:-1.7976931348623157e+308/ffefffffffffffff, u64:1',
                4: 'f64:0/0, f64:0/0, u64:2',
                5: 'f64:NaN, f64:NaN, u64:2',
                10: 'f64:0/0, f64:0/0, u64:2',
                11: 'f64:-0/8000000000000000, f64:-0/8000000000000000, u64:2',
            };

            // Without group_by the extrema follow the total order, where -0 lies below +0,
            // negative NaNs at the bottom and positive NaNs at the top.
            const scalar: Record<number, string[]> = {
                4: ['f64:0/0', 'f64:NaN', 'u64:2'],
                6: ['f64:NaN', 'f64:-Infinity/fff0000000000000', 'u64:2'],
                10: ['f64:-0/8000000000000000', 'f64:0/0', 'u64:2'],
                12: ['f64:1/3ff0000000000000', 'f64:NaN', 'u64:3'],
            };
            for (const [index, values] of inputs.entries()) {
                const dataset = await pair.store(floats(...values));
                const reducers = [R.min(f64(0)), R.max(f64(0)), R.count(f64(0))];
                await expectAnswer(dataset, { reducers }, { results: scalar[index] });
                await expectAnswer(dataset, { reducers, groupBy: [int(0)] },
                    { groups: grouped[index] === undefined ? undefined : ['i64:0 => ' + grouped[index]] });
            }
        });

        test('decimal sums wrap at their word in every group', async () => {
            const groups = 64;
            const max256 = (1n << 255n) - 1n;
            const rows: Row[] = [];
            for (const pass of [0, 1]) {
                for (let group = 0; group < groups; group++) {
                    const filled = group !== 0;
                    rows.push([be(pass * groups + group, 8), encodeRow([
                        SV.str(String(group).padStart(8, '0') + '-' + 'x'.repeat(64)),
                        filled ? SV.d128(pass === 0 ? (1n << 127n) - 1n : 1n) : null,
                        filled ? SV.d256(pass === 0 ? max256 : 1n) : null,
                        filled ? SV.f64(pass === 0 ? -100 : 100) : null,
                    ])]);
                }
            }
            const [d128, d256] = [X.v(1, K.DECIMAL128), X.v(2, K.DECIMAL256)];
            const { actual } = await expectAnswer(await pair.store(rows), {
                reducers: [R.countAll(), R.sum(d128), R.sum(d256), R.min(d128), R.max(d256), R.min(f64(3)), R.max(f64(3))],
                groupBy: [text(0)],
            });
            const lines = groupLines(actual);
            expect(lines).toHaveLength(groups);
            expect(lines[0]).toMatch(/^utf8:"00000000-x+" => u64:2, NULL, NULL, NULL, NULL, NULL, NULL$/);
            expect(lines[1]).toBe('utf8:"00000001-' + 'x'.repeat(64) + '" => u64:2, d128:' + -(1n << 127n) + ', d256:' + -(1n << 255n)
                + ', d128:1, d256:' + max256 + ', f64:-100/c059000000000000, f64:100/4059000000000000');
        });
    });

    describe('input batches', () => {
        // A sum that tells where a batch ends, for an end that is a multiple of the four lanes.
        // Next to 1e16 a single 1 is lost and two of them are not. The sum is 1e16 + 2 when a batch
        // ends right before row end, 1e16 + 4 when it ends one row earlier, and 1e16 when it ends
        // one row later or holds every row. 1e16 stands in row 1 so that a batch of every row adds
        // each 1 to it alone.
        const endsBefore = (end: number): number[] => {
            const values = new Array<number>(end + 2).fill(0);
            values[1] = 1e16;
            values[end - 1] = values[end] = values[end + 1] = 1;
            return values;
        };
        const ENDS_THERE = 'f64:10000000000000002/4341c37937e08001';
        const sum = R.sum(f64(0));

        test('a float sum without group_by adds a batch in four lanes, and in two when it holds a NULL', async () => {
            const sumOf = async (values: (number | null)[], want: string) => {
                const dataset = await pair.store(table(...values.map((value) => [value === null ? null : SV.f64(value)])));
                await expectAnswer(dataset, { reducers: [sum] }, { results: [want] });
                return dataset;
            };

            // Row j joins lane j modulo 4. The lanes of rows 1 and 3 add up to 2 before they meet
            // 1e16, and rows 2 and 4 are lost next to it.
            const dataset = await sumOf([1e16, 1, 1, 1, 1], ENDS_THERE);

            // The fold adds lane 2 to lane 0 and lane 3 to lane 1, so the two large values cancel
            // and the two small ones add up before the halves meet.
            await sumOf([1e16, 1, -1e16, 1], 'f64:2/4000000000000000');

            // With group_by the values are added one by one, and each 1 is lost.
            await expectAnswer(dataset, { reducers: [sum], groupBy: [int(0)] }, { groups: ['i64:0 => f64:10000000000000000/4341c37937e08000'] });

            // Rows 0 and 4 share a lane and cancel before row 8 joins them.
            await sumOf([1e16, 0, 0, 0, -1e16, 0, 0, 0, 1], 'f64:1/3ff0000000000000');

            // With a NULL in the batch, rows 0, 2 and 4 share one of two lanes.
            await sumOf([1e16, null, -1e16, 1, 1], 'f64:2/4000000000000000');
        });

        // The tests run the store on fake-indexeddb, where walking a cursor over a key range takes
        // time that grows with the square of its rows. This is the one case with more rows than a
        // chunk, and it scans them twice, so it gets a longer timeout.
        test('a batch ends with its chunk of 4096 rows, and a frame with its 4096th group', async () => {
            const dataset = await pair.store(table(...endsBefore(4096).map((value, row) => [SV.f64(value), SV.i64(row)])));
            await expectAnswer(dataset, { reducers: [sum] }, { results: [ENDS_THERE] });

            const { expected, actual } = await expectAnswer(dataset, { reducers: [R.countAll()], groupBy: [i64(1)] });
            for (const [outcome, sequence] of [[actual, dataset.sequence.store], [expected, dataset.sequence.simulator]] as const) {
                expect(outcome.frames.map((frame) => [frame.groups.length, frame.detail?.sequenceNumber]))
                    .toEqual([[4096, sequence], [2, sequence]]);
            }
        }, 240_000);

        test('an expression over literals runs once per batch, also when the filter rejects every row', async () => {
            const reducers = [R.min(X.div(int(1), int(0)))];
            await expectAnswer(await pair.store([]), { reducers }, { results: ['NULL'] });
            const dataset = await pair.store(ints(1, 2));
            await expectAnswer(dataset, { reducers, filter: atLeast(0, 5) }, failedPrecondition('Arrow error: Divide by zero error'));
            await expectAnswer(dataset, { reducers: [R.min(X.div(i64(0), int(0)))], filter: atLeast(0, 5) }, { results: ['NULL'] });
            await expectAnswer(dataset, { reducers: [R.min(X.div(int(1), int(0)), pred([], true))] },
                failedPrecondition('Arrow error: Divide by zero error'));
        });

        test('a decode error in a later row comes before an arithmetic error in an earlier row of the batch', async () => {
            const dataset = await pair.store([[be(0, 8), encodeRow([SV.i64(1)])], [be(1, 8), utf8('malformed')]]);
            await expectAnswer(dataset, { reducers: [R.sum(X.div(i64(0), int(0)))] },
                failedPrecondition('Invalid Bool: Expected 0 or 1, found different value'));
        });

        describe('the byte budget of a batch', () => {
            // A batch holds at most 16 MiB of rows by the plan's size formula. At 65281 bytes per
            // row, 257 rows pass the budget by one byte, and at 65536 bytes 256 rows fill it
            // exactly. Both sizes end the batch before row 256. One byte less per row moves the end
            // at the first size, and one byte more moves it at the second. A literal makes up the
            // rest of each row size after the bytes that a case measures.
            const ROW_SIZES = [65281, 65536];
            const WORDS = '\u00c9'.repeat(10) + '\u{1f600}'.repeat(5);
            const WORD_BYTES = 40;
            const rows = table(...endsBefore(256).map((value, row) =>
                [SV.f64(value), SV.i64(row), SV.i64(-row), SV.str(WORDS + 'ab'.charAt(row % 2))]));
            const [a, b, words] = [i64(1), i64(2), text(3)];
            /** Bytes that the summed column adds to every row. */
            const SUMMED = 48;

            /**
             * Expects the float sum to end its batch before row 256 when `reducers` add `measured`
             * bytes to every row and a literal fills the rest of each row size.
             */
            async function expectMeasured(measured: number, reducers: ParamsInit['reducers'] = []): Promise<void> {
                const dataset = await pair.store(rows);
                for (const size of ROW_SIZES) {
                    const filler = R.count(X.lit(V.str('X'.repeat(size - SUMMED - measured - 48))));
                    const { actual } = await expectAnswer(dataset, { reducers: [sum, ...reducers, filler] });
                    expect(renderResults(actual.frames[0].results)[0]).toBe(ENDS_THERE);
                }
            }

            test('counts 48 bytes for a column and for a literal', () => expectMeasured(0));

            test('counts every column that is read, and text by its UTF-8 bytes', () =>
                expectMeasured(2 * 48 + 48 + WORD_BYTES + 1, [R.max(a), R.max(b), R.min(words)]));

            test('counts a column once more for every expression that computes with it', () =>
                expectMeasured(4 * 48 + 2 * 48, [R.max(X.cast(a)), R.max(X.add(a, X.mul(a, b)))]));

            test('counts the literal of COUNT_ALL and one byte for every reducer FILTER', () =>
                expectMeasured(3 * (48 + 1), [R.countAll(atLeast(1, 0)), R.countAll(atLeast(1, 100)), R.countAll(pred([], true))]));

            test('counts twelve times what lower computes with', () =>
                expectMeasured(13 * (48 + WORD_BYTES + 1) + 144 * (48 + 2), [R.min(X.lower(words)), R.count(X.lower(X.lower(X.lit(V.str('Ab')))))]));
        });
    });

    describe('frames', () => {
        const frameSizes = (outcome: Outcome): number[] => outcome.frames.map((frame) => frame.groups.length);

        test('a grouped request without groups answers one frame with only detail', async () => {
            const { actual } = await expectAnswer(await pair.store([]), { reducers: [R.countAll()], groupBy: [i64(0)] });
            expect(actual.frames).toHaveLength(1);
            expect(actual.frames[0].detail).toEqual(expect.objectContaining({ sequenceNumber: 0n, extra: {} }));
        });

        test('frames stay near 16 MiB and a larger group travels alone', async () => {
            // Each group encodes to exactly 1 MiB. A frame counts 16 bytes more per group, so it
            // takes 15 of them.
            const key = (row: number, length: number) => String(row).padStart(2, '0') + 'k'.repeat(length - 2);
            const encoded = (length: number) => toBinary(RangeReduceGroupSchema, create(RangeReduceGroupSchema, {
                groupValues: [V.str(key(0, length))],
                groupValuesPresent: [true],
                results: [{ value: V.u64(1) }],
            })).length;
            const length = MIB - (encoded(MIB) - MIB);
            expect(encoded(length)).toBe(MIB);
            const dataset = await pair.store(table(...Array.from({ length: 17 }, (_, row) => [SV.str(key(row, length))])));
            const checked = await pair.check(dataset, { reducers: [R.countAll()], groupBy: [text(0)] }, false);
            expect(checked.comparison.status).toBe('identical');
            expect(frameSizes(checked.actual)).toEqual(frameSizes(checked.expected));
            expect(frameSizes(checked.actual)).toEqual([15, 2]);
            await pair.release();

            const wide = await pair.store(table([SV.str('w'.repeat(9 * MIB))]));
            const alone = await pair.check(wide, { reducers: [R.countAll(), R.min(text(0))], groupBy: [text(0)] }, false);
            expect(alone.comparison.status).toBe('identical');
            expect(frameSizes(alone.actual)).toEqual([1]);
        });

        test('a result the wire cannot carry fails the request', async () => {
            const dataset = await pair.store(table([SV.i64(5), SV.i64(3)], [null, SV.i64(3)]));
            const elapsed = X.sub(X.v(0, K.TIMESTAMP), X.v(1, K.TIMESTAMP));
            const unsupported = failedPrecondition('Execution error: unsupported native Reduce result type');
            await expectAnswer(dataset, { reducers: [R.min(elapsed)] }, unsupported);
            await expectAnswer(dataset, { reducers: [R.countAll()], groupBy: [elapsed] }, unsupported);
            await expectAnswer(dataset, { reducers: [R.count(elapsed), R.min(X.cast(elapsed))] }, { results: ['u64:1', 'f64:2/4000000000000000'] });
        });
    });

    describe('errors', () => {
        test('rejects long range bounds and empty params, and an inverted range holds no row', async () => {
            const dataset = await pair.store(ints(1));
            const long = new Uint8Array(255);
            const countAll: ParamsInit = { reducers: [R.countAll()] };
            const keyLength = (field: string): ErrorDescription => ({
                code: 'InvalidArgument',
                message: field + ' key length is outside store limits',
                field,
                description: 'key length 255 exceeds max 254',
                reason: 'INVALID_KEY_LENGTH',
                domain: 'store.query',
                metadata: { description: 'key length 255 exceeds max 254', max_key_len: '254' },
            });
            const empty: ErrorDescription = {
                code: 'InvalidArgument',
                message: 'reduce request must specify at least one reducer or group_by',
                field: 'params',
                description: 'at least one reducer or group_by field is required',
                reason: 'INVALID_REDUCE_PARAMS',
                domain: 'store.query',
                metadata: { description: 'at least one reducer or group_by field is required' },
            };
            const cases: [ReduceRequest, ErrorDescription][] = [
                [rangeRequest({ start: long, end: dataset.end }, countAll), keyLength('start')],
                [rangeRequest({ start: dataset.start, end: long }, countAll), keyLength('end')],
                [rangeRequest({ start: long, end: long }, {}), keyLength('start')],
                [rangeRequest(dataset, {}), empty],
                [rangeRequest(dataset, { filter: pred([]) }), empty],
                [create(ReduceRequestSchema, { start: dataset.start, end: dataset.end }), empty],
            ];
            for (const [message, want] of cases) {
                const { comparison, actual } = await pair.request(dataset, message);
                expect(comparison).toEqual(expect.objectContaining({ status: 'identical', detail: '' }));
                expect(describeError(actual.error as ConnectError)).toEqual(want);
            }

            // A range whose start lies above its end holds no row.
            const inverted = await pair.request(dataset, rangeRequest({ start: dataset.end, end: dataset.start }, countAll));
            expect(inverted.comparison.status).toBe('identical');
            expect(renderResults(inverted.actual.frames[0].results)).toEqual(['u64:0']);
        });

        test('rejects params that cannot be converted', async () => {
            const dataset = await pair.store(ints(1));
            const field = (init: Parameters<typeof X.f>[0]): ParamsInit => ({ reducers: [R.min(X.f(init))] });
            const literal = (init: Parameters<typeof X.lit>[0]): ParamsInit => ({ reducers: [R.min(X.lit(init))] });
            const check1 = (init: NonNullable<ReturnType<typeof pred>['checks']>[number]): ParamsInit =>
                ({ reducers: [R.countAll()], filter: { checks: [init] } });
            const cases: [ParamsInit, string][] = [
                [{ reducers: [{ op: 9 as RangeReduceOp }] }, 'unsupported RangeReduceOp'],
                [{ reducers: [{ op: RangeReduceOp.MIN_FIELD, expr: {} }] }, 'missing expr'],
                [{ reducers: [{ op: RangeReduceOp.COUNT_ALL, expr: {} }] }, 'missing expr'],
                [{ reducers: [R.min(X.lower({}))] }, 'missing expr'],
                [{ reducers: [R.min({ expr: { case: 'add', value: { right: int(1) } } })] }, 'missing add.left'],
                [{ reducers: [R.min({ expr: { case: 'div', value: { left: int(1) } } })] }, 'missing div.right'],
                [field({}), 'missing field ref'],
                [field(F.key(65536, K.INT64)), 'byte_offset 65536 does not fit in u16'],
                [field(F.zorder(65536, 0, [8], K.INT64)), 'bit_offset 65536 does not fit in u16'],
                [field(F.zorder(0, 256, [8], K.INT64)), 'field_position 256 does not fit in u8'],
                [field(F.zorder(0, 0, [8, 256, 300], K.INT64)), 'field width 256 does not fit in u8'],
                [field(F.value(65536, K.INT64)), 'index 65536 does not fit in u16'],
                [field(F.value(0, 11 as KvFieldKind)), 'unsupported KvFieldKind'],
                [field(F.value(0, { fsb: 256 })), 'fixed_size_binary_len 256 does not fit in u8'],
                [literal({}), 'missing reduced value'],
                [literal(V.d128raw(new Uint8Array(15))), 'decimal128 must be exactly 16 bytes'],
                [literal(V.d256raw(new Uint8Array(33))), 'decimal256 must be exactly 32 bytes'],
                [check1({ constraint: C.isNull() }), 'missing predicate field'],
                [check1({ field: F.value(0, K.INT64) }), 'missing predicate constraint'],
                [check1({ field: F.value(0, K.INT64), constraint: {} }), 'missing predicate constraint'],
                [check1({ field: F.value(0, K.DECIMAL128), constraint: C.d128Range(new Uint8Array(1), new Uint8Array(2)) }),
                    'decimal128 min must be exactly 16 bytes'],
                [check1({ field: F.value(0, K.DECIMAL128), constraint: C.d128Range(null, new Uint8Array(2)) }),
                    'decimal128 max must be exactly 16 bytes'],
                [check1({ field: F.value(0, K.DECIMAL256), constraint: C.d256Range(new Uint8Array(1)) }),
                    'decimal256 min must be exactly 32 bytes'],
                [check1({ field: F.value(0, K.DECIMAL256), constraint: C.d256Range(null, new Uint8Array(31)) }),
                    'decimal256 max must be exactly 32 bytes'],
                // The whole request is converted before any reducer rule or typing.
                [{ reducers: [R.countAll(), { op: RangeReduceOp.COUNT_ALL, expr: int(1) }], groupBy: [X.lower(int(1)), {}] }, 'missing expr'],
                [{ reducers: [R.sum(text(0))], filter: { checks: [{}], contradiction: true } }, 'missing predicate field'],
            ];
            for (const [params, description] of cases) await expectAnswer(dataset, params, invalidArgument(description));
        });

        test('rejects params that cannot be planned', async () => {
            const dataset = await pair.store(ints(1));
            const cases: [ParamsInit, string][] = [
                [{ reducers: [{ op: RangeReduceOp.COUNT_ALL, expr: i64(0) }] }, 'count_all reducer must not specify an expression'],
                ...[RangeReduceOp.COUNT_FIELD, RangeReduceOp.SUM_FIELD, RangeReduceOp.MIN_FIELD, RangeReduceOp.MAX_FIELD]
                    .map((op): [ParamsInit, string] => [{ reducers: [{ op }] }, 'expression reducer requires an expression']),
                // Reducer rules come before typing, and typing visits group_by before the reducers.
                [{ reducers: [R.sum(text(0)), { op: RangeReduceOp.SUM_FIELD }] }, 'expression reducer requires an expression'],
                [{ reducers: [R.sum(text(0))], groupBy: [X.add(i64(0), text(1))] },
                    'Error during planning: Cannot coerce arithmetic expression Int64 + Utf8 to valid types'],
                [{ reducers: [R.sum(text(0))] }, 'Execution error: [return_type] SUM not supported for Utf8'],
                [{ reducers: [R.min(X.mul(X.v(0, K.DATE32), int(2)))] },
                    'Error during planning: Cannot get result type for temporal operation Date32 * Int64: Invalid argument error: Invalid date arithmetic operation: Date32 * Interval(MonthDayNano)'],
                [{ reducers: [R.min(X.add(X.v(0, K.TIMESTAMP), X.v(1, K.TIMESTAMP)))] },
                    'Error during planning: Cannot get result type for temporal operation Timestamp(\u00b5s) + Timestamp(\u00b5s): Invalid argument error: Invalid timestamp arithmetic operation: Timestamp(\u00b5s) + Timestamp(\u00b5s)'],
                [{ reducers: [R.min(X.add(X.div(X.v(0, K.DECIMAL128), X.v(0, K.DECIMAL128)), X.v(1, K.DECIMAL256)))] },
                    'Error during planning: Cannot coerce arithmetic expression Decimal128(38, 4) + Decimal256(76, 0) to valid types'],
                [{ reducers: [R.min(X.lower(i64(0)))] },
                    "Error during planning: Function 'lower' requires String, but received Int64 (DataType: Int64)."],
                [{ reducers: [R.min(X.cast(X.v(0, K.DATE32)))] }, 'This feature is not implemented: Unsupported CAST from Date32 to Float64'],
                // Operand typing of a whole expression comes before an unsupported cast inside it.
                [{ reducers: [R.min(X.sub(X.v(0, K.DATE64), X.cast(X.v(0, K.DATE64))))] },
                    'Error during planning: Cannot coerce arithmetic expression Date64 - Float64 to valid types'],
            ];
            for (const [params, description] of cases) await expectAnswer(dataset, params, invalidArgument(description));
            const sumOfText = await expectAnswer(dataset, { reducers: [R.sum(text(0))] });
            expect(describeError(sumOfText.actual.error as ConnectError)).toEqual({
                code: 'InvalidArgument',
                message: 'reduce params are invalid',
                field: 'params',
                description: 'Execution error: [return_type] SUM not supported for Utf8',
                reason: 'INVALID_REDUCE_PARAMS',
                domain: 'store.query',
                metadata: { description: 'Execution error: [return_type] SUM not supported for Utf8' },
            });
            const { actual } = await expectAnswer(dataset, { reducers: [R.min(X.trunc(i64(0)))] });
            expect(actual.error?.code).toBe(Code.Internal);
            expect(actual.error?.rawMessage).toContain("Function 'date_trunc' failed to match any signature");

            // Typing is static. An ill typed request fails over an empty range too.
            await expectAnswer(await pair.store([]), { reducers: [R.sum(text(0))] },
                invalidArgument('Execution error: [return_type] SUM not supported for Utf8'));
        });

        test('rows that do not decode or do not fit a field reference fail the request', async () => {
            const row = (...values: (Uint8Array | null)[]): Row[] => table(values);
            const sum = { reducers: [R.countAll(), R.sum(i64(0))] };
            const cases: [Row[], ParamsInit, string][] = [
                [[[be(0, 8), utf8('invalid row')]], sum, 'Invalid Bool: Expected 0 or 1, found different value'],
                [[[be(0, 8), Uint8Array.from([1, 1, 0, 0])]], sum, 'Unexpected End-of-Buffer: Not enough bytes remaining to read data'],
                [[[be(0, 8), Uint8Array.from([1, 1, 9])]], sum, 'Invalid Enum: Expected a valid enum variant, found 9'],
                [[[be(0, 8), Uint8Array.from([0x80, 0x00])]], sum, 'Invalid 4-byte varint'],
                [row(SV.i64(1), SV.rawStr(Uint8Array.from([0xff]))), sum, 'Validation Error: Context(Utf8), Message(invalid utf8)'],
                [row(SV.i64(1), SV.list([SV.list([SV.i64(1), SV.rawStr(Uint8Array.from([0xc0, 0x80]))])])), sum,
                    'Validation Error: Context(Utf8), Message(invalid utf8)'],
                [row(SV.i64(7)), { reducers: [R.countAll()], filter: pred([[F.value(2, K.INT64), C.isNotNull()]]) }, 'stored row index out of bounds'],
                [row(null), { reducers: [R.sum(X.add(i64(0), X.div(i64(1), i64(2))))] }, 'stored row index out of bounds'],
                [row(null), { reducers: [R.sum(i64(0, false))] }, 'non-nullable field stored as null'],
                [row(SV.str('hello')), { reducers: [R.min(i64(0))] }, 'stored field type mismatch'],
                [row(SV.list([SV.i64(1)])), { reducers: [R.min(i64(0))] }, 'stored field type mismatch'],
                [row(SV.bytes(new Uint8Array(15))), { reducers: [R.min(X.v(0, K.DECIMAL128))] }, 'invalid Decimal128 byte width'],
                [row(SV.bytes(new Uint8Array(31))), { reducers: [R.min(X.v(0, K.DECIMAL256))] }, 'invalid Decimal256 byte width'],
                [row(SV.bytes(new Uint8Array(3))), { reducers: [R.min(X.v(0, { fsb: 2 }))] }, 'invalid FixedSizeBinary byte width'],
                [row(SV.i64(1)), { reducers: [R.min(X.k(250, K.INT64))] }, 'invalid key field'],
                [row(SV.i64(1)), { reducers: [R.min(X.f(F.zorder(0, 0, [200, 200], K.INT64)))] }, 'invalid z-order key field'],
                [row(SV.i64(1)), { reducers: [R.min(X.f(F.zorder(0, 2, [1, 1], { fsb: 1 })))] }, 'invalid z-order key field'],
            ];
            for (const [rows, params, message] of cases) await expectAnswer(await pair.store(rows), params, failedPrecondition(message));
        });

        test('expressions that fail on a value fail the request', async () => {
            const dataset = await pair.store(table([SV.i64(7), SV.i64(0), SV.i64(I64_MIN), SV.u64((1n << 64n) - 1n), SV.d128((1n << 127n) - 1n),
                SV.i64(95026237), SV.i64(I64_MAX), SV.str('abc'), SV.i64(I64_MIN)]));
            const date32 = X.v(5, K.DATE32);
            const cases: [ExprInit, string][] = [
                [X.div(i64(0), i64(1)), 'Arrow error: Divide by zero error'],
                [X.add(i64(0), X.div(i64(0), i64(1))), 'Arrow error: Divide by zero error'],
                [X.div(i64(2), int(-1)), 'Arrow error: Arithmetic overflow: Overflow happened on: -9223372036854775808 / -1'],
                [X.div(X.v(4, K.DECIMAL128), X.lit(V.d128(1))),
                    'Arrow error: Arithmetic overflow: Overflow happened on: 170141183460469231731687303715884105727 * 10000'],
                [X.add(date32, int(0)),
                    'Arrow error: Compute error: Date arithmetic overflow: 95026237 + IntervalMonthDayNano { months: 0, days: 0, nanoseconds: 0 }'],
                [X.add(X.lit(V.date32(0)), int(106752)), 'Arrow error: Compute error: Cannot cast to Interval(MonthDayNano). Overflowing on 9223372800'],
                [X.add(X.lit(V.date32(0)), X.v(3, K.UINT64)), "Arrow error: Cast error: Can't cast value 18446744073709551615 to type Int64"],
                [X.sub(X.v(6, K.TIMESTAMP), X.lit(V.ts(-1))), 'Arrow error: Arithmetic overflow: Overflow happened on: 9223372036854775807 - -1'],
                [X.trunc(date32), 'Execution error: Cannot cast Date32 value 95026237 to Timestamp(ns): converted value exceeds the representable i64 range'],
                [X.cast(text(7)), "Arrow error: Cast error: Cannot cast string 'abc' to value of Float64 type"],
                [X.trunc(X.lit(V.ts(I64_MAX))), 'Execution error: Timestamp 9223372036854775807 out of range'],
                [X.trunc(X.lit(V.ts(-9223372036854775n))),
                    'Execution error: Timestamp -9223372036854775000 out of range after truncating to day'],
            ];
            for (const [expr, message] of cases) await expectAnswer(dataset, { reducers: [R.min(expr)] }, failedPrecondition(message));
            const { actual } = await expectAnswer(dataset, { reducers: [R.min(X.trunc(X.v(8, K.TIMESTAMP)))] });
            expect([actual.error?.code, actual.error?.rawMessage.split('.')[0]]).toEqual([Code.Internal, 'Internal error: native Reduce execution panicked']);
            await expectAnswer(dataset, { reducers: [R.countAll()] }, { results: ['u64:1'] });
        });
    });

    describe('freshness', () => {
        test('the envelope is checked before the floor and the floor before the params', async () => {
            const dataset = await pair.store(ints(1, 2));
            if (dataset.client === undefined) throw new Error('the dataset must be in the IndexedDB store');
            const stores: [Client, bigint][] = [[pair.simulator, dataset.sequence.simulator], [dataset.client, dataset.sequence.store]];
            for (const [client, sequence] of stores) {
                const stale = { minSequenceNumber: sequence + 1n };
                const unknownOp = rangeRequest(dataset, { reducers: [{ op: 9 as RangeReduceOp }] }, stale);
                expect((await failure(client.query.reduce(unknownOp))).code).toBe(Code.Aborted);
                const longStart = rangeRequest({ start: new Uint8Array(255), end: dataset.end }, { reducers: [R.countAll()] }, stale);
                expect((await failure(client.query.reduce(longStart))).code).toBe(Code.InvalidArgument);

                const reached = rangeRequest(dataset, { reducers: [R.countAll()] }, { minSequenceNumber: sequence });
                const frames = await collect(client.query.reduce(reached));
                expect(frames.map((frame) => [renderResults(frame.results), frame.detail?.sequenceNumber])).toEqual([[['u64:2'], sequence]]);
            }
        });
    });

    describe('NaN', () => {
        const [ONE, NAN_1, NAN_2, NEGATIVE_NAN_1, SIGNALING_NAN_1, INFINITY] = [0x3ff0000000000000n, 0x7ff8000000000001n,
            0x7ff8000000000002n, 0xfff8000000000001n, 0x7ff0000000000001n, 0x7ff0000000000000n];
        const x = f64(0);
        const float = (value: number): ExprInit => X.lit(V.f64(value));
        /** The bits of the Float64 result at an index of a request without group_by. */
        const bitsOf = (outcome: Outcome, index: number): string => {
            const value = outcome.frames[0].results[index].value?.value;
            return value?.case === 'float64Value' ? floatBits(value.value).toString(16) : 'no Float64';
        };

        test('arithmetic keeps the sign of its one NaN operand, and the sign places the NaN at one end of the total order', async () => {
            const kept = [X.mul(x, float(1)), X.add(float(1), x), X.sub(x, float(1)), X.div(float(1), x)];
            const reducers = kept.flatMap((expr) => [R.min(expr), R.max(expr)]);
            const number = 'f64:';
            const below = await expectAnswer(await pair.store(floats(NEGATIVE_NAN_1, ONE)), { reducers });
            expect(renderResults(below.actual.frames[0].results).map((result) => (result === 'f64:NaN' ? result : number)))
                .toEqual(kept.flatMap(() => ['f64:NaN', number]));
            const above = await expectAnswer(await pair.store(floats(NAN_1, ONE)), { reducers });
            expect(renderResults(above.actual.frames[0].results).map((result) => (result === 'f64:NaN' ? result : number)))
                .toEqual(kept.flatMap(() => [number, 'f64:NaN']));
        });

        test('arithmetic keeps the payload of its one NaN operand and sets the quiet bit', async () => {
            const dataset = await pair.store(floats(NAN_1, NAN_2, SIGNALING_NAN_1));
            await expectAnswer(dataset, { reducers: [R.countAll()], groupBy: [x] },
                { groups: ['f64:NaN => u64:1', 'f64:NaN => u64:1', 'f64:NaN => u64:1'] });
            await expectAnswer(dataset, { reducers: [R.countAll()], groupBy: [X.add(x, float(0))] },
                { groups: ['f64:NaN => u64:2', 'f64:NaN => u64:1'] });
        });

        test('a sum keeps the sign and payload of its one NaN', async () => {
            const dataset = await pair.store(floats(ONE, NEGATIVE_NAN_1, ONE));
            for (const params of [{ reducers: [R.sum(x)] }, { reducers: [R.sum(X.mul(x, float(2)))] }]) {
                const { expected, actual } = await expectAnswer(dataset, params, { results: ['f64:NaN'] });
                expect([bitsOf(actual, 0), bitsOf(expected, 0)]).toEqual(['fff8000000000001', 'fff8000000000001']);
            }
            await expectAnswer(dataset, { reducers: [R.sum(x)], groupBy: [int(0)] }, { groups: ['i64:0 => f64:NaN'] });
        });

        test('a NaN without a defined sign and payload is compared as far as it is defined', async () => {
            // Infinity minus itself is an invalid operation. Its NaN may lie at either end of the
            // total order, and it keys a group of its own.
            const dataset = await pair.store(floats(INFINITY, INFINITY, ONE));
            const invalid = X.sub(x, x);
            for (const params of [{ reducers: [R.min(invalid), R.max(invalid), R.sum(invalid)] }, { reducers: [R.countAll()], groupBy: [invalid] }]) {
                expect((await pair.check(dataset, params)).comparison.status).toBe('identical');
            }
            expect(evaluate(dataset.rows, rangeRequest(dataset, { reducers: [R.min(invalid)] })).unspecifiedNaN).toBe(true);
            expect(evaluate(dataset.rows, rangeRequest(dataset, { reducers: [R.min(X.mul(x, float(2)))] })).unspecifiedNaN).toBe(false);
        });
    });

    describe('predicates', () => {
        const KINDS: [string, Parameters<typeof F.value>[1]][] = [['Int64', K.INT64], ['UInt64', K.UINT64], ['Float64', K.FLOAT64],
            ['Boolean', K.BOOLEAN], ['Utf8', K.UTF8], ['Date32', K.DATE32], ['Date64', K.DATE64], ['Timestamp', K.TIMESTAMP],
            ['Decimal128', K.DECIMAL128], ['Decimal256', K.DECIMAL256], ['FixedSizeBinary(2)', { fsb: 2 }]];
        const [NAN, NEGATIVE_NAN] = [0x7ff8000000000000n, 0xfff8000000000000n];
        const bytes = (...values: number[]) => Uint8Array.from(values);
        /**
         * A row with one value per kind, in the order of KINDS. The integer, date, timestamp and
         * decimal columns hold n, and the UInt64 column holds its absolute value.
         */
        const row = (n: bigint, float: bigint, flag: boolean, word: string, binary: Uint8Array) =>
            [SV.i64(n), SV.u64(n < 0n ? -n : n), SV.f64bits(float), SV.bool(flag), SV.str(word), SV.i64(n), SV.i64(n), SV.i64(n),
                SV.d128(n), SV.d256(n), SV.bytes(binary)];
        const rows = table(
            row(-1n, 0xfff0000000000000n, false, '', bytes(0, 0)),
            row(0n, 0xbff0000000000000n, true, 'a', bytes(1, 2)),
            row(1n, 0x8000000000000000n, false, 'b', bytes(1, 3)),
            row(2n, 0n, true, 'B', bytes(2, 0)),
            row(5n, 0x3ff0000000000000n, false, 'ab', bytes(1, 2)),
            row(7n, 0x7ff0000000000000n, true, 'b', bytes(9, 9)),
            row(8n, NAN, false, '\u00e9', bytes(1, 2)),
            row(9n, NEGATIVE_NAN, true, 'e\u0301', bytes(0, 1)),
            KINDS.map(() => null),
        );
        const range = <T>(make: (min?: T | null, max?: T | null) => ConstraintInit, low: T, high: T) =>
            [make(low, high), make(low), make(null, high), make(high, low), make()];
        const constraints: [string, ConstraintInit][] = [
            C.isNull(), C.isNull(false), C.isNotNull(), C.isNotNull(false),
            C.strEq('b'), C.strEq(''), C.boolEq(true), C.boolEq(false), C.fsbEq(bytes(1, 2)), C.fsbEq(bytes(1)),
            ...range(C.intRange, 0, 5), ...range(C.u64Range, 1, 7), ...range(C.d128Range, 0n, 5n), ...range(C.d256Range, -1n, 2n),
            ...[true, false].flatMap((inclusive) => [
                C.floatRange([0, inclusive], [1, inclusive]),
                C.floatRange([-1, inclusive]),
                C.floatRange(null, [Infinity, inclusive]),
                C.floatRange([Number.NaN, inclusive]),
                C.floatRange(null, [Number.NaN, inclusive]),
                C.floatRange([-Infinity, inclusive], [-0, inclusive]),
            ]),
            C.strIn(['b', 'ab', 'zz']), C.strIn([]), C.intIn([0, 5, 6]), C.intIn([]), C.u64In([1, 7]), C.u64In([]),
            C.fsbIn([bytes(1, 2), bytes(9, 9), bytes(9)]), C.fsbIn([]),
        ].map((constraint, n): [string, ConstraintInit] => [n + ' ' + constraint.constraint?.case, constraint]);

        test('both stores agree on every constraint over a field of every kind', async () => {
            const dataset = await pair.store(rows);
            const tally = new Tally();
            for (const [column, [kind, declared]] of KINDS.entries()) {
                for (const [label, constraint] of constraints) {
                    const check = pred([[F.value(column, declared), constraint]]);
                    tally.note(label + ' over ' + kind, await pair.check(dataset, { reducers: [R.countAll(), R.countAll(check)], filter: check }));
                }
            }
            expect(tally.requests).toBe(KINDS.length * constraints.length);
            expect(tally.outside).toBe(0);
            tally.expectClean();
        });

        test('a constraint holds for the kinds it is made for and for no other', async () => {
            const dataset = await pair.store(rows);
            /** How many of the nine rows pass a check of the column at an index of KINDS. */
            const passing = async (column: number, constraint: ConstraintInit) => {
                const filter = pred([[F.value(column, KINDS[column][1]), constraint]]);
                const { actual } = await expectAnswer(dataset, { reducers: [R.countAll()], filter });
                return renderResults(actual.frames[0].results)[0];
            };

            // An integer range reads dates and timestamps as well. A list of integers does not.
            for (const column of [0, 5, 6, 7]) expect(await passing(column, C.intRange(0, 5))).toBe('u64:4');
            expect(await passing(0, C.intIn([0, 5, 6]))).toBe('u64:2');
            for (const column of [1, 5, 6, 7, 8]) expect(await passing(column, C.intIn([0, 5, 6]))).toBe('u64:0');
            expect(await passing(4, C.intRange(0, 5))).toBe('u64:0');

            // A float range follows the total order, from the negative NaN over the two zeros to
            // the positive NaN.
            expect(await passing(2, C.floatRange([0, true]))).toBe('u64:4');
            expect(await passing(2, C.floatRange([0, false]))).toBe('u64:3');
            expect(await passing(2, C.floatRange(null, [0, true]))).toBe('u64:5');
            expect(await passing(2, C.floatRange(null, [0, false]))).toBe('u64:4');
            expect(await passing(2, C.floatRange([Number.NaN, true]))).toBe('u64:1');
            expect(await passing(2, C.floatRange([Number.NaN, false]))).toBe('u64:0');
            expect(await passing(2, C.floatRange(null, [Number.NaN, false]))).toBe('u64:7');

            // Only is_null holds for NULL, whatever bool it carries.
            expect(await passing(2, C.isNull(false))).toBe('u64:1');
            expect(await passing(2, C.isNotNull(false))).toBe('u64:8');

            // Text and binary constraints match exact bytes.
            expect(await passing(4, C.strEq('b'))).toBe('u64:2');
            expect(await passing(4, C.strIn(['b', 'ab', 'zz']))).toBe('u64:3');
            expect(await passing(10, C.fsbIn([bytes(1, 2), bytes(9, 9), bytes(9)]))).toBe('u64:4');
        });
    });

    describe('expressions the IndexedDB store does not compute', () => {
        const [ts, date32] = [X.v(0, K.TIMESTAMP), X.v(0, K.DATE32)];

        // Durations of microseconds and of nanoseconds add up to an interval.
        const interval = X.add(X.sub(ts, ts), X.sub(ts, date32));

        test('a request that is invalid for another reason answers that reason', async () => {
            const dataset = await pair.store(ints(1));
            const cases: [ParamsInit, string][] = [
                [{ reducers: [R.min(X.trunc(text(0))), R.sum(text(0))] }, 'Execution error: [return_type] SUM not supported for Utf8'],
                [{ reducers: [R.min(X.lower(i64(0)))], groupBy: [X.trunc(text(0))] },
                    "Error during planning: Function 'lower' requires String, but received Int64 (DataType: Int64)."],
                [{ reducers: [R.min(X.add(interval, int(1)))] },
                    'Error during planning: Cannot automatically convert Int64 to Interval(MonthDayNano)'],
                [{ reducers: [R.min(X.sub(X.lit(V.f64(1)), interval))] },
                    'Error during planning: Cannot automatically convert Float64 to Interval(MonthDayNano)'],
                [{ reducers: [R.min(X.mul(interval, int(2)))] },
                    'Error during planning: Cannot get result type for temporal operation Interval(MonthDayNano) * Int64: Invalid argument error: Invalid interval arithmetic operation: Interval(MonthDayNano) * Interval(MonthDayNano)'],
                [{ reducers: [R.min(X.cast(interval))] }, 'This feature is not implemented: Unsupported CAST from Interval(MonthDayNano) to Float64'],
                [{ reducers: [R.sum(X.add(ts, X.sub(ts, date32)))] }, 'Execution error: [return_type] SUM not supported for Timestamp(\u00b5s)'],
            ];
            for (const [params, description] of cases) await expectAnswer(dataset, params, invalidArgument(description));
        });

        test('a request that is valid otherwise answers UNIMPLEMENTED', async () => {
            const dataset = await pair.store(ints(1));
            const requests: ParamsInit[] = [
                { reducers: [R.count(interval)] },
                { reducers: [R.sum(interval), R.min(interval)] },
                { reducers: [R.countAll()], groupBy: [X.trunc(text(0))] },
                { reducers: [R.max(X.sub(X.trunc(date32), X.sub(ts, ts)))] },
            ];
            for (const params of requests) expect((await pair.check(dataset, params)).comparison.status).toBe('outside');
        });
    });

    test('a float_range bound of -0 is +0 once the request is on the wire', async () => {
        const [NEGATIVE_ZERO, ZERO, ONE] = [1n << 63n, 0n, 0x3ff0000000000000n];
        const filter = pred([[F.value(0, K.FLOAT64), C.floatRange([-0, true])]]);

        // The second dataset is kept out of the IndexedDB store, so the evaluator answers for it.
        for (const indexedDb of [true, false]) {
            const dataset = await pair.store(floats(NEGATIVE_ZERO, ZERO, ONE), { indexedDb });
            await expectAnswer(dataset, { reducers: [R.countAll()], filter }, { results: ['u64:2'] });
        }
    });

    test('a row at either end of the range is inside it', async () => {
        const name = 'ends';
        const last = new Uint8Array(MAX_KEY_LEN - utf8('reduce/' + name + '/').length).fill(0xff);
        const rows: Row[] = [[new Uint8Array(), encodeRow([SV.i64(1)])], [be(0, 8), encodeRow([SV.i64(2)])], [last, encodeRow([SV.i64(4)])]];
        const dataset = await pair.store(rows, { name });
        expect([dataset.rows[0][0], dataset.rows[2][0]]).toEqual([dataset.start, dataset.end]);
        await expectAnswer(dataset, { reducers: [R.countAll(), R.sum(i64(0))] }, { results: ['u64:3', 'i64:7'] });
    });

    test('the keys of a named dataset do not depend on the datasets stored before it', async () => {
        await pair.store([], { indexedDb: false });
        const dataset = await pair.store([], { name: 'named', indexedDb: false });
        expect(Buffer.from(dataset.prefix).toString()).toBe('reduce/named/');
    });

    test('accepts the smallest Date64 literal as a whole expression', async () => {
        await expectAnswer(await pair.store(ints(1)), { reducers: [R.min(X.lit(V.date64(I64_MIN)))], groupBy: [X.lit(V.date64(I64_MIN))] },
            { groups: ['date64:' + I64_MIN + ' => date64:' + I64_MIN] });
    });

    test('both stores agree on every operator over every pair of kinds and every function over every kind', async () => {
        const bytes = Uint8Array.from([1, 2]);
        const columns: [string, Parameters<typeof X.v>[1], Uint8Array, ReturnType<typeof V.i64>][] = [
            ['Int64', K.INT64, SV.i64(7), V.i64(7)],
            ['UInt64', K.UINT64, SV.u64(3), V.u64(3)],
            ['Float64', K.FLOAT64, SV.f64(2.5), V.f64(2.5)],
            ['Boolean', K.BOOLEAN, SV.bool(true), V.bool(true)],
            ['Utf8', K.UTF8, SV.str('4'), V.str('4')],
            ['Date32', K.DATE32, SV.i64(10), V.date32(10)],
            ['Date64', K.DATE64, SV.i64(86400000n * 3n + 5n), V.date64(86400000n * 3n + 5n)],
            ['Timestamp', K.TIMESTAMP, SV.i64(5000000), V.ts(5000000)],
            ['Decimal128', K.DECIMAL128, SV.d128(9), V.d128(9)],
            ['Decimal256', K.DECIMAL256, SV.d256(11), V.d256(11)],
            ['FixedSizeBinary(2)', { fsb: 2 }, SV.bytes(bytes), V.fsb(bytes)],
        ];
        const dataset = await pair.store(table(columns.map((column) => column[2]), columns.map(() => null)));
        const tally = new Tally();
        const run = async (label: string, params: ParamsInit) => tally.note(label, await pair.check(dataset, params));
        const field = (column: number) => X.v(column, columns[column][1]);
        const literal = (column: number) => X.lit(columns[column][3]);
        for (const [name, op] of Object.entries({ add: X.add, sub: X.sub, mul: X.mul, div: X.div })) {
            for (const l of columns.keys()) {
                for (const r of columns.keys()) {
                    const expr = op(field(l), field(r));
                    const label = columns[l][0] + ' ' + name + ' ' + columns[r][0];
                    await run(label + ' [min, max, count]', { reducers: [R.min(expr), R.max(expr), R.count(expr)] });
                    await run(label + ' [count]', { reducers: [R.count(expr), R.countAll()] });
                    await run(label + ' [min cast]', { reducers: [R.min(X.cast(expr))] });
                    await run(label + ' [sum]', { reducers: [R.sum(expr)] });
                    await run(label + ' [group by]', { reducers: [R.countAll()], groupBy: [expr] });
                    await run(label + ' [literal right]', { reducers: [R.min(op(field(l), literal(r)))] });
                    await run(label + ' [literals, grouped]', { reducers: [R.max(op(literal(l), literal(r)))], groupBy: [field(0)] });
                }
            }
        }
        for (const column of columns.keys()) {
            const kind = columns[column][0];
            for (const [name, f] of Object.entries({ lower: X.lower, date_trunc_day: X.trunc, cast_float64: X.cast })) {
                const expr = f(field(column));
                const label = name + '(' + kind + ')';
                await run(label + ' [min, max, count]', { reducers: [R.min(expr), R.max(expr), R.count(expr)] });
                await run(label + ' [sum]', { reducers: [R.sum(expr)] });
                await run(label + ' [group by]', { reducers: [R.countAll()], groupBy: [expr] });
                await run('cast_float64(' + label + ')', { reducers: [R.min(X.cast(expr))] });
            }
            await run('reducers over ' + kind, { reducers: [R.count(field(column)), R.min(field(column)), R.max(field(column))] });
            await run('sum over ' + kind, { reducers: [R.sum(field(column))] });
            await run('group by ' + kind, { reducers: [R.countAll(), R.min(field(column)), R.max(field(column))], groupBy: [field(column)] });
        }
        console.log('reduce directed matrix: ' + tally.summary());
        tally.expectClean();

        // date_trunc_day over the string column is not computed. Its SUM is invalid, and the three
        // other requests over it are valid otherwise.
        expect(tally.outsideClasses).toEqual({ 'date_trunc_day over a string is not implemented': 3 });
    }, 120_000);
});

describe('Reduce on the IndexedDB store alone', () => {
    const opened: { store: IndexedDbStore; name: string }[] = [];
    const countAll: ParamsInit = { reducers: [R.countAll()] };

    afterEach(async () => {
        jest.restoreAllMocks();
        for (const { store, name } of opened.splice(0)) {
            store.close();
            await deleteIndexedDbStore(name);
        }
    });

    /** A store of its own that holds the rows, with a query memory limit when one is given. */
    async function storeOf(rows: Row[], maxQueryBytes?: number): Promise<Client> {
        const name = freshDatabaseName();
        const store = await openIndexedDbStore(name, maxQueryBytes === undefined ? {} : { maxQueryBytes });
        opened.push({ store, name });
        const client = new Client(store.transport);
        if (rows.length > 0) await put(client, rows);
        return client;
    }

    /** The answer to params over every row of a store, as its results or its error. */
    async function resultOf(client: Client, params: ParamsInit): Promise<string> {
        const outcome = await answer(client.query.reduce({ params }));
        return outcome.error === undefined ? renderResults(outcome.frames[0].results).join(', ') : showError(outcome.error);
    }

    const nest = (wrap: (inner: ExprInit) => ExprInit, levels: number, inner: ExprInit): ExprInit => {
        let expr = inner;
        for (let level = 0; level < levels; level++) expr = wrap(expr);
        return expr;
    };

    test('messages nest at most 100 deep', async () => {
        // A reducer's expression lies at depth 3 and a group_by expression at depth 2. Arithmetic
        // puts its operands two levels deeper and cast_float64 one, and below the innermost
        // expression a field reference takes two more levels and a literal one.
        const client = await storeOf(ints(1, 2, 3));
        const tooDeep = 'InvalidArgument [reduce params are invalid] [request nesting exceeds 100 messages]';
        const plusOne = (inner: ExprInit) => X.add(inner, int(1));
        const cases: [ParamsInit, string][] = [
            [{ reducers: [R.sum(nest(plusOne, 47, i64(0)))] }, 'i64:147'],
            [{ reducers: [R.sum(nest(plusOne, 48, int(0)))] }, 'i64:144'],
            [{ reducers: [R.sum(nest(plusOne, 48, i64(0)))] }, tooDeep],
            [{ reducers: [R.sum(nest(X.cast, 95, i64(0)))] }, 'f64:6/4018000000000000'],
            [{ reducers: [R.sum(nest(X.cast, 96, i64(0)))] }, tooDeep],
            [{ reducers: [R.countAll()], groupBy: [nest(X.cast, 97, i64(0))] }, tooDeep],
            [{ reducers: [R.sum(nest(X.cast, 300, i64(0)))] }, tooDeep],
        ];
        for (const [params, want] of cases) expect(await resultOf(client, params)).toBe(want);
    });

    test('the smallest Date64 literal is accepted only as a whole expression', async () => {
        const client = await storeOf(ints(1));
        const smallest = X.lit(V.date64(I64_MIN));
        const rejected = 'InvalidArgument [reduce params are invalid] [a date64 literal of -9223372036854775808 is not supported inside an expression]';
        expect(await resultOf(client, { reducers: [R.min(smallest)] })).toBe('date64:' + I64_MIN);
        expect(await resultOf(client, { reducers: [R.min(X.sub(smallest, X.lit(V.date64(0))))] })).toBe(rejected);
        expect(await resultOf(client, { reducers: [R.min(X.trunc(smallest))] })).toBe(rejected);
        expect(await resultOf(client, { reducers: [R.min(X.sub(X.lit(V.date64(I64_MIN + 1n)), X.lit(V.date64(0))))] })).toBe('i64:-106751991167');
    });

    test('a stored list of any depth is validated without deep calls', async () => {
        const depth = 200000;
        const nested = new Uint8Array(2 + 2 * depth + 9);
        nested.set([1, 1]);
        for (let level = 0; level < depth; level++) nested.set([6, 1], 2 + 2 * level);
        nested.set(SV.i64(5), 2 + 2 * depth);
        const params: ParamsInit = { reducers: [R.min(i64(0))] };
        expect(await resultOf(await storeOf([[be(0, 8), nested]]), params)).toBe('FailedPrecondition [stored field type mismatch]');
        expect(await resultOf(await storeOf([[be(0, 8), nested.subarray(0, nested.length - 1)]]), params))
            .toBe('FailedPrecondition [Unexpected End-of-Buffer: Not enough bytes remaining to read data]');
    });

    test('the aggregation state is bounded by the query memory limit', async () => {
        // A group costs 48 bytes for each key and each reducer. Without group_by an extremum of
        // text costs the bytes it holds.
        const exhausted = (limit: number) => "ResourceExhausted [reduce state exceeds the store's query memory limit of " + limit + ' bytes]';
        const grouped: ParamsInit = { reducers: [R.countAll()], groupBy: [i64(0)] };
        const rows = ints(1, 2, 3);
        expect((await answer((await storeOf(rows, 288)).query.reduce({ params: grouped }))).frames[0].groups).toHaveLength(3);
        const short = await answer((await storeOf(rows, 287)).query.reduce({ params: grouped }));
        expect([short.frames.length, showError(short.error as ConnectError)]).toEqual([0, exhausted(287)]);

        const words = table([SV.str('a'.repeat(300))]);
        expect(await resultOf(await storeOf(words, 300), { reducers: [R.max(text(0))] })).toBe('utf8:"' + 'a'.repeat(300) + '"');
        expect(await resultOf(await storeOf(words, 299), { reducers: [R.max(text(0))] })).toBe(exhausted(299));
    });

    describe('working memory of a batch', () => {
        // A literal fills each of 258 rows up to 65536 bytes, so the first batch ends at 16 MiB
        // before row 256. Ten sums over computed arguments then hold 10 * 256 * 48 bytes of
        // results for that batch.
        const rows = ints(...Array.from({ length: 258 }, (_, row) => row));
        const sums = Array.from({ length: 10 }, (_, n) => R.sum(X.add(i64(0), int(n + 1))));
        const filler = (others: number) => R.count(X.lit(V.str('X'.repeat(65536 - others - 48))));
        const totals = sums.map((_, n) => 'i64:' + (33153 + 258 * (n + 1)));
        const RESULTS = 10 * 256 * 48;
        const exhausted = (what: string, limit: number) =>
            'ResourceExhausted [reduce ' + what + " exceeds the store's query memory limit of " + limit + ' bytes]';

        test('the results of a batch with group_by count against the query memory limit until the batch is folded', async () => {
            // The group costs 48 bytes for its key and for each of 11 reducers.
            const GROUP = 12 * 48;
            const params: ParamsInit = { reducers: [...sums, filler(48 + 10 * 48 + 11 * 48)], groupBy: [int(0)] };
            const groupsOf = async (limit: number) => {
                const outcome = await answer((await storeOf(rows, limit)).query.reduce({ params }));
                return outcome.error === undefined ? groupLines(outcome).join() : showError(outcome.error);
            };
            expect(await groupsOf(RESULTS + GROUP)).toBe('i64:0 => ' + [...totals, 'u64:258'].join(', '));
            expect(await groupsOf(RESULTS + GROUP - 1)).toBe(exhausted('state', RESULTS + GROUP - 1));
            expect(await groupsOf(RESULTS - 1)).toBe(exhausted('batch', RESULTS - 1));
        });

        test('a batch without group_by holds the result of one reducer at a time', async () => {
            const params: ParamsInit = { reducers: [...sums, filler(10 * 48 + 11 * 48)] };
            expect(await resultOf(await storeOf(rows, RESULTS / 10), params)).toBe([...totals, 'u64:258'].join(', '));
            expect(await resultOf(await storeOf(rows, RESULTS / 10 - 1), params)).toBe(exhausted('batch', RESULTS / 10 - 1));
        });

        test('a batch stops computing at the first result that passes the limit', async () => {
            const client = await storeOf(table([SV.str('A'.repeat(MIB))]), 2 * MIB);
            const computed = jest.spyOn(lowercase, 'toLowercase');
            const params: ParamsInit = { reducers: Array.from({ length: 32 }, () => R.min(X.lower(text(0)))), groupBy: [int(0)] };
            expect(await resultOf(client, params)).toBe(exhausted('batch', 2 * MIB));
            expect(computed).toHaveBeenCalledTimes(2);
        });
    });

    describe('lower', () => {
        const SIGMA = '\u03a3';

        test('maps a whole text to lowercase and chooses the final sigma by its context', () => {
            const cases: [string, string][] = [
                ['', ''],
                ['plain ascii 123', 'plain ascii 123'],
                ['MiXeD', 'mixed'],
                ['\u0130', 'i\u0307'],
                [SIGMA, '\u03c3'],
                ['\u0391' + SIGMA, '\u03b1\u03c2'],
                ['\u0391' + SIGMA + '\u0391', '\u03b1\u03c3\u03b1'],
                // An apostrophe is skipped on either side of the sigma.
                ["\u0391'" + SIGMA, "\u03b1'\u03c2"],
                ['\u0391' + SIGMA + "'\u0391", "\u03b1\u03c3'\u03b1"],
                // Cased letters and skipped marks above the basic plane.
                ['\u{10400}' + SIGMA, '\u{10428}\u03c2'],
                ['\u0391\u{e0001}' + SIGMA + '\u{e0001}', '\u03b1\u{e0001}\u03c2\u{e0001}'],
                ['\u0391' + SIGMA + '\u{e0001}\u{10400}', '\u03b1\u03c3\u{e0001}\u{10428}'],
                [SIGMA + SIGMA, '\u03c3\u03c2'],
                // U+0345 and U+02B0 are both cased and case ignorable. The rule for a sigma treats
                // them as case ignorable.
                ['\u0345' + SIGMA, '\u0345\u03c3'],
                ['A\u0345' + SIGMA, 'a\u0345\u03c2'],
                ['A' + SIGMA + '\u0345', 'a\u03c2\u0345'],
                ['A' + SIGMA + '\u0345A', 'a\u03c3\u0345a'],
                ['\u02b0' + SIGMA, '\u02b0\u03c3'],
                ['A\u02b0' + SIGMA, 'a\u02b0\u03c2'],
                ['A' + SIGMA + '\u02b0', 'a\u03c2\u02b0'],
                ['A' + SIGMA + '\u02b0A', 'a\u03c3\u02b0a'],
                // Two skipped scalar values on either side, in and above the basic plane.
                ["A''" + SIGMA, "a''\u03c2"],
                ['A' + SIGMA + "''A", "a\u03c3''a"],
                ['A\u{e0001}\u{e0001}' + SIGMA, 'a\u{e0001}\u{e0001}\u03c2'],
                ['A' + SIGMA + '\u{e0001}\u{e0001}A', 'a\u03c3\u{e0001}\u{e0001}a'],
            ];
            for (const [text, lower] of cases) expect(toLowercase(text)).toBe(lower);
        });

        test('the README names the Unicode version of the tables', () => {
            expect(UNICODE_VERSION).toMatch(/^\d+\.\d+\.\d+$/);

            // The version may end a sentence. A digit after it, or a dot and a digit, would make
            // it the beginning of a longer version.
            const named = new RegExp('Unicode ' + UNICODE_VERSION.replace(/\./g, '\\.') + '(?![0-9]|\\.[0-9])');
            expect(readFileSync(path.join(__dirname, '..', 'README.md'), 'utf8')).toMatch(named);
        });

        test('gives the lowercase forms of the standard library for every scalar value alone and around a sigma', () => {
            const { imul } = Math;
            let digest = 0x811c9dc5;
            for (let scalar = 0; scalar < 0x110000; scalar++) {
                if (scalar >= 0xd800 && scalar <= 0xdfff) continue;
                const c = String.fromCodePoint(scalar);
                for (const text of [c, c + SIGMA, SIGMA + c, 'A' + c + SIGMA, 'A' + SIGMA + c, 'A' + c + SIGMA + 'A', 'A' + SIGMA + c + 'A']) {
                    const lower = toLowercase(text) + '\n';
                    for (let i = 0; i < lower.length; i++) digest = imul(digest ^ lower.charCodeAt(i), 0x01000193);
                }
            }
            if (digest >>> 0 !== LOWERCASE_DIGEST) {
                throw new Error('toLowercase does not give the lowercase forms of the standard library that the tables were generated '
                    + 'from. Either lowercase.ts reads the tables wrongly or the tables were edited by hand. Its digest is 0x'
                    + (digest >>> 0).toString(16) + ' and the tables name 0x' + LOWERCASE_DIGEST.toString(16) + '. The tables are '
                    + 'written anew with: cargo test -p exoware-sdk --test lowercase_tables -- --ignored regenerate_lowercase_tables');
            }
        });
    });

    test('planning 50000 Z-order references takes less than 2 seconds and 64 MiB', () => {
        const check = { field: F.zorder(0, 0, [255], { fsb: 255 }), constraint: C.isNull() };
        const message = rangeRequest({ start: new Uint8Array(), end: new Uint8Array() },
            { reducers: [R.countAll()], filter: { checks: new Array(50000).fill(check) } });
        const [heap, started] = [process.memoryUsage().heapUsed, performance.now()];
        validateReduceEnvelope(message);
        const plan = planReduce(message);
        expect(performance.now() - started).toBeLessThan(2000);
        expect(process.memoryUsage().heapUsed - heap).toBeLessThan(64 * MIB);
        expect(plan.filter?.checks).toHaveLength(50000);
    });

    test('a NaN without a defined sign and payload marks the run that made it', () => {
        const [NAN_1, NEGATIVE_NAN_2] = [0x7ff8000000000001n, 0xfff8000000000002n];
        const rows = table([SV.f64bits(NAN_1), SV.f64bits(NEGATIVE_NAN_2), SV.f64(0), SV.f64(1)]);
        const [a, b, zero, one] = [f64(0), f64(1), f64(2), f64(3)];
        /** The bits of the Float64 result of a reducer, and whether the run was marked. */
        const run = (reducer: ReturnType<typeof R.min>): [string, boolean] => {
            const outcome = evaluate(rows, rangeRequest({ start: new Uint8Array(), end: new Uint8Array() }, { reducers: [reducer] }));
            const value = outcome.frames[0].results[0].value?.value;
            return [value?.case === 'float64Value' ? floatBits(value.value).toString(16) : 'no Float64', outcome.unspecifiedNaN];
        };

        // Arithmetic keeps its one NaN operand. With two NaN operands it keeps the left one and
        // marks the run.
        expect(run(R.min(X.add(a, one)))).toEqual(['7ff8000000000001', false]);
        expect(run(R.min(X.add(a, b)))).toEqual(['7ff8000000000001', true]);
        expect(run(R.min(X.add(b, a)))).toEqual(['fff8000000000002', true]);

        // An invalid operation gives the default quiet NaN and marks the run. A nonzero number
        // divided by zero is an infinity and leaves the run unmarked.
        expect(run(R.min(X.div(zero, zero)))).toEqual(['7ff8000000000000', true]);
        expect(run(R.min(X.div(one, zero)))).toEqual(['7ff0000000000000', false]);

        // A sum over one NaN keeps it. A sum over two NaNs adds one to the other and marks the
        // run.
        expect(run(R.sum(a))).toEqual(['7ff8000000000001', false]);
        expect(evaluate(table([SV.f64bits(NAN_1)], [SV.f64bits(NEGATIVE_NAN_2)]),
            rangeRequest({ start: new Uint8Array(), end: new Uint8Array() }, { reducers: [R.sum(a)] })).unspecifiedNaN).toBe(true);
    });

    test('a stored row keeps only the columns that a field can address', async () => {
        // A row of 70000 columns, all NULL but column 65535, the last that a field can name, and
        // column 69999. damaged gives one column the invalid presence byte 2.
        const wide = (damaged?: number): Uint8Array => {
            const columns = Array.from({ length: 70000 }, (_, column) =>
                (column === 65535 ? [1, ...SV.i64(7)] : column === 69999 ? [1, ...SV.i64(9)] : [column === damaged ? 2 : 0]));
            return Uint8Array.from([...varint(70000), ...columns.flat()]);
        };
        expect(decodeStoredRow(wide())).toHaveLength(65536);

        const last: ParamsInit = { reducers: [R.min(i64(65535)), R.count(i64(65534))] };
        expect(await resultOf(await storeOf([[be(0, 8), wide()]]), last)).toBe('i64:7, u64:0');
        expect(await resultOf(await storeOf([[be(0, 8), wide(69000)]]), last))
            .toBe('FailedPrecondition [Invalid Bool: Expected 0 or 1, found different value]');
        const narrow = encodeRow(new Array<null>(65535).fill(null));
        expect(await resultOf(await storeOf([[be(0, 8), narrow]]), last)).toBe('FailedPrecondition [stored row index out of bounds]');
    });

    test('a request that the transport cannot decode gets an error, and the store answers the next one', async () => {
        const client = await storeOf(ints(1));
        const router = createConnectRouter();
        opened[opened.length - 1].store.routes(router);
        const reduce = router.handlers.find((handler) => handler.method.name === 'Reduce')!;

        // A length delimited protobuf field around a message.
        const field = (number: number, message: Uint8Array) =>
            Uint8Array.from([(number << 3) | 2, ...varint(message.length), ...message]);

        // A Reduce request with MIN over an Int64 literal inside nested cast_float64 calls. It is
        // written as bytes because building or encoding a message nested as deep as the one below
        // exhausts the call stack as well.
        const nested = (levels: number): Uint8Array => {
            let expr = Uint8Array.from([0x12, 2, 8, 1]);
            for (let level = 0; level < levels; level++) expr = field(9, expr);
            return field(3, field(1, Uint8Array.from([8, RangeReduceOp.MIN_FIELD, ...field(2, expr)])));
        };

        // The error in the trailer of the response stream, undefined for a call that succeeded.
        const errorOf = async (request: Uint8Array): Promise<unknown> => {
            const envelope = new Uint8Array(5 + request.length);
            new DataView(envelope.buffer).setUint32(1, request.length);
            envelope.set(request, 5);
            const response = await reduce({
                httpVersion: '1.1',
                url: 'http://localhost' + reduce.requestPath,
                method: 'POST',
                header: new Headers({ 'Content-Type': 'application/connect+proto', 'Connect-Protocol-Version': '1' }),
                body: (async function* () {
                    yield envelope;
                })(),
                signal: new AbortController().signal,
            });
            const chunks: Uint8Array[] = [];
            for await (const chunk of response.body ?? []) chunks.push(chunk);

            // The stream is a sequence of envelopes of a flag byte, a length and a payload. The
            // last envelope is the trailer, in JSON.
            const body = Buffer.concat(chunks);
            let trailer = body.subarray(0, 0);
            for (let at = 0; at < body.length; at += 5 + trailer.length) trailer = body.subarray(at + 5, at + 5 + body.readUInt32BE(at + 1));
            return (JSON.parse(trailer.toString()) as { error?: unknown }).error;
        };

        expect(await errorOf(nested(10))).toBeUndefined();
        expect(await errorOf(nested(10000))).toBeDefined();
        expect(await errorOf(nested(10))).toBeUndefined();
        expect(await resultOf(client, countAll)).toBe('u64:1');
    });

    test('expressions the store does not compute answer UNIMPLEMENTED', async () => {
        const client = await storeOf(ints(1));
        const [ts, date32] = [X.v(0, K.TIMESTAMP), X.v(0, K.DATE32)];
        const nanos = X.sub(ts, date32);
        const micros = X.sub(ts, ts);
        const mixed = 'Unimplemented [timestamp and duration arithmetic with mixed units is not implemented: ';
        const cases: [ParamsInit, string][] = [
            [{ reducers: [R.min(X.trunc(text(0)))] }, 'Unimplemented [date_trunc_day over a string is not implemented]'],
            [{ reducers: [R.min(X.trunc(X.lit(V.str('2020-01-02'))))] }, 'Unimplemented [date_trunc_day over a string is not implemented]'],
            [{ reducers: [R.min(X.add(ts, nanos))] }, mixed + 'Timestamp(\u00b5s) + Duration(ns)]'],
            [{ reducers: [R.min(X.sub(X.trunc(date32), micros))] }, mixed + 'Timestamp(ns) - Duration(\u00b5s)]'],
            [{ reducers: [R.count(X.add(micros, nanos))] }, mixed + 'Duration(\u00b5s) + Duration(ns)]'],
            [{ reducers: [R.count(X.add(nanos, ts))] }, mixed + 'Duration(ns) + Timestamp(\u00b5s)]'],
        ];
        for (const [params, want] of cases) expect(await resultOf(client, params)).toBe(want);
    });

    test('a call canceled while its range is read aborts the transaction at the next row', async () => {
        const client = await storeOf(ints(1, 2, 3));

        // The call is canceled as the scan opens its cursor, so the handler stops at the first
        // row and never steps the cursor.
        const controller = new AbortController();
        const cursors = jest.spyOn(IDBObjectStore.prototype, 'openCursor');
        cursors.mockImplementation(function (this: IDBObjectStore, ...args) {
            cursors.mockRestore();
            abortCall(controller);
            return this.openCursor(...args);
        });
        const aborts = jest.spyOn(IDBTransaction.prototype, 'abort');
        const steps = jest.spyOn(IDBCursor.prototype, 'continue');
        const call = client.query.reduce({ params: countAll }, { signal: controller.signal });
        expect((await failure(call)).code).toBe(Code.Canceled);
        await until(() => aborts.mock.calls.length > 0);
        expect(aborts).toHaveBeenCalledTimes(1);
        expect(steps).not.toHaveBeenCalled();
    });
});

describe('the comparison of two answers', () => {
    const results = (...values: (ValueInit | undefined)[]): Outcome => ({
        frames: [create(ReduceResponseSchema, { detail: {}, results: values.map((value) => ({ value })) })],
    });
    const groups = (...keyed: [key: ValueInit, count: number][]): Outcome => {
        const rows = keyed.map(([key, count]) => ({ groupValues: [key], groupValuesPresent: [true], results: [{ value: V.u64(count) }] }));
        return { frames: [create(ReduceResponseSchema, { detail: {}, groups: rows })] };
    };
    const failed = (code: Code, message: string, frames: Outcome['frames'] = []): Outcome => ({ frames, error: new ConnectError(message, code) });
    const range = { start: new Uint8Array(), end: new Uint8Array() };
    const x = f64(0);
    const computed = X.mul(x, X.lit(V.f64(1)));
    const status = (params: ParamsInit, expected: Outcome, actual: Outcome, unspecifiedNaN = false) =>
        compare(rangeRequest(range, params), expected, actual, { unspecifiedNaN }).status;

    test('UNIMPLEMENTED is outside only for a documented class and a request that the reference does not reject as invalid', () => {
        const params: ParamsInit = { reducers: [R.count(X.trunc(text(0)))] };
        const documented = failed(Code.Unimplemented, 'date_trunc_day over a string is not implemented');
        const mixed = failed(Code.Unimplemented, 'timestamp and duration arithmetic with mixed units is not implemented: Duration(\u00b5s) + Duration(ns)');
        expect(status(params, results(V.u64(1)), documented)).toBe('outside');
        expect(status(params, failed(Code.FailedPrecondition, 'a row does not decode'), mixed)).toBe('outside');
        expect(status(params, failed(Code.InvalidArgument, 'reduce params are invalid'), documented)).toBe('different');
        expect(status(params, results(V.u64(1)), failed(Code.Unimplemented, 'cast_float64 of a decimal is not implemented'))).toBe('different');
    });

    test('a documented UNIMPLEMENTED class is outside only where it fits the request', () => {
        const one = results(V.u64(1));
        const truncated = failed(Code.Unimplemented, 'date_trunc_day over a string is not implemented');
        const mixed = (operands: string) =>
            failed(Code.Unimplemented, 'timestamp and duration arithmetic with mixed units is not implemented: ' + operands);
        const countAll: ParamsInit = { reducers: [R.countAll()] };

        // date_trunc_day over a string needs a date_trunc_day somewhere in a reducer or a key.
        expect(status({ reducers: [R.min(X.cast(X.trunc(text(0))))] }, one, truncated)).toBe('outside');
        expect(status({ reducers: [R.countAll()], groupBy: [X.add(X.trunc(text(0)), x)] }, one, truncated)).toBe('outside');
        expect(status(countAll, one, truncated)).toBe('different');
        expect(status({ reducers: [R.min(X.lower(text(0)))], groupBy: [x] }, one, truncated)).toBe('different');

        // Mixed units name a unit for each of two operands, and the two differ.
        for (const operands of ['Timestamp(\u00b5s) + Duration(ns)', 'Duration(ns) - Timestamp(\u00b5s)', 'Duration(ns) + Duration(\u00b5s)']) {
            expect(status(countAll, one, mixed(operands))).toBe('outside');
        }
        for (const operands of ['Duration(ns) + Duration(ns)', 'Timestamp(\u00b5s) - Timestamp(\u00b5s)', 'Timestamp(\u00b5s) - Date32', '']) {
            expect(status(countAll, one, mixed(operands))).toBe('different');
        }
    });

    test('the bits of a NaN are compared unless the request made an unspecified NaN', () => {
        const [quiet, payload, negative] = [0x7ff8000000000000n, 0x7ff8000000000001n, 0xfff8000000000000n]
            .map((bits) => V.f64(floatOfBits(bits)));
        const min: ParamsInit = { reducers: [R.min(computed)] };
        expect(status(min, results(quiet), results(quiet))).toBe('identical');
        expect(status(min, results(quiet), results(payload))).toBe('different');
        expect(status(min, results(quiet), results(negative))).toBe('different');
        expect(status(min, results(quiet), results(payload), true)).toBe('identical');

        const grouped: ParamsInit = { reducers: [R.countAll()], groupBy: [x] };
        expect(status(grouped, groups([payload, 1]), groups([payload, 1]))).toBe('identical');
        expect(status(grouped, groups([payload, 1]), groups([negative, 1]))).toBe('different');
        expect(status(grouped, groups([quiet, 1], [payload, 2]), groups([payload, 1], [quiet, 2]))).toBe('different');
        expect(status(grouped, groups([payload, 1]), groups([negative, 1]), true)).toBe('identical');
    });

    test('a frame before the error of a request without group_by is a difference', () => {
        const error = (frames?: Outcome['frames']) => failed(Code.FailedPrecondition, 'a row does not decode', frames);
        const early = results(V.u64(1)).frames;
        expect(status({ reducers: [R.countAll()] }, error(), error())).toBe('identical');
        expect(status({ reducers: [R.countAll()] }, error(), error(early))).toBe('different');
        expect(status({ reducers: [R.countAll()], groupBy: [x] }, error(), error(groups([V.f64(1), 1]).frames))).toBe('identical');
    });

    test('a NaN next to a number passes only for an extremum over arithmetic in a request that made an unspecified NaN', () => {
        const [nan, one] = [results(V.f64(Number.NaN)), results(V.f64(1))];
        expect(status({ reducers: [R.min(computed)] }, nan, one, true)).toBe('identical');
        expect(status({ reducers: [R.min(computed)] }, nan, one, false)).toBe('different');
        expect(status({ reducers: [R.min(x)] }, nan, one, true)).toBe('different');
        expect(status({ reducers: [R.sum(computed)] }, nan, one, true)).toBe('different');
        expect(status({ reducers: [R.min(computed)] }, nan, results(undefined), true)).toBe('different');
    });

    test('groups keyed by an unspecified NaN are compared by their other keys and their counts', () => {
        const params: ParamsInit = { reducers: [R.countAll()], groupBy: [computed] };
        const nan = V.f64(Number.NaN);
        const split = groups([nan, 1], [nan, 2], [V.f64(1), 5]);
        expect(status(params, split, groups([nan, 3], [V.f64(1), 5]), true)).toBe('identical');
        expect(status(params, split, groups([nan, 99], [V.f64(1), 5]), true)).toBe('different');
        expect(status(params, split, groups([V.f64(1), 5]), true)).toBe('different');
        expect(status(params, split, groups([nan, 3], [V.f64(1), 5]), false)).toBe('different');
        expect(status({ ...params, groupBy: [x] }, split, groups([nan, 3], [V.f64(1), 5]), true)).toBe('different');
    });
});
