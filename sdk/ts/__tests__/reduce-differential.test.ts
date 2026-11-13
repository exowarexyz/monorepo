/**
 * Random Reduce requests over random rows, on the isolated simulator and on the IndexedDB store.
 *
 * A case draws a schema, rows and several requests from one seed, writes the rows to the stores
 * and compares the two answers to every request (support/reduce-compare.ts states what is
 * compared, support/reduce-gen.ts what is generated). The size and the seed of a run come from
 * the environment:
 *
 *   REDUCE_FUZZ_SEED       base seed of the run
 *   REDUCE_FUZZ_CASES      datasets of up to 257 rows, 8 requests each
 *   REDUCE_FUZZ_BIG_CASES  datasets of 4095 to 9000 rows, 4 requests each
 *   REDUCE_FUZZ_ONLY       replays one request, as printed by a failure
 *
 * The tests run the IndexedDB store on fake-indexeddb, where walking a cursor over a key range
 * takes time that grows with the square of its rows. So only a dataset of up to 257 rows goes
 * into that store, and a dataset of thousands of rows runs on the store's evaluator fed with the
 * rows directly. Such a dataset crosses the 4096 rows of a scan chunk, and some of its requests
 * carry a literal large enough to end batches at their byte budget.
 */
import { hex, utf8 } from './support/contract';
import { renderKeys, renderResults, showError, type Outcome } from './support/reduce-compare';
import { BIG_SIZES, genRequest, genRows, genSchema, rng, SIZES } from './support/reduce-gen';
import { ReducePair, Tally } from './support/reduce-pair';

/** A count or seed from the environment. A value that is not a whole number fails the run. */
function setting(name: string, fallback: number, text = process.env[name]): number {
    if (text === undefined) return fallback;
    const value = Number(text);
    if (!/^\d+$/.test(text) || !Number.isSafeInteger(value)) throw new Error(name + ' must be a whole number, got ' + text);
    return value;
}

const BASE_SEED = setting('REDUCE_FUZZ_SEED', 20261112);
const CASES = setting('REDUCE_FUZZ_CASES', 400);
const BIG_CASES = setting('REDUCE_FUZZ_BIG_CASES', 12);

/** The request to replay: its case seed, its request index and whether its case is big. */
const ONLY = ((text = process.env.REDUCE_FUZZ_ONLY) => {
    if (text === undefined) return undefined;
    const [seed, index, size, ...rest] = text.split(':');
    if (rest.length > 0 || (size !== undefined && size !== 'big')) throw new Error('REDUCE_FUZZ_ONLY must be seed:index or seed:index:big');
    return { seed: setting('REDUCE_FUZZ_ONLY', 0, seed), index: setting('REDUCE_FUZZ_ONLY', 0, index ?? ''), big: size === 'big' };
})();

/** An answer as text. Its error comes first, then its results or its groups. */
function show(outcome: Outcome): string {
    const lines = outcome.error === undefined ? [] : [showError(outcome.error)];
    for (const frame of outcome.frames) {
        if (frame.results.length > 0) lines.push(renderResults(frame.results, true).join(', '));
        for (const group of frame.groups) lines.push(renderKeys(group, true).join(' | ') + ' => ' + renderResults(group.results, true).join(', '));
    }
    return lines.join('\n');
}

/** A JSON replacer that prints bigints and bytes. */
const printable = (_: string, value: unknown) => (typeof value === 'bigint' ? value + 'n'
    : value instanceof Uint8Array ? 'hex:' + hex(value) : value);

describe('Reduce on random requests', () => {
    let pair: ReducePair;

    beforeAll(async () => {
        pair = await ReducePair.open();
    });

    afterAll(() => pair.close());

    test('the IndexedDB store answers as the simulator does', async () => {
        const tally = new Tally();

        // Runs one case. With replay set, it runs only that request and prints both answers. The
        // key prefix of the dataset comes from the seed, because requests hold offsets into the
        // keys and a replay must build the same ones.
        const runCase = async (seed: number, big: boolean, replay?: number) => {
            const r = rng(seed);
            const schema = genSchema(r);
            const rows = genRows(r, schema, r.pick(big ? BIG_SIZES : SIZES));

            // One case in 50 replaces the value of a random row with bytes that do not decode.
            if (rows.length > 0 && r.chance(0.02)) rows[r.int(rows.length)][1] = utf8('malformed row');
            const dataset = await pair.store(rows, { name: (big ? 'big-' : '') + seed.toString(36), indexedDb: !big });
            for (let index = 0; index < (big ? 4 : 8); index++) {
                const params = genRequest(r, { schema, prefixLength: dataset.prefix.length }, { largeLiteral: big });
                if (replay !== undefined && replay !== index) continue;
                const label = 'REDUCE_FUZZ_ONLY=' + seed + ':' + index + (big ? ':big' : '') + ' rows=' + rows.length;
                const checked = await pair.check(dataset, params);
                tally.note(label, checked);
                if (replay === undefined) continue;
                console.log([label, JSON.stringify(params, printable), JSON.stringify(checked.comparison), '--- simulator',
                    show(checked.expected), '--- store under test', show(checked.actual)].join('\n'));
            }
            await pair.release();
        };

        // A replay runs its one request. Otherwise every small case runs and then every big case,
        // each from its own seed derived from the base seed.
        if (ONLY !== undefined) await runCase(ONLY.seed, ONLY.big, ONLY.index);
        else {
            for (let index = 0; index < CASES; index++) await runCase((BASE_SEED * 1000003 + index) >>> 0, false);
            for (let index = 0; index < BIG_CASES; index++) await runCase(((BASE_SEED ^ 0x5f3759df) * 1000003 + index) >>> 0, true);
        }
        console.log('reduce random requests: base seed=' + BASE_SEED + ' ' + tally.summary());
        tally.expectClean();
    }, 600_000);
});
