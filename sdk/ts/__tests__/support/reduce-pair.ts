/**
 * The stores that Reduce tests compare: the isolated simulator, the IndexedDB store, and the
 * evaluator of the IndexedDB store fed with rows directly.
 *
 * A dataset is written to the simulator under a key prefix of its own and, unless it is kept out
 * of the IndexedDB store, under the same keys to a fresh IndexedDB database. A suite releases
 * that database when it is done with the dataset. A request runs on both through a Client. For a
 * dataset kept out, the evaluator answers in place of the store, as the store's handler would
 * after a scan of the database. The evaluator runs on every request, and where the store
 * answered too, the two answers must have the same error and the same results and groups.
 */
import { create, fromBinary, toBinary, type MessageInitShape } from '@bufbuild/protobuf';
import { Code, ConnectError } from '@connectrpc/connect';
import type { Client } from '../../src/client';
import { ReduceRequestSchema, type ReduceRequest } from '../../src/gen/ts/store/v1/query_pb';
import { planReduce, ReduceRun, validateReduceEnvelope } from '../../src/indexeddb/reduce';
import { MAX_KEY_LEN } from '../../src/limits';
import { indexedDb, isolatedSimulator, type OpenBackend } from './backends';
import { concat, put, utf8, type Row } from './contract';
import { answer, compare, exactDifference, type Comparison, type Outcome } from './reduce-compare';
import type { ParamsInit } from './reduce-gen';

/** The rows of one case. */
export interface Dataset {
    /** The key prefix of every row of the dataset. */
    prefix: Uint8Array;
    /** First key of the range that holds exactly the rows of the dataset. */
    start: Uint8Array;
    /** Last key of that range, the prefix followed by 0xff up to the longest key. */
    end: Uint8Array;
    /** The rows with their whole keys, in key order. */
    rows: Row[];
    /** Client of the IndexedDB store of this dataset alone, absent for a dataset kept out. */
    client?: Client;
    /** The sequence number each store gave the write of the rows, 0 where nothing was written. */
    sequence: { simulator: bigint; store: bigint };
}

/** The answers of both sides to one request and how they compare. */
export interface Checked {
    /** How the two answers compare. */
    comparison: Comparison;
    /** The answer of the simulator. */
    expected: Outcome;
    /** The answer of the IndexedDB store, or of its evaluator for a dataset outside the store. */
    actual: Outcome;
}

const inRange = (key: Uint8Array, request: ReduceRequest): boolean =>
    Buffer.compare(key, request.start) >= 0 && (request.end.length === 0 || Buffer.compare(key, request.end) <= 0);

/**
 * Runs a request on the evaluator over rows in key order, as the store's handler does after it
 * reads them. The request first makes a round trip through its wire form, as on its way to a
 * store, because a message object can hold values that the wire does not carry, such as a float
 * bound of -0. unspecifiedNaN tells whether the run made a NaN whose sign and payload the service
 * does not define.
 */
export function evaluate(rows: readonly Row[], request: ReduceRequest, maxStateBytes = 64 * 1024 * 1024): Outcome & { unspecifiedNaN: boolean } {
    const outcome: Outcome & { unspecifiedNaN: boolean } = { frames: [], unspecifiedNaN: false };
    const received = fromBinary(ReduceRequestSchema, toBinary(ReduceRequestSchema, request));
    let run: ReduceRun | undefined;
    try {
        validateReduceEnvelope(received);
        run = new ReduceRun(planReduce(received), { maxStateBytes });
        for (const [key, value] of rows) {
            if (inRange(key, received)) run.push(key, value);
        }
        run.finish();
        for (const frame of run.frames(0n)) outcome.frames.push(frame);
    } catch (error) {
        if (!(error instanceof ConnectError)) throw error;
        outcome.error = error;
    }
    outcome.unspecifiedNaN = run?.unspecifiedNaN ?? false;
    return outcome;
}

/** The simulator and the IndexedDB stores of one suite, with the datasets written to them. */
export class ReducePair {
    private readonly stores: OpenBackend[] = [];
    private datasets = 0;

    private constructor(private readonly simulatorBackend: OpenBackend) {}

    static async open(): Promise<ReducePair> {
        return new ReducePair(await isolatedSimulator.open());
    }

    get simulator(): Client {
        return this.simulatorBackend.client;
    }

    /**
     * Writes rows with keys relative to a new prefix to the simulator and, unless indexedDb is
     * false, to a new IndexedDB store of their own. name becomes part of the prefix and must
     * differ between the datasets of a suite. A dataset without a name gets the next number.
     */
    async store(rows: Row[], options: { name?: string; indexedDb?: boolean } = {}): Promise<Dataset> {
        const prefix = utf8('reduce/' + (options.name ?? (this.datasets++).toString(36)) + '/');
        const stored = rows
            .map(([key, value]): Row => [concat(prefix, key), value])
            .sort((a, b) => Buffer.compare(a[0], b[0]));
        const end = concat(prefix, new Uint8Array(MAX_KEY_LEN - prefix.length).fill(0xff));
        const dataset: Dataset = { prefix, start: prefix, end, rows: stored, sequence: { simulator: 0n, store: 0n } };

        // A Put needs at least one row, so a dataset without rows writes nothing.
        if (stored.length > 0) dataset.sequence.simulator = await put(this.simulator, stored);
        if (options.indexedDb ?? true) {
            const store = await indexedDb.open();
            this.stores.push(store);
            dataset.client = store.client;
            if (stored.length > 0) dataset.sequence.store = await put(store.client, stored);
        }
        return dataset;
    }

    /**
     * Runs one request on the simulator and on the IndexedDB store, or on the evaluator for a
     * dataset outside the store, and compares the answers. The evaluator runs on every request to
     * tell whether the request made a NaN that the comparison must allow for. Where the store
     * answered as well, any difference between its answer and the evaluator's is reported.
     */
    async request(dataset: Dataset, message: ReduceRequest, smallGroups = true): Promise<Checked> {
        const expected = await answer(this.simulator.query.reduce(message));
        const evaluated = evaluate(dataset.rows, message);
        const actual = dataset.client === undefined ? evaluated : await answer(dataset.client.query.reduce(message));
        const drift = actual === evaluated ? undefined : exactDifference(actual, evaluated);
        const comparison: Comparison = drift === undefined
            ? compare(message, expected, actual, { unspecifiedNaN: evaluated.unspecifiedNaN, smallGroups })
            : { status: 'different', detail: 'the store and the evaluator of the tests disagree: ' + drift, textDiffers: false, limited: false };
        return { comparison, expected, actual };
    }

    /** Runs params over the whole dataset and compares the answers as request does. */
    check(dataset: Dataset, params: ParamsInit, smallGroups = true): Promise<Checked> {
        return this.request(dataset, rangeRequest(dataset, params), smallGroups);
    }

    /** Closes and deletes the IndexedDB stores of the datasets stored so far. */
    async release(): Promise<void> {
        for (const store of this.stores.splice(0)) await store.close();
    }

    async close(): Promise<void> {
        await this.release();
        await this.simulatorBackend.close();
    }
}

/** A request over a range with the given params and any other fields of the request. */
export function rangeRequest(
    range: { start: Uint8Array; end: Uint8Array },
    params: ParamsInit,
    rest: Omit<MessageInitShape<typeof ReduceRequestSchema>, 'start' | 'end' | 'params' | '$typeName'> = {},
): ReduceRequest {
    return create(ReduceRequestSchema, { ...rest, start: range.start, end: range.end, params });
}

/** Counts of one run of comparisons. */
export class Tally {
    /** Requests noted. */
    requests = 0;
    /** Requests whose answers agree. */
    identical = 0;
    /** Requests that the store under test answered UNIMPLEMENTED for a documented class. */
    outside = 0;
    /** Requests with a part of the answer compared only as far as it is defined. */
    limited = 0;
    /** Requests whose answers agree on the error code and differ in its text. */
    textDiffers = 0;
    /** Labels and differences of the requests whose answers differ. */
    readonly different: string[] = [];
    /** Labels and differences of the first 10 requests whose error texts differ. */
    readonly textDifferences: string[] = [];
    /** Counts of the outside requests by class. A class is the message up to its first colon. */
    readonly outsideClasses: Record<string, number> = {};
    /** Counts of the simulator's answers by error code or by shape of the result. */
    readonly answers: Record<string, number> = {};

    /** Counts one compared request under its label. */
    note(label: string, { comparison, expected }: Checked): void {
        this.requests++;
        const shape = expected.error !== undefined ? Code[expected.error.code]
            : expected.frames[0]?.results.length ? 'results'
                : expected.frames.some((frame) => frame.groups.length > 0) ? 'groups' : 'no groups';
        this.answers[shape] = (this.answers[shape] ?? 0) + 1;
        if (comparison.limited) this.limited++;
        if (comparison.status === 'outside') {
            this.outside++;
            const reason = comparison.detail.split(':')[0];
            this.outsideClasses[reason] = (this.outsideClasses[reason] ?? 0) + 1;
        } else if (comparison.status === 'different') {
            this.different.push(label + ' | ' + comparison.detail.slice(0, 600));
        } else {
            this.identical++;
            if (comparison.textDiffers) {
                this.textDiffers++;
                if (this.textDifferences.length < 10) this.textDifferences.push(label + ' | ' + comparison.detail.slice(0, 600));
            }
        }
    }

    summary(): string {
        return 'requests=' + this.requests + ' identical=' + this.identical + ' different=' + this.different.length
            + ' outside=' + this.outside + ' ' + JSON.stringify(this.outsideClasses) + ' limited=' + this.limited
            + ' text differences=' + this.textDiffers + ' simulator answers=' + JSON.stringify(this.answers);
    }

    /** Expects that requests were compared and that no answer and no error text differs. */
    expectClean(): void {
        expect(this.requests).toBeGreaterThan(0);
        expect(this.different).toEqual([]);
        expect(this.textDifferences).toEqual([]);
    }
}
