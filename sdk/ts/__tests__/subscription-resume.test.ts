import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import { Code, ConnectError, type CallOptions } from '@connectrpc/connect';
import { Client } from '../src/client';
import { SelectorSchema } from '../src/gen/ts/common/v1/kv_pb';
import { ErrorInfoSchema } from '../src/gen/ts/google/rpc/error_details_pb';
import {
    SubscribeRequestSchema,
    SubscribeResponseSchema,
    type SubscribeRequest,
    type SubscribeResponse,
} from '../src/gen/ts/log/v1/stream_pb';
import { HttpError } from '../src/error';
import { ReadSession, StoreKeyPrefix, type StoreBatch } from '../src/store';
import { normalizeSubscriptionRetry, type SubscriptionRetryConfig } from '../src/subscription';

const MAX_U64 = (1n << 64n) - 1n;
const key = new Uint8Array([7]);
const selectors = [create(SelectorSchema)];

type Step = SubscribeResponse | Error | { wait: number } | { hang: 'abortable' | 'forever' };
type Attempt = Step[] | ((request: SubscribeRequest, options: CallOptions) => AsyncIterable<SubscribeResponse>);

function frame(sequenceNumber: bigint, keys: Uint8Array[] = [key]): SubscribeResponse {
    return create(SubscribeResponseSchema, {
        sequenceNumber,
        entries: keys.map((entryKey) => ({ key: entryKey, value: entryKey })),
    });
}

function checkpoint(sequenceNumber: bigint): SubscribeResponse {
    return create(SubscribeResponseSchema, { sequenceNumber });
}

function abortError(signal: AbortSignal): ConnectError {
    return ConnectError.from(signal.reason, Code.Canceled);
}

function waitFor(ms: number, signal: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(resolve, ms);
        signal.addEventListener('abort', () => {
            clearTimeout(timer);
            reject(abortError(signal));
        }, { once: true });
    });
}

async function* play(steps: Step[], options: CallOptions): AsyncGenerator<SubscribeResponse> {
    const signal = options.signal!;
    for (const step of steps) {
        if (step instanceof Error) throw step;
        if ('wait' in step) {
            await waitFor(step.wait, signal);
        } else if ('hang' in step) {
            if (step.hang === 'forever') await new Promise<never>(() => {});
            await waitFor(2 ** 31 - 1, signal);
        } else {
            yield step;
        }
    }
}

function evicted(): ConnectError {
    const detail = create(ErrorInfoSchema, {
        domain: 'log.stream',
        reason: 'BATCH_EVICTED',
        metadata: { oldest_retained: '9' },
    });
    return new ConnectError('batch evicted', Code.OutOfRange, undefined, [
        { desc: ErrorInfoSchema, value: detail },
    ]);
}

function shutdown(): ConnectError {
    const detail = create(ErrorInfoSchema, { domain: 'log.stream', reason: 'SERVER_SHUTDOWN' });
    return new ConnectError('server shutting down', Code.Unavailable, undefined, [
        { desc: ErrorInfoSchema, value: detail },
    ]);
}

function harness(attempts: Attempt[], retry: Partial<SubscriptionRetryConfig> = {}) {
    const client = new Client('http://127.0.0.1:1', {
        token: '',
        subscriptionRetry: { initialBackoffMs: 1, maxBackoffMs: 1, ...retry },
    });
    const requests: SubscribeRequest[] = [];
    const options: CallOptions[] = [];
    client.stream.subscribe = ((request: SubscribeRequest, callOptions: CallOptions) => {
        requests.push(request);
        options.push(callOptions);
        const attempt = attempts.shift() ?? [{ hang: 'abortable' }];
        return typeof attempt === 'function' ? attempt(request, callOptions) : play(attempt, callOptions);
    }) as typeof client.stream.subscribe;
    const since = () => requests.map((request) => request.sinceSequenceNumber);
    return { client, store: client.store(), requests, options, since };
}

async function take(
    stream: AsyncIterable<StoreBatch>,
    count: number,
): Promise<bigint[]> {
    const sequences: bigint[] = [];
    const iterator = stream[Symbol.asyncIterator]();
    try {
        while (sequences.length < count) {
            const next = await iterator.next();
            if (next.done) break;
            sequences.push(next.value.sequenceNumber);
        }
    } finally {
        await iterator.return?.();
    }
    return sequences;
}

async function drain(stream: AsyncIterable<StoreBatch>): Promise<bigint[]> {
    const sequences: bigint[] = [];
    for await (const batch of stream) sequences.push(batch.sequenceNumber);
    return sequences;
}

afterEach(() => {
    jest.restoreAllMocks();
});

describe('resume', () => {
    test('a server restart with writes during the outage yields one continuous sequence', async () => {
        const { store, since } = harness([
            [checkpoint(10n), frame(11n), frame(12n), shutdown()],
            [checkpoint(12n), frame(13n), frame(14n), frame(15n)],
        ]);

        await expect(take(store.subscribe({ selectors }), 5)).resolves.toEqual([11n, 12n, 13n, 14n, 15n]);
        expect(since()).toEqual([undefined, 13n]);
    });

    test('a clean end of the stream reconnects after the highest frame', async () => {
        const { store, since } = harness([
            [checkpoint(5n), frame(6n)],
            [checkpoint(6n), frame(7n)],
        ]);

        await expect(take(store.subscribe({ selectors }), 2)).resolves.toEqual([6n, 7n]);
        expect(since()).toEqual([undefined, 7n]);
    });

    test.each([
        ['reset', new ConnectError('terminated', Code.Unknown, undefined, undefined, new TypeError('terminated'))],
        ['internal', new ConnectError('stream failed', Code.Internal)],
        ['aborted', new ConnectError('aborted', Code.Aborted)],
        ['exhausted', new ConnectError('busy', Code.ResourceExhausted)],
        ['unavailable', new ConnectError('unavailable', Code.Unavailable)],
    ])('a %s mid-stream resumes from the next sequence', async (_name, failure) => {
        const { store, since } = harness([
            [checkpoint(1n), frame(2n), failure],
            [checkpoint(2n), frame(3n)],
        ]);

        await expect(take(store.subscribe({ selectors }), 2)).resolves.toEqual([2n, 3n]);
        expect(since()).toEqual([undefined, 3n]);
    });

    test('the initial checkpoint fixes the resume point of a live-only subscription', async () => {
        const { store, since } = harness([
            [checkpoint(41n), new ConnectError('down', Code.Unavailable)],
            [checkpoint(41n), frame(42n)],
        ]);

        await expect(take(store.subscribe({ selectors }), 1)).resolves.toEqual([42n]);
        expect(since()).toEqual([undefined, 42n]);
    });

    test('empty frames and frames emptied by the key prefix advance the cursor', async () => {
        const harnessed = harness([
            [
                checkpoint(3n),
                frame(4n, [new Uint8Array([2, 7])]),
                checkpoint(5n),
                new ConnectError('down', Code.Unavailable),
            ],
            [checkpoint(5n), frame(6n, [new Uint8Array([1, 7])])],
        ]);
        const store = harnessed.store.withKeyPrefix(new StoreKeyPrefix(new Uint8Array([1])));

        await expect(take(store.subscribe({ selectors }), 1)).resolves.toEqual([6n]);
        expect(harnessed.since()).toEqual([undefined, 6n]);
    });

    test('a positive since sequence is kept across opens that fail before any frame', async () => {
        const { store, since } = harness([
            [new ConnectError('connection refused', Code.Unknown)],
            [new ConnectError('down', Code.Unavailable)],
            [],
            [checkpoint(8n), frame(9n)],
        ]);

        await expect(take(store.subscribe({ selectors, sinceSequenceNumber: 9n }), 1)).resolves.toEqual([9n]);
        expect(since()).toEqual([9n, 9n, 9n, 9n]);
    });

    test('a since sequence of zero is live-only', async () => {
        const { store, since } = harness([[new ConnectError('down', Code.Unavailable)]]);

        await expect(drain(store.subscribe({ selectors, sinceSequenceNumber: 0n }))).rejects.toMatchObject({
            connectCode: Code.Unavailable,
        });
        expect(since()).toEqual([0n]);
    });

    test('frames below the cursor are dropped instead of delivered twice', async () => {
        const { store, since } = harness([
            [checkpoint(1n), frame(2n), frame(3n), new ConnectError('down', Code.Unavailable)],
            [frame(2n), frame(3n), frame(4n)],
        ]);

        await expect(take(store.subscribe({ selectors }), 3)).resolves.toEqual([2n, 3n, 4n]);
        expect(since()).toEqual([undefined, 4n]);
    });

    test('backoff grows exponentially within one outage and resets after a frame', async () => {
        jest.spyOn(Math, 'random').mockReturnValue(1);
        const opened: number[] = [];
        const down = new ConnectError('down', Code.Unavailable);
        const attempts: Attempt[] = [
            [checkpoint(1n), down],
            [down],
            [down],
            [checkpoint(1n), frame(2n), down],
            [checkpoint(2n), frame(3n)],
        ].map((steps) => (_request: SubscribeRequest, options: CallOptions) => {
            opened.push(performance.now());
            return play(steps as Step[], options);
        });
        const { store, since } = harness(attempts, { initialBackoffMs: 40, maxBackoffMs: 100 });

        await expect(take(store.subscribe({ selectors }), 2)).resolves.toEqual([2n, 3n]);
        expect(since()).toEqual([undefined, 2n, 2n, 2n, 3n]);
        const gaps = opened.slice(1).map((at, index) => at - opened[index]);
        expect(gaps[0]).toBeGreaterThanOrEqual(39);
        expect(gaps[1]).toBeGreaterThanOrEqual(79);
        expect(gaps[2]).toBeGreaterThanOrEqual(99);
        expect(gaps[3]).toBeGreaterThanOrEqual(39);
        expect(gaps[3]).toBeLessThan(99);
    });

    test('backoff keeps growing while stale checkpoints reset the budget', async () => {
        jest.spyOn(Math, 'random').mockReturnValue(1);
        const unreadable = new ConnectError('batch 5 is unreadable', Code.Internal);
        const failing: Attempt[] = Array.from({ length: 6 }, () => [checkpoint(4n), unreadable]);
        const { store, since } = harness(
            [...failing, [checkpoint(4n), frame(5n)]],
            { initialBackoffMs: 20, maxBackoffMs: 80, outageBudgetMs: 150 },
        );

        const started = performance.now();
        await expect(take(store.subscribe({ selectors, sinceSequenceNumber: 5n }), 1)).resolves.toEqual([5n]);

        // Six reconnects whose backoff restarted at every checkpoint would take 120 ms. Doubling up
        // to the cap takes 20 + 40 + 4 * 80 ms, which also outlasts the budget that the checkpoints
        // keep resetting.
        expect(performance.now() - started).toBeGreaterThanOrEqual(370);
        expect(since()).toEqual(Array(7).fill(5n));
    });
});

describe('failures before the first frame of a live-only subscription', () => {
    test.each([
        ['an open error', [new ConnectError('down', Code.Unavailable)], Code.Unavailable],
        ['a stream reset', [new ConnectError('terminated', Code.Unknown)], Code.Unknown],
        ['a clean end', [], Code.Unavailable],
    ])('%s surfaces without reopening', async (_name, steps, code) => {
        const { store, since } = harness([steps as Step[]]);

        await expect(drain(store.subscribe({ selectors }))).rejects.toMatchObject({ connectCode: code });
        expect(since()).toEqual([undefined]);
    });
});

describe('permanent errors', () => {
    test.each([
        ['Unauthenticated', () => new ConnectError('no credential', Code.Unauthenticated), 401],
        ['PermissionDenied', () => new ConnectError('denied', Code.PermissionDenied), 403],
        ['InvalidArgument', () => new ConnectError('bad regex', Code.InvalidArgument), 400],
        ['BATCH_EVICTED', evicted, 400],
        ['NotFound', () => new ConnectError('missing', Code.NotFound), 404],
        ['FailedPrecondition', () => new ConnectError('precondition', Code.FailedPrecondition), 400],
        ['Unimplemented', () => new ConnectError('unimplemented', Code.Unimplemented), 501],
        ['DeadlineExceeded', () => new ConnectError('timed out', Code.DeadlineExceeded), 504],
        ['Canceled', () => new ConnectError('canceled', Code.Canceled), 499],
    ])('%s is surfaced without retrying', async (_name, failure, status) => {
        for (const steps of [[failure()], [checkpoint(8n), frame(9n), failure()]]) {
            const { store, since } = harness([steps]);
            const delivered: bigint[] = [];

            const error = await (async () => {
                for await (const batch of store.subscribe({ selectors, sinceSequenceNumber: 9n })) {
                    delivered.push(batch.sequenceNumber);
                }
            })().catch((err: unknown) => err);

            expect(error).toBeInstanceOf(HttpError);
            expect(error).toMatchObject({ status, connectCode: failure().code });
            expect(since()).toEqual([9n]);
            expect(delivered).toEqual(steps.length === 1 ? [] : [9n]);
        }
    });

    test('BATCH_EVICTED keeps its error details', async () => {
        const { store } = harness([[evicted()]]);

        const error = await drain(store.subscribe({ selectors, sinceSequenceNumber: 1n }))
            .catch((err: unknown) => err as HttpError);

        const cause = (error as HttpError).cause as ConnectError;
        expect(cause.findDetails(ErrorInfoSchema)).toMatchObject([
            { domain: 'log.stream', reason: 'BATCH_EVICTED', metadata: { oldest_retained: '9' } },
        ]);
    });
});

describe('outage budget', () => {
    test('repeated transient failures surface the last failure once the budget is spent', async () => {
        const failures = Array.from({ length: 1000 }, (_, index) => [
            new ConnectError(`down ${index}`, Code.Unavailable),
        ]);
        const { store, requests } = harness(failures, { outageBudgetMs: 80, initialBackoffMs: 5, maxBackoffMs: 5 });
        const started = performance.now();

        const error = await drain(store.subscribe({ selectors, sinceSequenceNumber: 3n }))
            .catch((err: unknown) => err as HttpError);

        const elapsed = performance.now() - started;
        expect(error).toMatchObject({ connectCode: Code.Unavailable });
        expect(((error as HttpError).cause as ConnectError).rawMessage).toBe(`down ${requests.length - 1}`);
        expect(requests.length).toBeGreaterThan(3);
        expect(elapsed).toBeGreaterThanOrEqual(79);
        expect(elapsed).toBeLessThan(1000);
    });

    test.each(['abortable', 'forever'] as const)(
        'an open that hangs (%s) is bounded by the budget',
        async (hang) => {
            const { store, options } = harness([[{ hang }]], { outageBudgetMs: 50 });

            await expect(drain(store.subscribe({ selectors, sinceSequenceNumber: 3n }))).rejects.toMatchObject({
                connectCode: Code.DeadlineExceeded,
                message: expect.stringContaining('outage budget'),
            });
            expect(options[0].signal?.aborted).toBe(true);
        },
    );

    test('a reopened stream that never sends a frame surfaces the failure that started the outage', async () => {
        const { store, since } = harness(
            [[checkpoint(1n), frame(2n), shutdown()], [{ hang: 'abortable' }]],
            { outageBudgetMs: 60 },
        );
        const delivered: bigint[] = [];

        const error = await (async () => {
            for await (const batch of store.subscribe({ selectors })) delivered.push(batch.sequenceNumber);
        })().catch((err: unknown) => err as HttpError);

        expect(delivered).toEqual([2n]);
        expect(error).toMatchObject({ connectCode: Code.Unavailable, message: expect.stringContaining('shutting down') });
        expect(since()).toEqual([undefined, 3n]);
    });

    test('a clean end followed by silence surfaces a deadline error', async () => {
        const { store } = harness([[checkpoint(1n), frame(2n)], [{ hang: 'abortable' }]], { outageBudgetMs: 60 });

        await expect(drain(store.subscribe({ selectors }))).rejects.toMatchObject({
            connectCode: Code.DeadlineExceeded,
        });
    });

    test('each frame ends the outage, so separate short outages never exhaust the budget', async () => {
        const down = new ConnectError('down', Code.Unavailable);
        const attempts: Attempt[] = [[{ wait: 30 }, checkpoint(0n), frame(1n), down]];
        for (let sequence = 2n; sequence <= 6n; sequence++) {
            attempts.push([{ wait: 30 }, checkpoint(sequence - 1n), frame(sequence), down]);
        }
        const { store, since } = harness(attempts, { outageBudgetMs: 60 });

        await expect(take(store.subscribe({ selectors }), 6)).resolves.toEqual([1n, 2n, 3n, 4n, 5n, 6n]);
        expect(since()).toEqual([undefined, 2n, 3n, 4n, 5n, 6n]);
    });

    test('a healthy idle stream is not bounded by the budget', async () => {
        const { store, since } = harness([[checkpoint(0n), { wait: 120 }, frame(1n)]], { outageBudgetMs: 40 });

        await expect(take(store.subscribe({ selectors }), 1)).resolves.toEqual([1n]);
        expect(since()).toEqual([undefined]);
    });

    test('a checkpoint below the cursor ends the outage of a replaying or resumed stream', async () => {
        const down = new ConnectError('down', Code.Unavailable);
        const { store, since } = harness(
            [
                [checkpoint(4n), { wait: 120 }, frame(5n), down],
                [checkpoint(5n), { wait: 120 }, frame(6n)],
            ],
            { outageBudgetMs: 40 },
        );

        await expect(take(store.subscribe({ selectors, sinceSequenceNumber: 5n }), 2)).resolves.toEqual([5n, 6n]);
        expect(since()).toEqual([5n, 6n]);
    });

    test('an unlimited budget keeps retrying', async () => {
        const down = new ConnectError('down', Code.Unavailable);
        const attempts: Attempt[] = Array.from({ length: 30 }, () => [down]);
        attempts.push([checkpoint(4n), frame(5n)]);
        const { store, requests } = harness(attempts, { outageBudgetMs: Infinity });

        await expect(take(store.subscribe({ selectors, sinceSequenceNumber: 5n }), 1)).resolves.toEqual([5n]);
        expect(requests).toHaveLength(31);
    });
});

describe('cancellation', () => {
    test('aborting during backoff ends the subscription promptly', async () => {
        const controller = new AbortController();
        const { store, requests } = harness(
            [[checkpoint(1n), frame(2n), new ConnectError('down', Code.Unavailable)]],
            { initialBackoffMs: 60_000, maxBackoffMs: 60_000 },
        );
        const iterator = store.subscribe({ selectors }, { signal: controller.signal })[Symbol.asyncIterator]();

        expect((await iterator.next()).value?.sequenceNumber).toBe(2n);
        const pending = iterator.next();
        setTimeout(() => controller.abort(), 20);
        const started = performance.now();

        await expect(pending).rejects.toMatchObject({ connectCode: Code.Canceled });
        expect(performance.now() - started).toBeLessThan(1000);
        expect(requests).toHaveLength(1);
    });

    test.each(['abortable', 'forever'] as const)(
        'aborting a hanging open (%s) ends the subscription and its attempt',
        async (hang) => {
            const controller = new AbortController();
            const { store, options } = harness([[{ hang }]], { outageBudgetMs: Infinity });
            const pending = drain(store.subscribe({ selectors, sinceSequenceNumber: 1n }, { signal: controller.signal }));
            setTimeout(() => controller.abort(), 20);

            await expect(pending).rejects.toMatchObject({ connectCode: Code.Canceled });
            expect(options).toHaveLength(1);
            expect(options[0].signal?.aborted).toBe(true);
        },
    );

    test('an already aborted signal opens nothing', async () => {
        const { store, requests } = harness([]);

        await expect(drain(store.subscribe({ selectors }, { signal: AbortSignal.abort() }))).rejects.toMatchObject({
            connectCode: Code.Canceled,
        });
        expect(requests).toHaveLength(0);
    });

    test('stopping iteration aborts the attempt and closes its stream', async () => {
        let closed = false;
        const { store, options, requests } = harness([
            (_request, callOptions) => (async function* () {
                try {
                    yield* play([checkpoint(1n), frame(2n), { hang: 'abortable' }], callOptions);
                } finally {
                    closed = true;
                }
            })(),
        ]);

        for await (const batch of store.subscribe({ selectors })) {
            expect(batch.sequenceNumber).toBe(2n);
            break;
        }

        expect(closed).toBe(true);
        expect(options[0].signal?.aborted).toBe(true);
        await new Promise((resolve) => setTimeout(resolve, 20));
        expect(requests).toHaveLength(1);
    });

    test('every attempt gets the caller options with its own signal', async () => {
        const controller = new AbortController();
        const headers = { 'x-trace': 'abc' };
        const { store, options } = harness([
            [checkpoint(1n), frame(2n), new ConnectError('down', Code.Unavailable)],
            [checkpoint(2n), frame(3n)],
        ]);

        await take(store.subscribe({ selectors }, { signal: controller.signal, headers, timeoutMs: 0 }), 2);

        expect(options).toHaveLength(2);
        for (const callOptions of options) {
            expect(callOptions.headers).toBe(headers);
            expect(callOptions.timeoutMs).toBe(0);
            expect(callOptions.signal).not.toBe(controller.signal);
            expect(callOptions.signal?.aborted).toBe(true);
        }
        expect(options[0].signal).not.toBe(options[1].signal);
        expect(controller.signal.aborted).toBe(false);
    });
});

test('the cursor stops at the last u64 sequence and nothing is reopened past it', async () => {
    const ended = harness([[checkpoint(MAX_U64 - 1n), frame(MAX_U64)]]);
    await expect(drain(ended.store.subscribe({ selectors, sinceSequenceNumber: MAX_U64 }))).resolves.toEqual([MAX_U64]);
    expect(ended.since()).toEqual([MAX_U64]);

    const failed = harness([[checkpoint(MAX_U64 - 1n), frame(MAX_U64), new ConnectError('down', Code.Unavailable)]]);
    await expect(drain(failed.store.subscribe({ selectors, sinceSequenceNumber: MAX_U64 }))).rejects.toMatchObject({
        connectCode: Code.Unavailable,
    });
    expect(failed.since()).toEqual([MAX_U64]);
});

test('resumed requests ignore caller mutations made while subscribed', async () => {
    const selector = create(SelectorSchema, { prefix: new Uint8Array([4]), payloadRegex: 'a' });
    const filters = { selectors: [selector], sinceSequenceNumber: 2n };
    const { store, requests } = harness([
        [checkpoint(1n), frame(2n), new ConnectError('down', Code.Unavailable)],
        [checkpoint(2n), frame(3n)],
    ]);
    const stream = store.subscribe(filters)[Symbol.asyncIterator]();
    expect((await stream.next()).value?.sequenceNumber).toBe(2n);

    selector.prefix[0] = 9;
    selector.payloadRegex = 'b';
    filters.selectors.push(create(SelectorSchema));
    filters.sinceSequenceNumber = 7n;

    expect((await stream.next()).value?.sequenceNumber).toBe(3n);
    await stream.return?.();
    for (const request of requests) {
        expect(request.selectors).toHaveLength(1);
        expect(request.selectors[0].prefix).toEqual(new Uint8Array([4]));
        expect(request.selectors[0].payloadRegex).toBe('a');
    }
    expect(requests.map((request) => request.sinceSequenceNumber)).toEqual([2n, 3n]);
});

describe('disabled retries', () => {
    const disabled = { enabled: false, outageBudgetMs: 10 };

    test('a clean end finishes the subscription', async () => {
        for (const sinceSequenceNumber of [undefined, 5n]) {
            const { store, since } = harness([[checkpoint(4n), frame(5n)]], disabled);

            await expect(drain(store.subscribe({ selectors, sinceSequenceNumber }))).resolves.toEqual([5n]);
            expect(since()).toEqual([sinceSequenceNumber]);
        }
    });

    test('a live-only clean end before any frame finishes the subscription', async () => {
        const { store, since } = harness([[]], disabled);

        await expect(drain(store.subscribe({ selectors }))).resolves.toEqual([]);
        expect(since()).toEqual([undefined]);
    });

    test('a transient error is thrown after one attempt', async () => {
        const { store, since } = harness([[checkpoint(4n), frame(5n), shutdown()]], disabled);

        await expect(drain(store.subscribe({ selectors, sinceSequenceNumber: 5n }))).rejects.toMatchObject({
            connectCode: Code.Unavailable,
        });
        expect(since()).toEqual([5n]);
    });

    test('a slow first frame is not bounded by an outage budget', async () => {
        const { store } = harness([[{ wait: 60 }, checkpoint(4n), frame(5n)]], disabled);

        await expect(drain(store.subscribe({ selectors }))).resolves.toEqual([5n]);
    });
});

test('ReadSession observes delivered batches but not the resume cursor', async () => {
    let reopened!: () => void;
    const reopen = new Promise<void>((resolve) => {
        reopened = resolve;
    });
    let release!: () => void;
    const released = new Promise<void>((resolve) => {
        release = resolve;
    });
    const inside = new Uint8Array([1, 7]);
    const outside = new Uint8Array([2, 7]);
    const { client, since } = harness([
        [checkpoint(10n), frame(11n, [inside]), frame(12n, [outside]), checkpoint(13n), shutdown()],
        (_request, options) => (async function* () {
            reopened();
            await released;
            yield* play([checkpoint(13n), frame(14n, [inside])], options);
        })(),
    ]);
    const session = ReadSession.monotonic(client.store(new StoreKeyPrefix(new Uint8Array([1]))));
    const iterator = session.subscribe({ selectors })[Symbol.asyncIterator]();

    expect((await iterator.next()).value?.sequenceNumber).toBe(11n);
    expect(session.evaluatedSequence()).toBe(11n);

    const second = iterator.next();
    await reopen;
    expect(since()).toEqual([undefined, 14n]);
    expect(session.evaluatedSequence()).toBe(11n);
    expect(session.minSequenceNumber()).toBe(11n);

    release();
    expect((await second).value?.sequenceNumber).toBe(14n);
    expect(session.evaluatedSequence()).toBe(14n);
    await iterator.return?.();
});

describe('over the Connect transport', () => {
    function envelope(flags: number, data: Uint8Array): Uint8Array {
        const out = new Uint8Array(5 + data.length);
        out[0] = flags;
        new DataView(out.buffer).setUint32(1, data.length);
        out.set(data, 5);
        return out;
    }

    function streamResponse(frames: SubscribeResponse[]): Response {
        const parts = frames.map((response) => envelope(0, toBinary(SubscribeResponseSchema, response)));
        parts.push(envelope(2, new TextEncoder().encode('{}')));
        return new Response(Buffer.concat(parts), {
            headers: { 'content-type': 'application/connect+proto' },
        });
    }

    function unavailable(): Response {
        return new Response(JSON.stringify({ code: 'unavailable', message: 'down' }), {
            status: 503,
            headers: { 'content-type': 'application/json' },
        });
    }

    function requestSince(init: RequestInit | undefined): bigint | undefined {
        const body = init?.body as Uint8Array;
        return fromBinary(SubscribeRequestSchema, body.subarray(5)).sinceSequenceNumber;
    }

    test('the generic retry policy does not retry subscriptions', async () => {
        const fetch = jest.spyOn(globalThis, 'fetch').mockImplementation(async () => unavailable());
        const client = new Client('http://subscribe.test', {
            token: '',
            retry: { maxAttempts: 3, initialBackoffMs: 1, maxBackoffMs: 1 },
            subscriptionRetry: { enabled: false },
        });

        await expect(drain(client.store().subscribe({ selectors, sinceSequenceNumber: 5n }))).rejects.toMatchObject({
            status: 503,
        });
        expect(fetch).toHaveBeenCalledTimes(1);
    });

    test('an unavailable open is retried with the same cursor', async () => {
        const fetch = jest.spyOn(globalThis, 'fetch')
            .mockImplementationOnce(async () => unavailable())
            .mockImplementationOnce(async () => streamResponse([checkpoint(4n), frame(5n)]));
        const client = new Client('http://subscribe.test', {
            token: '',
            retry: { maxAttempts: 1, initialBackoffMs: 1, maxBackoffMs: 1 },
            subscriptionRetry: { initialBackoffMs: 1, maxBackoffMs: 1 },
        });

        await expect(take(client.store().subscribe({ selectors, sinceSequenceNumber: 5n }), 1)).resolves.toEqual([5n]);
        expect(fetch.mock.calls.map(([, init]) => requestSince(init))).toEqual([5n, 5n]);
    });
});

describe('configuration', () => {
    test('defaults', () => {
        expect(new Client('http://127.0.0.1:1', { token: '' }).subscriptionRetry).toEqual({
            enabled: true,
            outageBudgetMs: 60_000,
            initialBackoffMs: 100,
            maxBackoffMs: 2_000,
        });
    });

    test('a maximum backoff below the initial backoff is raised to it', () => {
        expect(normalizeSubscriptionRetry({ initialBackoffMs: 500, maxBackoffMs: 50 })).toMatchObject({
            initialBackoffMs: 500,
            maxBackoffMs: 500,
        });
    });

    test('an unlimited budget is accepted', () => {
        expect(normalizeSubscriptionRetry({ outageBudgetMs: Infinity }).outageBudgetMs).toBe(Infinity);
    });

    test('a field set to undefined keeps its default', () => {
        expect(normalizeSubscriptionRetry({ outageBudgetMs: undefined, enabled: undefined })).toEqual({
            enabled: true,
            outageBudgetMs: 60_000,
            initialBackoffMs: 100,
            maxBackoffMs: 2_000,
        });
    });

    test.each([
        { outageBudgetMs: 0 },
        { outageBudgetMs: -1 },
        { outageBudgetMs: NaN },
        { initialBackoffMs: -1 },
        { initialBackoffMs: Infinity },
        { maxBackoffMs: NaN },
    ])('%p is rejected', (config) => {
        expect(() => new Client('http://127.0.0.1:1', { token: '', subscriptionRetry: config })).toThrow(RangeError);
    });
});
