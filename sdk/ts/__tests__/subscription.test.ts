import { create } from '@bufbuild/protobuf';
import { Code, ConnectError, type CallOptions } from '@connectrpc/connect';
import { Client } from '../src/client';
import { HttpError } from '../src/error';
import { ErrorInfoSchema } from '../src/gen/ts/google/rpc/error_details_pb';
import {
    SubscribeResponseSchema,
    type SubscribeRequest,
    type SubscribeResponse,
} from '../src/gen/ts/log/v1/stream_pb';
import { GetResponseSchema } from '../src/gen/ts/store/v1/query_pb';
import { ReadSession, StoreClient, StoreKeyPrefix } from '../src/store';
import type { SubscriptionRetryConfig } from '../src/subscription';

const key = new Uint8Array([1]);
const filters = { selectors: [{ prefix: key }] };
const unavailable = () => new ConnectError('connection lost', Code.Unavailable);
const frame = (sequenceNumber: bigint, entries = true) => create(SubscribeResponseSchema, {
    sequenceNumber,
    entries: entries ? [{ key, value: key }] : [],
});
const never = () => new Promise<never>(() => {});

function setup(
    subscribe: Client['stream']['subscribe'],
    policy: SubscriptionRetryConfig = {},
) {
    const client = {
        stream: { subscribe },
        query: { get: async () => create(GetResponseSchema) },
        credential: 'absent',
        subscriptionRetry: { budgetMs: 1_000, initialBackoffMs: 100, maxBackoffMs: 200, ...policy },
    } as unknown as Client;
    return { client, store: new StoreClient(client) };
}

beforeEach(() => {
    jest.useFakeTimers();
    jest.spyOn(Math, 'random').mockReturnValue(1);
});

afterEach(() => {
    jest.useRealTimers();
    jest.restoreAllMocks();
});

test('empty checkpoints advance the resume cursor before being skipped', async () => {
    const requests: SubscribeRequest[] = [];
    let attempt = 0;
    const { store } = setup((request) => {
        requests.push(request as SubscribeRequest);
        return (async function* () {
            attempt++;
            if (attempt === 1) {
                yield frame(7n, false);
                throw unavailable();
            }
            if (attempt === 2) {
                yield frame(7n, false);
                yield frame(10n, false);
                throw unavailable();
            }
            yield frame(11n);
        })();
    });
    const subscription = store.subscribe(filters);
    const next = subscription.next();
    await jest.advanceTimersByTimeAsync(200);
    await expect(next).resolves.toMatchObject({ value: { sequenceNumber: 11n } });
    expect(requests.map((request) => request.sinceSequenceNumber)).toEqual([undefined, 8n, 11n]);
    await subscription.return?.();
});

test('a delivered sequence resumes once with the original selector and value filters', async () => {
    const requests: SubscribeRequest[] = [];
    const input = { selectors: [{ prefix: new Uint8Array([4]) }], valueFilters: [{}], sinceSequenceNumber: 3n };
    const { client } = setup((request) => {
        requests.push(request as SubscribeRequest);
        return (async function* () {
            if (requests.length === 1) {
                yield create(SubscribeResponseSchema, {
                    sequenceNumber: 3n,
                    entries: [{ key: new Uint8Array([8, 4]), value: key }],
                });
                throw unavailable();
            }
            yield create(SubscribeResponseSchema, {
                sequenceNumber: 4n,
                entries: [{ key: new Uint8Array([8, 4]), value: key }],
            });
        })();
    });
    const store = new StoreClient(client, new StoreKeyPrefix(new Uint8Array([8])));
    const subscription = store.subscribe(input);
    expect((await subscription.next()).value?.sequenceNumber).toBe(3n);
    input.selectors[0].prefix[0] = 99;
    input.valueFilters.push({});
    const next = subscription.next();
    await jest.advanceTimersByTimeAsync(100);
    expect((await next).value?.sequenceNumber).toBe(4n);
    expect(requests.map((request) => request.sinceSequenceNumber)).toEqual([3n, 4n]);
    expect(requests[1].selectors).toEqual(requests[0].selectors);
    expect(requests[1].selectors[0].prefix).toEqual(new Uint8Array([8, 4]));
    expect(requests[1].valueFilters).toEqual(requests[0].valueFilters);
    await subscription.return?.();
});

test.each([undefined, 0n])('live subscription since=%s never retries a cursorless open error', async (sinceSequenceNumber) => {
    const open = jest.fn(() => (async function* () { throw unavailable(); })());
    const { store } = setup(open);
    await expect(store.subscribe({ ...filters, sinceSequenceNumber }).next()).rejects.toMatchObject({
        connectCode: Code.Unavailable,
    });
    expect(open).toHaveBeenCalledTimes(1);
});

test('cursorless clean close produces a meaningful error', async () => {
    const open = jest.fn(() => (async function* () {})());
    const { store } = setup(open);
    await expect(store.subscribe(filters).next()).rejects.toMatchObject({
        connectCode: Code.Unavailable,
        message: expect.stringContaining('subscription closed'),
    });
    expect(open).toHaveBeenCalledTimes(1);
});

test.each([-1n, 1n << 64n])('invalid replay cursor %s cannot silently become a live subscription', (sinceSequenceNumber) => {
    const open = jest.fn(() => (async function* () {})());
    const { store } = setup(open);
    expect(() => store.subscribe({ ...filters, sinceSequenceNumber })).toThrow();
    expect(open).not.toHaveBeenCalled();
});

test('lagging reconnects cannot lower the cursor or redeliver a batch', async () => {
    const requests: SubscribeRequest[] = [];
    const { store } = setup((request) => {
        requests.push(request as SubscribeRequest);
        return (async function* () {
            if (requests.length === 1) {
                yield frame(8n);
                throw unavailable();
            }
            yield frame(4n, false);
            yield frame(8n);
            yield frame(9n);
        })();
    });
    const subscription = store.subscribe(filters);
    expect((await subscription.next()).value?.sequenceNumber).toBe(8n);
    const next = subscription.next();
    await jest.advanceTimersByTimeAsync(100);
    expect((await next).value?.sequenceNumber).toBe(9n);
    expect(requests[1].sinceSequenceNumber).toBe(9n);
    await subscription.return?.();
});

test.each([0, 1])('jitter draw %s stays in the capped exponential backoff interval', async (random) => {
    jest.mocked(Math.random).mockReturnValue(random);
    const attempts: number[] = [];
    const open = jest.fn(() => {
        attempts.push(performance.now());
        return (async function* () { throw unavailable(); })();
    });
    const { store } = setup(open, { budgetMs: 500, initialBackoffMs: 100, maxBackoffMs: 200 });
    const failure = expect(store.subscribe({ ...filters, sinceSequenceNumber: 1n }).next())
        .rejects.toMatchObject({ connectCode: Code.DeadlineExceeded });
    await jest.advanceTimersByTimeAsync(500);
    await failure;
    const multiplier = random === 0 ? 0.5 : 1;
    expect(attempts.slice(0, 4)).toEqual([0, 100 * multiplier, 300 * multiplier, 500 * multiplier]
        .filter((elapsed) => elapsed < 500));
});

test('an explicit replay cursor retries failed initial opens without advancing it', async () => {
    const requests: SubscribeRequest[] = [];
    const { store } = setup((request) => {
        requests.push(request as SubscribeRequest);
        return (async function* () {
            if (requests.length < 3) throw unavailable();
            yield frame(9n, false);
            yield frame(10n);
        })();
    });
    const subscription = store.subscribe({ ...filters, sinceSequenceNumber: 10n });
    const next = subscription.next();
    await jest.advanceTimersByTimeAsync(300);
    expect((await next).value?.sequenceNumber).toBe(10n);
    expect(requests.map((request) => request.sinceSequenceNumber)).toEqual([10n, 10n, 10n]);
    await subscription.return?.();
});

test('a clean close after a checkpoint reconnects from that checkpoint', async () => {
    const requests: SubscribeRequest[] = [];
    const { store } = setup((request) => {
        requests.push(request as SubscribeRequest);
        return (async function* () {
            if (requests.length === 1) yield frame(4n, false);
            else yield frame(5n);
        })();
    });
    const subscription = store.subscribe(filters);
    const next = subscription.next();
    await jest.advanceTimersByTimeAsync(100);
    expect((await next).value?.sequenceNumber).toBe(5n);
    expect(requests[1].sinceSequenceNumber).toBe(5n);
    await subscription.return?.();
});

test('the outage budget caps both the retry sleep and a stalled reconnect', async () => {
    let opens = 0;
    let signal: AbortSignal | undefined;
    const { store } = setup((_request, options) => (async function* () {
        signal = options?.signal;
        if (++opens === 1) throw unavailable();
        await never();
    })());
    const subscription = store.subscribe({ ...filters, sinceSequenceNumber: 4n });
    const next = subscription.next();
    const failure = expect(next).rejects.toMatchObject({
        connectCode: Code.DeadlineExceeded,
        cause: { cause: { code: Code.Unavailable } },
    });
    await jest.advanceTimersByTimeAsync(1_000);
    await failure;
    expect(opens).toBe(2);
    expect(signal?.aborted).toBe(true);

    const open = jest.fn(() => (async function* () { throw unavailable(); })());
    const short = setup(open, { budgetMs: 50 }).store.subscribe({ ...filters, sinceSequenceNumber: 1n });
    const shortFailure = expect(short.next()).rejects.toMatchObject({ connectCode: Code.DeadlineExceeded });
    await jest.advanceTimersByTimeAsync(50);
    await shortFailure;
    expect(open).toHaveBeenCalledTimes(1);
});

test('the initial outage budget also bounds waiting for the first live checkpoint', async () => {
    const { store } = setup(() => (async function* () { await never(); })());
    const failure = expect(store.subscribe(filters).next()).rejects.toMatchObject({
        connectCode: Code.DeadlineExceeded,
    });
    await jest.advanceTimersByTimeAsync(1_000);
    await failure;
});

test('a frame first observed after the budget elapsed does not revive the outage', async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const { store } = setup(() => (async function* () {
        await gate;
        yield frame(1n);
    })());
    const next = store.subscribe({ ...filters, sinceSequenceNumber: 1n }).next();
    const failure = expect(next).rejects.toMatchObject({ connectCode: Code.DeadlineExceeded });

    // The clock passes the budget before its timer callback gets to run, then the frame
    // arrives in that window.
    await jest.advanceTimersByTimeAsync(999);
    jest.spyOn(performance, 'now').mockReturnValue(performance.now() + 1);
    release();
    await failure;
});

test('response headers alone do not reset the budget', async () => {
    const { store } = setup((_request, options) => {
        options?.onHeader?.(new Headers());
        return (async function* () { await never(); })();
    });
    const onHeader = jest.fn();
    const failure = expect(store.subscribe(filters, { onHeader }).next()).rejects.toMatchObject({
        connectCode: Code.DeadlineExceeded,
    });
    await jest.advanceTimersByTimeAsync(1_000);
    await failure;
    expect(onHeader).toHaveBeenCalledTimes(1);
});

test('each frame resets the outage budget even when it has no matching entries', async () => {
    let opens = 0;
    const { store } = setup(() => (async function* () {
        opens++;
        if (opens === 1) {
            await new Promise((resolve) => setTimeout(resolve, 900));
            yield frame(10n, false);
            throw unavailable();
        }
        await new Promise((resolve) => setTimeout(resolve, 850));
        yield frame(11n);
    })());
    const subscription = store.subscribe(filters);
    const next = subscription.next();
    await jest.advanceTimersByTimeAsync(1_850);
    expect((await next).value?.sequenceNumber).toBe(11n);
    await subscription.return?.();
});

test.each([Code.Aborted, Code.Unavailable, Code.ResourceExhausted, Code.Unknown, Code.Internal, Code.DeadlineExceeded])(
    'retries server code %s with a safe replay cursor', async (code) => {
        let opens = 0;
        const { store } = setup(() => (async function* () {
            if (++opens === 1) throw new ConnectError('server failure', code);
            yield frame(1n);
        })());
        const subscription = store.subscribe({ ...filters, sinceSequenceNumber: 1n });
        const next = subscription.next();
        await jest.advanceTimersByTimeAsync(100);
        expect((await next).value?.sequenceNumber).toBe(1n);
        await subscription.return?.();
    },
);

test.each([Code.Unauthenticated, Code.PermissionDenied, Code.InvalidArgument, Code.OutOfRange, Code.Canceled])(
    'never retries permanent server code %s even inside a retryable wrapper', async (code) => {
        const error = new ConnectError('wrapper', Code.Unknown, undefined, undefined,
            new ConnectError('permanent', code));
        const open = jest.fn(() => (async function* () { throw error; })());
        const { store } = setup(open);
        await expect(store.subscribe({ ...filters, sinceSequenceNumber: 1n }).next()).rejects.toBeInstanceOf(HttpError);
        expect(open).toHaveBeenCalledTimes(1);
    },
);

test('never retries BATCH_EVICTED even under a retryable status and wrapper', async () => {
    const eviction = new ConnectError('evicted', Code.Internal, undefined, [{
        desc: ErrorInfoSchema,
        value: create(ErrorInfoSchema, { domain: 'log.stream', reason: 'BATCH_EVICTED' }),
    }]);
    const open = jest.fn(() => (async function* () { throw new Error('wrapper', { cause: eviction }); })());
    const { store } = setup(open);
    await expect(store.subscribe({ ...filters, sinceSequenceNumber: 1n }).next()).rejects.toThrow('wrapper');
    expect(open).toHaveBeenCalledTimes(1);
});

test.each(['open', 'sleep'] as const)('caller cancellation interrupts a stalled %s', async (stage) => {
    const controller = new AbortController();
    const { store } = setup(() => (async function* () {
        if (stage === 'sleep') throw unavailable();
        await never();
    })());
    const subscription = store.subscribe({ ...filters, sinceSequenceNumber: 1n }, { signal: controller.signal });
    const next = subscription.next();
    const failure = expect(next).rejects.toMatchObject({ connectCode: Code.Canceled });
    await jest.advanceTimersByTimeAsync(0);
    controller.abort();
    await failure;
    expect(jest.getTimerCount()).toBe(0);
});

test('iterator return interrupts a pending read and closes its transport signal', async () => {
    let signal: AbortSignal | undefined;
    const { store } = setup((_request, options) => {
        signal = options?.signal;
        return (async function* () { await never(); })();
    });
    const subscription = store.subscribe(filters);
    const next = subscription.next();
    await expect(subscription.return?.()).resolves.toMatchObject({ done: true });
    await expect(next).resolves.toMatchObject({ done: true });
    expect(signal?.aborted).toBe(true);
    expect(jest.getTimerCount()).toBe(0);
});

test('an unlimited zero-backoff policy still yields for caller cancellation', async () => {
    const controller = new AbortController();
    const open = jest.fn(() => (async function* () { throw unavailable(); })());
    const { store } = setup(open, { budgetMs: null, initialBackoffMs: 0, maxBackoffMs: 0 });
    const failure = expect(store.subscribe({ ...filters, sinceSequenceNumber: 1n }, {
        signal: controller.signal,
    }).next()).rejects.toMatchObject({ connectCode: Code.Canceled });
    setTimeout(() => controller.abort(), 10);
    await jest.advanceTimersByTimeAsync(10);
    await failure;
    expect(open.mock.calls.length).toBeLessThanOrEqual(10);
    expect(jest.getTimerCount()).toBe(0);
});

test('read sessions keep resume checkpoints separate from observations and floors', async () => {
    let opens = 0;
    const { store } = setup(() => (async function* () {
        if (++opens === 1) {
            yield frame(20n, false);
            throw unavailable();
        }
        yield frame(21n);
    })());
    const session = ReadSession.monotonic(store, 100n);
    const subscription = session.subscribe(filters);
    const next = subscription.next();
    await jest.advanceTimersByTimeAsync(0);
    expect(session.evaluatedSequence()).toBeUndefined();
    expect(session.minSequenceNumber()).toBe(100n);
    await jest.advanceTimersByTimeAsync(100);
    expect((await next).value?.sequenceNumber).toBe(21n);
    expect(session.evaluatedSequence()).toBe(21n);
    expect(session.minSequenceNumber()).toBe(100n);
    await subscription.return?.();
});

test('subscriptions omit per-call timeouts and disabled ones retain legacy closes', async () => {
    const seen: Array<CallOptions | undefined> = [];
    const { store } = setup((_request, options) => {
        seen.push(options);
        return (async function* () {
            yield frame(1n);
            await new Promise((resolve) => setTimeout(resolve, 100));
            yield frame(2n);
        })();
    });
    const subscription = store.subscribe(filters, { timeoutMs: 1 });
    await subscription.next();
    const next = subscription.next();
    await jest.advanceTimersByTimeAsync(100);
    expect((await next).value?.sequenceNumber).toBe(2n);
    expect(seen[0]?.timeoutMs).toBeUndefined();
    await subscription.return?.();

    const disabled = setup((_request, options) => {
        seen.push(options);
        return (async function* () {})();
    }, { enabled: false }).store.subscribe(filters, { timeoutMs: 7 });
    await expect(disabled.next()).resolves.toMatchObject({ done: true });
    expect(seen[1]?.timeoutMs).toBeUndefined();
});

test('subscription policy defaults, unlimited budget, and validation are independent of request retries', async () => {
    const client = new Client('http://subscription.test', {
        token: '',
        retry: { maxAttempts: 1, initialBackoffMs: 1, maxBackoffMs: 1 },
    });
    expect(client.subscriptionRetry).toEqual({ enabled: true, budgetMs: 60_000, initialBackoffMs: 100, maxBackoffMs: 2_000 });
    expect(new Client('http://subscription.test', { token: '', subscriptionRetry: { budgetMs: null } })
        .subscriptionRetry.budgetMs).toBeNull();
    expect(() => new Client('http://subscription.test', { token: '', subscriptionRetry: { budgetMs: -1 } }))
        .toThrow(RangeError);
    let opens = 0;
    const { store } = setup(() => (async function* () {
        if (++opens < 8) throw unavailable();
        yield frame(1n);
    })(), { budgetMs: null });
    const subscription = store.subscribe({ ...filters, sinceSequenceNumber: 1n });
    const next = subscription.next();
    await jest.advanceTimersByTimeAsync(1_300);
    expect((await next).value?.sequenceNumber).toBe(1n);
    expect(opens).toBe(8);
    await subscription.return?.();
});
