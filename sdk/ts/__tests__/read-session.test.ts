import { create } from '@bufbuild/protobuf';
import { Code, ConnectError } from '@connectrpc/connect';
import { Client } from '../src/client';
import { SelectorSchema } from '../src/gen/ts/common/v1/kv_pb';
import {
    GetResponseSchema as StreamGetResponseSchema,
    SubscribeResponseSchema,
    type GetRequest as StreamGetRequest,
    type SubscribeRequest,
} from '../src/gen/ts/log/v1/stream_pb';
import {
    GetManyFrameSchema,
    GetResponseSchema,
    RangeFrameSchema,
    ReduceParamsSchema,
    ReduceResponseSchema,
    type GetRequest,
    type GetManyRequest,
    type RangeRequest,
    type ReduceRequest,
} from '../src/gen/ts/store/v1/query_pb';
import { ReadSession, StoreClient, StoreKeyPrefix } from '../src/store';

function mockClient(
    query: Partial<Client['query']>,
    stream: Partial<Client['stream']> = {},
): Client {
    return { query, stream, credential: 'absent' } as unknown as Client;
}

const key = new Uint8Array([3]);

test('monotonic sessions advance across point and range reads without treating the seed as observed', async () => {
    const getFloors: Array<bigint | undefined> = [];
    const rangeFloors: Array<bigint | undefined> = [];
    const client = mockClient({
        get: async (request) => {
            getFloors.push((request as GetRequest).minSequenceNumber);
            return create(GetResponseSchema, { detail: { sequenceNumber: 7n } });
        },
        range: async function* (request) {
            rangeFloors.push((request as RangeRequest).minSequenceNumber);
            yield create(RangeFrameSchema, { detail: { sequenceNumber: 9n } });
            yield create(RangeFrameSchema, { detail: { sequenceNumber: 8n } });
        },
    });
    const session = ReadSession.monotonic(new StoreClient(client), 5n);

    expect(session.minSequenceNumber()).toBe(5n);
    expect(session.evaluatedSequence()).toBeUndefined();
    await expect(session.get(key)).resolves.toBeNull();
    expect(session.evaluatedSequence()).toBe(7n);
    expect(session.minSequenceNumber()).toBe(7n);

    await session.query();
    expect(session.evaluatedSequence()).toBe(9n);
    expect(session.minSequenceNumber()).toBe(9n);
    expect(getFloors).toEqual([5n]);
    expect(rangeFloors).toEqual([7n]);
});

test('fixed floors are handle-local while observations are shared across clones and clients', async () => {
    const requests: GetRequest[] = [];
    let sequence = 8n;
    const client = mockClient({
        get: async (request) => {
            requests.push(request as GetRequest);
            return create(GetResponseSchema, { detail: { sequenceNumber: sequence } });
        },
    });
    const firstStore = new StoreClient(client, new StoreKeyPrefix(new Uint8Array([1])));
    const secondStore = new StoreClient(client, new StoreKeyPrefix(new Uint8Array([2])));
    const fixed = ReadSession.fixed(firstStore, 4n);
    const clone = fixed.clone();

    await fixed.get(key);
    expect(fixed.minSequenceNumber()).toBe(4n);
    expect(clone.evaluatedSequence()).toBe(8n);

    const derived = clone.withMinSequenceNumber(10n);
    expect(derived.minSequenceNumber()).toBe(10n);
    expect(fixed.minSequenceNumber()).toBe(4n);

    sequence = 12n;
    const rebound = derived.withClient(secondStore);
    await rebound.get(key);
    expect(requests[1].minSequenceNumber).toBe(10n);
    expect(requests[1].key).toEqual(new Uint8Array([2, 3]));
    expect(fixed.evaluatedSequence()).toBe(12n);
    expect(rebound.minSequenceNumber()).toBe(10n);
});

test('monotonic derivation strengthens only the derived handle and legacy factories remain monotonic', async () => {
    const floors: Array<bigint | undefined> = [];
    let sequence = 6n;
    const client = mockClient({
        get: async (request) => {
            floors.push((request as GetRequest).minSequenceNumber);
            return create(GetResponseSchema, { detail: { sequenceNumber: sequence }, value: key });
        },
    });
    const store = new StoreClient(client);
    const session = store.createSessionWithSequence(2n);

    expect(session.evaluatedSequence()).toBeUndefined();
    await session.get(key);
    expect(session.withMinSequenceNumber(5n).minSequenceNumber()).toBe(6n);
    const derived = session.withMinSequenceNumber(10n);
    expect(session.minSequenceNumber()).toBe(6n);
    expect(derived.minSequenceNumber()).toBe(10n);
    expect(derived.evaluatedSequence()).toBe(6n);

    sequence = 11n;
    await derived.get(key);
    expect(session.minSequenceNumber()).toBe(11n);
    expect(derived.minSequenceNumber()).toBe(11n);
    expect(floors).toEqual([2n, 10n]);
});

test('constructors distinguish an absent floor from an explicit zero floor', () => {
    const client = mockClient({});
    const store = new StoreClient(client);

    expect(new ReadSession(client).minSequenceNumber()).toBeUndefined();
    expect(ReadSession.monotonic(store).minSequenceNumber()).toBeUndefined();
    expect(ReadSession.monotonic(store, 0n).minSequenceNumber()).toBe(0n);
    expect(ReadSession.fixed(store).minSequenceNumber()).toBeUndefined();
    expect(ReadSession.fixed(store, 0n).clone().minSequenceNumber()).toBe(0n);
    expect(store.createSession().minSequenceNumber()).toBeUndefined();
    expect(store.createSessionWithSequence(0n).minSequenceNumber()).toBe(0n);
});

test.each([
    { value: -1n, error: RangeError },
    { value: 1n << 64n, error: RangeError },
    { value: 1 as unknown as bigint, error: TypeError },
])('invalid minimum $value is rejected before a request is sent', async ({ value, error }) => {
    const get = jest.fn(async () => create(GetResponseSchema));
    const store = new StoreClient(mockClient({ get }));

    expect(() => ReadSession.fixed(store, value)).toThrow(error);
    expect(() => ReadSession.monotonic(store).withMinSequenceNumber(value)).toThrow(error);
    await expect(store.get(key, value)).rejects.toThrow(error);
    expect(get).not.toHaveBeenCalled();
});

test('direct read methods preserve omitted and explicit zero floors', async () => {
    const floors = {
        get: [] as Array<bigint | undefined>,
        getMany: [] as Array<bigint | undefined>,
        range: [] as Array<bigint | undefined>,
        reduce: [] as Array<bigint | undefined>,
    };
    const client = mockClient({
        get: async (request) => {
            floors.get.push((request as GetRequest).minSequenceNumber);
            return create(GetResponseSchema);
        },
        getMany: async function* (request) {
            floors.getMany.push((request as GetManyRequest).minSequenceNumber);
            yield create(GetManyFrameSchema);
        },
        range: async function* (request) {
            floors.range.push((request as RangeRequest).minSequenceNumber);
            yield create(RangeFrameSchema);
        },
        reduce: async function* (request) {
            floors.reduce.push((request as ReduceRequest).minSequenceNumber);
            yield create(ReduceResponseSchema);
        },
    });
    const store = new StoreClient(client);
    const params = create(ReduceParamsSchema);

    for (const floor of [undefined, 0n]) {
        await store.get(key, floor);
        await store.getMany([key], undefined, undefined, floor);
        await store.query(undefined, undefined, undefined, undefined, undefined, floor);
        for await (const _frame of store.reduce(key, key, params, floor)) {}
    }

    expect(floors.get).toEqual([undefined, 0n]);
    expect(floors.getMany).toEqual([undefined, 0n]);
    expect(floors.range).toEqual([undefined, 0n]);
    expect(floors.reduce).toEqual([undefined, 0n]);
});

describe.each(['monotonic', 'fixed'] as const)('%s sessions observe zero details', (policy) => {
    test.each(['get', 'getMany', 'query', 'reduce'] as const)('%s', async (method) => {
        const client = mockClient({
            get: async () => create(GetResponseSchema, { detail: { sequenceNumber: 0n } }),
            getMany: async function* () {
                yield create(GetManyFrameSchema, { detail: { sequenceNumber: 0n } });
            },
            range: async function* () {
                yield create(RangeFrameSchema, { detail: { sequenceNumber: 0n } });
            },
            reduce: async function* () {
                yield create(ReduceResponseSchema, { detail: { sequenceNumber: 0n } });
            },
        });
        const store = new StoreClient(client);
        const session = policy === 'monotonic'
            ? ReadSession.monotonic(store)
            : ReadSession.fixed(store);
        const clone = session.clone();

        expect(session.minSequenceNumber()).toBeUndefined();
        expect(session.evaluatedSequence()).toBeUndefined();

        switch (method) {
            case 'get':
                await session.get(key);
                break;
            case 'getMany':
                await session.getMany([key]);
                break;
            case 'query':
                await session.query();
                break;
            case 'reduce': {
                const stream = session.reduce(key, key, create(ReduceParamsSchema))[
                    Symbol.asyncIterator
                ]();
                const first = await stream.next();
                expect(first.done).toBe(false);
                expect(session.evaluatedSequence()).toBe(0n);
                expect(clone.evaluatedSequence()).toBe(0n);
                expect(first.value?.detail?.sequenceNumber).toBe(0n);
                await stream.return?.();
                break;
            }
        }

        expect(session.evaluatedSequence()).toBe(0n);
        expect(clone.evaluatedSequence()).toBe(0n);
        const expectedFloor = policy === 'monotonic' ? 0n : undefined;
        expect(session.minSequenceNumber()).toBe(expectedFloor);
        expect(clone.minSequenceNumber()).toBe(expectedFloor);
    });
});

test('a present zero detail is observed and prevents reinitialization across clones', async () => {
    const floors: Array<bigint | undefined> = [];
    let response = 0;
    const client = mockClient({
        get: async (request) => {
            floors.push((request as GetRequest).minSequenceNumber);
            response += 1;
            return response === 1
                ? create(GetResponseSchema)
                : create(GetResponseSchema, { detail: { sequenceNumber: 0n } });
        },
    });
    const session = ReadSession.monotonic(new StoreClient(client));
    const clone = session.clone();

    await session.get(key);
    expect(session.evaluatedSequence()).toBeUndefined();
    expect(session.minSequenceNumber()).toBeUndefined();

    await clone.get(key);
    expect(session.evaluatedSequence()).toBe(0n);
    expect(clone.evaluatedSequence()).toBe(0n);
    expect(session.minSequenceNumber()).toBe(0n);

    await session.get(key);
    expect(floors).toEqual([undefined, undefined, 0n]);
});

test('deriving zero from an absent floor strengthens only the derived handle', async () => {
    const floors: Array<bigint | undefined> = [];
    const client = mockClient({
        get: async (request) => {
            floors.push((request as GetRequest).minSequenceNumber);
            return create(GetResponseSchema);
        },
    });
    const session = ReadSession.monotonic(new StoreClient(client));
    const derived = session.withMinSequenceNumber(0n);

    expect(session.minSequenceNumber()).toBeUndefined();
    expect(derived.minSequenceNumber()).toBe(0n);
    expect(session.evaluatedSequence()).toBeUndefined();
    expect(derived.evaluatedSequence()).toBeUndefined();
    await derived.get(key);
    expect(floors).toEqual([0n]);
    expect(session.minSequenceNumber()).toBeUndefined();
});

test('getMany observes empty frames and publishes detail before onChunk', async () => {
    const getFloors: Array<bigint | undefined> = [];
    const client = mockClient({
        getMany: async function* () {
            yield create(GetManyFrameSchema, { detail: { sequenceNumber: 6n } });
            yield create(GetManyFrameSchema, {
                results: [{ key, value: key }],
                detail: { sequenceNumber: 8n },
            });
        },
        get: async (request) => {
            getFloors.push((request as GetRequest).minSequenceNumber);
            return create(GetResponseSchema, { detail: { sequenceNumber: 8n }, value: key });
        },
    });
    const session = ReadSession.monotonic(new StoreClient(client));
    let dependent: Promise<unknown> | undefined;

    await session.getMany([key], undefined, () => {
        expect(session.evaluatedSequence()).toBe(8n);
        dependent = session.get(key);
    });
    await dependent;
    expect(getFloors).toEqual([8n]);
});

test('concurrent unseeded reads start together and observations only advance', async () => {
    let releaseLower!: () => void;
    let releaseHigher!: () => void;
    const floors: Array<bigint | undefined> = [];
    const client = mockClient({
        get: async (request) => {
            const call = floors.length;
            floors.push((request as GetRequest).minSequenceNumber);
            if (call === 0) {
                await new Promise<void>((resolve) => {
                    releaseLower = resolve;
                });
                return create(GetResponseSchema, { detail: { sequenceNumber: 7n }, value: key });
            }
            if (call === 1) {
                await new Promise<void>((resolve) => {
                    releaseHigher = resolve;
                });
                return create(GetResponseSchema, { detail: { sequenceNumber: 12n }, value: key });
            }
            return create(GetResponseSchema, { detail: { sequenceNumber: 12n }, value: key });
        },
    });
    const session = ReadSession.monotonic(new StoreClient(client));
    const clone = session.clone();
    const lower = session.get(key);
    const higher = clone.get(key);

    expect(floors).toEqual([undefined, undefined]);
    releaseHigher();
    await higher;
    expect(session.evaluatedSequence()).toBe(12n);

    releaseLower();
    await lower;
    expect(session.evaluatedSequence()).toBe(12n);

    await session.get(key);
    expect(floors).toEqual([undefined, undefined, 12n]);
    expect(session.evaluatedSequence()).toBe(12n);
});

test('canceling one concurrent unseeded read does not cancel or delay another', async () => {
    let releaseSuccessful!: () => void;
    const floors: Array<bigint | undefined> = [];
    const client = mockClient({
        get: async (request, options) => {
            const call = floors.length;
            floors.push((request as GetRequest).minSequenceNumber);
            if (call === 0) {
                await new Promise<void>((_resolve, reject) => {
                    options?.signal?.addEventListener('abort', () => {
                        reject(new ConnectError('canceled', Code.Canceled));
                    });
                });
            }
            await new Promise<void>((resolve) => {
                releaseSuccessful = resolve;
            });
            return create(GetResponseSchema, { detail: { sequenceNumber: 15n }, value: key });
        },
    });
    const session = ReadSession.monotonic(new StoreClient(client));
    const controller = new AbortController();
    const canceled = session.get(key, { signal: controller.signal });
    const successful = session.clone().get(key);

    expect(floors).toEqual([undefined, undefined]);
    controller.abort();
    await expect(canceled).rejects.toMatchObject({ connectCode: Code.Canceled });

    releaseSuccessful();
    await expect(successful).resolves.toEqual({ value: key });
    expect(session.evaluatedSequence()).toBe(15n);
});

test('a pending first reduce frame does not block reads or prefetch later frames', async () => {
    let releaseFirst!: () => void;
    const firstReady = new Promise<void>((resolve) => {
        releaseFirst = resolve;
    });
    let secondPolled = false;
    let canceled = false;
    const getFloors: Array<bigint | undefined> = [];
    const client = mockClient({
        reduce: async function* () {
            try {
                await firstReady;
                yield create(ReduceResponseSchema, { detail: { sequenceNumber: 12n } });
                secondPolled = true;
                yield create(ReduceResponseSchema, { detail: { sequenceNumber: 14n } });
            } finally {
                canceled = true;
            }
        },
        get: async (request) => {
            getFloors.push((request as GetRequest).minSequenceNumber);
            return create(GetResponseSchema, { detail: { sequenceNumber: 10n }, value: key });
        },
    });
    const session = ReadSession.monotonic(new StoreClient(client));
    const stream = session.reduce(key, key, create(ReduceParamsSchema))[Symbol.asyncIterator]();
    const first = stream.next();

    await expect(session.clone().get(key)).resolves.toEqual({ value: key });
    expect(getFloors).toEqual([undefined]);
    expect(session.evaluatedSequence()).toBe(10n);
    expect(secondPolled).toBe(false);

    releaseFirst();
    expect((await first).value?.detail?.sequenceNumber).toBe(12n);
    expect(session.evaluatedSequence()).toBe(12n);
    expect(secondPolled).toBe(false);

    await stream.return?.();
    expect(secondPolled).toBe(false);
    expect(canceled).toBe(true);
});

test('getBatch observes successful replay without using the query floor as its cursor', async () => {
    const requests: StreamGetRequest[] = [];
    const getFloors: Array<bigint | undefined> = [];
    const options = { signal: new AbortController().signal, timeoutMs: 1_234 };
    let seenOptions: unknown;
    const client = mockClient(
        {
            get: async (request) => {
                getFloors.push((request as GetRequest).minSequenceNumber);
                return create(GetResponseSchema, { detail: { sequenceNumber: 12n } });
            },
        },
        {
            get: async (request, callOptions) => {
                requests.push(request as StreamGetRequest);
                seenOptions = callOptions;
                return create(StreamGetResponseSchema, {
                    sequenceNumber: 3n,
                    entries: [{ key, value: key }],
                });
            },
        },
    );
    const session = ReadSession.monotonic(new StoreClient(client), 10n);
    const clone = session.clone();

    const batch = await clone.getBatch(3n, options);

    expect(requests.map((request) => request.sequenceNumber)).toEqual([3n]);
    expect(seenOptions).toBe(options);
    expect(batch?.sequenceNumber).toBe(3n);
    expect(session.evaluatedSequence()).toBe(3n);
    expect(session.minSequenceNumber()).toBe(10n);

    await session.get(key);
    expect(getFloors).toEqual([10n]);
    expect(session.evaluatedSequence()).toBe(12n);
});

test.each(['monotonic', 'fixed'] as const)(
    '%s getBatch observations are shared and preserve policy',
    async (policy) => {
        const client = mockClient({}, {
            get: async () => create(StreamGetResponseSchema, {
                sequenceNumber: 8n,
                entries: [{ key, value: key }],
            }),
        });
        const store = new StoreClient(client);
        const session = policy === 'monotonic'
            ? ReadSession.monotonic(store, 4n)
            : ReadSession.fixed(store, 4n);
        const clone = session.clone();

        await session.getBatch(8n);

        expect(clone.evaluatedSequence()).toBe(8n);
        expect(clone.minSequenceNumber()).toBe(policy === 'monotonic' ? 8n : 4n);
    },
);

test.each(['getBatch', 'subscribe'] as const)(
    '%s observes sequence zero on an unseeded monotonic session',
    async (method) => {
        const client = mockClient({}, {
            get: async () => create(StreamGetResponseSchema, {
                sequenceNumber: 0n,
                entries: [{ key, value: key }],
            }),
            subscribe: () => (async function* () {
                yield create(SubscribeResponseSchema, {
                    sequenceNumber: 0n,
                    entries: [{ key, value: key }],
                });
            })(),
        });
        const session = ReadSession.monotonic(new StoreClient(client));

        expect(session.evaluatedSequence()).toBeUndefined();
        expect(session.minSequenceNumber()).toBeUndefined();

        if (method === 'getBatch') {
            await session.getBatch(0n);
        } else {
            const stream = session.subscribe({ selectors: [create(SelectorSchema)] })[
                Symbol.asyncIterator
            ]();
            await stream.next();
            await stream.return?.();
        }

        expect(session.evaluatedSequence()).toBe(0n);
        expect(session.minSequenceNumber()).toBe(0n);
    },
);

test('getBatch does not observe missing batches or terminal errors', async () => {
    let response = 0;
    const client = mockClient({}, {
        get: async () => {
            response += 1;
            throw response === 1
                ? new ConnectError('missing', Code.NotFound)
                : new ConnectError('failed', Code.Internal);
        },
    });
    const session = ReadSession.monotonic(new StoreClient(client));

    await expect(session.getBatch(1n)).resolves.toBeNull();
    expect(session.evaluatedSequence()).toBeUndefined();
    await expect(session.getBatch(2n)).rejects.toMatchObject({ status: 500 });
    expect(session.evaluatedSequence()).toBeUndefined();
});

test('log reads do not wait for query initialization', async () => {
    let releaseQuery!: () => void;
    const queryBlocked = new Promise<void>((resolve) => {
        releaseQuery = resolve;
    });
    let queryStarted!: () => void;
    const started = new Promise<void>((resolve) => {
        queryStarted = resolve;
    });
    const client = mockClient(
        {
            get: async () => {
                queryStarted();
                await queryBlocked;
                return create(GetResponseSchema);
            },
        },
        {
            get: async () => create(StreamGetResponseSchema, {
                sequenceNumber: 5n,
                entries: [{ key, value: key }],
            }),
            subscribe: () => (async function* () {
                yield create(SubscribeResponseSchema, {
                    sequenceNumber: 6n,
                    entries: [{ key, value: key }],
                });
            })(),
        },
    );
    const session = ReadSession.monotonic(new StoreClient(client));
    const pendingQuery = session.get(key);
    await started;

    await expect(session.getBatch(5n)).resolves.toMatchObject({ sequenceNumber: 5n });
    const subscription = session.subscribe({ selectors: [create(SelectorSchema)] })[
        Symbol.asyncIterator
    ]();
    await expect(subscription.next()).resolves.toMatchObject({
        value: { sequenceNumber: 6n },
    });

    releaseQuery();
    await pendingQuery;
    await subscription.return?.();
});

test('subscribe observes emitted batches before yielding and ignores omitted frames', async () => {
    const prefix = new StoreKeyPrefix(new Uint8Array([1]));
    const physicalKey = new Uint8Array([1, 3]);
    const requests: SubscribeRequest[] = [];
    const getFloors: Array<bigint | undefined> = [];
    const client = mockClient(
        {
            get: async (request) => {
                getFloors.push((request as GetRequest).minSequenceNumber);
                return create(GetResponseSchema, { detail: { sequenceNumber: 9n } });
            },
        },
        {
            subscribe: (request) => {
                requests.push(request as SubscribeRequest);
                return (async function* () {
                    yield create(SubscribeResponseSchema, { sequenceNumber: 20n });
                    yield create(SubscribeResponseSchema, {
                        sequenceNumber: 21n,
                        entries: [{ key: new Uint8Array([2, 3]), value: key }],
                    });
                    yield create(SubscribeResponseSchema, {
                        sequenceNumber: 9n,
                        entries: [{ key: physicalKey, value: key }],
                    });
                })();
            },
        },
    );
    const store = new StoreClient(client, prefix);
    const session = ReadSession.monotonic(store, 7n);
    const clone = session.clone();
    const stream = session.subscribe({
        selectors: [create(SelectorSchema)],
        sinceSequenceNumber: 2n,
    })[Symbol.asyncIterator]();

    const first = await stream.next();

    expect(first.value).toEqual({
        sequenceNumber: 9n,
        entries: [{ key, value: key }],
    });
    expect(requests[0].sinceSequenceNumber).toBe(2n);
    expect(clone.evaluatedSequence()).toBe(9n);
    expect(clone.minSequenceNumber()).toBe(9n);
    await clone.get(key);
    expect(getFloors).toEqual([9n]);
    await stream.return?.();
});

test('subscribe forwards cancellation options and cleans up when the consumer stops', async () => {
    const options = { signal: new AbortController().signal };
    let seenOptions: unknown;
    let cleanedUp = false;
    const client = mockClient({}, {
        subscribe: (_request, callOptions) => {
            seenOptions = callOptions;
            return (async function* () {
                try {
                    yield create(SubscribeResponseSchema, {
                        sequenceNumber: 6n,
                        entries: [{ key, value: key }],
                    });
                    await new Promise<never>(() => {});
                } finally {
                    cleanedUp = true;
                }
            })();
        },
    });
    const session = ReadSession.fixed(new StoreClient(client), 4n);
    const stream = session.subscribe({ selectors: [create(SelectorSchema)] }, options)[
        Symbol.asyncIterator
    ]();

    expect((await stream.next()).value?.sequenceNumber).toBe(6n);
    expect(session.evaluatedSequence()).toBe(6n);
    expect(session.minSequenceNumber()).toBe(4n);
    expect(seenOptions).toBe(options);
    await stream.return?.();
    expect(cleanedUp).toBe(true);
});

test('subscribe preserves prior observations when the stream ends with an error', async () => {
    let cleanedUp = false;
    const client = mockClient({}, {
        subscribe: () => (async function* () {
            try {
                yield create(SubscribeResponseSchema, {
                    sequenceNumber: 6n,
                    entries: [{ key, value: key }],
                });
                throw new ConnectError('stream failed', Code.Internal);
            } finally {
                cleanedUp = true;
            }
        })(),
    });
    const session = ReadSession.monotonic(new StoreClient(client));
    const stream = session.subscribe({ selectors: [create(SelectorSchema)] })[
        Symbol.asyncIterator
    ]();

    expect((await stream.next()).value?.sequenceNumber).toBe(6n);
    await expect(stream.next()).rejects.toMatchObject({ status: 500 });
    expect(cleanedUp).toBe(true);
    expect(session.evaluatedSequence()).toBe(6n);
});
