import { create } from '@bufbuild/protobuf';
import { Client } from '../src/client';
import {
    GetManyFrameSchema,
    GetResponseSchema,
    RangeFrameSchema,
    ReduceParamsSchema,
    ReduceResponseSchema,
    type GetRequest,
    type RangeRequest,
} from '../src/gen/ts/store/v1/query_pb';
import { ReadSession, StoreClient, StoreKeyPrefix } from '../src/store';

function mockClient(query: Partial<Client['query']>): Client {
    return { query, credential: 'absent' } as unknown as Client;
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

test('zero observations do not become request floors', async () => {
    const floors: Array<bigint | undefined> = [];
    const client = mockClient({
        get: async (request) => {
            floors.push((request as GetRequest).minSequenceNumber);
            return create(GetResponseSchema, { detail: { sequenceNumber: 0n } });
        },
    });
    const session = ReadSession.monotonic(new StoreClient(client), 0n);

    await session.get(key);
    await session.get(key);
    expect(floors).toEqual([undefined, undefined]);
    expect(session.evaluatedSequence()).toBeUndefined();
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
    const session = ReadSession.monotonic(new StoreClient(client), 0n);
    let dependent: Promise<unknown> | undefined;

    await session.getMany([key], undefined, () => {
        expect(session.evaluatedSequence()).toBe(8n);
        dependent = session.get(key);
    });
    await dependent;
    expect(getFloors).toEqual([8n]);
});

test('the initialization gate waits for the first reduce frame without buffering later frames', async () => {
    let releaseFirst!: () => void;
    const firstReady = new Promise<void>((resolve) => {
        releaseFirst = resolve;
    });
    let secondPolled = false;
    const getFloors: Array<bigint | undefined> = [];
    const client = mockClient({
        reduce: async function* () {
            await firstReady;
            yield create(ReduceResponseSchema, { detail: { sequenceNumber: 12n } });
            secondPolled = true;
            yield create(ReduceResponseSchema, { detail: { sequenceNumber: 14n } });
        },
        get: async (request) => {
            getFloors.push((request as GetRequest).minSequenceNumber);
            return create(GetResponseSchema, { detail: { sequenceNumber: 12n }, value: key });
        },
    });
    const session = ReadSession.monotonic(new StoreClient(client), 0n);
    const clone = session.clone();
    const stream = session.reduce(key, key, create(ReduceParamsSchema))[Symbol.asyncIterator]();
    const first = stream.next();
    const dependent = clone.get(key);

    await Promise.resolve();
    expect(getFloors).toEqual([]);
    releaseFirst();
    expect((await first).value?.detail?.sequenceNumber).toBe(12n);
    await dependent;
    expect(getFloors).toEqual([12n]);
    expect(secondPolled).toBe(false);

    expect((await stream.next()).value?.detail?.sequenceNumber).toBe(14n);
    expect(session.evaluatedSequence()).toBe(14n);
    await stream.return?.();
});
