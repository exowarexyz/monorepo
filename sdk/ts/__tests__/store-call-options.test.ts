import { create } from '@bufbuild/protobuf';
import { Code, ConnectError } from '@connectrpc/connect';

jest.mock('../src/credential', () => ({
    ...jest.requireActual('../src/credential'),
    environmentApiKey: () => undefined,
}));

import { StoreClient } from '../src/client';
import { PutResponseSchema } from '../src/gen/ts/log/v1/ingest_pb';
import { PruneResponseSchema } from '../src/gen/ts/store/v1/prune_pb';
import { GetResponseSchema, ReduceParamsSchema } from '../src/gen/ts/store/v1/query_pb';
import { ReadSession, StoreWriteBatch } from '../src/store';

test('PrefixedStoreClient.get forwards Connect call options', async () => {
    const client = new StoreClient('http://127.0.0.1:1');
    const store = client.unprefixed();
    const key = new Uint8Array([1, 2, 3]);
    const value = new Uint8Array([4, 5, 6]);
    const minSequenceNumber = 37n;
    const controller = new AbortController();
    const callOptions = { signal: controller.signal, timeoutMs: 1_234 };
    let seenRequest: Parameters<typeof client.query.get>[0] | undefined;
    let seenOptions: Parameters<typeof client.query.get>[1];

    client.query.get = async (request, options) => {
        seenRequest = request;
        seenOptions = options;
        return create(GetResponseSchema, { value });
    };

    await expect(store.get(key, minSequenceNumber, callOptions)).resolves.toEqual({ value });
    expect(seenRequest?.key).toEqual(key);
    expect(seenRequest?.minSequenceNumber).toBe(minSequenceNumber);
    expect(seenOptions).toBe(callOptions);
    expect(seenOptions?.signal).toBe(controller.signal);
});

test('PrefixedStoreClient.range forwards Connect call options', async () => {
    const client = new StoreClient('http://127.0.0.1:1');
    const store = client.unprefixed();
    const controller = new AbortController();
    const callOptions = { signal: controller.signal, timeoutMs: 1_234 };
    let seenOptions: Parameters<typeof client.query.range>[1];

    client.query.range = ((_request, options) => {
        seenOptions = options;
        return (async function* () {})();
    }) as typeof client.query.range;

    await store.range(undefined, undefined, 1, 1, undefined, undefined, callOptions);
    expect(seenOptions).toBe(callOptions);
});

test('ReadSession.get forwards Connect call options with its captured floor', async () => {
    const client = new StoreClient('http://127.0.0.1:1');
    const session = ReadSession.fixed(client.unprefixed(), 37n);
    const controller = new AbortController();
    const callOptions = { signal: controller.signal, timeoutMs: 1_234 };
    let seenRequest: Parameters<typeof client.query.get>[0] | undefined;
    let seenOptions: Parameters<typeof client.query.get>[1];

    client.query.get = async (request, options) => {
        seenRequest = request;
        seenOptions = options;
        return create(GetResponseSchema);
    };

    await expect(session.get(new Uint8Array([1]), callOptions)).resolves.toBeNull();
    expect(seenRequest?.minSequenceNumber).toBe(37n);
    expect(seenOptions).toBe(callOptions);
    expect(seenOptions?.signal).toBe(controller.signal);
});

test('ReadSession.range forwards Connect call options with its captured floor', async () => {
    const client = new StoreClient('http://127.0.0.1:1');
    const session = ReadSession.monotonic(client.unprefixed(), 41n);
    const controller = new AbortController();
    const callOptions = { signal: controller.signal, timeoutMs: 1_234 };
    let seenFloor: bigint | undefined;
    let seenOptions: Parameters<typeof client.query.range>[1];

    client.query.range = ((request, options) => {
        seenFloor = request.minSequenceNumber;
        seenOptions = options;
        return (async function* () {})();
    }) as typeof client.query.range;

    await session.range(undefined, undefined, 1, 1, undefined, callOptions);
    expect(seenFloor).toBe(41n);
    expect(seenOptions).toBe(callOptions);
    expect(seenOptions?.signal).toBe(controller.signal);
});

test('PrefixedStoreClient writes, batch commits, prune, and getMany forward Connect call options', async () => {
    const client = new StoreClient('http://127.0.0.1:1');
    const store = client.unprefixed();
    const key = new Uint8Array([1]);
    const value = new Uint8Array([2]);
    const callOptions = { timeoutMs: 1_234 };
    const seen: unknown[] = [];

    client.ingest.put = async (_request, options) => {
        seen.push(options);
        return create(PutResponseSchema, { sequenceNumber: 1n });
    };
    client.prune.prune = async (_request, options) => {
        seen.push(options);
        return create(PruneResponseSchema);
    };
    client.query.getMany = ((_request, options) => {
        seen.push(options);
        return (async function* () {})();
    }) as typeof client.query.getMany;

    await store.put(key, value, callOptions);
    await store.putMany([{ key, value }], callOptions);
    await store.putPrepared(new StoreWriteBatch().push(store, key, value), callOptions);
    await new StoreWriteBatch().push(store, key, value).commit(client, callOptions);
    await store.prune([], callOptions);
    await store.getMany([key], undefined, undefined, undefined, callOptions);
    await ReadSession.monotonic(store).getMany([key], undefined, undefined, callOptions);
    expect(seen).toHaveLength(7);
    for (const options of seen) {
        expect(options).toBe(callOptions);
    }
});

test('rangeReduce forwards call options and rejects with HttpError 499 when the caller signal aborts', async () => {
    for (const abortedBeforeCall of [false, true]) {
        const client = new StoreClient('http://127.0.0.1:1');
        const controller = new AbortController();
        const canceled = new ConnectError('canceled', Code.Canceled);
        let seenOptions: Parameters<typeof client.query.reduce>[1];

        client.query.reduce = ((_request, options) => {
            seenOptions = options;
            return (async function* () {
                await new Promise<void>((_resolve, reject) => {
                    if (options?.signal?.aborted) {
                        reject(canceled);
                        return;
                    }
                    options?.signal?.addEventListener('abort', () => reject(canceled), { once: true });
                });
            })();
        }) as typeof client.query.reduce;

        if (abortedBeforeCall) {
            controller.abort();
        }
        const stream = client.unprefixed().rangeReduce(
            new Uint8Array(),
            new Uint8Array(),
            create(ReduceParamsSchema),
            undefined,
            { signal: controller.signal, timeoutMs: 1_234 },
        )[Symbol.asyncIterator]();
        const pending = stream.next();
        expect(seenOptions?.timeoutMs).toBe(1_234);
        expect(seenOptions?.signal?.aborted).toBe(abortedBeforeCall);

        controller.abort();
        expect(seenOptions?.signal?.aborted).toBe(true);
        await expect(pending).rejects.toMatchObject({
            name: 'HttpError',
            status: 499,
            connectCode: Code.Canceled,
            cause: canceled,
        });
    }
});
