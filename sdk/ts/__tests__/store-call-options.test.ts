import { create } from '@bufbuild/protobuf';

jest.mock('../src/credential', () => ({
    ...jest.requireActual('../src/credential'),
    environmentApiKey: () => undefined,
}));

import { Client } from '../src/client';
import { GetResponseSchema } from '../src/gen/ts/store/v1/query_pb';
import { ReadSession } from '../src/store';

test('StoreClient.get forwards Connect call options', async () => {
    const client = new Client('http://127.0.0.1:1');
    const store = client.store();
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

test('StoreClient.query forwards Connect call options', async () => {
    const client = new Client('http://127.0.0.1:1');
    const store = client.store();
    const controller = new AbortController();
    const callOptions = { signal: controller.signal, timeoutMs: 1_234 };
    let seenOptions: Parameters<typeof client.query.range>[1];

    client.query.range = ((_request, options) => {
        seenOptions = options;
        return (async function* () {})();
    }) as typeof client.query.range;

    await store.query(undefined, undefined, 1, 1, undefined, undefined, callOptions);
    expect(seenOptions).toBe(callOptions);
});

test('ReadSession.get forwards Connect call options with its captured floor', async () => {
    const client = new Client('http://127.0.0.1:1');
    const session = ReadSession.fixed(client.store(), 37n);
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

test('ReadSession.query forwards Connect call options with its captured floor', async () => {
    const client = new Client('http://127.0.0.1:1');
    const session = ReadSession.monotonic(client.store(), 41n);
    const controller = new AbortController();
    const callOptions = { signal: controller.signal, timeoutMs: 1_234 };
    let seenFloor: bigint | undefined;
    let seenOptions: Parameters<typeof client.query.range>[1];

    client.query.range = ((request, options) => {
        seenFloor = request.minSequenceNumber;
        seenOptions = options;
        return (async function* () {})();
    }) as typeof client.query.range;

    await session.query(undefined, undefined, 1, 1, undefined, callOptions);
    expect(seenFloor).toBe(41n);
    expect(seenOptions).toBe(callOptions);
    expect(seenOptions?.signal).toBe(controller.signal);
});
