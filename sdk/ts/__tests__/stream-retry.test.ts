import { create, toBinary } from '@bufbuild/protobuf';
import { Code, createClient } from '@connectrpc/connect';
import { encodeEnvelope } from '@connectrpc/connect/protocol';
import { Client, createTransport } from '../src/client';
import { HttpError } from '../src/error';
import { SubscribeResponseSchema } from '../src/gen/ts/log/v1/stream_pb';
import * as query from '../src/gen/ts/store/v1/query_pb';
import { GetManyFrameSchema, RangeFrameSchema } from '../src/gen/ts/store/v1/query_pb';
import { StoreClient, type StoreBatch } from '../src/store';

const rows = [
    { key: new Uint8Array([1]), value: new Uint8Array([10]) },
    { key: new Uint8Array([2]), value: new Uint8Array([20]) },
];

// Two frames, so a passing read shows the frames after the prefetched one still arrive.
const frames = {
    range: rows.map((row) => toBinary(RangeFrameSchema, create(RangeFrameSchema, {
        results: [row],
        detail: { sequenceNumber: 7n },
    }))),
    getMany: rows.map((row) => toBinary(GetManyFrameSchema, create(GetManyFrameSchema, {
        results: [row],
        detail: { sequenceNumber: 7n },
    }))),
};

type Method = keyof typeof frames;
const methods: Method[] = ['range', 'getMany'];

// Connect sends a stream's error, including one raised before the first frame, in the end-stream
// message of an HTTP 200 body.
function streamResponse(frames: Uint8Array[], code?: string): Response {
    return new Response(new ReadableStream<Uint8Array>({
        start(controller) {
            for (const frame of frames) controller.enqueue(encodeEnvelope(0, frame));
            const end = code ? { error: { code, message: 'query failed' } } : {};
            controller.enqueue(encodeEnvelope(2, new TextEncoder().encode(JSON.stringify(end))));
            controller.close();
        },
    }), { headers: { 'content-type': 'application/connect+proto' } });
}

const url = 'http://stream-retry.test';

function options(maxAttempts: number, backoffMs = 0) {
    return {
        token: '',
        useBinaryFormat: true,
        retry: { maxAttempts, initialBackoffMs: backoffMs, maxBackoffMs: backoffMs },
    };
}

function storeClient(maxAttempts: number): StoreClient {
    return new StoreClient(new Client(url, options(maxAttempts)));
}

async function drain<T>(stream: AsyncIterable<T>): Promise<T[]> {
    const received: T[] = [];
    for await (const item of stream) received.push(item);
    return received;
}

function read(method: Method, maxAttempts = 2) {
    const store = storeClient(maxAttempts);
    return method === 'range'
        ? store.query(new Uint8Array([0]), new Uint8Array([9])).then((result) => result.results)
        : store.getMany(rows.map((row) => row.key));
}

function mockFetch(...responses: Array<() => Response>) {
    const bodies: Array<BodyInit | null | undefined> = [];
    const fetch = jest.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
        bodies.push(init?.body);
        return responses[Math.min(bodies.length, responses.length) - 1]();
    });
    return { fetch, bodies };
}

afterEach(() => {
    jest.restoreAllMocks();
});

describe.each(methods)('%s', (method) => {
    test.each(['aborted', 'unavailable', 'resource_exhausted'])('retries %s before the first frame', async (code) => {
        const { fetch, bodies } = mockFetch(
            () => streamResponse([], code),
            () => streamResponse(frames[method]),
        );
        await expect(read(method)).resolves.toEqual(rows);
        expect(fetch).toHaveBeenCalledTimes(2);
        expect(bodies[1]).toEqual(bodies[0]);
    });

    test('retries an HTTP error status with the same request', async () => {
        const { fetch, bodies } = mockFetch(
            () => new Response(null, { status: 503 }),
            () => streamResponse(frames[method]),
        );
        await expect(read(method)).resolves.toEqual(rows);
        expect(fetch).toHaveBeenCalledTimes(2);
        expect(bodies[1]).toEqual(bodies[0]);
    });

    test('stops after maxAttempts', async () => {
        const { fetch } = mockFetch(() => streamResponse([], 'aborted'));
        await expect(read(method, 3)).rejects.toBeInstanceOf(HttpError);
        expect(fetch).toHaveBeenCalledTimes(3);
    });

    test('does not retry invalid_argument', async () => {
        const { fetch } = mockFetch(() => streamResponse([], 'invalid_argument'));
        await expect(read(method, 3)).rejects.toMatchObject({ status: 400 });
        expect(fetch).toHaveBeenCalledTimes(1);
    });

    test('does not retry an error after the first frame', async () => {
        const { fetch } = mockFetch(() => streamResponse(frames[method].slice(0, 1), 'unavailable'));
        await expect(read(method)).rejects.toBeInstanceOf(HttpError);
        expect(fetch).toHaveBeenCalledTimes(1);
    });

    test('accepts a stream that ends without a frame', async () => {
        const { fetch } = mockFetch(() => streamResponse([]));
        await expect(read(method)).resolves.toEqual([]);
        expect(fetch).toHaveBeenCalledTimes(1);
    });
});

describe('subscribe', () => {
    const batch = { sequenceNumber: 7n, entries: [rows[0]] };
    const frame = toBinary(SubscribeResponseSchema, create(SubscribeResponseSchema, batch));

    async function subscribe() {
        const batches: StoreBatch[] = [];
        for await (const received of storeClient(2).subscribe({ selectors: [] })) batches.push(received);
        return batches;
    }

    test('retries an HTTP error status with the same request', async () => {
        const { fetch, bodies } = mockFetch(
            () => new Response(null, { status: 503 }),
            () => streamResponse([frame]),
        );
        await expect(subscribe()).resolves.toEqual([batch]);
        expect(fetch).toHaveBeenCalledTimes(2);
        expect(bodies[1]).toEqual(bodies[0]);
    });

    // Subscribe does not wait for its first frame, which may not arrive for a long time, so an
    // error inside the HTTP 200 body reaches the caller.
    test('does not retry an error in the stream body', async () => {
        const { fetch } = mockFetch(() => streamResponse([], 'unavailable'));
        await expect(subscribe()).rejects.toBeInstanceOf(HttpError);
        expect(fetch).toHaveBeenCalledTimes(1);
    });
});

// A custom client passes its own generated descriptors to `createTransport`. A separate module
// instance of the generated code stands in for them.
describe('a client with its own descriptors', () => {
    let own!: typeof query;
    jest.isolateModules(() => {
        own = require('../src/gen/ts/store/v1/query_pb');
    });
    // Built after mockFetch, because the cookie jar captures `fetch` when the transport is made.
    const client = () => createClient(own.Service, createTransport(url, options(2)));

    test('uses separate descriptor objects', () => {
        expect(own.Service.method.range).not.toBe(query.Service.method.range);
    });

    test('retries before the first frame', async () => {
        const { fetch } = mockFetch(
            () => streamResponse([], 'aborted'),
            () => streamResponse(frames.range),
        );
        const received = await drain(client().range({}));
        const results = received.flatMap((frame) => frame.results.map(({ key, value }) => ({ key, value })));
        expect(results).toEqual(rows);
        expect(fetch).toHaveBeenCalledTimes(2);
    });

    test('rejects a Reduce stream that ends without a frame', async () => {
        mockFetch(() => streamResponse([]));
        await expect(drain(client().reduce({}))).rejects.toMatchObject({ code: Code.Internal });
    });
});

describe('retry backoff', () => {
    // The backoff is long enough that a call waiting it out would fail the elapsed-time check.
    const client = () => new Client(url, options(2, 10_000));

    test('ends when the caller aborts', async () => {
        const { fetch } = mockFetch(() => streamResponse([], 'aborted'));
        const controller = new AbortController();
        const started = performance.now();
        setTimeout(() => controller.abort(), 20);
        await expect(drain(client().query.range({}, { signal: controller.signal })))
            .rejects.toMatchObject({ code: Code.Canceled });
        expect(performance.now() - started).toBeLessThan(1_000);
        expect(fetch).toHaveBeenCalledTimes(1);
    });

    test('ends when the call times out', async () => {
        const { fetch } = mockFetch(() => streamResponse([], 'aborted'));
        const started = performance.now();
        await expect(drain(client().query.range({}, { timeoutMs: 50 })))
            .rejects.toMatchObject({ code: Code.DeadlineExceeded });
        expect(performance.now() - started).toBeLessThan(1_000);
        expect(fetch).toHaveBeenCalledTimes(1);
    });
});
