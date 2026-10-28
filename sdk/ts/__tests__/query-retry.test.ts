import { create, toBinary } from '@bufbuild/protobuf';
import { encodeEnvelope } from '@connectrpc/connect/protocol';
import { Client } from '../src/client';
import { HttpError } from '../src/error';
import { GetManyFrameSchema, RangeFrameSchema } from '../src/gen/ts/store/v1/query_pb';
import { StoreClient } from '../src/store';

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

function read(method: Method, maxAttempts = 2) {
    const store = new StoreClient(new Client('http://query-retry.test', {
        token: '',
        useBinaryFormat: true,
        retry: { maxAttempts, initialBackoffMs: 0, maxBackoffMs: 0 },
    }));
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
