import { create, fromBinary, toBinary, toJsonString } from '@bufbuild/protobuf';
import { Code, ConnectError } from '@connectrpc/connect';
import { encodeEnvelope } from '@connectrpc/connect/protocol';
import { Client } from '../src/client';
import { HttpError } from '../src/error';
import {
    ReduceParamsSchema,
    ReduceRequestSchema,
    ReduceResponseSchema,
    RangeReduceOp,
    type ReduceRequest,
    type ReduceResponse,
} from '../src/gen/ts/store/v1/query_pb';
import { SerializableReadSession, StoreClient, StoreKeyPrefix } from '../src/store';

const start = new Uint8Array([1]);
const end = new Uint8Array([2]);
const params = create(ReduceParamsSchema);

function frame(group: bigint, sequenceNumber: bigint = 7n) {
    return create(ReduceResponseSchema, {
        groups: [{
            groupValues: [{ value: { case: 'uint64Value', value: group } }],
            groupValuesPresent: [true],
        }],
        detail: { sequenceNumber },
    });
}

function clientWithReduce(reduce: Client['query']['reduce']): Client {
    return { query: { reduce }, credential: 'absent' } as unknown as Client;
}

test.each(['store', 'session'])('reduce round trips and prefixes nested casts through %s', async (kind) => {
    const paramsAt = (byteOffset: number, bitOffset: number) => create(ReduceParamsSchema, {
        reducers: [{
            op: RangeReduceOp.SUM_FIELD,
            expr: { expr: { case: 'castFloat64', value: { expr: { case: 'add', value: {
                left: { expr: { case: 'field', value: { field: { case: 'key', value: { byteOffset } } } } },
                right: { expr: { case: 'castFloat64', value: { expr: {
                    case: 'field', value: { field: { case: 'value', value: { index: 2, nullable: true } } },
                } } } },
            } } } } },
        }],
        groupBy: [{ expr: { case: 'castFloat64', value: { expr: {
            case: 'field', value: { field: { case: 'zOrderKey', value: { bitOffset, fieldPosition: 0, fieldWidths: [8] } } },
        } } } }],
    });
    const params = paramsAt(9, 12);
    let received: ReduceRequest | undefined;
    const client = clientWithReduce(async function* (request) {
        received = fromBinary(ReduceRequestSchema, toBinary(ReduceRequestSchema, request as ReduceRequest));
        yield frame(1n);
    });
    const prefix = new StoreKeyPrefix(new Uint8Array([1, 2, 3]));
    const store = kind === 'store'
        ? new StoreClient(client, prefix)
        : new SerializableReadSession(client, prefix);
    for await (const result of store.reduce(start, end, params)) {
        expect(result).toEqual(frame(1n));
    }
    expect(received!.params).toEqual(paramsAt(12, 36));
    expect(params).toEqual(paramsAt(9, 12));
});

test('reduce preserves a missing cast child expression for server validation', async () => {
    const params = create(ReduceParamsSchema, {
        reducers: [{ expr: { expr: { case: 'castFloat64', value: {} } } }],
    });
    let received: ReduceRequest | undefined;
    const client = clientWithReduce(async function* (request) {
        received = fromBinary(ReduceRequestSchema, toBinary(ReduceRequestSchema, request as ReduceRequest));
        yield frame(1n);
    });
    const store = new StoreClient(client, new StoreKeyPrefix(new Uint8Array([1])));
    for await (const result of store.reduce(start, end, params)) {
        expect(result).toEqual(frame(1n));
    }
    expect(received!.params).toEqual(params);
});

test.each(['store', 'session'])('reduce prefixes reducer filters through %s', async (kind) => {
    const params = create(ReduceParamsSchema, {
        reducers: [{
            op: RangeReduceOp.COUNT_ALL,
            filter: {
                checks: [
                    {
                        field: { field: { case: 'key', value: { byteOffset: 9 } } },
                        constraint: { constraint: { case: 'isNotNull', value: true } },
                    },
                    {
                        field: { field: { case: 'zOrderKey', value: { bitOffset: 12, fieldPosition: 0, fieldWidths: [8] } } },
                        constraint: { constraint: { case: 'isNotNull', value: true } },
                    },
                    {
                        field: { field: { case: 'value', value: { index: 2, nullable: true } } },
                        constraint: { constraint: { case: 'isNull', value: true } },
                    },
                ],
            },
        }, { op: RangeReduceOp.COUNT_ALL }],
        filter: { contradiction: true },
    });
    const original = toBinary(ReduceParamsSchema, params);
    let received: ReduceRequest | undefined;
    const client = clientWithReduce(async function* (request) {
        received = fromBinary(ReduceRequestSchema, toBinary(ReduceRequestSchema, request as ReduceRequest));
        yield frame(1n);
    });
    const prefix = new StoreKeyPrefix(new Uint8Array([1, 2, 3]));
    const store = kind === 'store'
        ? new StoreClient(client, prefix)
        : new SerializableReadSession(client, prefix);
    for await (const result of store.reduce(start, end, params)) {
        expect(result).toEqual(frame(1n));
    }
    const checks = received!.params!.reducers[0].filter!.checks;
    expect(checks[0].field!.field).toMatchObject({ case: 'key', value: { byteOffset: 12 } });
    expect(checks[1].field!.field).toMatchObject({ case: 'zOrderKey', value: { bitOffset: 36 } });
    expect(checks[2]).toEqual(params.reducers[0].filter!.checks[2]);
    expect(received!.params!.reducers[1].filter).toBeUndefined();
    expect(received!.params!.filter).toEqual(params.filter);
    expect(toBinary(ReduceParamsSchema, params)).toEqual(original);
});

function response(frames: ReduceResponse[], code?: string, useBinaryFormat = true): Response {
    return new Response(new ReadableStream<Uint8Array>({
        start(controller) {
            for (const frame of frames) {
                const bytes = useBinaryFormat
                    ? toBinary(ReduceResponseSchema, frame)
                    : new TextEncoder().encode(toJsonString(ReduceResponseSchema, frame));
                controller.enqueue(encodeEnvelope(0, bytes));
            }
            const terminal = code ? { error: { code, message: 'retryable failure' } } : {};
            controller.enqueue(encodeEnvelope(2, new TextEncoder().encode(JSON.stringify(terminal))));
            controller.close();
        },
    }), { headers: { 'content-type': `application/connect+${useBinaryFormat ? 'proto' : 'json'}` } });
}

describe.each([true, false])('Reduce responses with binary format %s', (useBinaryFormat) => {
    test.each(['client', 'store', 'session'])('rejects a missing response through %s', async (kind) => {
        let signal: AbortSignal | null | undefined;
        const fetch = jest.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
            signal = init?.signal;
            return response([], undefined, useBinaryFormat);
        });
        try {
            const client = new Client('http://reduce.test', {
                token: '', useBinaryFormat,
                retry: { maxAttempts: 3, initialBackoffMs: 0, maxBackoffMs: 0 },
            });
            const session = new SerializableReadSession(client);
            const params = create(ReduceParamsSchema, { reducers: [{ op: RangeReduceOp.COUNT_ALL }] });
            const stream = kind === 'client'
                ? client.query.reduce({ start, end, params })
                : (kind === 'store' ? new StoreClient(client) : session).reduce(start, end, params);
            const next = stream[Symbol.asyncIterator]().next();
            if (kind === 'client') {
                await expect(next).rejects.toBeInstanceOf(ConnectError);
                await expect(next).rejects.toMatchObject({ code: Code.Internal });
            } else {
                await expect(next).rejects.toBeInstanceOf(HttpError);
                await expect(next).rejects.toMatchObject({ status: 500, connectCode: Code.Internal });
            }
            expect(fetch).toHaveBeenCalledTimes(1);
            expect(signal?.aborted).toBe(true);
            if (kind === 'session') expect(session.fixedSequence()).toBeUndefined();
        } finally {
            fetch.mockRestore();
        }
    });

    test('accepts a detail-only frame for an empty grouped reduction', async () => {
        const detail = create(ReduceResponseSchema, { detail: { sequenceNumber: 7n } });
        const fetch = jest.spyOn(globalThis, 'fetch').mockImplementation(async () =>
            response([detail], undefined, useBinaryFormat));
        try {
            const session = new SerializableReadSession(new Client('http://reduce.test', { token: '', useBinaryFormat }));
            const params = create(ReduceParamsSchema, {
                groupBy: [{ expr: { case: 'literal', value: { value: { case: 'uint64Value', value: 1n } } } }],
            });
            const stream = session.reduce(start, end, params)[Symbol.asyncIterator]();
            expect((await stream.next()).value).toEqual(detail);
            expect(session.fixedSequence()).toBe(7n);
            expect((await stream.next()).done).toBe(true);
            expect(fetch).toHaveBeenCalledTimes(1);
        } finally {
            fetch.mockRestore();
        }
    });
});

test.each(['aborted', 'unavailable', 'resource_exhausted'])('reduce retries %s before its first frame', async (code) => {
    const requests: Array<BodyInit | null | undefined> = [];
    const fetch = jest.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
        requests.push(init?.body);
        return requests.length === 1 ? response([], code) : response([frame(1n)]);
    });
    try {
        const client = new Client('http://reduce.test', {
            token: '',
            useBinaryFormat: true,
            retry: { maxAttempts: 2, initialBackoffMs: 0, maxBackoffMs: 0 },
        });
        const received = [];
        for await (const result of new StoreClient(client).reduce(start, end, params)) {
            received.push(result);
        }
        expect(received).toEqual([frame(1n)]);
        expect(requests).toHaveLength(2);
        expect(requests[1]).toEqual(requests[0]);
    } finally {
        fetch.mockRestore();
    }
});

test('canceling Reduce during retry backoff prevents another request', async () => {
    jest.useFakeTimers();
    const fetch = jest.spyOn(globalThis, 'fetch').mockImplementation(async () => response([], 'unavailable'));
    try {
        const controller = new AbortController();
        const client = new Client('http://reduce.test', {
            token: '',
            useBinaryFormat: true,
            retry: { maxAttempts: 2, initialBackoffMs: 100, maxBackoffMs: 100 },
        });
        const stream = client.query.reduce({ start, end, params }, { signal: controller.signal })[Symbol.asyncIterator]();
        const result = expect(stream.next()).rejects.toMatchObject({ code: Code.Canceled });
        await jest.advanceTimersByTimeAsync(0);
        expect(fetch).toHaveBeenCalledTimes(1);
        controller.abort();
        await jest.advanceTimersByTimeAsync(100);
        await result;
        expect(fetch).toHaveBeenCalledTimes(1);
    } finally {
        fetch.mockRestore();
        jest.useRealTimers();
    }
});

test.each(['store', 'session'])('returning a %s reduce iterator aborts the native Connect request', async (kind) => {
    let signal: AbortSignal | null | undefined;
    let body: ReadableStreamDefaultController<Uint8Array>;
    const fetch = jest.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
        signal = init?.signal;
        return new Response(new ReadableStream<Uint8Array>({
            start(controller) {
                body = controller;
                controller.enqueue(encodeEnvelope(0, toBinary(ReduceResponseSchema, frame(1n))));
            },
        }), { headers: { 'content-type': 'application/connect+proto' } });
    });
    try {
        const client = new Client('http://reduce.test', { token: '', useBinaryFormat: true });
        const store = kind === 'store' ? new StoreClient(client) : new SerializableReadSession(client);
        const stream = store.reduce(start, end, params)[Symbol.asyncIterator]();
        expect((await stream.next()).value).toEqual(frame(1n));
        expect(signal?.aborted).toBe(false);
        await stream.return?.();
        expect(signal?.aborted).toBe(true);
    } finally {
        body!.close();
        fetch.mockRestore();
    }
});

test('reduce yields frames on demand and returning cancels the underlying stream', async () => {
    let secondPolled = false;
    let cancelled = false;
    const client = clientWithReduce(async function* () {
        try {
            yield frame(1n);
            secondPolled = true;
            yield frame(2n, 7n);
        } finally {
            cancelled = true;
        }
    });
    const stream = new StoreClient(client).reduce(start, end, params)[Symbol.asyncIterator]();
    expect((await stream.next()).value).toEqual(frame(1n));
    expect(secondPolled).toBe(false);
    expect(cancelled).toBe(false);
    await stream.return?.();
    expect(cancelled).toBe(true);
    expect(secondPolled).toBe(false);
});

test('reduce observes metadata on frame consumption and sends the fixed session floor', async () => {
    const floors: Array<bigint | undefined> = [];
    const client = clientWithReduce(async function* (request) {
        floors.push((request as ReduceRequest).minSequenceNumber);
        yield frame(1n);
        yield frame(2n, 7n);
    });
    const session = new SerializableReadSession(client);
    const stream = session.reduce(start, end, params)[Symbol.asyncIterator]();
    expect(session.fixedSequence()).toBeUndefined();
    await stream.next();
    expect(session.fixedSequence()).toBe(7n);
    await stream.next();
    expect(session.fixedSequence()).toBe(7n);
    expect((await stream.next()).done).toBe(true);
    const second = session.reduce(start, end, params)[Symbol.asyncIterator]();
    await second.next();
    await second.return?.();
    expect(floors).toEqual([undefined, 7n]);
});

test('reduce returns a midstream error without replaying delivered groups', async () => {
    const fetch = jest.spyOn(globalThis, 'fetch').mockImplementation(async () => response([frame(1n)], 'unavailable'));
    try {
        const client = new Client('http://reduce.test', {
            token: '',
            useBinaryFormat: true,
            retry: { maxAttempts: 2, initialBackoffMs: 0, maxBackoffMs: 0 },
        });
        const stream = new StoreClient(client).reduce(start, end, params)[Symbol.asyncIterator]();
        expect((await stream.next()).value).toEqual(frame(1n));
        await expect(stream.next()).rejects.toBeInstanceOf(HttpError);
        expect(fetch).toHaveBeenCalledTimes(1);
    } finally {
        fetch.mockRestore();
    }
});
