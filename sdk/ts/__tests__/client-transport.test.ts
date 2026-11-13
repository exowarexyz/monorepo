import { create } from '@bufbuild/protobuf';
import { createRouterTransport } from '@connectrpc/connect';
import { Client } from '../src/client';
import { Service as IngestService } from '../src/gen/ts/log/v1/ingest_pb';
import { Service as RetentionService } from '../src/gen/ts/log/v1/retention_pb';
import { Service as StreamService } from '../src/gen/ts/log/v1/stream_pb';
import { Service as PruneService } from '../src/gen/ts/store/v1/prune_pb';
import { Service as QueryService } from '../src/gen/ts/store/v1/query_pb';
import { ReadSession } from '../src/store';

const encoder = new TextEncoder();

/**
 * An in-memory store behind a router transport. Each Put appends one batch whose sequence number
 * is its position in the log. Every call except Subscribe records its method name and
 * Authorization header.
 */
function memoryTransport() {
    const log: { key: Uint8Array; value: Uint8Array }[][] = [];
    const calls: string[] = [];
    const authorization: Array<string | null> = [];
    const record = (method: string, header: Headers) => {
        calls.push(method);
        authorization.push(header.get('Authorization'));
    };
    const latest = (key: Uint8Array) => log
        .flat()
        .filter((entry) => Buffer.from(entry.key).equals(key))
        .at(-1);
    const detail = () => ({ sequenceNumber: BigInt(log.length) });
    const transport = createRouterTransport(({ service }) => {
        service(IngestService, {
            put: (request, context) => {
                record('put', context.requestHeader);
                log.push(request.kvs.map(({ key, value }) => ({ key, value })));
                return { sequenceNumber: BigInt(log.length) };
            },
        });
        service(QueryService, {
            get: (request, context) => {
                record('get', context.requestHeader);
                return { value: latest(request.key)?.value, detail: detail() };
            },
            async *range(_request, context) {
                record('range', context.requestHeader);
                yield { results: log.flat(), detail: detail() };
            },
        });
        service(PruneService, {
            prune: (_request, context) => {
                record('prune', context.requestHeader);
                return {};
            },
        });
        service(RetentionService, {
            setRetention: (_request, context) => {
                record('setRetention', context.requestHeader);
                return {};
            },
        });
        service(StreamService, {
            get: (request, context) => {
                record('streamGet', context.requestHeader);
                const entries = log[Number(request.sequenceNumber) - 1] ?? [];
                return { sequenceNumber: request.sequenceNumber, entries };
            },
        });
    });
    return { transport, calls, authorization };
}

const realFetch = globalThis.fetch;
const fetchSpy = jest.fn(() => Promise.reject(new Error('a client on a transport must not call fetch')));

beforeEach(() => {
    fetchSpy.mockClear();
    globalThis.fetch = fetchSpy as unknown as typeof fetch;
});

afterEach(() => {
    globalThis.fetch = realFetch;
    delete process.env.EXOWARE_API_KEY;
});

test('every service is reached through the given transport without a credential', async () => {
    const { transport, calls, authorization } = memoryTransport();
    process.env.EXOWARE_API_KEY = 'environment-token';
    const client = new Client(transport, { token: 'option-token' });
    const store = client.store();
    const key = encoder.encode('k');
    const value = encoder.encode('v');

    expect(client.baseUrl).toBe('');
    expect(client.credential).toBe('absent');
    await expect(store.set(key, value)).resolves.toBe(1n);
    await expect(store.get(key)).resolves.toMatchObject({ value });
    await store.prune([]);
    await client.retention.setRetention({});
    await expect(store.getBatch(1n)).resolves.toEqual({
        sequenceNumber: 1n,
        entries: [{ key, value }],
    });

    expect(calls).toEqual(['put', 'get', 'prune', 'setRetention', 'streamGet']);
    expect(authorization).toEqual([null, null, null, null, null]);
    expect(fetchSpy).not.toHaveBeenCalled();
});

test('put limits apply to a client built on a transport', async () => {
    const { transport, calls } = memoryTransport();
    const store = new Client(transport, { putLimits: { maxEntries: 1 } }).store();

    await expect(store.setMany([
        { key: encoder.encode('a'), value: encoder.encode('1') },
        { key: encoder.encode('b'), value: encoder.encode('2') },
    ])).rejects.toThrow(RangeError);
    expect(calls).toEqual([]);
});

test('a read session observes sequence numbers over the given transport', async () => {
    const { transport } = memoryTransport();
    const store = new Client(transport).store();
    const key = encoder.encode('k');
    const value = encoder.encode('v');
    const session = ReadSession.monotonic(store);

    await store.set(key, value);
    await store.set(key, encoder.encode('w'));
    await expect(session.query()).resolves.toMatchObject({ sequenceNumber: 2n });
    expect(session.minSequenceNumber()).toBe(2n);
    await expect(session.get(key)).resolves.toMatchObject({ value: encoder.encode('w') });
    expect(fetchSpy).not.toHaveBeenCalled();
});
