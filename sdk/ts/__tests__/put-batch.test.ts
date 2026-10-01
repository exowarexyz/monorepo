import { create, toBinary, toJsonString } from '@bufbuild/protobuf';

jest.mock('../src/credential', () => ({
    ...jest.requireActual('../src/credential'),
    environmentApiKey: () => undefined,
}));

import { Client } from '../src/client';
import { EntrySchema } from '../src/gen/ts/common/v1/kv_pb';
import { PutRequestSchema, PutResponseSchema } from '../src/gen/ts/log/v1/ingest_pb';
import { GetRequestSchema, GetResponseSchema } from '../src/gen/ts/store/v1/query_pb';
import {
    StoreKeyPrefix,
    StoreWriteBatch,
    type StoreBatchEntry,
} from '../src/store';

function client(options: ConstructorParameters<typeof Client>[1] = { token: '' }): Client {
    return new Client('http://put-batch.test', options);
}

function request(entries: readonly StoreBatchEntry[]) {
    return create(PutRequestSchema, {
        kvs: entries.map((entry) => create(EntrySchema, entry)),
    });
}

function serializedLen(entries: readonly StoreBatchEntry[]): number {
    return toBinary(PutRequestSchema, request(entries)).byteLength;
}

function filled(length: number, byte: number): Uint8Array {
    const value = new Uint8Array(length);
    value.fill(byte);
    return value;
}

function batch(entries: readonly StoreBatchEntry[], store = client().store()): StoreWriteBatch {
    const result = new StoreWriteBatch();
    for (const entry of entries) result.push(store, entry.key, entry.value);
    return result;
}

describe('protobuf Put accounting', () => {
    test.each([
        [0, 0],
        [1, 0],
        [0, 1],
        [2, 3],
        [127, 128],
        [128, 127],
        [16_383, 1],
        [16_384, 2],
    ])('matches the real serializer for key %i and value %i', (keyLen, valueLen) => {
        const write = batch([{
            key: filled(keyLen, 0x4b),
            value: filled(valueLen, 0x56),
        }]);

        expect(write.encodedLen()).toBe(serializedLen(write.entries()));
    });

    test('matches the real serializer for empty and mixed batches', () => {
        const empty = new StoreWriteBatch();
        expect(empty.encodedLen()).toBe(serializedLen([]));

        const write = batch([
            { key: new Uint8Array(), value: new Uint8Array() },
            { key: filled(2, 1), value: new Uint8Array() },
            { key: new Uint8Array(), value: filled(3, 2) },
            { key: filled(128, 3), value: filled(16_384, 4) },
        ]);
        expect(write.encodedLen()).toBe(serializedLen(write.entries()));
    });

    test('counts the physical prefixed key', () => {
        const store = client().store(new StoreKeyPrefix(filled(127, 0x50)));
        const write = batch([{ key: filled(1, 0x4b), value: filled(2, 0x56) }], store);

        expect(write.entries()[0].key).toHaveLength(128);
        expect(write.encodedLen()).toBe(serializedLen(write.entries()));
    });

    test('splits at the exact serialized byte boundary', () => {
        const original = batch([
            { key: filled(1, 1), value: filled(1, 2) },
            { key: filled(127, 3), value: filled(128, 4) },
            { key: filled(2, 5), value: filled(3, 6) },
        ]);
        const originalEntries = [...original.entries()];
        const boundary = serializedLen(originalEntries.slice(0, 2));
        const chunks = original.split({ maxEncodedBytes: boundary });

        expect(chunks.map((chunk) => chunk.length)).toEqual([2, 1]);
        expect(chunks[0].encodedLen()).toBe(boundary);
        expect(chunks.every((chunk) => serializedLen(chunk.entries()) <= boundary))
            .toBe(true);
        expect(chunks.flatMap((chunk) => [...chunk.entries()])).toEqual(originalEntries);
        expect(original.entries()).toEqual(originalEntries);
        for (let i = 0; i < originalEntries.length; i++) {
            const splitEntry = chunks.flatMap((chunk) => [...chunk.entries()])[i];
            expect(splitEntry).not.toBe(originalEntries[i]);
            expect(splitEntry.key).toBe(originalEntries[i].key);
            expect(splitEntry.value).toBe(originalEntries[i].value);
        }
    });

    test('honors the entry boundary without changing the original', () => {
        const original = batch([
            { key: filled(1, 1), value: filled(1, 1) },
            { key: filled(2, 2), value: filled(2, 2) },
            { key: filled(3, 3), value: filled(3, 3) },
        ]);

        const chunks = original.split({ maxEntries: 1 });

        expect(chunks.map((chunk) => chunk.length)).toEqual([1, 1, 1]);
        expect(original.length).toBe(3);
    });

    test('rejects an entry that cannot fit alone', () => {
        const original = batch([{ key: filled(2, 1), value: filled(3, 2) }]);
        const single = serializedLen(original.entries());

        expect(() => original.validate({ maxEncodedBytes: single })).not.toThrow();
        expect(() => original.validate({ maxEncodedBytes: single - 1 }))
            .toThrow(`Put encoded size ${single} exceeds ${single - 1}`);
        expect(() => original.split({ maxEncodedBytes: single - 1 }))
            .toThrow(`Put entry 0 encoded size ${single} exceeds ${single - 1}`);
    });
});

test('validates empty batches, value limits, and option domains', () => {
    const empty = new StoreWriteBatch();
    expect(empty.split()).toEqual([]);
    expect(() => empty.validate()).toThrow('Put requires between 1');

    const write = batch([{ key: filled(1, 1), value: filled(2, 2) }]);
    expect(() => write.validate({ maxValueLen: 1 })).toThrow('value length 2 exceeds 1');
    expect(() => write.validate({ maxEntries: 0 })).toThrow('maxEntries must be a positive safe integer');
    expect(() => write.split({ maxEncodedBytes: 0 })).toThrow('maxEncodedBytes must be a positive safe integer');
    expect(() => write.split({ maxValueLen: -1 })).toThrow('maxValueLen must be a nonnegative safe integer');
    expect(() => write.split({ maxEntries: Number.MAX_SAFE_INTEGER + 1 }))
        .toThrow('maxEntries must be a positive safe integer');
});

test('validation uses live mutable entry buffers', () => {
    const write = batch([{ key: filled(1, 1), value: filled(1, 2) }]);
    const firstLength = write.encodedLen();
    write.entries()[0].value = filled(128, 3);

    expect(write.encodedLen()).not.toBe(firstLength);
    expect(write.encodedLen()).toBe(serializedLen(write.entries()));
    expect(() => write.validate({ maxValueLen: 127 })).toThrow('value length 128 exceeds 127');
});

test('set, setMany, and putPrepared validate before invoking the transport', async () => {
    const sdk = client({
        token: '',
        putLimits: { maxEntries: 1, maxEncodedBytes: 64, maxValueLen: 1 },
    });
    const store = sdk.store();
    const put = jest.spyOn(sdk.ingest, 'put');

    await expect(store.set(filled(1, 1), filled(2, 2))).rejects.toThrow('value length 2 exceeds 1');
    await expect(store.setMany([
        { key: filled(1, 1), value: filled(1, 1) },
        { key: filled(1, 2), value: filled(1, 2) },
    ])).rejects.toThrow('between 1 and 1 entries');
    await expect(store.setMany([])).rejects.toThrow('between 1 and 1 entries');

    const prepared = batch([{ key: filled(1, 1), value: filled(2, 2) }], store);
    await expect(store.putPrepared(prepared)).rejects.toThrow('value length 2 exceeds 1');
    expect(put).not.toHaveBeenCalled();
});

test('rejects an oversized raw key before invoking the transport', async () => {
    const sdk = client({ token: '' });
    const put = jest.spyOn(sdk.ingest, 'put');

    await expect(sdk.store().set(filled(255, 1), new Uint8Array()))
        .rejects.toThrow('Put entry 0 key length 255 exceeds 254');
    expect(put).not.toHaveBeenCalled();
});

test.each([undefined, false, true])('applies protobuf byte limits when binary is %s', async (useBinaryFormat) => {
    const key = filled(1, 1);
    const value = filled(1, 2);
    const entries = [{ key, value }];
    const binaryBytes = serializedLen(entries);

    const sdk = client({
        token: '',
        useBinaryFormat,
        putLimits: { maxEncodedBytes: binaryBytes },
    });
    const binaryPut = jest.spyOn(sdk.ingest, 'put')
        .mockResolvedValue(create(PutResponseSchema, { sequenceNumber: 9n }));
    await expect(sdk.store().set(key, value)).resolves.toBe(9n);
    expect(binaryPut).toHaveBeenCalledTimes(1);

    const tooSmall = client({ token: '', useBinaryFormat, putLimits: { maxEncodedBytes: binaryBytes - 1 } });
    const rejectedPut = jest.spyOn(tooSmall.ingest, 'put');
    await expect(tooSmall.store().set(key, value))
        .rejects.toThrow(`Put encoded size ${binaryBytes} exceeds ${binaryBytes - 1}`);
    expect(rejectedPut).not.toHaveBeenCalled();
});

test('validates the prefixed request at its exact serialized-byte budget', async () => {
    const prefix = new StoreKeyPrefix(filled(2, 0x50));
    const key = filled(1, 0x4b);
    const value = filled(2, 0x56);
    const physical = [{ key: prefix.encodeKey(key), value }];
    const exact = serializedLen(physical);

    const accepted = client({ token: '', putLimits: { maxEncodedBytes: exact } });
    const acceptedPut = jest.spyOn(accepted.ingest, 'put')
        .mockResolvedValue(create(PutResponseSchema, { sequenceNumber: 11n }));
    await expect(accepted.store(prefix).set(key, value)).resolves.toBe(11n);
    expect(acceptedPut).toHaveBeenCalledTimes(1);

    const rejected = client({ token: '', putLimits: { maxEncodedBytes: exact - 1 } });
    const rejectedPut = jest.spyOn(rejected.ingest, 'put');
    await expect(rejected.store(prefix).set(key, value))
        .rejects.toThrow(`Put encoded size ${exact} exceeds ${exact - 1}`);
    expect(rejectedPut).not.toHaveBeenCalled();
});

test.each([undefined, false, true])('Put is protobuf while Query follows binary option %s', async (useBinaryFormat) => {
    const sent: Array<{ path: string; contentType: string | null; body: Uint8Array }> = [];
    const fetch = jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
        const path = new URL(String(input)).pathname;
        sent.push({ path, contentType: new Headers(init?.headers).get('content-type'), body: init?.body as Uint8Array });
        if (path.endsWith('/Put')) {
            return new Response(toBinary(PutResponseSchema, create(PutResponseSchema, { sequenceNumber: 7n })), {
                headers: { 'content-type': 'application/proto' },
            });
        }
        const response = create(GetResponseSchema, { value: filled(3, 2) });
        return new Response(useBinaryFormat
            ? toBinary(GetResponseSchema, response)
            : toJsonString(GetResponseSchema, response), {
            headers: { 'content-type': useBinaryFormat ? 'application/proto' : 'application/json' },
        });
    });

    try {
        const sdk = client(useBinaryFormat === undefined ? { token: '' } : { token: '', useBinaryFormat });
        const store = sdk.store();
        const key = filled(2, 1);
        const value = filled(3, 2);
        const entries = [{ key, value }];

        await expect(store.set(key, value)).resolves.toBe(7n);
        await expect(store.get(key)).resolves.toEqual({ value });
        expect(store.putOptions).toEqual({
            maxEntries: 2_000_000,
            maxEncodedBytes: 256 * 1024 * 1024,
            maxValueLen: 32 * 1024 * 1024,
        });
        expect(sent).toHaveLength(2);
        expect(sent[0].contentType).toBe('application/proto');
        expect(sent[0].body).toEqual(toBinary(PutRequestSchema, request(entries)));
        expect(batch(entries, store).encodedLen()).toBe(sent[0].body.byteLength);
        expect(sent[1].contentType).toBe(useBinaryFormat ? 'application/proto' : 'application/json');
        const get = create(GetRequestSchema, { key });
        expect(sent[1].body).toEqual(useBinaryFormat
            ? toBinary(GetRequestSchema, get)
            : new TextEncoder().encode(toJsonString(GetRequestSchema, get)));
    } finally {
        fetch.mockRestore();
    }
});

test('ingest and query share authentication, retries, and cookies in both directions', async () => {
    const seen: Array<{ method: string; cookie: string | null; authorization: string | null }> = [];
    let putAttempts = 0;
    let getAttempts = 0;
    const fetch = jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
        const url = String(input);
        const method = new URL(url).pathname.split('/').at(-1)!;
        const headers = new Headers(init?.headers);
        seen.push({ method, cookie: headers.get('cookie'), authorization: headers.get('authorization') });
        let response: Response;
        if (method === 'Put' && ++putAttempts === 1) {
            response = new Response(JSON.stringify({ code: 'unavailable', message: 'retry Put' }), {
                status: 503,
                headers: { 'content-type': 'application/json', 'set-cookie': 'fromPut=one; Path=/' },
            });
        } else if (method === 'Get' && ++getAttempts === 1) {
            response = new Response(JSON.stringify({ code: 'unavailable', message: 'retry Get' }), {
                status: 503,
                headers: { 'content-type': 'application/json', 'set-cookie': 'fromGet=two; Path=/' },
            });
        } else if (method === 'Put') {
            response = new Response(toBinary(PutResponseSchema, create(PutResponseSchema, { sequenceNumber: 7n })), {
                headers: { 'content-type': 'application/proto' },
            });
        } else {
            response = new Response(toJsonString(GetResponseSchema, create(GetResponseSchema, { value: filled(1, 2) })), {
                headers: { 'content-type': 'application/json' },
            });
        }
        Object.defineProperty(response, 'url', { value: url });
        return response;
    });

    try {
        const sdk = client({
            token: 'shared-token',
            retry: { maxAttempts: 2, initialBackoffMs: 0, maxBackoffMs: 0 },
        });
        const key = filled(1, 1);
        await expect(sdk.store().set(key, filled(1, 2))).resolves.toBe(7n);
        await expect(sdk.store().get(key)).resolves.toEqual({ value: filled(1, 2) });
        await expect(sdk.store().set(key, filled(1, 2))).resolves.toBe(7n);
        await expect(sdk.query.get(create(GetRequestSchema, { key }), {
            headers: { Authorization: 'Bearer caller-token' },
        })).resolves.toMatchObject({ value: filled(1, 2) });

        expect(seen.map(({ method }) => method)).toEqual(['Put', 'Put', 'Get', 'Get', 'Put', 'Get']);
        expect(seen.map(({ cookie }) => cookie)).toEqual([
            null,
            'fromPut=one',
            'fromPut=one',
            'fromPut=one; fromGet=two',
            'fromPut=one; fromGet=two',
            'fromPut=one; fromGet=two',
        ]);
        expect(seen.map(({ authorization }) => authorization)).toEqual([
            ...Array(5).fill('Bearer shared-token'),
            'Bearer caller-token',
        ]);
    } finally {
        fetch.mockRestore();
    }
});
