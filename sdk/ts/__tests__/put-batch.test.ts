import { create, toBinary, toJsonString } from '@bufbuild/protobuf';

jest.mock('../src/credential', () => ({
    ...jest.requireActual('../src/credential'),
    environmentApiKey: () => undefined,
}));

import { Client } from '../src/client';
import { EntrySchema } from '../src/gen/ts/common/v1/kv_pb';
import { PutRequestSchema, PutResponseSchema } from '../src/gen/ts/log/v1/ingest_pb';
import {
    StoreKeyPrefix,
    StoreWriteBatch,
    type StoreBatchEntry,
} from '../src/store';
import type { PutEncoding } from '../src/limits';

const textEncoder = new TextEncoder();

function client(options: ConstructorParameters<typeof Client>[1] = { token: '' }): Client {
    return new Client('http://put-batch.test', options);
}

function request(entries: readonly StoreBatchEntry[]) {
    return create(PutRequestSchema, {
        kvs: entries.map((entry) => create(EntrySchema, entry)),
    });
}

function serializedLen(entries: readonly StoreBatchEntry[], encoding: PutEncoding): number {
    const message = request(entries);
    return encoding === 'binary'
        ? toBinary(PutRequestSchema, message).byteLength
        : textEncoder.encode(toJsonString(PutRequestSchema, message)).byteLength;
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

describe.each<PutEncoding>(['binary', 'json'])('%s Put accounting', (encoding) => {
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

        expect(write.encodedLen(encoding)).toBe(serializedLen(write.entries(), encoding));
    });

    test('matches the real serializer for empty and mixed batches', () => {
        const empty = new StoreWriteBatch();
        expect(empty.encodedLen(encoding)).toBe(serializedLen([], encoding));

        const write = batch([
            { key: new Uint8Array(), value: new Uint8Array() },
            { key: filled(2, 1), value: new Uint8Array() },
            { key: new Uint8Array(), value: filled(3, 2) },
            { key: filled(128, 3), value: filled(16_384, 4) },
        ]);
        expect(write.encodedLen(encoding)).toBe(serializedLen(write.entries(), encoding));
    });

    test('counts the physical prefixed key', () => {
        const store = client().store(new StoreKeyPrefix(filled(127, 0x50)));
        const write = batch([{ key: filled(1, 0x4b), value: filled(2, 0x56) }], store);

        expect(write.entries()[0].key).toHaveLength(128);
        expect(write.encodedLen(encoding)).toBe(serializedLen(write.entries(), encoding));
    });

    test('splits at the exact serialized byte boundary', () => {
        const original = batch([
            { key: filled(1, 1), value: filled(1, 2) },
            { key: filled(127, 3), value: filled(128, 4) },
            { key: filled(2, 5), value: filled(3, 6) },
        ]);
        const originalEntries = [...original.entries()];
        const boundary = serializedLen(originalEntries.slice(0, 2), encoding);
        const chunks = original.split({ encoding, maxEncodedBytes: boundary });

        expect(chunks.map((chunk) => chunk.length)).toEqual([2, 1]);
        expect(chunks[0].encodedLen(encoding)).toBe(boundary);
        expect(chunks.every((chunk) => serializedLen(chunk.entries(), encoding) <= boundary))
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

        const chunks = original.split({ encoding, maxEntries: 1 });

        expect(chunks.map((chunk) => chunk.length)).toEqual([1, 1, 1]);
        expect(original.length).toBe(3);
    });

    test('rejects an entry that cannot fit alone', () => {
        const original = batch([{ key: filled(2, 1), value: filled(3, 2) }]);
        const single = serializedLen(original.entries(), encoding);

        expect(() => original.validate({ encoding, maxEncodedBytes: single })).not.toThrow();
        expect(() => original.validate({ encoding, maxEncodedBytes: single - 1 }))
            .toThrow(`Put encoded size ${single} exceeds ${single - 1}`);
        expect(() => original.split({ encoding, maxEncodedBytes: single - 1 }))
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
    const firstLength = write.encodedLen('json');
    write.entries()[0].value = filled(128, 3);

    expect(write.encodedLen('json')).not.toBe(firstLength);
    expect(write.encodedLen('json')).toBe(serializedLen(write.entries(), 'json'));
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

test('applies encoded-byte limits to the selected transport codec', async () => {
    const key = filled(1, 1);
    const value = filled(1, 2);
    const entries = [{ key, value }];
    const binaryBytes = serializedLen(entries, 'binary');
    const jsonBytes = serializedLen(entries, 'json');
    expect(jsonBytes).toBeGreaterThan(binaryBytes);

    const jsonClient = client({ token: '', putLimits: { maxEncodedBytes: binaryBytes } });
    const jsonPut = jest.spyOn(jsonClient.ingest, 'put');
    await expect(jsonClient.store().set(key, value))
        .rejects.toThrow(`Put encoded size ${jsonBytes} exceeds ${binaryBytes}`);
    expect(jsonPut).not.toHaveBeenCalled();

    const binaryClient = client({
        token: '',
        useBinaryFormat: true,
        putLimits: { maxEncodedBytes: binaryBytes },
    });
    const binaryPut = jest.spyOn(binaryClient.ingest, 'put')
        .mockResolvedValue(create(PutResponseSchema, { sequenceNumber: 9n }));
    await expect(binaryClient.store().set(key, value)).resolves.toBe(9n);
    expect(binaryPut).toHaveBeenCalledTimes(1);
});

test('validates the prefixed request at its exact serialized-byte budget', async () => {
    const prefix = new StoreKeyPrefix(filled(2, 0x50));
    const key = filled(1, 0x4b);
    const value = filled(2, 0x56);
    const physical = [{ key: prefix.encodeKey(key), value }];
    const exact = serializedLen(physical, 'json');

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

test.each([
    [undefined, 'json' as const, 'application/json'],
    [true, 'binary' as const, 'application/proto'],
])('the transport and Put limits use the same codec when binary is %s', async (
    useBinaryFormat,
    encoding,
    contentType,
) => {
    let sentBody: Uint8Array | undefined;
    let sentContentType: string | null = null;
    const fetch = jest.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
        sentContentType = new Headers(init?.headers).get('content-type');
        sentBody = init?.body as Uint8Array;
        const response = create(PutResponseSchema, { sequenceNumber: 7n });
        const body = useBinaryFormat
            ? toBinary(PutResponseSchema, response)
            : toJsonString(PutResponseSchema, response);
        return new Response(body, { headers: { 'content-type': contentType } });
    });

    try {
        const sdk = client(useBinaryFormat === undefined
            ? { token: '' }
            : { token: '', useBinaryFormat });
        const store = sdk.store();
        const key = filled(2, 1);
        const value = filled(3, 2);
        const entries = [{ key, value }];

        await expect(store.set(key, value)).resolves.toBe(7n);
        expect(store.putOptions.encoding).toBe(encoding);
        expect(sentContentType).toBe(contentType);
        expect(sentBody).toEqual(
            encoding === 'binary'
                ? toBinary(PutRequestSchema, request(entries))
                : textEncoder.encode(toJsonString(PutRequestSchema, request(entries))),
        );
    } finally {
        fetch.mockRestore();
    }
});
