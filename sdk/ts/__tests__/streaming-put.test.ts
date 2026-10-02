import { create, fromBinary, fromJsonString, toBinary, toJsonString } from '@bufbuild/protobuf';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Client } from '../src/client';
import { PutRequestSchema, PutResponseSchema } from '../src/gen/ts/log/v1/ingest_pb';
import {
    MAX_PUT_CHUNK_BYTES,
    MAX_VALUE_LEN,
    PUT_CHUNK_TARGET_BYTES,
    putChunks,
    putEncodedLen,
    validatePut,
    type PutEncoding,
} from '../src/limits';

function envelope(payload: Uint8Array, flags = 0): Buffer {
    const header = Buffer.alloc(5);
    header[0] = flags;
    header.writeUInt32BE(payload.length, 1);
    return Buffer.concat([header, payload]);
}

function frames(body: Buffer): Buffer[] {
    const result: Buffer[] = [];
    let offset = 0;
    while (offset < body.length) {
        expect(body[offset]).toBe(0);
        const length = body.readUInt32BE(offset + 1);
        offset += 5;
        expect(length).toBeLessThanOrEqual(MAX_PUT_CHUNK_BYTES);
        result.push(body.subarray(offset, offset + length));
        offset += length;
    }
    expect(offset).toBe(body.length);
    return result;
}

async function withServer(
    handler: (req: IncomingMessage, res: ServerResponse) => Promise<void>,
    run: (baseUrl: string) => Promise<void>,
): Promise<void> {
    const failures: unknown[] = [];
    const server = createServer((req, res) => {
        handler(req, res).catch((error) => {
            failures.push(error);
            res.destroy();
        });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
        await run(`http://127.0.0.1:${(server.address() as AddressInfo).port}`);
        expect(failures).toEqual([]);
    } catch (error) {
        if (failures.length > 0) throw failures[0];
        throw error;
    } finally {
        server.closeAllConnections();
        await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
}

async function body(req: IncomingMessage): Promise<Buffer> {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    return Buffer.concat(chunks);
}

function respond(res: ServerResponse, encoding: PutEncoding): void {
    const response = create(PutResponseSchema, { sequenceNumber: 7n });
    const payload = encoding === 'binary'
        ? toBinary(PutResponseSchema, response)
        : Buffer.from(toJsonString(PutResponseSchema, response));
    res.setHeader('content-type', `application/connect+${encoding === 'binary' ? 'proto' : 'json'}`);
    res.end(Buffer.concat([envelope(payload), envelope(Buffer.from('{}'), 2)]));
}

function entries(valueLength: number, count: number) {
    return Array.from({ length: count }, (_, i) => ({
        key: new Uint8Array([i]),
        value: new Uint8Array(valueLength).fill(i + 1),
    }));
}

test.each<PutEncoding>(['binary', 'json'])('%s sends ordered chunk envelopes in one RPC', async (encoding) => {
    const rows = entries(400_000, 4);
    let requests = 0;
    await withServer(async (req, res) => {
        requests++;
        expect(req.httpVersion).toBe('1.1');
        expect(req.headers['content-type']).toBe(`application/connect+${encoding === 'binary' ? 'proto' : 'json'}`);
        expect(req.headers.authorization).toBe('Bearer client-token');
        const payloads = frames(await body(req));
        expect(payloads).toHaveLength(encoding === 'binary' ? 2 : 4);
        expect(payloads.every((payload) => payload.length <= PUT_CHUNK_TARGET_BYTES)).toBe(true);
        const decoded = payloads.map((payload) => encoding === 'binary'
            ? fromBinary(PutRequestSchema, payload)
            : fromJsonString(PutRequestSchema, payload.toString()));
        const received = decoded.flatMap((message) => message.kvs);
        expect(received).toHaveLength(rows.length);
        for (const [i, entry] of received.entries()) {
            expect(Buffer.from(entry.key).equals(rows[i].key)).toBe(true);
            expect(Buffer.from(entry.value).equals(rows[i].value)).toBe(true);
        }
        respond(res, encoding);
    }, async (url) => {
        const sdk = new Client(url, { token: 'client-token', useBinaryFormat: encoding === 'binary' });
        expect(sdk.store().putOptions.encoding).toBe(encoding);
        await expect(sdk.store().setMany(rows)).resolves.toBe(7n);
    });
    expect(requests).toBe(1);
});

test.each<PutEncoding>(['binary', 'json'])('%s allows a 32 MiB entry in its own message', (encoding) => {
    const rows = [...entries(2, 1), ...entries(MAX_VALUE_LEN, 1), ...entries(2, 1)];
    validatePut(rows, { encoding });
    const chunks = [...putChunks(rows, encoding)];
    expect(chunks.map((chunk) => chunk.length)).toEqual([1, 1, 1]);
    expect(putEncodedLen(chunks[1], encoding)).toBeGreaterThan(PUT_CHUNK_TARGET_BYTES);
    expect(putEncodedLen(chunks[1], encoding)).toBeLessThanOrEqual(MAX_PUT_CHUNK_BYTES);
});

test('hard cap remains enforced when aggregate and value limits are raised', () => {
    const rows = entries(MAX_PUT_CHUNK_BYTES, 1);
    expect(() => validatePut(rows, {
        encoding: 'binary', maxValueLen: MAX_PUT_CHUNK_BYTES, maxEncodedBytes: 2 * MAX_PUT_CHUNK_BYTES,
    })).toThrow(`exceeds ${MAX_PUT_CHUNK_BYTES}`);
});

test('a retryable Put failure sends the iterator once', async () => {
    let requests = 0;
    await withServer(async (req, res) => {
        requests++;
        expect(frames(await body(req))).toHaveLength(2);
        res.setHeader('content-type', 'application/connect+proto');
        res.end(envelope(Buffer.from('{"error":{"code":"unavailable","message":"ambiguous write"}}'), 2));
    }, async (url) => {
        const sdk = new Client(url, {
            token: '', useBinaryFormat: true,
            retry: { maxAttempts: 3, initialBackoffMs: 0, maxBackoffMs: 0 },
        });
        await expect(sdk.store().setMany(entries(400_000, 4))).rejects.toThrow('ambiguous write');
    });
    expect(requests).toBe(1);
});

test('cookies cross ingestion and fetch services and preserve caller overrides', async () => {
    let calls = 0;
    await withServer(async (req, res) => {
        calls++;
        await body(req);
        if (req.url?.endsWith('/Put')) {
            if (calls === 1) {
                expect(req.headers.cookie).toBeUndefined();
                res.setHeader('set-cookie', ['affinity=node; Path=/', 'other=value; Path=/']);
            } else {
                expect(req.headers.cookie).toContain('affinity=caller');
                expect(req.headers.cookie).not.toContain('affinity=fetch');
                expect(req.headers.cookie).toContain('other=value');
                expect(req.headers.authorization).toBe('Bearer caller-token');
            }
            respond(res, 'json');
        } else {
            expect(req.headers.cookie).toContain('affinity=node');
            expect(req.headers.cookie).toContain('other=value');
            res.setHeader('set-cookie', 'affinity=fetch; Path=/');
            res.setHeader('content-type', 'application/json');
            res.end('{}');
        }
    }, async (url) => {
        const sdk = new Client(url, { token: 'client-token' });
        await sdk.store().set(new Uint8Array([1]), new Uint8Array([2]));
        await sdk.query.get({ key: new Uint8Array([1]) });
        await sdk.ingest.put((async function* () {
            yield { kvs: entries(1, 1) };
        })(), { headers: { cookie: 'affinity=caller', authorization: 'Bearer caller-token' } });
    });
    expect(calls).toBe(3);
});


test('a 32 MiB value travels alone in an actual stream', async () => {
    const rows = [...entries(1, 1), ...entries(MAX_VALUE_LEN, 1), ...entries(1, 1)];
    await withServer(async (req, res) => {
        const payloads = frames(await body(req));
        expect(payloads).toHaveLength(3);
        expect(payloads[1].length).toBeGreaterThan(PUT_CHUNK_TARGET_BYTES);
        const lengths = payloads.map((payload) =>
            fromBinary(PutRequestSchema, payload).kvs.map((entry) => entry.value.length));
        expect(lengths).toEqual([[1], [MAX_VALUE_LEN], [1]]);
        respond(res, 'binary');
    }, async (url) => {
        await expect(new Client(url, { token: '', useBinaryFormat: true }).store().setMany(rows))
            .resolves.toBe(7n);
    });
});

test('chunking honors an exact binary target and hard limit', () => {
    const target = entries(PUT_CHUNK_TARGET_BYTES - 11, 1);
    expect(putEncodedLen(target, 'binary')).toBe(PUT_CHUNK_TARGET_BYTES);
    expect([...putChunks([...target, ...entries(1, 1)], 'binary')].map((chunk) => chunk.length))
        .toEqual([1, 1]);
    const hard = entries(MAX_PUT_CHUNK_BYTES - 13, 1);
    expect(putEncodedLen(hard, 'binary')).toBe(MAX_PUT_CHUNK_BYTES);
    validatePut(hard, { encoding: 'binary', maxValueLen: MAX_PUT_CHUNK_BYTES });
    expect([...putChunks(hard, 'binary')]).toHaveLength(1);
});

test('a rejected Put response still updates the shared cookie jar', async () => {
    await withServer(async (req, res) => {
        await body(req);
        if (req.url?.endsWith('/Put')) {
            res.setHeader('set-cookie', 'affinity=error-node; Path=/');
            res.setHeader('content-type', 'application/connect+json');
            res.end(envelope(Buffer.from('{"error":{"code":"unavailable","message":"failed write"}}'), 2));
        } else {
            expect(req.headers.cookie).toContain('affinity=error-node');
            res.setHeader('content-type', 'application/json');
            res.end('{}');
        }
    }, async (url) => {
        const sdk = new Client(url, { token: '' });
        await expect(sdk.store().setMany(entries(1, 1))).rejects.toThrow('failed write');
        await sdk.query.get({ key: new Uint8Array([1]) });
    });
});
