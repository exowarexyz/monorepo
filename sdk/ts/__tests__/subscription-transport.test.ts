import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Code } from '@connectrpc/connect';
import { Client } from '../src/client';

function envelope(value: unknown, end = false): Buffer {
    const json = Buffer.from(JSON.stringify(value));
    const result = Buffer.alloc(5 + json.length);
    result[0] = end ? 2 : 0;
    result.writeUInt32BE(json.length, 1);
    json.copy(result, 5);
    return result;
}

function checkpoint(sequenceNumber: number): Buffer {
    return envelope({ sequenceNumber: String(sequenceNumber) });
}

function batch(sequenceNumber: number): Buffer {
    return envelope({ sequenceNumber: String(sequenceNumber), entries: [{ key: 'AQ==', value: 'Ag==' }] });
}

async function withServer(
    handle: (request: IncomingMessage, response: ServerResponse, body: Record<string, unknown>) => void,
    run: (baseUrl: string) => Promise<void>,
): Promise<void> {
    const server = createServer((request, response) => {
        void (async () => {
            const chunks: Buffer[] = [];
            for await (const chunk of request) chunks.push(Buffer.from(chunk));
            const body = JSON.parse(Buffer.concat(chunks).subarray(5).toString()) as Record<string, unknown>;
            handle(request, response, body);
        })().catch((error: Error) => response.destroy(error));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
        await run(`http://127.0.0.1:${(server.address() as AddressInfo).port}`);
    } finally {
        server.closeAllConnections();
        await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
}

test('Connect duration errors resume after the delivered batch and iterator return aborts HTTP', async () => {
    const requests: Record<string, unknown>[] = [];
    let closed!: () => void;
    const transportClosed = new Promise<void>((resolve) => { closed = resolve; });
    await withServer((request, response, body) => {
        requests.push(body);
        expect(request.headers['connect-timeout-ms']).toBeUndefined();
        response.writeHead(200, { 'content-type': 'application/connect+json' });
        if (requests.length === 1) {
            response.write(checkpoint(0));
            response.write(batch(1));
            setTimeout(() => response.end(envelope({
                error: { code: 'unavailable', message: 'maximum subscription duration reached' },
            }, true)), 30);
        } else {
            response.once('close', closed);
            response.write(checkpoint(1));
            response.write(batch(2));
        }
    }, async (baseUrl) => {
        const client = new Client(baseUrl, {
            token: '',
            subscriptionRetry: { budgetMs: 1_000, initialBackoffMs: 5, maxBackoffMs: 5 },
        });
        const subscription = client.store().subscribe({ selectors: [{ prefix: new Uint8Array([1]) }] }, { timeoutMs: 1 });
        expect((await subscription.next()).value?.sequenceNumber).toBe(1n);
        expect((await subscription.next()).value?.sequenceNumber).toBe(2n);
        expect(requests).toHaveLength(2);
        expect(requests[0].sinceSequenceNumber).toBeUndefined();
        expect(requests[1].sinceSequenceNumber).toBe('2');
        expect(requests[1].selectors).toEqual(requests[0].selectors);
        await subscription.return?.();
        await transportClosed;
    });
}, 5_000);

test('HTTP failures before a live checkpoint bypass generic request retries', async () => {
    let requests = 0;
    await withServer((_request, response) => {
        requests++;
        response.writeHead(503, { 'content-type': 'application/json' });
        response.end(JSON.stringify({ code: 'unavailable', message: 'temporarily unavailable' }));
    }, async (baseUrl) => {
        const client = new Client(baseUrl, {
            token: '',
            retry: { maxAttempts: 50, initialBackoffMs: 1, maxBackoffMs: 1 },
        });
        await expect(client.store().subscribe({ selectors: [{}] }).next()).rejects.toMatchObject({
            connectCode: Code.Unavailable,
        });
        expect(requests).toBe(1);
    });
}, 5_000);

test('an explicit cursor retries HTTP open failures under the subscription policy', async () => {
    const requests: Record<string, unknown>[] = [];
    await withServer((_request, response, body) => {
        requests.push(body);
        if (requests.length === 1) {
            response.writeHead(503, { 'content-type': 'application/json' });
            response.end(JSON.stringify({ code: 'unavailable', message: 'temporarily unavailable' }));
        } else {
            response.writeHead(200, { 'content-type': 'application/connect+json' });
            response.write(checkpoint(6));
            response.write(batch(7));
        }
    }, async (baseUrl) => {
        const client = new Client(baseUrl, {
            token: '',
            retry: { maxAttempts: 1, initialBackoffMs: 1, maxBackoffMs: 1 },
            subscriptionRetry: { budgetMs: 1_000, initialBackoffMs: 5, maxBackoffMs: 5 },
        });
        const subscription = client.store().subscribe({ selectors: [{}], sinceSequenceNumber: 7n });
        expect((await subscription.next()).value?.sequenceNumber).toBe(7n);
        expect(requests.map((request) => request.sinceSequenceNumber)).toEqual(['7', '7']);
        await subscription.return?.();
    });
}, 5_000);

test('a real HTTP read stalled after headers is aborted when its outage budget expires', async () => {
    let closed!: () => void;
    const transportClosed = new Promise<void>((resolve) => { closed = resolve; });
    await withServer((_request, response) => {
        response.once('close', closed);
        response.writeHead(200, { 'content-type': 'application/connect+json' });
        response.flushHeaders();
    }, async (baseUrl) => {
        const client = new Client(baseUrl, { token: '', subscriptionRetry: { budgetMs: 50 } });
        await expect(client.store().subscribe({ selectors: [{}] }).next()).rejects.toMatchObject({
            connectCode: Code.DeadlineExceeded,
        });
        await transportClosed;
    });
}, 5_000);
