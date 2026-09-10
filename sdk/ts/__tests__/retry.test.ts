import { Code, ConnectError } from '@connectrpc/connect';
import { Client } from '../src/client';

const methods = [
    { name: 'Put', call: (client: Client) => client.ingest.put({}), attempts: 1 },
    { name: 'Prune', call: (client: Client) => client.prune.prune({}), attempts: 1 },
    { name: 'SetRetention', call: (client: Client) => client.retention.setRetention({}), attempts: 1 },
    { name: 'query Get', call: (client: Client) => client.query.get({}), attempts: 3 },
    { name: 'stream Get', call: (client: Client) => client.stream.get({}), attempts: 3 },
];

describe.each([
    { code: 'aborted', connectCode: Code.Aborted, status: 409 },
    { code: 'unavailable', connectCode: Code.Unavailable, status: 503 },
    { code: 'resource_exhausted', connectCode: Code.ResourceExhausted, status: 429 },
])('retryable $code failures', ({ code, connectCode, status }) => {
    test.each(methods)('$name makes $attempts attempts', async ({ call, attempts }) => {
        const fetch = jest.spyOn(globalThis, 'fetch').mockImplementation(async () =>
            new Response(JSON.stringify({ code, message: 'retryable failure' }), {
                status,
                headers: { 'content-type': 'application/json' },
            }));
        try {
            const client = new Client('http://retry.test', {
                token: '',
                retry: { maxAttempts: 3, initialBackoffMs: 0, maxBackoffMs: 0 },
            });
            const result = call(client);
            await expect(result).rejects.toBeInstanceOf(ConnectError);
            await expect(result).rejects.toMatchObject({ code: connectCode });
            expect(fetch).toHaveBeenCalledTimes(attempts);
        } finally {
            fetch.mockRestore();
        }
    });
});
