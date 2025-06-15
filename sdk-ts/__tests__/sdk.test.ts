import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { Data } from 'ws';
import { Client } from '../src/client';

const tempDir = path.join(os.tmpdir(), 'exoware-ts-sdk-tests');
const configFile = path.join(tempDir, 'config.json');

describe('Exoware TS SDK', () => {
    let client: Client;

    beforeAll(() => {
        const config = JSON.parse(fs.readFileSync(configFile, 'utf-8'));
        const baseUrl = `http://127.0.0.1:${config.port}`;
        client = new Client(baseUrl, config.token);
    });

    // Store tests
    describe('StoreClient', () => {
        it('should set and get a value', async () => {
            const store = client.store();
            const key = 'test-key';
            const value = Buffer.from('test-value');

            await store.set(key, value);
            const result = await store.get(key);

            expect(result).not.toBeNull();
            expect(Buffer.from(result!.value)).toEqual(value);
        });

        it('should return null for a non-existent key', async () => {
            const store = client.store();
            const result = await store.get('non-existent-key');
            expect(result).toBeNull();
        });

        it('should query for key-value pairs', async () => {
            const store = client.store();
            const prefix = 'query-test-';
            const pairs = [
                { key: `${prefix}a`, value: Buffer.from('a') },
                { key: `${prefix}b`, value: Buffer.from('b') },
                { key: `${prefix}c`, value: Buffer.from('c') },
            ];

            for (const pair of pairs) {
                await store.set(pair.key, pair.value);
            }

            const result = await store.query(`${prefix}a`, `${prefix}z`);
            expect(result.results.length).toBe(3);
            expect(result.results.map(r => Buffer.from(r.value))).toEqual(pairs.map(p => p.value));
            expect(result.results.map(r => r.key).sort()).toEqual(pairs.map(p => p.key).sort());
        });
    });

    // Stream tests
    describe('StreamClient', () => {
        it('should publish and subscribe to a stream', async () => {
            const stream = client.stream();
            const streamName = 'test-stream';
            const message = Buffer.from('hello stream');

            const subscription = await stream.subscribe(streamName);

            const received = new Promise<Data>(resolve => {
                subscription.onMessage(data => {
                    resolve(data);
                    subscription.close();
                });
            });

            // Need a small delay to ensure subscription is active before publishing
            await new Promise(resolve => setTimeout(resolve, 100));

            await stream.publish(streamName, message);

            const receivedMessage = await received;
            expect(receivedMessage.toString()).toEqual(message.toString());
        });
    });
});