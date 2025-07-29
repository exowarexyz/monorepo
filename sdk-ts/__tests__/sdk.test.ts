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
            const key = new TextEncoder().encode('test-key');
            const value = Buffer.from('test-value');

            await store.set(key, value);
            const result = await store.get(key);

            expect(result).not.toBeNull();
            expect(Buffer.from(result!.value)).toEqual(value);
        });

        it('should return null for a non-existent key', async () => {
            const store = client.store();
            const result = await store.get(new TextEncoder().encode('non-existent-key'));
            expect(result).toBeNull();
        });

        it('should query for key-value pairs', async () => {
            const store = client.store();
            const encoder = new TextEncoder();
            const prefix = 'query-test-';
            const pairs = [
                { key: encoder.encode(`${prefix}a`), value: Buffer.from('a') },
                { key: encoder.encode(`${prefix}b`), value: Buffer.from('b') },
                { key: encoder.encode(`${prefix}c`), value: Buffer.from('c') },
            ];

            for (const pair of pairs) {
                await store.set(pair.key, pair.value);
            }

            const result = await store.query(encoder.encode(`${prefix}a`), encoder.encode(`${prefix}z`));
            expect(result.results.length).toBe(3);
            expect(result.results.map(r => Buffer.from(r.value))).toEqual(pairs.map(p => p.value));
            expect(result.results.map(r => r.key).sort()).toEqual(pairs.map(p => p.key).sort());
        });

        describe('limits', () => {
            it('should handle key at size limit', async () => {
                const store = client.store();
                const key = new TextEncoder().encode('a'.repeat(512));
                const value = Buffer.from('test-value');

                await store.set(key, value);
                const result = await store.get(key);

                expect(result).not.toBeNull();
                expect(Buffer.from(result!.value)).toEqual(value);
            });

            it('should reject key over size limit', async () => {
                const store = client.store();
                const key = new TextEncoder().encode('a'.repeat(513));
                const value = Buffer.from('test-value');

                await expect(store.set(key, value)).rejects.toThrow('HTTP error: 413 Payload Too Large');
            });

            it('should handle value at size limit', async () => {
                const store = client.store();
                const key = new TextEncoder().encode('value_at_limit');
                const value = Buffer.alloc(20 * 1024 * 1024);

                await store.set(key, value);
                const result = await store.get(key);

                expect(result).not.toBeNull();
                expect(result!.value).toEqual(value);
            }, 60000);

            it('should reject value over size limit', async () => {
                const store = client.store();
                const key = new TextEncoder().encode('value_over_limit');
                const value = Buffer.alloc(20 * 1024 * 1024 + 1);

                await expect(store.set(key, value)).rejects.toThrow('HTTP error: 413 Payload Too Large');
            }, 60000);
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

        describe('limits', () => {
            it('should handle stream name at size limit', async () => {
                const stream = client.stream();
                const streamName = 'a'.repeat(512);
                const message = Buffer.from('hello stream');
                const subscription = await stream.subscribe(streamName);
                const received = new Promise<Data>(resolve => {
                    subscription.onMessage(data => {
                        resolve(data);
                        subscription.close();
                    });
                });
                await new Promise(resolve => setTimeout(resolve, 100));
                await stream.publish(streamName, message);
                const receivedMessage = await received;
                expect(receivedMessage.toString()).toEqual(message.toString());
            });

            it('should reject stream name over size limit for publish', async () => {
                const stream = client.stream();
                const streamName = 'a'.repeat(513);
                const message = Buffer.from('hello stream');
                await expect(stream.publish(streamName, message)).rejects.toThrow('HTTP error: 413 Payload Too Large');
            });

            it('should reject stream name over size limit for subscribe', async () => {
                const stream = client.stream();
                const streamName = 'a'.repeat(513);
                await expect(stream.subscribe(streamName)).rejects.toThrow('WebSocket connection failed');
            });

            it('should handle stream message at size limit', async () => {
                const stream = client.stream();
                const streamName = 'stream-value-at-limit';
                const message = Buffer.alloc(20 * 1024 * 1024);
                const subscription = await stream.subscribe(streamName);
                const received = new Promise<Data>(resolve => {
                    subscription.onMessage(data => {
                        resolve(data);
                        subscription.close();
                    });
                });
                await new Promise(resolve => setTimeout(resolve, 100));
                await stream.publish(streamName, message);
                const receivedMessage = await received;
                expect(receivedMessage).toEqual(message);
            }, 60000);

            it('should reject stream message over size limit', async () => {
                const stream = client.stream();
                const streamName = 'stream-value-over-limit';
                const message = Buffer.alloc(20 * 1024 * 1024 + 1);
                await expect(stream.publish(streamName, message)).rejects.toThrow('HTTP error: 413 Payload Too Large');
            }, 60000);
        });
    });
});