import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { Client } from '../src/client';

/** Matches `exoware_common::keys::MAX_KEY_LEN`. */
const MAX_KEY_LEN = 254;
/** Matches `exoware_common::keys::MAX_VALUE_SIZE` (`u16::MAX`). */
const MAX_VALUE_SIZE = 65535;

const tempDir = path.join(os.tmpdir(), 'exoware-ts-sdk-tests');
const configFile = path.join(tempDir, 'config.json');

describe('Exoware TS SDK', () => {
    let client: Client;

    beforeAll(() => {
        const config = JSON.parse(fs.readFileSync(configFile, 'utf-8'));
        const baseUrl = `http://127.0.0.1:${config.port}`;
        client = new Client(baseUrl);
    });

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
                const key = new TextEncoder().encode('a'.repeat(MAX_KEY_LEN));
                const value = Buffer.from('test-value');

                await store.set(key, value);
                const result = await store.get(key);

                expect(result).not.toBeNull();
                expect(Buffer.from(result!.value)).toEqual(value);
            });

            it('should reject key over size limit', async () => {
                const store = client.store();
                const key = new TextEncoder().encode('a'.repeat(MAX_KEY_LEN + 1));
                const value = Buffer.from('test-value');

                await expect(store.set(key, value)).rejects.toMatchObject({
                    name: 'HttpError',
                    status: 400,
                });
            });

            it('should handle value at size limit', async () => {
                const store = client.store();
                const key = new TextEncoder().encode('value_at_limit');
                const value = Buffer.alloc(MAX_VALUE_SIZE);

                await store.set(key, value);
                const result = await store.get(key);

                expect(result).not.toBeNull();
                expect(result!.value).toEqual(value);
            });

            it('should reject value over size limit', async () => {
                const store = client.store();
                const key = new TextEncoder().encode('value_over_limit');
                const value = Buffer.alloc(MAX_VALUE_SIZE + 1);

                await expect(store.set(key, value)).rejects.toMatchObject({
                    name: 'HttpError',
                    status: 400,
                });
            });
        });
    });
});
