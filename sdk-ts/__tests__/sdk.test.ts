import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { create } from '@bufbuild/protobuf';
import { Client } from '../src/client';
import { TraversalMode } from '../src/store';
import {
    ReduceParamsSchema,
    RangeReducerSpecSchema,
    RangeReduceOp,
    KvExprSchema,
    KvFieldRefSchema,
    KvFieldRef_ValueFieldSchema,
    KvFieldKind,
} from '../src/index';

const MAX_KEY_LEN = 254;

const tempDir = path.join(os.tmpdir(), 'exoware-ts-sdk-tests');
const configFile = path.join(tempDir, 'config.json');

function encodeStoredRowInt64(value: bigint): Uint8Array {
    const buf = new ArrayBuffer(11);
    const view = new DataView(buf);
    view.setUint8(0, 0x01);
    view.setUint8(1, 0x01);
    view.setUint8(2, 0x00);
    view.setBigInt64(3, value, false);
    return new Uint8Array(buf);
}

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

        it('should setMany with multiple KVs', async () => {
            const store = client.store();
            const encoder = new TextEncoder();
            const prefix = 'setmany-test-';
            const kvs = [
                { key: encoder.encode(`${prefix}x`), value: Buffer.from('val-x') },
                { key: encoder.encode(`${prefix}y`), value: Buffer.from('val-y') },
                { key: encoder.encode(`${prefix}z`), value: Buffer.from('val-z') },
            ];

            const sn = await store.setMany(kvs);
            expect(sn).toBeGreaterThan(0n);

            for (const kv of kvs) {
                const result = await store.get(kv.key);
                expect(result).not.toBeNull();
                expect(Buffer.from(result!.value)).toEqual(kv.value);
            }
        });

        it('should getMany', async () => {
            const store = client.store();
            const encoder = new TextEncoder();
            const prefix = 'getmany-test-';
            const kvs = [
                { key: encoder.encode(`${prefix}a`), value: Buffer.from('ga') },
                { key: encoder.encode(`${prefix}b`), value: Buffer.from('gb') },
            ];

            await store.setMany(kvs);

            const missingKey = encoder.encode(`${prefix}missing`);
            const results = await store.getMany(
                [kvs[0].key, kvs[1].key, missingKey],
            );

            expect(results.length).toBe(3);
            const byKey = new Map(results.map(r => [
                new TextDecoder().decode(r.key),
                r.value ? Buffer.from(r.value) : undefined,
            ]));
            expect(byKey.get(`${prefix}a`)).toEqual(Buffer.from('ga'));
            expect(byKey.get(`${prefix}b`)).toEqual(Buffer.from('gb'));
            expect(byKey.get(`${prefix}missing`)).toBeUndefined();
        });

        it('should query with reverse mode', async () => {
            const store = client.store();
            const encoder = new TextEncoder();
            const prefix = 'reverse-test-';
            const pairs = [
                { key: encoder.encode(`${prefix}a`), value: Buffer.from('ra') },
                { key: encoder.encode(`${prefix}b`), value: Buffer.from('rb') },
                { key: encoder.encode(`${prefix}c`), value: Buffer.from('rc') },
            ];

            for (const pair of pairs) {
                await store.set(pair.key, pair.value);
            }

            const forward = await store.query(
                encoder.encode(`${prefix}a`),
                encoder.encode(`${prefix}z`),
                undefined,
                4096,
                TraversalMode.FORWARD,
            );
            const reverse = await store.query(
                encoder.encode(`${prefix}a`),
                encoder.encode(`${prefix}z`),
                undefined,
                4096,
                TraversalMode.REVERSE,
            );

            expect(forward.results.length).toBe(3);
            expect(reverse.results.length).toBe(3);
            expect(reverse.results.map(r => Buffer.from(r.value))).toEqual(
                [...forward.results].reverse().map(r => Buffer.from(r.value)),
            );
        });

        it('should reduce with COUNT_ALL', async () => {
            const store = client.store();
            const encoder = new TextEncoder();
            const prefix = 'reduce-count-';
            const kvs = [
                { key: encoder.encode(`${prefix}1`), value: Buffer.from('v1') },
                { key: encoder.encode(`${prefix}2`), value: Buffer.from('v2') },
                { key: encoder.encode(`${prefix}3`), value: Buffer.from('v3') },
            ];

            await store.setMany(kvs);

            const params = create(ReduceParamsSchema, {
                reducers: [
                    create(RangeReducerSpecSchema, {
                        op: RangeReduceOp.COUNT_ALL,
                    }),
                ],
            });

            const response = await store.reduce(
                encoder.encode(`${prefix}1`),
                encoder.encode(`${prefix}z`),
                params,
            );

            expect(response.results.length).toBe(1);
            const countValue = response.results[0].value;
            expect(countValue).toBeDefined();
            expect(countValue!.value.case).toBe('uint64Value');
            expect(countValue!.value.value).toBe(3n);
        });

        it('should reduce with SUM on a value field', async () => {
            const store = client.store();
            const encoder = new TextEncoder();
            const prefix = 'reduce-sum-';

            const kvs = [1, 2, 3].map((n) => ({
                key: encoder.encode(`${prefix}${n}`),
                value: encodeStoredRowInt64(BigInt(n * 10)),
            }));

            await store.setMany(kvs);

            const params = create(ReduceParamsSchema, {
                reducers: [
                    create(RangeReducerSpecSchema, {
                        op: RangeReduceOp.SUM_FIELD,
                        expr: create(KvExprSchema, {
                            expr: {
                                case: 'field',
                                value: create(KvFieldRefSchema, {
                                    field: {
                                        case: 'value',
                                        value: create(KvFieldRef_ValueFieldSchema, {
                                            index: 0,
                                            kind: KvFieldKind.INT64,
                                        }),
                                    },
                                }),
                            },
                        }),
                    }),
                ],
            });

            const response = await store.reduce(
                encoder.encode(`${prefix}1`),
                encoder.encode(`${prefix}z`),
                params,
            );

            expect(response.results.length).toBe(1);
            const sumValue = response.results[0].value;
            expect(sumValue).toBeDefined();
            expect(sumValue!.value.case).toBe('int64Value');
            expect(sumValue!.value.value).toBe(60n);
        });

        it('should track sequence numbers from put', async () => {
            const store = client.store();
            const encoder = new TextEncoder();

            const sn1 = await store.set(encoder.encode('sn-test-1'), Buffer.from('v1'));
            expect(sn1).toBeGreaterThan(0n);
            expect(store.sequenceNumber).toBe(sn1);

            const sn2 = await store.set(encoder.encode('sn-test-2'), Buffer.from('v2'));
            expect(sn2).toBeGreaterThan(sn1);
            expect(store.sequenceNumber).toBe(sn2);
        });

        describe('retry config', () => {
            it('should accept retry config in client constructor', () => {
                const c = new Client('http://localhost:1234', {
                    retry: { maxAttempts: 5, initialBackoffMs: 200, maxBackoffMs: 5000 },
                });
                expect(c.retryConfig.maxAttempts).toBe(5);
                expect(c.retryConfig.initialBackoffMs).toBe(200);
                expect(c.retryConfig.maxBackoffMs).toBe(5000);
            });

            it('should use default retry config when not specified', () => {
                const c = new Client('http://localhost:1234');
                expect(c.retryConfig.maxAttempts).toBe(3);
                expect(c.retryConfig.initialBackoffMs).toBe(100);
                expect(c.retryConfig.maxBackoffMs).toBe(2000);
            });
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

            it('should handle large values', async () => {
                const store = client.store();
                const key = new TextEncoder().encode('large_value');
                const value = Buffer.alloc(128 * 1024);

                await store.set(key, value);
                const result = await store.get(key);

                expect(result).not.toBeNull();
                expect(new Uint8Array(result!.value)).toEqual(new Uint8Array(value));
            });
        });
    });
});
