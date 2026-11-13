import type { MessageInitShape } from '@bufbuild/protobuf';
import { Code } from '@connectrpc/connect';
import type { Client } from '../src/client';
import { ErrorInfoSchema, RetryInfoSchema } from '../src/gen/ts/google/rpc/error_details_pb';
import type { RetentionPolicySchema } from '../src/gen/ts/log/v1/retention_pb';
import type { SubscribeRequestSchema } from '../src/gen/ts/log/v1/stream_pb';
import { PolicyOrderEncoding, type PolicySchema } from '../src/gen/ts/store/v1/prune_pb';
import { DetailSchema, RangeReduceOp, TraversalMode } from '../src/gen/ts/store/v1/query_pb';
import { ReadSession } from '../src/store';
import {
    indexedDb,
    isolatedSimulator,
    type Backend,
    type RestartableBackend,
} from './support/backends';
import {
    Subscriptions,
    allRows,
    be64,
    bytes,
    collect,
    concat,
    details,
    detailTypes,
    everyKey,
    expectFieldError,
    expectInvalidArgument,
    expectLogError,
    failure,
    hex,
    nextWithTimeout,
    put,
    sleep,
    utf8,
    type Row,
} from './support/contract';

const backends: Backend<RestartableBackend>[] = [isolatedSimulator, indexedDb];

const encoder = new TextEncoder();

type Retention = NonNullable<MessageInitShape<typeof RetentionPolicySchema>['kind']>;
type PolicyInit = MessageInitShape<typeof PolicySchema>;
type Retain = NonNullable<NonNullable<PolicyInit['retain']>['kind']>;

const keepLatest = (count: bigint): Retention => ({ case: 'keepLatest', value: { count } });
const dropAll: Retention = { case: 'dropAll', value: {} };

/** Five rows in key order, with the empty key, an empty value and a key that extends another. */
const sampleRows: Row[] = [
    [bytes(), bytes(9)],
    [bytes(1), bytes(2)],
    [bytes(1, 0), bytes()],
    [bytes(2), bytes(3)],
    [bytes(0xff), bytes(4)],
];
const sampleKeys = sampleRows.map(([key]) => hex(key));

function prunePolicy(spec: {
    prefix?: Uint8Array;
    regex: string;
    groupBy?: string[];
    orderBy?: [captureGroup: string, encoding: PolicyOrderEncoding];
    retain: Retain;
}): PolicyInit {
    return {
        keys: {
            selector: { prefix: spec.prefix ?? bytes(), payloadRegex: spec.regex },
            groupBy: spec.groupBy && { captureGroups: spec.groupBy },
            orderBy: spec.orderBy && { captureGroup: spec.orderBy[0], encoding: spec.orderBy[1] },
        },
        retain: { kind: spec.retain },
    };
}

describe.each(backends)('store contract on $name', (backend) => {
    let store: RestartableBackend;
    let client: Client;
    const subscriptions = new Subscriptions();

    beforeEach(async () => {
        store = await backend.open();
        client = store.client;
    });

    afterEach(async () => {
        subscriptions.closeAll();
        await store.close();
    });

    const subscribe = (request: MessageInitShape<typeof SubscribeRequestSchema>) =>
        subscriptions.open(client, request).frames;
    const setRetention = async (kind?: Retention) =>
        (await client.retention.setRetention({ policy: kind && { kind } })).oldestRetainedSequence;
    const putOne = (key: string, value = 'v') => put(client, [[utf8(key), utf8(value)]]);
    const keysInStore = async () => (await allRows(client)).rows.map(([key]) => hex(key));

    describe('sequence numbers', () => {
        it('numbers sequential Puts from 1 on a fresh store', async () => {
            const writer = client.store();
            for (const expected of [1n, 2n, 3n]) {
                await expect(
                    writer.set(encoder.encode(`key-${expected}`), encoder.encode('value')),
                ).resolves.toBe(expected);
            }
        });

        it('keeps the sequence number, rows and the next number across reopen', async () => {
            const key = encoder.encode('durable');
            const value = encoder.encode('kept');
            const writer = client.store();
            await writer.set(encoder.encode('first'), encoder.encode('1'));
            await expect(writer.set(key, value)).resolves.toBe(2n);

            const reopened = (await store.reopen()).store();
            const session = ReadSession.monotonic(reopened);
            await expect(session.get(key)).resolves.toMatchObject({ value });
            expect(session.evaluatedSequence()).toBe(2n);
            await expect(reopened.set(encoder.encode('next'), value)).resolves.toBe(3n);
        });

        it('reports sequence number 0 and one empty frame for an empty store', async () => {
            const got = await client.query.get({ key: utf8('missing') });
            expect(got.value).toBeUndefined();
            expect(got.detail).toMatchObject({ sequenceNumber: 0n, extra: {} });
            const frames = await collect(client.query.range({ batchSize: 10 }));
            expect(frames).toHaveLength(1);
            expect(frames[0].results).toHaveLength(0);
            expect(frames[0].detail?.sequenceNumber).toBe(0n);
        });

        it('gives each concurrent Put the sequence number of the batch that holds its entries in order', async () => {
            const count = 20;
            const batches = Array.from({ length: count }, (_, i) =>
                ['x', 'y', 'x'].map((part, position): Row => [utf8(`put-${i}-${part}`), bytes(position)]));
            const sequences = await Promise.all(batches.map((rows) => put(client, rows)));

            const distinct = [...new Set(sequences)].sort((a, b) => Number(a - b));
            if (backend.mergesConcurrentPuts) {
                // The simulator's writer may commit Puts that queue together as one batch, so
                // there can be fewer numbers than Puts.
                expect(distinct[0]).toBeGreaterThanOrEqual(1n);
                expect(distinct[distinct.length - 1]).toBeLessThanOrEqual(BigInt(count));
            } else {
                expect(distinct).toEqual(batches.map((_, i) => BigInt(i + 1)));
            }
            expect((await allRows(client)).sequenceNumber).toBe(distinct[distinct.length - 1]);

            const pair = ([key, value]: Row) => `${hex(key)}=${hex(value)}`;
            let logged = 0;
            for (const sequenceNumber of distinct) {
                const batch = await client.stream.get({ sequenceNumber });
                const entries = batch.entries.map(({ key, value }) => pair([key, value]));
                logged += entries.length;

                // Each Put that returned this number has its entries in the batch, together and in
                // the order it sent them. A batch of one Put holds nothing else.
                for (const [index, rows] of batches.entries()) {
                    if (sequences[index] !== sequenceNumber) continue;
                    const start = entries.indexOf(pair(rows[0]));
                    expect(entries.slice(start, start + rows.length)).toEqual(rows.map(pair));
                    if (!backend.mergesConcurrentPuts) expect(entries).toHaveLength(rows.length);
                }
            }
            expect(logged).toBe(count * 3);
        });
    });

    describe('Put', () => {
        it('keeps the last value of a duplicate key and every entry of the batch in the log', async () => {
            const rows: Row[] = [
                [bytes(1), bytes(1)],
                [bytes(2), bytes(3)],
                [bytes(1), bytes(2)],
            ];
            const sequenceNumber = await put(client, rows);
            expect((await client.query.get({ key: bytes(1) })).value).toEqual(bytes(2));

            const batch = await client.stream.get({ sequenceNumber });
            expect(batch.sequenceNumber).toBe(sequenceNumber);
            expect(batch.entries.map(({ key, value }) => [hex(key), hex(value)])).toEqual(
                rows.map(([key, value]) => [hex(key), hex(value)]),
            );
        });

        it('overwrites a key and tells an empty value from a missing key', async () => {
            const key = utf8('overwritten');
            await put(client, [[key, utf8('old')], [utf8('empty'), bytes()]]);
            await put(client, [[key, utf8('new')]]);
            expect((await client.query.get({ key })).value).toEqual(utf8('new'));
            expect((await client.query.get({ key: utf8('empty') })).value).toEqual(bytes());
            expect((await client.query.get({ key: utf8('missing') })).value).toBeUndefined();
        });

        it('stores the empty key and a key of 254 bytes', async () => {
            const longest = new Uint8Array(254).fill(0xff);
            await put(client, [[bytes(), utf8('empty key')], [longest, utf8('longest key')]]);
            expect((await client.query.get({ key: bytes() })).value).toEqual(utf8('empty key'));
            expect((await client.query.get({ key: longest })).value).toEqual(utf8('longest key'));
            expect(await keysInStore()).toEqual([hex(bytes()), hex(longest)]);
        });

        it('rejects an empty batch', async () => {
            expectFieldError(await failure(client.ingest.put({ kvs: [] })), {
                message: 'put request must contain at least one key-value pair',
                field: 'kvs',
                description: 'at least one key-value pair is required',
                reason: 'INVALID_BATCH',
                domain: 'log.ingest',
            });
        });

        it('rejects a key of 255 bytes, names its entry and writes nothing', async () => {
            const rows: Row[] = [[utf8('fine'), bytes(1)], [new Uint8Array(255), bytes(2)]];
            expectFieldError(await failure(put(client, rows)), {
                message: 'kvs[1].key key length is outside store limits',
                field: 'kvs[1].key',
                description: 'key length 255 exceeds max 254',
                reason: 'INVALID_KEY_LENGTH',
                domain: 'log.ingest',
                metadata: { max_key_len: '254' },
            });
            expect(await allRows(client)).toEqual({ sequenceNumber: 0n, rows: [] });
        });
    });

    describe('key order', () => {
        it('returns keys in unsigned byte order, a prefix before its extensions', async () => {
            // A fixed generator makes a failure repeatable.
            let state = 0x2545f491;
            const random = (bound: number) => {
                state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
                return state % bound;
            };
            const alphabet = [0x00, 0x01, 0x7f, 0x80, 0xff];
            const keys = new Map<string, Uint8Array>([['', bytes()]]);
            while (keys.size < 300) {
                const key = Uint8Array.from({ length: random(7) }, () => alphabet[random(alphabet.length)]);
                keys.set(hex(key), key);
            }
            await put(client, [...keys.values()].map((key): Row => [key, key]));

            const sorted = [...keys.values()].sort(Buffer.compare).map(hex);
            const scan = async (mode: TraversalMode) =>
                (await collect(client.query.range({ batchSize: 4096, mode })))
                    .flatMap((frame) => frame.results.map(({ key }) => hex(key)));
            expect(await scan(TraversalMode.FORWARD)).toEqual(sorted);
            expect(await scan(TraversalMode.REVERSE)).toEqual([...sorted].reverse());
        });
    });

    describe('Range', () => {
        const [empty, k01, k0100, k02, kff] = sampleKeys;

        it.each<[string, { start?: Uint8Array; end?: Uint8Array; limit?: number; mode?: TraversalMode }, string[]]>([
            ['includes both bounds', { start: bytes(1), end: bytes(2) }, [k01, k0100, k02]],
            ['has no upper bound for an empty end', { start: bytes(1) }, [k01, k0100, k02, kff]],
            ['starts at the empty key for an empty start', {}, sampleKeys],
            ['stops at the limit', { limit: 2 }, [empty, k01]],
            ['returns nothing for limit 0', { limit: 0 }, []],
            ['descends from the last key in reverse', { mode: TraversalMode.REVERSE }, [...sampleKeys].reverse()],
            [
                'descends from the end bound in reverse',
                { start: bytes(1), end: bytes(2), limit: 2, mode: TraversalMode.REVERSE },
                [k02, k0100],
            ],
            ['returns nothing for a start above the end', { start: bytes(2), end: bytes(1) }, []],
            ['returns one key for equal bounds', { start: bytes(1, 0), end: bytes(1, 0) }, [k0100]],
        ])('%s', async (_, request, expected) => {
            const sequenceNumber = await put(client, sampleRows);
            const frames = await collect(client.query.range({ batchSize: 4096, ...request }));
            expect(frames).toHaveLength(1);
            expect(frames[0].results.map(({ key }) => hex(key))).toEqual(expected);
            expect(frames[0].detail).toMatchObject({ sequenceNumber, extra: {} });
        });

        it('returns values with their keys', async () => {
            await put(client, sampleRows);
            const { rows } = await allRows(client);
            expect(rows.map(([key, value]) => [hex(key), hex(value)])).toEqual(
                sampleRows.map(([key, value]) => [hex(key), hex(value)]),
            );
        });

        it.each([
            [10, 3, [3, 3, 3, 1]],
            [5000, 10000, [4096, 904]],
        ])('cuts %i rows with batch_size %i into frames of %j', async (rows, batchSize, sizes) => {
            const sequenceNumber = await put(
                client,
                Array.from({ length: rows }, (_, i): Row => [be64(BigInt(i)), bytes(1)]),
            );
            const frames = await collect(client.query.range({ batchSize }));
            expect(frames.map((frame) => frame.results.length)).toEqual(sizes);
            for (const frame of frames) expect(frame.detail?.sequenceNumber).toBe(sequenceNumber);
        });

        it('rejects batch_size 0', async () => {
            expectFieldError(await failure(client.query.range({ batchSize: 0 })), {
                message: 'range batch_size must be positive',
                field: 'batch_size',
                description: 'batch_size must be greater than 0',
                reason: 'INVALID_BATCH_SIZE',
                domain: 'store.query',
            });
        });

        it('rejects an unknown traversal mode', async () => {
            const request = { batchSize: 1, mode: 99 as TraversalMode };
            expectFieldError(await failure(client.query.range(request)), {
                message: 'range mode must be TRAVERSAL_MODE_FORWARD (0) or TRAVERSAL_MODE_REVERSE (1)',
                field: 'mode',
                description: 'unknown TraversalMode enum value 99',
                reason: 'INVALID_TRAVERSAL_MODE',
                domain: 'store.query',
            });
        });

        it.each([
            ['start', { start: new Uint8Array(255), end: new Uint8Array(300) }, 255],
            ['end', { end: new Uint8Array(300) }, 300],
        ])('rejects a %s bound longer than a key', async (field, bounds, length) => {
            expectFieldError(await failure(client.query.range({ batchSize: 1, ...bounds })), {
                message: `${field} key length is outside store limits`,
                field,
                description: `key length ${length} exceeds max 254`,
                reason: 'INVALID_KEY_LENGTH',
                domain: 'store.query',
                metadata: { max_key_len: '254' },
            });
        });
    });

    describe('GetMany', () => {
        it('answers in request order with duplicates and missing keys, in frames of batch_size', async () => {
            const sequenceNumber = await put(client, sampleRows);
            const keys = [bytes(2), bytes(7), bytes(2), bytes(), bytes(1, 0)];
            const frames = await collect(client.query.getMany({ keys, batchSize: 2 }));
            expect(
                frames.map((frame) => frame.results.map(({ key, value }) => [hex(key), value && hex(value)])),
            ).toEqual([
                [['02', '03'], ['07', undefined]],
                [['02', '03'], ['', '09']],
                [['0100', '']],
            ]);
            for (const frame of frames) expect(frame.detail).toMatchObject({ sequenceNumber, extra: {} });
        });

        it('rejects a request without keys', async () => {
            expectFieldError(await failure(client.query.getMany({ keys: [], batchSize: 1 })), {
                message: 'get_many request must contain at least one key',
                field: 'keys',
                description: 'at least one key is required',
                reason: 'INVALID_BATCH',
                domain: 'store.query',
            });
        });

        it('rejects a key of 255 bytes and names its position', async () => {
            const keys = [bytes(1), new Uint8Array(255)];
            expectFieldError(await failure(client.query.getMany({ keys, batchSize: 1 })), {
                message: 'keys[1] key length is outside store limits',
                field: 'keys[1]',
                description: 'key length 255 exceeds max 254',
                reason: 'INVALID_KEY_LENGTH',
                domain: 'store.query',
                metadata: { max_key_len: '254' },
            });
        });

        it('rejects batch_size 0', async () => {
            expectFieldError(await failure(client.query.getMany({ keys: [bytes(1)], batchSize: 0 })), {
                message: 'get_many batch_size must be positive',
                field: 'batch_size',
                description: 'batch_size must be greater than 0',
                reason: 'INVALID_BATCH_SIZE',
                domain: 'store.query',
            });
        });
    });

    describe('Get', () => {
        it('rejects a key of 255 bytes', async () => {
            expectFieldError(await failure(client.query.get({ key: new Uint8Array(255) })), {
                message: 'key key length is outside store limits',
                field: 'key',
                description: 'key length 255 exceeds max 254',
                reason: 'INVALID_KEY_LENGTH',
                domain: 'store.query',
                metadata: { max_key_len: '254' },
            });
        });
    });

    describe('freshness', () => {
        const queries: [string, boolean, (floor: bigint) => Promise<unknown> | AsyncIterable<unknown>][] = [
            ['Get', true, (floor) => client.query.get({ key: bytes(1), minSequenceNumber: floor })],
            ['GetMany', true, (floor) =>
                client.query.getMany({ keys: [bytes(1)], batchSize: 1, minSequenceNumber: floor })],
            ['Range', true, (floor) => client.query.range({ batchSize: 1, minSequenceNumber: floor })],
            ['Reduce', backend.reduce, (floor) =>
                client.query.reduce({
                    params: { reducers: [{ op: RangeReduceOp.COUNT_ALL }] },
                    minSequenceNumber: floor,
                })],
        ];

        describe.each(queries)('%s', (_, supported, query) => {
            const check = supported ? it : it.skip;

            check('answers when the floor equals the sequence number', async () => {
                const sequenceNumber = await put(client, sampleRows);
                const answer = query(sequenceNumber);
                await (Symbol.asyncIterator in answer ? collect(answer) : answer);
            });

            check('fails with the store sequence number when the floor is above it', async () => {
                const sequenceNumber = await put(client, sampleRows);
                const error = await failure(query(sequenceNumber + 1n));
                expect(error.code).toBe(Code.Aborted);
                expect(error.rawMessage).toBe('minimum consistency token is not yet visible');
                expect(detailTypes(error)).toEqual([
                    RetryInfoSchema.typeName,
                    ErrorInfoSchema.typeName,
                    DetailSchema.typeName,
                ]);
                expect(details(error, RetryInfoSchema)[0].retryDelay).toMatchObject({ seconds: 1n, nanos: 0 });
                expect(details(error, ErrorInfoSchema)[0]).toMatchObject({
                    reason: 'CONSISTENCY_NOT_READY',
                    domain: 'store.query',
                    metadata: {
                        required_sequence_number: (sequenceNumber + 1n).toString(),
                        current_sequence_number: sequenceNumber.toString(),
                    },
                });
                expect(details(error, DetailSchema)[0].sequenceNumber).toBe(sequenceNumber);
            });
        });
    });

    describe('consistency', () => {
        it('serves every frame of a Range from the state of its first frame', async () => {
            const keys = [1, 2, 3, 4, 5].map((n) => bytes(n));
            const sequenceNumber = await put(client, keys.map((key): Row => [key, utf8('old')]));

            const frames = client.query.range({ batchSize: 1 })[Symbol.asyncIterator]();
            const seen = [(await frames.next()).value];
            await put(client, keys.slice(1).map((key): Row => [key, utf8('new')]));
            for (let next = await frames.next(); !next.done; next = await frames.next()) seen.push(next.value);

            expect(seen).toHaveLength(keys.length);
            for (const [index, frame] of seen.entries()) {
                expect(frame.detail.sequenceNumber).toBe(sequenceNumber);
                expect(frame.results.map(({ key, value }: { key: Uint8Array; value: Uint8Array }) => [hex(key), hex(value)]))
                    .toEqual([[hex(keys[index]), hex(utf8('old'))]]);
            }
        });

        it('reports with every answer the sequence number of the batch whose values it holds', async () => {
            const keys = Array.from({ length: 8 }, (_, i) => utf8(`row-${i}`));
            const batchOf = new Map<bigint, string>();
            const write = async (batch: number) => {
                const value = String(batch);
                batchOf.set(await put(client, keys.map((key): Row => [key, utf8(value)])), value);
            };
            await write(0);

            // GetMany, Range and Get read in a loop while Puts rewrite every row. Each answer must
            // hold the values of exactly the batch whose sequence number it reports.
            type Observation = { sequenceNumber: bigint; values: (Uint8Array | undefined)[] };
            const reads: (() => Promise<Observation>)[] = [
                async () => {
                    const frames = await collect(client.query.getMany({ keys, batchSize: 3 }));
                    return {
                        sequenceNumber: frames[0].detail!.sequenceNumber,
                        values: frames.flatMap((frame) => frame.results.map(({ value }) => value)),
                    };
                },
                async () => {
                    const { sequenceNumber, rows } = await allRows(client);
                    return { sequenceNumber, values: rows.map(([, value]) => value) };
                },
                async () => {
                    const got = await client.query.get({ key: keys[3] });
                    return { sequenceNumber: got.detail!.sequenceNumber, values: [got.value] };
                },
            ];
            let writing = true;
            const observed: Observation[][] = reads.map(() => []);
            const readers = reads.map(async (readOnce, reader) => {
                while (writing) observed[reader].push(await readOnce());
            });

            // The Puts run for at least 20 batches, then continue up to batch 2000 until every kind
            // of read has seen two or more sequence numbers. Two numbers show that the answers of
            // that kind of read interleaved with writes.
            const sawWrites = () =>
                observed.every((answers) => new Set(answers.map((answer) => answer.sequenceNumber)).size >= 2);
            for (let batch = 1; batch <= 20 || (!sawWrites() && batch <= 2000); batch++) await write(batch);
            writing = false;
            await Promise.all(readers);

            expect(sawWrites()).toBe(true);
            for (const { sequenceNumber, values } of observed.flat()) {
                const expected = batchOf.get(sequenceNumber);
                expect(expected).toBeDefined();
                expect(values.map((value) => value && new TextDecoder().decode(value))).toEqual(
                    values.map(() => expected),
                );
            }
        });
    });

    describe('log Get', () => {
        it('fails with NOT_FOUND for a sequence number that no Put has reached', async () => {
            const sequenceNumber = await putOne('a');
            const error = await failure(client.stream.get({ sequenceNumber: sequenceNumber + 1n }));
            expect(error.rawMessage).toBe('batch not found');
            expectLogError(error, { code: Code.NotFound, reason: 'BATCH_NOT_FOUND' });
        });

        it('fails with OUT_OF_RANGE and the oldest retained batch for 0 and for an evicted batch', async () => {
            await putOne('a');
            await putOne('b');
            const zero = await failure(client.stream.get({ sequenceNumber: 0n }));
            expect(zero.rawMessage).toBe('batch has been evicted from the log');
            expectLogError(zero, { code: Code.OutOfRange, reason: 'BATCH_EVICTED', oldestRetained: 1n });

            await setRetention(keepLatest(1n));
            const evicted = await failure(client.stream.get({ sequenceNumber: 1n }));
            expectLogError(evicted, { code: Code.OutOfRange, reason: 'BATCH_EVICTED', oldestRetained: 2n });
        });

        it('names no oldest retained batch when the log is empty', async () => {
            await putOne('a');
            await setRetention(dropAll);
            const error = await failure(client.stream.get({ sequenceNumber: 1n }));
            expectLogError(error, { code: Code.OutOfRange, reason: 'BATCH_EVICTED' });
        });
    });

    describe('retention', () => {
        const retained = async (sequenceNumber: bigint) =>
            client.stream.get({ sequenceNumber }).then(() => true, () => false);

        it('keeps the newest batches as the store advances', async () => {
            for (const key of ['a', 'b', 'c']) await putOne(key);
            await expect(setRetention(keepLatest(2n))).resolves.toBe(2n);
            await expect(putOne('d')).resolves.toBe(4n);
            expect(await Promise.all([1n, 2n, 3n, 4n].map(retained))).toEqual([false, false, true, true]);
            expectLogError(
                await failure(client.stream.get({ sequenceNumber: 2n })),
                { code: Code.OutOfRange, reason: 'BATCH_EVICTED', oldestRetained: 3n },
            );
        });

        it.each<[string, Retention, bigint | undefined]>([
            ['greater_than keeps the batches above its threshold', { case: 'greaterThan', value: { threshold: 2n } }, 3n],
            [
                'greater_than_or_equal keeps the batches from its threshold on',
                { case: 'greaterThanOrEqual', value: { threshold: 2n } },
                2n,
            ],
            ['a threshold above the sequence number keeps nothing', { case: 'greaterThan', value: { threshold: 9n } }, undefined],
            ['keep_latest with more than the log holds keeps everything', keepLatest(100n), 1n],
            ['drop_all keeps nothing', dropAll, undefined],
        ])('%s', async (_, kind, oldest) => {
            for (const key of ['a', 'b', 'c', 'd']) await putOne(key);
            await expect(setRetention(kind)).resolves.toBe(oldest);
            const kept = await Promise.all([1n, 2n, 3n, 4n].map(retained));
            expect(kept).toEqual([1n, 2n, 3n, 4n].map((n) => oldest !== undefined && n >= oldest));
        });

        it('leaves rows readable when their batches are evicted', async () => {
            await putOne('a', 'kept');
            await setRetention(dropAll);
            expect((await client.query.get({ key: utf8('a') })).value).toEqual(utf8('kept'));
        });

        it('stops evicting when the rule is cleared and restores nothing', async () => {
            for (const key of ['a', 'b', 'c']) await putOne(key);
            await expect(setRetention(keepLatest(1n))).resolves.toBe(3n);
            await expect(setRetention()).resolves.toBe(3n);
            await putOne('d');
            await putOne('e');
            expect(await Promise.all([1n, 2n, 3n, 4n, 5n].map(retained))).toEqual([false, false, true, true, true]);
        });

        it('reports no oldest batch for a store without batches', async () => {
            await expect(setRetention(keepLatest(1n))).resolves.toBeUndefined();
        });

        it('keeps applying the rule after reopen', async () => {
            await putOne('a');
            await setRetention(keepLatest(1n));
            client = await store.reopen();
            await expect(putOne('b')).resolves.toBe(2n);
            expect(await Promise.all([1n, 2n].map(retained))).toEqual([false, true]);
        });

        it.each<[string, MessageInitShape<typeof RetentionPolicySchema>, string]>([
            ['a policy without a kind', {}, 'retention policy kind is required'],
            ['keep_latest with count 0', { kind: keepLatest(0n) }, 'keep_latest count must be > 0'],
        ])('rejects %s', async (_, policy, message) => {
            expectInvalidArgument(await failure(client.retention.setRetention({ policy })), message);
        });
    });

    describe('Subscribe', () => {
        const entriesOf = (frame: { entries: { key: Uint8Array; value: Uint8Array }[] }) =>
            frame.entries.map(({ key, value }) => [new TextDecoder().decode(key), new TextDecoder().decode(value)]);

        it('delivers a batch written after the subscription started', async () => {
            const frames = subscribe({ selectors: [everyKey] });
            let delivered: { sequenceNumber: bigint; entries: { key: Uint8Array; value: Uint8Array }[] } | undefined;
            const arrival = nextWithTimeout(frames).then((next) => {
                delivered = next.value;
            });

            // A subscription with no cursor starts at the batch after the one the store holds when
            // it handles the call, so batches are written until one of them arrives.
            const written = new Map<bigint, string>();
            while (delivered === undefined && written.size < 200) {
                const value = `live-${written.size}`;
                written.set(await putOne('live', value), value);
                await sleep(10);
            }
            await arrival;
            expect(entriesOf(delivered!)).toEqual([['live', written.get(delivered!.sequenceNumber)]]);
        });

        it('skips a batch without a match and delivers a matching entry once, in batch order', async () => {
            const first = await putOne('other');
            const second = await put(client, [
                [utf8('match-b'), utf8('1')],
                [utf8('other'), utf8('2')],
                [utf8('match-b'), utf8('3')],
                [utf8('match-a'), utf8('4')],
            ]);

            // Both selectors accept every matching key, so a matching entry must still arrive once.
            const frames = subscribe({
                selectors: [
                    { prefix: utf8('match-'), payloadRegex: '^[ab]$' },
                    { prefix: bytes(), payloadRegex: '^match-' },
                ],
                sinceSequenceNumber: first,
            });
            const { value } = await nextWithTimeout(frames);
            expect(value.sequenceNumber).toBe(second);
            expect(entriesOf(value)).toEqual([['match-b', '1'], ['match-b', '3'], ['match-a', '4']]);
        });

        it('replays retained batches and continues with new ones in increasing order', async () => {
            for (const key of ['a', 'b', 'c']) await putOne(key);
            const frames = subscribe({ selectors: [everyKey], sinceSequenceNumber: 1n });
            const seen: bigint[] = [];
            for (let i = 0; i < 3; i++) seen.push((await nextWithTimeout(frames)).value.sequenceNumber);
            await putOne('d');
            seen.push((await nextWithTimeout(frames)).value.sequenceNumber);
            expect(seen).toEqual([1n, 2n, 3n, 4n]);
        });

        it('waits for the batch of a cursor that is ahead of the store', async () => {
            await putOne('a');
            const frames = subscribe({ selectors: [everyKey], sinceSequenceNumber: 3n });
            const next = nextWithTimeout(frames);
            await putOne('skipped');
            await putOne('wanted', 'now');
            const { value } = await next;
            expect(value.sequenceNumber).toBe(3n);
            expect(entriesOf(value)).toEqual([['wanted', 'now']]);
        });

        it('fails with OUT_OF_RANGE for a cursor at an evicted batch', async () => {
            for (const key of ['a', 'b', 'c']) await putOne(key);
            await setRetention(keepLatest(1n));
            const frames = subscribe({ selectors: [everyKey], sinceSequenceNumber: 1n });
            const error = await failure(nextWithTimeout(frames));
            expectLogError(error, { code: Code.OutOfRange, reason: 'BATCH_EVICTED', oldestRetained: 3n });
        });

        it('treats a batch that retention drops as it is written as evicted', async () => {
            await putOne('a');
            await setRetention(dropAll);
            const frames = subscribe({ selectors: [everyKey], sinceSequenceNumber: 2n });
            const next = nextWithTimeout(frames).then(
                (result) => result.value.sequenceNumber as bigint,
                (error) => error,
            );
            await putOne('b');
            const outcome = await next;
            if (backend.trimsAfterCommit && outcome === 2n) {
                // The simulator trims the log after the commit, so a waiting subscriber can read
                // the batch before it is gone.
                return;
            }
            expectLogError(outcome, { code: Code.OutOfRange, reason: 'BATCH_EVICTED' });
        });

        it.each<[string, NonNullable<MessageInitShape<typeof SubscribeRequestSchema>['valueFilters']>, string[]]>([
            ['an exact value', [{ kind: { case: 'exact', value: utf8('abc') } }], ['k1']],
            ['a value prefix', [{ kind: { case: 'prefix', value: utf8('ab') } }], ['k1', 'k2']],
            ['a value regex', [{ kind: { case: 'regex', value: 'c$' } }], ['k1', 'k3']],
            [
                'any of several filters',
                [{ kind: { case: 'exact', value: bytes() } }, { kind: { case: 'regex', value: '^x' } }],
                ['k3', 'k4'],
            ],
        ])('filters entries by %s', async (_, valueFilters, expected) => {
            const sequenceNumber = await put(client, [
                [utf8('k1'), utf8('abc')],
                [utf8('k2'), utf8('abd')],
                [utf8('k3'), utf8('xbc')],
                [utf8('k4'), bytes()],
            ]);
            const frames = subscribe({ selectors: [everyKey], valueFilters, sinceSequenceNumber: sequenceNumber });
            const { value } = await nextWithTimeout(frames);
            expect(entriesOf(value).map(([key]) => key)).toEqual(expected);
        });

        const seventeen = <T>(item: T) => Array.from({ length: 17 }, () => item);

        it.each<[string, MessageInitShape<typeof SubscribeRequestSchema>, string | RegExp]>([
            ['no selector', {}, 'stream filter must contain at least one selector'],
            ['17 selectors', { selectors: seventeen(everyKey) }, 'stream filter capped at 16 selectors'],
            [
                '17 value filters',
                { selectors: [everyKey], valueFilters: seventeen({ kind: { case: 'exact' as const, value: bytes() } }) },
                'stream filter capped at 16 value_filters',
            ],
            [
                'a selector prefix of 255 bytes',
                { selectors: [{ prefix: new Uint8Array(255), payloadRegex: '.' }] },
                'invalid selector prefix: prefix length 255 exceeds max 254',
            ],
            [
                'a blank selector regex',
                { selectors: [{ prefix: bytes(), payloadRegex: ' \t' }] },
                'selector payload_regex must not be empty',
            ],
            [
                'a selector regex that does not parse',
                { selectors: [{ prefix: bytes(), payloadRegex: '(' }] },
                'invalid selector payload_regex "("',
            ],
            [
                'a value filter without a kind',
                { selectors: [everyKey], valueFilters: [{}] },
                'each value_filter must set exactly one of exact, prefix, or regex',
            ],
            [
                'a blank value regex',
                { selectors: [everyKey], valueFilters: [{ kind: { case: 'regex', value: '' } }] },
                'value_filter regex must not be empty',
            ],
            [
                // The text after the pattern is the regex engine's own.
                'a value regex that does not parse',
                { selectors: [everyKey], valueFilters: [{ kind: { case: 'regex', value: '(' } }] },
                /^invalid value_filter: invalid regex `\(`: /,
            ],
        ])('rejects %s', async (_, request, message) => {
            expectInvalidArgument(await failure(nextWithTimeout(subscribe(request))), message);
        });

        it('matches with a pattern outside the IndexedDB subset or refuses the subscription', async () => {
            const sequenceNumber = await putOne('a word', 'v');
            const frames = subscribe({
                selectors: [{ prefix: bytes(), payloadRegex: '\\bword' }],
                sinceSequenceNumber: sequenceNumber,
            });
            if (backend.fullRegex) {
                expect(entriesOf((await nextWithTimeout(frames)).value)).toEqual([['a word', 'v']]);
            } else {
                // The IndexedDB store compiles a subset of the Rust regex syntax without word
                // boundaries and refuses a pattern outside it.
                expect((await failure(nextWithTimeout(frames))).code).toBe(Code.Unimplemented);
            }
        });

    });

    describe('Prune', () => {
        const versioned = '(?s-u)^(?P<group>[a-z]+)\\x00(?P<version>.{8})$';
        const versionKey = (group: string, version: bigint, prefix = 'p/') =>
            concat(utf8(prefix), utf8(group), bytes(0), be64(version));
        const prune = (...policies: PolicyInit[]) => client.prune.prune({ policies });

        it('deletes every matching key under the prefix with drop_all and nothing else', async () => {
            const matching = [versionKey('a', 1n), versionKey('b', 2n)];
            const others = [utf8('p/UPPER'), utf8('q/a'), versionKey('a', 1n, 'q/')];
            const sequenceNumber = await put(client, [...matching, ...others].map((key): Row => [key, bytes(1)]));

            await prune(prunePolicy({ prefix: utf8('p/'), regex: versioned, retain: { case: 'dropAll', value: {} } }));
            const after = await allRows(client);
            expect(after.rows.map(([key]) => hex(key))).toEqual(others.map(hex).sort());
            expect(after.sequenceNumber).toBe(sequenceNumber);
            await expect(client.stream.get({ sequenceNumber })).resolves.toMatchObject({ sequenceNumber });
        });

        it('keeps the latest versions of each group and changes nothing on a second run', async () => {
            const keys = [
                versionKey('a', 1n), versionKey('a', 2n), versionKey('a', 3n),
                versionKey('b', 7n), versionKey('b', 9n),
                versionKey('c', 5n),
            ];
            await put(client, keys.map((key): Row => [key, bytes(1)]));
            const policy = prunePolicy({
                prefix: utf8('p/'),
                regex: versioned,
                groupBy: ['group'],
                orderBy: ['version', PolicyOrderEncoding.U64_BE],
                retain: { case: 'keepLatest', value: { count: 2n } },
            });
            const expected = [keys[1], keys[2], keys[3], keys[4], keys[5]].map(hex);

            await prune(policy);
            expect(await keysInStore()).toEqual(expected);
            await prune(policy);
            expect(await keysInStore()).toEqual(expected);
        });

        // Each key is a group letter, one byte that fixes the key order, and the order value. The
        // key order is the opposite of the order under the encoding, so only the encoding
        // explains which key stays.
        const ones = new Uint8Array(8).fill(0xff);
        it.each<[string, PolicyOrderEncoding, Uint8Array[], number]>([
            ['bytes_asc', PolicyOrderEncoding.BYTES_ASC, [concat(bytes(1), bytes(9)), concat(bytes(2), bytes(3, 3))], 0],
            ['u64_be', PolicyOrderEncoding.U64_BE, [concat(bytes(1), ones), concat(bytes(2), be64(1n))], 0],
            ['i64_be', PolicyOrderEncoding.I64_BE, [concat(bytes(1), be64(1n)), concat(bytes(2), ones)], 0],
        ])('orders by %s', async (_, encoding, tails, kept) => {
            const keys = tails.map((tail) => concat(utf8('g'), tail));
            await put(client, keys.map((key): Row => [key, bytes(1)]));
            await prune(prunePolicy({
                regex: '(?s-u)^(?P<group>[a-z]).(?P<order>.+)$',
                groupBy: ['group'],
                orderBy: ['order', encoding],
                retain: { case: 'keepLatest', value: { count: 1n } },
            }));
            expect(await keysInStore()).toEqual([hex(keys[kept])]);
        });

        it('keeps key order among equal order values', async () => {
            // An integer order value that is not 8 bytes long counts as 0.
            const keys = ['v1', 'v2', 'v3'].map(utf8);
            await put(client, keys.map((key): Row => [key, bytes(1)]));
            await prune(prunePolicy({
                regex: '(?s-u)^v(?P<order>.)$',
                orderBy: ['order', PolicyOrderEncoding.U64_BE],
                retain: { case: 'keepLatest', value: { count: 1n } },
            }));
            expect(await keysInStore()).toEqual([hex(keys[2])]);
        });

        it.each<[string, Retain, bigint[]]>([
            ['greater_than', { case: 'greaterThan', value: { threshold: 3n } }, [4n, 5n]],
            ['greater_than_or_equal', { case: 'greaterThanOrEqual', value: { threshold: 3n } }, [3n, 4n, 5n]],
        ])('keeps the versions that are %s the threshold', async (_, retain, kept) => {
            await put(client, [1n, 2n, 3n, 4n, 5n].map((version): Row => [versionKey('a', version), bytes(1)]));
            await prune(prunePolicy({
                prefix: utf8('p/'),
                regex: versioned,
                orderBy: ['version', PolicyOrderEncoding.U64_BE],
                retain,
            }));
            expect(await keysInStore()).toEqual(kept.map((version) => hex(versionKey('a', version))));
        });

        it('leaves a key whose match has no value for a group_by capture', async () => {
            await put(client, [[utf8('a1'), bytes(1)], [utf8('b1'), bytes(1)]]);
            await prune(prunePolicy({
                regex: '^(?:(?P<group>a)|b)1$',
                groupBy: ['group'],
                retain: { case: 'dropAll', value: {} },
            }));
            expect(await keysInStore()).toEqual([hex(utf8('b1'))]);
        });

        it('applies several policies with separate prefixes in one request', async () => {
            await put(client, ['a/1', 'b/1', 'c/1'].map((key): Row => [utf8(key), bytes(1)]));
            await prune(
                prunePolicy({ prefix: utf8('a/'), regex: '.', retain: { case: 'dropAll', value: {} } }),
                prunePolicy({ prefix: utf8('c/'), regex: '.', retain: { case: 'dropAll', value: {} } }),
            );
            expect(await keysInStore()).toEqual([hex(utf8('b/1'))]);
        });

        it('applies nothing of a request whose second policy is invalid', async () => {
            const rows = ['a/1', 'a/2', 'b/1'].map((key): Row => [utf8(key), bytes(1)]);
            await put(client, rows);
            const error = await failure(prune(
                prunePolicy({ prefix: utf8('a/'), regex: '.', retain: { case: 'dropAll', value: {} } }),
                prunePolicy({
                    prefix: utf8('b/'),
                    regex: '(?P<version>.)',
                    retain: { case: 'keepLatest', value: { count: 1n } },
                }),
            ));
            expectInvalidArgument(error, 'keep_latest requires order_by to be configured');
            expect(await keysInStore()).toEqual(rows.map(([key]) => hex(key)));
        });

        it('rejects a request without policies', async () => {
            expectFieldError(await failure(prune()), {
                message: 'prune request must contain at least one policy',
                field: 'policies',
                description: 'at least one policy is required',
                reason: 'INVALID_PRUNE_REQUEST',
                domain: 'store.prune',
            });
        });

        const drop: Retain = { case: 'dropAll', value: {} };
        const latest: Retain = { case: 'keepLatest', value: { count: 1n } };
        const named = '(?P<group>a)(?P<version>.)';
        it.each<[string, PolicyInit[], string]>([
            ['a policy without a keys scope', [{ retain: { kind: drop } }], 'prune policy keys scope is required'],
            ['a keys scope without a selector', [{ keys: {}, retain: { kind: drop } }], 'keys scope selector is required'],
            [
                'an unknown order encoding',
                [prunePolicy({ regex: named, orderBy: ['version', 99 as PolicyOrderEncoding], retain: latest })],
                'order_by.encoding must be a known PolicyOrderEncoding value',
            ],
            ['a policy without retain', [{ keys: { selector: everyKey } }], 'prune policy retain is required'],
            ['retain without a kind', [{ keys: { selector: everyKey }, retain: {} }], 'prune policy retain.kind is required'],
            [
                'a selector prefix of 255 bytes',
                [prunePolicy({ prefix: new Uint8Array(255), regex: '.', retain: drop })],
                'invalid selector prefix',
            ],
            ['a blank regex', [prunePolicy({ regex: ' ', retain: drop })], 'selector payload_regex must not be empty'],
            ['a regex that does not parse', [prunePolicy({ regex: '(', retain: drop })], 'invalid selector payload_regex "("'],
            [
                'a group_by capture the regex lacks',
                [prunePolicy({ regex: named, groupBy: ['group', 'nope'], retain: drop })],
                'group_by capture_groups references unknown capture group Utf8("nope")',
            ],
            [
                'a repeated group_by capture',
                [prunePolicy({ regex: named, groupBy: ['group', 'group'], retain: drop })],
                'group_by capture_groups must not contain duplicates',
            ],
            [
                'an order_by capture the regex lacks',
                [prunePolicy({ regex: named, orderBy: ['nope', PolicyOrderEncoding.U64_BE], retain: drop })],
                'order_by capture_group references unknown capture group Utf8("nope")',
            ],
            [
                'keep_latest with count 0',
                [prunePolicy({
                    regex: named,
                    orderBy: ['version', PolicyOrderEncoding.U64_BE],
                    retain: { case: 'keepLatest', value: { count: 0n } },
                })],
                'keep_latest count must be > 0',
            ],
            [
                'keep_latest without order_by',
                [prunePolicy({ regex: named, retain: latest })],
                'keep_latest requires order_by to be configured',
            ],
            [
                'a threshold without order_by',
                [prunePolicy({ regex: named, retain: { case: 'greaterThan', value: { threshold: 1n } } })],
                'threshold retention requires order_by to be configured',
            ],
            [
                'a threshold over an order that is not u64_be',
                [prunePolicy({
                    regex: named,
                    orderBy: ['version', PolicyOrderEncoding.BYTES_ASC],
                    retain: { case: 'greaterThanOrEqual', value: { threshold: 1n } },
                })],
                'threshold retention currently requires order_by.encoding = u64_be',
            ],
            [
                'a selector prefix that extends the prefix of another policy',
                [
                    prunePolicy({ prefix: bytes(1), regex: '.', retain: drop }),
                    prunePolicy({ prefix: bytes(1, 0), regex: '.', retain: drop }),
                ],
                'overlapping compaction prune policies for key prefixes [1] and [1, 0]',
            ],
            [
                'two policies with the same prefix',
                [prunePolicy({ regex: 'a', retain: drop }), prunePolicy({ regex: 'b', retain: drop })],
                'overlapping compaction prune policies for key prefixes [] and []',
            ],
        ])('rejects %s and deletes nothing', async (_, policies, message) => {
            await put(client, [[utf8('a1'), bytes(1)]]);
            expectInvalidArgument(await failure(prune(...policies)), message);
            expect(await keysInStore()).toEqual([hex(utf8('a1'))]);
        });
    });
});
