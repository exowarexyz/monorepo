import { ScalarType, fromBinary, toBinary, create, type MessageInitShape } from '@bufbuild/protobuf';
import { Code, createRouterTransport, type ConnectRouter, type Transport } from '@connectrpc/connect';

/**
 * Test hooks on protobuf encoding and decoding. `failing` names the schema whose encoding
 * throws, `observe` sees every message that is encoded, and `decoded` sees every message that
 * is decoded.
 */
const mockEncoding: {
    failing?: string;
    observe?: (typeName: string, message: unknown) => void;
    decoded?: (typeName: string, message: unknown) => void;
} = {};

jest.mock('@bufbuild/protobuf', () => {
    const actual = jest.requireActual('@bufbuild/protobuf');
    return {
        ...actual,
        toBinary: (schema: { typeName: string }, ...rest: unknown[]) => {
            if (schema.typeName === mockEncoding.failing) throw new Error('encoding failed');
            mockEncoding.observe?.(schema.typeName, rest[0]);
            return actual.toBinary(schema, ...rest);
        },
        fromBinary: (schema: { typeName: string }, ...rest: unknown[]) => {
            const message = actual.fromBinary(schema, ...rest);
            mockEncoding.decoded?.(schema.typeName, message);
            return message;
        },
    };
});

import { Client } from '../src/client';
import { EntrySchema } from '../src/gen/ts/common/v1/kv_pb';
import { PutRequestSchema } from '../src/gen/ts/log/v1/ingest_pb';
import { RetentionPolicySchema } from '../src/gen/ts/log/v1/retention_pb';
import { GetResponseSchema, type SubscribeRequestSchema } from '../src/gen/ts/log/v1/stream_pb';
import { PolicyOrderEncoding, type PolicySchema } from '../src/gen/ts/store/v1/prune_pb';
import { RangeReduceOp, type TraversalMode } from '../src/gen/ts/store/v1/query_pb';
import {
    deleteIndexedDbStore,
    openIndexedDbStore,
    type IndexedDbStore,
    type IndexedDbStoreOptions,
} from '../src/indexeddb';
import { quoted, toConnectError } from '../src/indexeddb/errors';
import { Notifier } from '../src/indexeddb/notifier';
import { MAX_PRUNE_POLICIES } from '../src/indexeddb/prune';
import {
    MAX_GROUP_DEPTH,
    MAX_INSTRUCTIONS,
    MAX_PATTERN_CHARS,
    MAX_REPEAT_COUNT,
    Regex,
} from '../src/indexeddb/regex';
import { Pacer } from '../src/indexeddb/selector';
import { LOG_BOUNDS, decodeBatch } from '../src/indexeddb/stream';
import { MAX_PUT_ENTRIES, MAX_REQUEST_MESSAGE_BYTES, MAX_VALUE_LEN } from '../src/limits';
import { freshDatabaseName } from './support/backends';
import {
    Subscriptions,
    abortCall,
    allRows,
    be64,
    bytes,
    collect,
    concat,
    everyKey,
    expectEveryCallFails,
    expectFieldError,
    failure,
    hex,
    nextFrame,
    nextWithTimeout,
    put,
    until,
    utf8,
    type Row,
} from './support/contract';

/** A Reduce that counts the rows of its range. A request without start and end covers every row. */
const countRows = { params: { reducers: [{ op: RangeReduceOp.COUNT_ALL }] } };

const STORES = ['kv', 'log', 'meta'];
const MAX_U64 = (1n << 64n) - 1n;
const PUT_SCOPE = [['kv', 'log', 'meta'], 'readwrite', 'strict'];
const QUERY_SCOPE = [['kv', 'meta'], 'readonly', 'default'];
const LOG_SCOPE = [['log', 'meta'], 'readonly', 'default'];

function done<T>(request: IDBRequest<T>): Promise<T> {
    return new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

/** Connections that tests open outside the store. One left open would block the cleanup. */
const rawConnections: IDBDatabase[] = [];

/** Opens a connection outside the store, creating the database with `stores` when it is new. */
async function openRaw(name: string, version?: number, stores: string[] = STORES): Promise<IDBDatabase> {
    const opening = indexedDB.open(name, version);
    opening.onupgradeneeded = (event) => {
        if (event.oldVersion === 0) stores.forEach((store) => opening.result.createObjectStore(store));
    };
    const db = await done(opening);
    rawConnections.push(db);
    return db;
}

/** Runs one transaction over the three object stores on a connection of its own. */
async function withRaw<T>(
    name: string,
    mode: IDBTransactionMode,
    body: (stores: Record<string, IDBObjectStore>) => Promise<T> | T,
): Promise<T> {
    const db = await openRaw(name);
    try {
        const tx = db.transaction(STORES, mode);
        const committed = new Promise<void>((resolve, reject) => {
            tx.oncomplete = () => resolve();
            tx.onabort = () => reject(tx.error);
        });
        const result = await body(Object.fromEntries(STORES.map((store) => [store, tx.objectStore(store)])));
        await committed;
        return result;
    } finally {
        db.close();
    }
}

type StoredRow = { key: IDBValidKey; value: unknown };

/** Every row of every object store as stored. */
function rawRows(name: string): Promise<Record<string, StoredRow[]>> {
    return withRaw(name, 'readonly', async (stores) => {
        const rows: Record<string, StoredRow[]> = {};
        for (const store of STORES) {
            const keys = await done(stores[store].getAllKeys());
            const values = await done(stores[store].getAll());
            rows[store] = keys.map((key, i) => ({ key, value: values[i] }));
        }
        return rows;
    });
}

function storedHex(data: unknown): string {
    if (data instanceof ArrayBuffer) return hex(new Uint8Array(data));
    if (data instanceof Uint8Array) return hex(data);
    return `not bytes: ${String(data)}`;
}

/** Every key and value of every object store as hex, so two reads of a database compare equal. */
async function contentOf(name: string): Promise<Record<string, string[][]>> {
    const rows = await rawRows(name);
    return Object.fromEntries(
        STORES.map((store) => [store, rows[store].map(({ key, value }) => [storedHex(key), storedHex(value)])]),
    );
}

const asciiKey = (name: string) => utf8(name).buffer as ArrayBuffer;
const exact = (data: Uint8Array) => data.slice().buffer as ArrayBuffer;

/** A view of `data` at an offset inside a larger buffer. */
function offsetView(data: Uint8Array): Uint8Array {
    const padded = new Uint8Array(data.byteLength + 16).fill(0xee);
    padded.set(data, 5);
    return padded.subarray(5, 5 + data.byteLength);
}

/** `pattern` repeated `count` times. */
function repeated(pattern: Uint8Array, count: number): Uint8Array {
    const bytes = new Uint8Array(pattern.byteLength * count);
    for (let i = 0; i < count; i++) bytes.set(pattern, i * pattern.byteLength);
    return bytes;
}

function encodedBatch(sequenceNumber: bigint, rows: Row[]): Uint8Array {
    const entries = rows.map(([key, value]) => ({ key, value }));
    return toBinary(GetResponseSchema, create(GetResponseSchema, { sequenceNumber, entries }));
}

describe('IndexedDB store', () => {
    const opened: IndexedDbStore[] = [];
    const names = new Set<string>();
    const subscriptions = new Subscriptions();
    const channels: BroadcastChannel[] = [];

    /** Opens the test's own channel on the name where stores of the database announce commits. */
    function openChannel(name: string): BroadcastChannel {
        const channel = new BroadcastChannel(`exoware-store:${name}`);
        channels.push(channel);
        return channel;
    }

    async function openStore(name = freshDatabaseName(), options?: IndexedDbStoreOptions) {
        names.add(name);
        const store = await openIndexedDbStore(name, options);
        opened.push(store);
        return { store, name, client: new Client(store.transport) };
    }

    const subscribe = (client: Client, request: MessageInitShape<typeof SubscribeRequestSchema>) =>
        subscriptions.open(client, request).frames;
    const sequenceOf = async (client: Client) =>
        (await client.query.get({ key: bytes() })).detail!.sequenceNumber;
    const putOne = (client: Client, key: string, value = 'v') => put(client, [[utf8(key), utf8(value)]]);

    /**
     * Watches for subscriptions that wait for a wake. It must be called before the subscription
     * starts. `waiting()` resolves with the notifier of the first one that waits.
     */
    const watchWaiters = () => {
        const waits = jest.spyOn(Notifier.prototype, 'after');
        const waiting = async () => {
            const notifiers = () => waits.mock.contexts as Notifier[];
            await until(() => notifiers().some((notifier) => notifier.waiting > 0));
            return notifiers().find((notifier) => notifier.waiting > 0)!;
        };
        return { waits, waiting };
    };

    /**
     * A transport over the store's handlers on a router that applies none of the options the
     * routes carry, so a request reaches a handler whatever its size.
     */
    const withoutServiceOptions = (store: IndexedDbStore): Transport =>
        createRouterTransport((router) => {
            const plain = {
                handlers: router.handlers,
                rpc: router.rpc,
                service: (service: never, implementation: never) => {
                    router.service(service, implementation);
                    return plain;
                },
            };
            store.routes(plain as unknown as ConnectRouter);
        });
    const spyOnTransactions = () => {
        const spy = jest.spyOn(IDBDatabase.prototype, 'transaction');
        const calls = () =>
            spy.mock.calls.map(([scope, mode, options]) => [scope, mode, options?.durability ?? 'default']);
        return { spy, calls };
    };

    /** Makes the nth call of an IDBObjectStore method act as `fault` says. */
    function onCall(
        method: 'put' | 'delete' | 'get' | 'openCursor' | 'openKeyCursor',
        nth: number,
        fault: (store: IDBObjectStore, placed: () => IDBRequest) => IDBRequest,
    ) {
        const original = IDBObjectStore.prototype[method] as (...args: unknown[]) => IDBRequest;
        let calls = 0;
        return jest.spyOn(IDBObjectStore.prototype, method).mockImplementation(function (
            this: IDBObjectStore,
            ...args: unknown[]
        ) {
            const place = () => original.apply(this, args);
            return ++calls === nth ? fault(this, place) : place();
        } as never);
    }

    afterEach(async () => {
        jest.restoreAllMocks();
        mockEncoding.failing = undefined;
        mockEncoding.observe = undefined;
        mockEncoding.decoded = undefined;
        subscriptions.closeAll();
        for (const channel of channels.splice(0)) channel.close();
        for (const db of rawConnections.splice(0)) db.close();
        for (const store of opened.splice(0)) store.close();
        for (const name of names) await deleteIndexedDbStore(name);
        names.clear();
    });

    describe('open, close and delete', () => {
        it('reports that it created the database on the first open only', async () => {
            const first = await openStore();
            expect(first.store.created).toBe(true);
            expect(first.store.name).toBe(first.name);
            await putOne(first.client, 'a');
            first.store.close();

            const second = await openStore(first.name);
            expect(second.store.created).toBe(false);
            expect(await sequenceOf(second.client)).toBe(1n);
        });

        it('creates the three object stores without key path, key generator or index', async () => {
            const { name } = await openStore();
            const db = await openRaw(name);
            expect(db.version).toBe(1);
            expect([...db.objectStoreNames]).toEqual(STORES);
            const tx = db.transaction(STORES);
            for (const store of STORES.map((each) => tx.objectStore(each))) {
                expect(store.keyPath).toBeNull();
                expect(store.autoIncrement).toBe(false);
                expect([...store.indexNames]).toEqual([]);
            }
            db.close();
        });

        it('deletes a database that a store has open and leaves that store closed', async () => {
            const { name, client } = await openStore();
            await putOne(client, 'a');
            await deleteIndexedDbStore(name);
            expect((await failure(putOne(client, 'b'))).code).toBe(Code.Unavailable);

            const again = await openStore(name);
            expect(again.store.created).toBe(true);
            expect(await sequenceOf(again.client)).toBe(0n);
        });

        it('closes when another connection upgrades the database', async () => {
            const { name, client } = await openStore();
            const upgraded = await openRaw(name, 2);
            upgraded.close();
            const error = await failure(client.query.get({ key: bytes() }));
            expect(error.code).toBe(Code.Unavailable);
            expect(error.rawMessage).toBe('store is closed');
        });

        it.each([
            ['an object store missing', ['kv', 'log']],
            ['an object store too many', [...STORES, 'other']],
        ])('refuses a database with %s and leaves it as it is', async (_, stores) => {
            const name = freshDatabaseName();
            names.add(name);
            (await openRaw(name, 1, stores)).close();
            await expect(openIndexedDbStore(name)).rejects.toThrow(/does not have the layout/);
            const db = await openRaw(name);
            expect([...db.objectStoreNames]).toEqual([...stores].sort());
            db.close();
        });

        it('refuses a database of a newer layout version and leaves it as it is', async () => {
            const name = freshDatabaseName();
            names.add(name);
            (await openRaw(name, 2)).close();
            await expect(openIndexedDbStore(name)).rejects.toThrow(/layout version/);
            const db = await openRaw(name);
            expect(db.version).toBe(2);
            db.close();
        });

        it.each<[string, IndexedDbStoreOptions]>([
            ['maxPutEntries 0', { maxPutEntries: 0 }],
            ['a negative maxValueLen', { maxValueLen: -1 }],
            ['a fractional maxRequestBytes', { maxRequestBytes: 1.5 }],
            ['maxQueryBytes that is not a number', { maxQueryBytes: Number.NaN }],
            ['maxPutEntries above 2,000,000', { maxPutEntries: MAX_PUT_ENTRIES + 1 }],
            ['maxValueLen above 32 MiB', { maxValueLen: MAX_VALUE_LEN + 1 }],
            ['maxRequestBytes above 256 MiB', { maxRequestBytes: MAX_REQUEST_MESSAGE_BYTES + 1 }],
        ])('rejects %s', async (_, options) => {
            await expect(openIndexedDbStore(freshDatabaseName(), options)).rejects.toThrow(RangeError);
        });

        it('accepts every limit of a Put at the limit of the Store API', async () => {
            expect([MAX_PUT_ENTRIES, MAX_VALUE_LEN, MAX_REQUEST_MESSAGE_BYTES]).toEqual([2_000_000, 32 << 20, 256 << 20]);
            const { client } = await openStore(undefined, {
                maxPutEntries: MAX_PUT_ENTRIES,
                maxValueLen: MAX_VALUE_LEN,
                maxRequestBytes: MAX_REQUEST_MESSAGE_BYTES,
            });
            await expect(putOne(client, 'a')).resolves.toBe(1n);
        });

        it('leaves no connection and no handler behind when it cannot open a database', async () => {
            const opens = jest.spyOn(indexedDB, 'open');
            const refused = async (name: string, reason: RegExp) => {
                names.add(name);
                await expect(openIndexedDbStore(name)).rejects.toThrow(reason);
                const request = opens.mock.results[opens.mock.results.length - 1].value as IDBOpenDBRequest;
                expect([request.onupgradeneeded, request.onsuccess, request.onerror]).toEqual([null, null, null]);

                // A connection that the failed open left behind would block the delete.
                await deleteIndexedDbStore(name);
            };

            const otherLayout = freshDatabaseName();
            (await openRaw(otherLayout, 1, ['kv'])).close();
            await refused(otherLayout, /does not have the layout/);

            const newer = freshDatabaseName();
            (await openRaw(newer, 2)).close();
            await refused(newer, /layout version/);

            jest.spyOn(globalThis, 'BroadcastChannel').mockImplementation(() => {
                throw new Error('no channel');
            });
            await refused(freshDatabaseName(), /no channel/);
        });

        it('detaches its handlers and closes its channel when it closes', async () => {
            const opens = jest.spyOn(indexedDB, 'open');
            const Channel = BroadcastChannel;
            const created: BroadcastChannel[] = [];
            jest.spyOn(globalThis, 'BroadcastChannel').mockImplementation((name) => {
                created.push(new Channel(name));
                return created[created.length - 1];
            });
            const { store, name } = await openStore();
            const db = (opens.mock.results[0].value as IDBOpenDBRequest).result;
            expect(created).toHaveLength(1);
            expect([typeof db.onversionchange, typeof db.onclose, typeof created[0].onmessage]).toEqual(
                ['function', 'function', 'function'],
            );

            store.close();
            expect([db.onversionchange, db.onclose, created[0].onmessage]).toEqual([null, null, null]);
            expect(() => created[0].postMessage(new Uint8Array(8))).toThrow();

            const deletes = jest.spyOn(indexedDB, 'deleteDatabase');
            await deleteIndexedDbStore(name);
            const deleting = deletes.mock.results[0].value as IDBOpenDBRequest;
            expect([deleting.onsuccess, deleting.onerror]).toEqual([null, null]);
        });

        it('fails every call with UNAVAILABLE after close', async () => {
            const { store, client } = await openStore();
            store.close();
            store.close();
            const calls: (() => Promise<unknown> | AsyncIterable<unknown>)[] = [
                () => putOne(client, 'a'),
                () => client.query.get({ key: bytes() }),
                () => client.query.getMany({ keys: [bytes()], batchSize: 1 }),
                () => client.query.range({ batchSize: 1 }),
                () => client.query.reduce(countRows),
                () => client.stream.get({ sequenceNumber: 1n }),
                () => client.stream.subscribe({ selectors: [everyKey] }),
                () => client.retention.setRetention({}),
                () => client.prune.prune({ policies: [] }),
            ];
            await expectEveryCallFails(calls, Code.Unavailable, 'store is closed');
        });
    });

    describe('layout', () => {
        it('stores rows, batches and meta rows in the forms of the layout document', async () => {
            const { name, client } = await openStore();
            const first: Row[] = [[bytes(), utf8('empty key')], [utf8('k'), bytes()], [utf8('k'), utf8('again')]];
            const second: Row[] = [[new Uint8Array(254).fill(7), new Uint8Array(1000).fill(1)]];
            await put(client, first);
            await client.retention.setRetention({ policy: { kind: { case: 'keepLatest', value: { count: 5n } } } });
            await put(client, second);

            const { kv, log, meta } = await rawRows(name);

            // Every key is an ArrayBuffer. Every value is an ArrayBuffer or a view of its whole
            // buffer, so no stored row holds bytes beyond its own.
            for (const { key, value } of [...kv, ...log, ...meta]) {
                expect(key).toBeInstanceOf(ArrayBuffer);
                if (value instanceof Uint8Array) {
                    expect([value.byteOffset, value.buffer.byteLength]).toEqual([0, value.byteLength]);
                } else {
                    expect(value).toBeInstanceOf(ArrayBuffer);
                }
            }
            expect(kv.map(({ key, value }) => [storedHex(key), storedHex(value)])).toEqual([
                ['', hex(utf8('empty key'))],
                [hex(second[0][0]), hex(second[0][1])],
                [hex(utf8('k')), hex(utf8('again'))],
            ]);

            expect(log.map(({ key }) => storedHex(key))).toEqual([hex(be64(1n)), hex(be64(2n))]);
            for (const [index, rows] of [first, second].entries()) {
                const batch = fromBinary(GetResponseSchema, new Uint8Array(log[index].value as ArrayBuffer));
                expect(batch.sequenceNumber).toBe(BigInt(index + 1));
                expect(batch.entries.map((entry) => [hex(entry.key), hex(entry.value)])).toEqual(
                    rows.map(([key, value]) => [hex(key), hex(value)]),
                );
            }

            expect(meta.map(({ key }) => new TextDecoder().decode(key as ArrayBuffer))).toEqual(['retention', 'sequence']);
            const rule = fromBinary(RetentionPolicySchema, new Uint8Array(meta[0].value as ArrayBuffer));
            expect(rule.kind).toMatchObject({ case: 'keepLatest', value: { count: 5n } });
            expect(storedHex(meta[1].value)).toBe(hex(be64(2n)));
        });

        it('passes every key as an ArrayBuffer and every value as a buffer of its own', async () => {
            const puts = jest.spyOn(IDBObjectStore.prototype, 'put');
            const { client } = await openStore();
            await put(client, [[bytes(), utf8('a')], [utf8('key'), bytes()]]);
            await client.retention.setRetention({ policy: { kind: { case: 'dropAll', value: {} } } });
            expect(puts.mock.calls.length).toBeGreaterThanOrEqual(5);
            for (const [value, key] of puts.mock.calls) {
                expect(key).toBeInstanceOf(ArrayBuffer);
                expect(value).toBeInstanceOf(ArrayBuffer);
            }
        });

        it('runs each operation in one transaction with the scope, mode and durability of the layout', async () => {
            const { client } = await openStore();
            const { spy, calls } = spyOnTransactions();
            const dropAll = { case: 'dropAll' as const, value: {} };
            const operations: [unknown[], () => Promise<unknown>][] = [
                [PUT_SCOPE, () => put(client, [[utf8('a'), bytes(1)], [utf8('b'), bytes(2)]])],
                [QUERY_SCOPE, () => client.query.get({ key: utf8('a') })],
                [QUERY_SCOPE, () => collect(client.query.getMany({ keys: [utf8('a'), utf8('b')], batchSize: 1 }))],
                [QUERY_SCOPE, () => collect(client.query.range({ batchSize: 1 }))],
                [QUERY_SCOPE, () => collect(client.query.reduce(countRows))],
                [LOG_SCOPE, () => client.stream.get({ sequenceNumber: 1n })],
                [[['log', 'meta'], 'readwrite', 'strict'], () =>
                    client.retention.setRetention({ policy: { kind: { case: 'keepLatest', value: { count: 9n } } } })],
                [[['kv'], 'readwrite', 'strict'], () =>
                    client.prune.prune({
                        policies: [{ keys: { selector: everyKey }, retain: { kind: dropAll } }],
                    })],
            ];
            for (const [expected, run] of operations) {
                spy.mockClear();
                await run();
                expect(calls()).toEqual([expected]);
            }

            // A subscription reads one batch per transaction. It reads the two it replays, then
            // looks for the one that is not written yet.
            await putOne(client, 'c');
            spy.mockClear();
            const frames = subscribe(client, { selectors: [everyKey], sinceSequenceNumber: 1n });
            await nextWithTimeout(frames);
            await nextWithTimeout(frames);
            const waiting = nextWithTimeout(frames);
            await until(() => calls().length >= 3);
            expect(calls()).toEqual([LOG_SCOPE, LOG_SCOPE, LOG_SCOPE]);
            await putOne(client, 'd');
            await waiting;
        });

        it('reads a database that another writer filled in every form the layout allows', async () => {
            const name = freshDatabaseName();
            const batches: Row[][] = [
                [[bytes(), utf8('one')], [utf8('view'), utf8('offset')]],
                [[utf8('buffer'), bytes()]],
            ];
            const rule = toBinary(
                RetentionPolicySchema,
                create(RetentionPolicySchema, { kind: { case: 'keepLatest', value: { count: 2n } } }),
            );
            (await openRaw(name)).close();
            await withRaw(name, 'readwrite', ({ kv, log, meta }) => {
                kv.put(utf8('one'), new ArrayBuffer(0));
                kv.put(offsetView(utf8('offset')), exact(utf8('view')));
                kv.put(new ArrayBuffer(0), exact(utf8('buffer')));
                log.put(exact(encodedBatch(1n, batches[0])), exact(be64(1n)));
                log.put(offsetView(encodedBatch(2n, batches[1])), exact(be64(2n)));
                meta.put(offsetView(be64(2n)), asciiKey('sequence'));
                meta.put(rule, asciiKey('retention'));
            });

            // Rows stored as views at an offset, as exact buffers and as empty buffers all read
            // back as the bytes they hold.
            const { store, client } = await openStore(name);
            expect(store.created).toBe(false);
            const { sequenceNumber, rows } = await allRows(client);
            expect(sequenceNumber).toBe(2n);
            expect(rows.map(([key, value]) => [hex(key), hex(value)])).toEqual([
                ['', hex(utf8('one'))],
                [hex(utf8('buffer')), ''],
                [hex(utf8('view')), hex(utf8('offset'))],
            ]);
            expect((await client.query.get({ key: utf8('view') })).value).toEqual(utf8('offset'));

            // A subscription replays both stored batches in order.
            const frames = subscribe(client, { selectors: [everyKey], sinceSequenceNumber: 1n });
            for (const [index, batch] of batches.entries()) {
                const value = await nextFrame(frames);
                expect(value.sequenceNumber).toBe(BigInt(index + 1));
                expect(value.entries.map((entry) => [hex(entry.key), hex(entry.value)])).toEqual(
                    batch.map(([key, value]) => [hex(key), hex(value)]),
                );
            }

            // The next Put continues the sequence and applies the stored rule.
            await expect(putOne(client, 'next')).resolves.toBe(3n);
            expect((await failure(client.stream.get({ sequenceNumber: 1n }))).code).toBe(Code.OutOfRange);
            await expect(client.stream.get({ sequenceNumber: 2n })).resolves.toMatchObject({ sequenceNumber: 2n });
        });

        it.each([
            ['a number of the same encoded width', 5n],
            ['a number of another encoded width', 127n],
        ])('numbers a batch after %s that another connection wrote', async (_, sequenceNumber) => {
            const { name, client } = await openStore();
            await withRaw(name, 'readwrite', ({ meta }) => {
                meta.put(exact(be64(sequenceNumber)), asciiKey('sequence'));
            });
            const rows: Row[] = [[utf8('a'), utf8('1')], [utf8('b'), utf8('2')]];
            await expect(put(client, rows)).resolves.toBe(sequenceNumber + 1n);
            const batch = await client.stream.get({ sequenceNumber: sequenceNumber + 1n });
            expect(batch.entries.map((entry) => [hex(entry.key), hex(entry.value)])).toEqual(
                rows.map(([key, value]) => [hex(key), hex(value)]),
            );
        });
    });

    describe('atomic writes', () => {
        const BATCH = 1100;
        const batch = Array.from({ length: BATCH }, (_, i): Row => [be64(BigInt(i)), utf8('new')]);
        const drop = { kind: { case: 'dropAll' as const, value: {} } };
        const prunePolicy: MessageInitShape<typeof PolicySchema> = {
            keys: { selector: { prefix: bytes(), payloadRegex: '(?s-u)^.{8}$' } },
            retain: drop,
        };

        /** A store with rows, a rule and two batches, and its content before the test's write. */
        async function filled() {
            const opened = await openStore();
            await put(opened.client, batch.slice(0, 1050).map(([key]): Row => [key, utf8('old')]));
            await put(opened.client, [[utf8('other'), utf8('old')]]);
            await opened.client.retention.setRetention({ policy: { kind: { case: 'keepLatest', value: { count: 1n } } } });
            return { ...opened, before: await contentOf(opened.name) };
        }

        const throwing = () => {
            throw new Error('cannot place the request');
        };

        // Calls 1 to 1100 write rows, in chunks of 1024. Call 1101 writes the batch and 1102 the
        // sequence number.
        it.each([1, 2, 1024, 1025, 1100, 1101, 1102])(
            'leaves nothing of a Put whose put call %i throws',
            async (nth) => {
                const { name, client, before } = await filled();
                const fault = onCall('put', nth, throwing);
                const error = await failure(put(client, batch));
                expect([error.code, error.rawMessage]).toEqual([Code.Internal, 'internal error']);
                fault.mockRestore();
                expect(await contentOf(name)).toEqual(before);
                await expect(putOne(client, 'after')).resolves.toBe(3n);
            },
        );

        it('leaves nothing of a Put whose delete of evicted batches throws', async () => {
            const { name, client, before } = await filled();
            onCall('delete', 1, throwing);
            expect((await failure(put(client, batch))).code).toBe(Code.Internal);
            expect(await contentOf(name)).toEqual(before);
        });

        it.each([1, 1024, 1025, 1050])('leaves nothing of a Prune whose delete call %i throws', async (nth) => {
            const { name, client, before } = await filled();
            onCall('delete', nth, throwing);
            expect((await failure(client.prune.prune({ policies: [prunePolicy] }))).code).toBe(Code.Internal);
            expect(await contentOf(name)).toEqual(before);
        });

        it.each<['put' | 'delete', string]>([
            ['put', 'the rule'],
            ['delete', 'the evicted batches'],
        ])('leaves nothing of a SetRetention whose %s of %s throws', async (method) => {
            const { name, client, before } = await filled();
            await putOne(client, 'third');
            const third = await contentOf(name);
            expect(third).not.toEqual(before);
            onCall(method, 1, throwing);
            const policy = { kind: { case: 'greaterThan' as const, value: { threshold: 2n } } };
            expect((await failure(client.retention.setRetention({ policy }))).code).toBe(Code.Internal);
            expect(await contentOf(name)).toEqual(third);
        });

        it.each([1, 1024, 1102])(
            'leaves nothing of a Put whose transaction aborts after request %i',
            async (nth) => {
                const { name, client, before } = await filled();
                onCall('put', nth, (store, place) => {
                    const request = place();
                    store.transaction.abort();
                    return request;
                });
                const error = await failure(put(client, batch));

                // Requests that the handler places after the abort are refused, and the one it
                // waits for fails with the abort. Either way the failure names its kind only.
                expect(error.code).toBe(Code.Internal);
                expect(error.rawMessage).toMatch(/^indexeddb transaction failed: (Abort|TransactionInactive)Error$/);
                expect(await contentOf(name)).toEqual(before);
                jest.restoreAllMocks();
                await expect(putOne(client, 'after')).resolves.toBe(3n);
            },
        );

        it('fails a Put whose transaction aborts after its last request succeeded', async () => {
            const { name, client, before } = await filled();
            onCall('delete', 1, (store, place) => {
                const request = place();
                request.addEventListener('success', () => store.transaction.abort());
                return request;
            });
            expect((await failure(put(client, batch))).code).toBe(Code.Internal);
            expect(await contentOf(name)).toEqual(before);
        });

        it('reports a transaction that runs out of space as RESOURCE_EXHAUSTED and leaves nothing', async () => {
            const { name, client, before } = await filled();
            onCall('delete', 1, (store, place) => {
                const request = place();

                // fake-indexeddb has no quota. Its transactions abort with a named error through
                // this method, as a browser does when a commit exceeds the quota.
                (store.transaction as unknown as { _abort(name: string): void })._abort('QuotaExceededError');
                return request;
            });
            const error = await failure(put(client, batch));
            expect([error.code, error.rawMessage]).toEqual([Code.ResourceExhausted, 'store is out of space']);
            expect(await contentOf(name)).toEqual(before);
        });

        it('reports a quota error that has an interface of its own as RESOURCE_EXHAUSTED', () => {
            class QuotaExceededError extends DOMException {
                get [Symbol.toStringTag]() {
                    return 'QuotaExceededError';
                }
            }
            const error = toConnectError(new QuotaExceededError('', 'QuotaExceededError'));
            expect([error.code, error.rawMessage]).toEqual([Code.ResourceExhausted, 'store is out of space']);
        });

        it.each<[string, (stores: Record<string, IDBObjectStore>) => void, string]>([
            ['a sequence row of 7 bytes', ({ meta }) => meta.put(new ArrayBuffer(7), asciiKey('sequence')), 'store metadata is corrupt'],
            ['a sequence row that is not bytes', ({ meta }) => meta.put('7', asciiKey('sequence')), 'store metadata is corrupt'],
            ['a retention row that does not decode', ({ meta }) => meta.put(exact(bytes(0xff, 0xff)), asciiKey('retention')), 'store metadata is corrupt'],
            ['a retention row without a rule', ({ meta }) => meta.put(new ArrayBuffer(0), asciiKey('retention')), 'store metadata is corrupt'],
            ['the highest sequence number', ({ meta }) => meta.put(exact(be64(MAX_U64)), asciiKey('sequence')), 'store sequence numbers are exhausted'],
        ])('refuses a Put over %s before its first write', async (_, damage, message) => {
            const { name, client } = await filled();
            await withRaw(name, 'readwrite', damage);
            const before = await contentOf(name);
            const writes = [
                jest.spyOn(IDBObjectStore.prototype, 'put'),
                jest.spyOn(IDBObjectStore.prototype, 'delete'),
            ];
            const error = await failure(put(client, batch));
            expect([error.code, error.rawMessage]).toEqual([Code.Internal, message]);
            for (const write of writes) expect(write).not.toHaveBeenCalled();
            jest.restoreAllMocks();
            expect(await contentOf(name)).toEqual(before);
        });

        it('refuses a SetRetention over a malformed sequence row before its first write', async () => {
            const { name, client } = await filled();
            await withRaw(name, 'readwrite', ({ meta }) => meta.put(new ArrayBuffer(9), asciiKey('sequence')));
            const puts = jest.spyOn(IDBObjectStore.prototype, 'put');
            const error = await failure(client.retention.setRetention({ policy: drop }));
            expect([error.code, error.rawMessage]).toEqual([Code.Internal, 'store metadata is corrupt']);
            expect(puts).not.toHaveBeenCalled();
        });

        it('reads the oldest batch for the answer of a SetRetention before its first write', async () => {
            const { client } = await filled();
            await putOne(client, 'third');
            const reads = jest.spyOn(IDBObjectStore.prototype, 'openKeyCursor');
            const writes = [
                jest.spyOn(IDBObjectStore.prototype, 'put'),
                jest.spyOn(IDBObjectStore.prototype, 'delete'),
            ];
            const policy = { kind: { case: 'greaterThan' as const, value: { threshold: 2n } } };
            const answer = await client.retention.setRetention({ policy });
            expect(answer.oldestRetainedSequence).toBe(3n);
            expect(reads).toHaveBeenCalledTimes(1);
            for (const write of writes) {
                expect(write).toHaveBeenCalledTimes(1);
                expect(reads.mock.invocationCallOrder[0]).toBeLessThan(write.mock.invocationCallOrder[0]);
            }
        });

        it('refuses a SetRetention over a malformed oldest log key before its first write', async () => {
            const { name, client } = await filled();
            await putOne(client, 'third');

            // The rule below keeps the batches from 3 on, and the first key from there has 9 bytes.
            await withRaw(name, 'readwrite', ({ log }) => {
                log.delete(exact(be64(3n)));
                log.put(exact(encodedBatch(3n, [[utf8('a'), utf8('v')]])), exact(concat(be64(3n), bytes(0))));
            });
            const before = await contentOf(name);
            const writes = [
                jest.spyOn(IDBObjectStore.prototype, 'put'),
                jest.spyOn(IDBObjectStore.prototype, 'delete'),
            ];
            const policy = { kind: { case: 'greaterThan' as const, value: { threshold: 2n } } };
            const error = await failure(client.retention.setRetention({ policy }));
            expect([error.code, error.rawMessage]).toEqual([Code.Internal, 'store data is corrupt']);
            for (const write of writes) expect(write).not.toHaveBeenCalled();
            jest.restoreAllMocks();
            expect(await contentOf(name)).toEqual(before);
        });

        it('opens no transaction for a Put that fails while it prepares its batch', async () => {
            const { client } = await openStore();
            const { calls } = spyOnTransactions();
            mockEncoding.failing = GetResponseSchema.typeName;
            expect((await failure(putOne(client, 'a'))).code).toBe(Code.Internal);
            expect(calls()).toEqual([]);
            mockEncoding.failing = undefined;
            await expect(putOne(client, 'a')).resolves.toBe(1n);
        });
    });

    describe('query budget', () => {
        // Four rows of a 1 byte key and a 35 byte value cost 4 * (1 + 35 + 64) bytes.
        const rows = [1, 2, 3, 4].map((n): Row => [bytes(n), new Uint8Array(35)]);
        const COST = 400;

        async function withBudget(maxQueryBytes: number) {
            const filled = await openStore();
            await put(filled.client, rows);
            return (await openStore(filled.name, { maxQueryBytes })).client;
        }

        it.each<[string, (client: Client) => AsyncIterable<{ results: unknown[] }>, string]>([
            ['Range', (client) => client.query.range({ batchSize: 1 }), 'range result'],
            [
                'GetMany',
                (client) => client.query.getMany({ keys: rows.map(([key]) => key), batchSize: 1 }),
                'get_many result',
            ],
        ])('%s answers within the budget and fails one byte above it before any frame', async (_, query, subject) => {
            const frames = await collect(query(await withBudget(COST)));
            expect(frames.flatMap((frame) => frame.results)).toHaveLength(rows.length);

            let received = 0;
            const error = await failure((async function* () {
                for await (const frame of query(await withBudget(COST - 1))) {
                    received++;
                    yield frame;
                }
            })());
            expect(error.code).toBe(Code.ResourceExhausted);
            expect(error.rawMessage).toBe(`${subject} exceeds the store's query memory limit of ${COST - 1} bytes`);
            expect(received).toBe(0);
        });

        it('GetMany refuses more keys than the budget has room for without reading', async () => {
            const client = await withBudget(3 * 64);
            const { calls } = spyOnTransactions();
            const missing = (count: number) => Array.from({ length: count }, (_, i) => bytes(100 + i));
            await collect(client.query.getMany({ keys: [bytes(), bytes(), bytes()], batchSize: 1 }));
            expect(calls()).toEqual([QUERY_SCOPE]);
            const error = await failure(client.query.getMany({ keys: missing(4), batchSize: 1 }));
            expect(error.code).toBe(Code.ResourceExhausted);
            expect(calls()).toEqual([QUERY_SCOPE]);
        });

        it('GetMany reads no further value after the one that exceeds the budget', async () => {
            const filled = await openStore();
            await put(filled.client, [[bytes(1), new Uint8Array(1000)]]);
            const { client } = await openStore(filled.name, { maxQueryBytes: 8 * 64 });
            const original = IDBObjectStore.prototype.get;
            let rowReads = 0;
            jest.spyOn(IDBObjectStore.prototype, 'get').mockImplementation(function (
                this: IDBObjectStore,
                query: IDBValidKey | IDBKeyRange,
            ) {
                if (this.name === 'kv') rowReads++;
                return original.call(this, query);
            });
            const keys = Array.from({ length: 8 }, () => bytes(1));
            const error = await failure(client.query.getMany({ keys, batchSize: 1 }));
            expect(error.code).toBe(Code.ResourceExhausted);
            expect(rowReads).toBe(1);
        });

        it('holds a value that was stored as a view of a larger buffer in a buffer of its own length', async () => {
            const name = freshDatabaseName();
            const large = new Uint8Array(1 << 16).fill(7);
            (await openRaw(name)).close();
            await withRaw(name, 'readwrite', ({ kv }) => {
                kv.put(large.subarray(100, 101), exact(bytes(1)));
                kv.put(large.subarray(0, 2), exact(bytes(2)));
            });
            const stored = (await rawRows(name)).kv.map(({ value }) => (value as Uint8Array).buffer.byteLength);
            expect(stored).toEqual([large.byteLength, large.byteLength]);

            // The budget has room for the three bytes of the two values and nothing more.
            const { client } = await openStore(name, { maxQueryBytes: 2 * (1 + 64) + 3 });
            const held: number[][] = [];
            mockEncoding.observe = (typeName, message) => {
                const values =
                    typeName === 'store.query.v1.GetResponse'
                        ? [(message as { value?: Uint8Array }).value]
                        : /^store\.query\.v1\.(Range|GetMany)Frame$/.test(typeName)
                          ? (message as { results: { value?: Uint8Array }[] }).results.map(({ value }) => value)
                          : [];
                for (const value of values) {
                    if (value !== undefined) held.push([value.byteLength, value.buffer.byteLength]);
                }
            };
            const frames = [
                ...(await collect(client.query.range({ batchSize: 10 }))),
                ...(await collect(client.query.getMany({ keys: [bytes(1), bytes(2)], batchSize: 10 }))),
            ];
            const got = await client.query.get({ key: bytes(1) });
            expect([...frames.flatMap((frame) => frame.results.map(({ value }) => value)), got.value]).toEqual(
                [bytes(7), bytes(7, 7), bytes(7), bytes(7, 7), bytes(7)],
            );
            expect(held).toEqual([[1, 1], [2, 2], [1, 1], [2, 2], [1, 1]]);
        });

        it('Get answers a row within the budget and fails one byte above it', async () => {
            const within = await withBudget(COST / rows.length);
            expect((await within.query.get({ key: bytes(1) })).value).toHaveLength(35);
            const error = await failure((await withBudget(COST / rows.length - 1)).query.get({ key: bytes(1) }));
            expect([error.code, error.rawMessage]).toEqual([
                Code.ResourceExhausted,
                "get result exceeds the store's query memory limit of 99 bytes",
            ]);
        });

        it('Prune fails before any delete when the keys it selects exceed the budget', async () => {
            // The first policy holds 3 keys of 3 bytes. The second holds 3 keys of 11 bytes, each
            // with an order value of 8 bytes, in 2 groups whose identities take 2 bytes each. A
            // policy holds the matcher of its pattern only while it selects, so one matcher is
            // held at a time, and the selection is largest while the second policy selects.
            const versionedPattern = '(?s-u)^(?P<g>[a-z])(?P<v>.{8})$';
            const MATCHER = Regex.compile(versionedPattern).capturerBytes(['g', 'v']);
            const SELECTION = 3 * (3 + 64) + 3 * (11 + 8 + 64) + 2 * 2 + MATCHER;
            const versioned = (group: string, version: bigint) =>
                new Uint8Array([...utf8(`b/` + group), ...be64(version)]);
            const kept = [utf8('c/1'), versioned('x', 2n), versioned('y', 1n)];
            const dropped = [utf8('a/1'), utf8('a/2'), utf8('a/3'), versioned('x', 1n)];
            const policies: MessageInitShape<typeof PolicySchema>[] = [
                {
                    keys: { selector: { prefix: utf8('a/'), payloadRegex: '.' } },
                    retain: { kind: { case: 'dropAll', value: {} } },
                },
                {
                    keys: {
                        selector: { prefix: utf8('b/'), payloadRegex: versionedPattern },
                        groupBy: { captureGroups: ['g'] },
                        orderBy: { captureGroup: 'v', encoding: PolicyOrderEncoding.U64_BE },
                    },
                    retain: { kind: { case: 'keepLatest', value: { count: 1n } } },
                },
            ];
            const filled = await openStore();
            await put(filled.client, [...kept, ...dropped].map((key): Row => [key, bytes(1)]));
            const before = await contentOf(filled.name);

            // One byte below the selection's cost, the Prune fails before its first delete.
            const short = (await openStore(filled.name, { maxQueryBytes: SELECTION - 1 })).client;
            const deletes = jest.spyOn(IDBObjectStore.prototype, 'delete');
            const error = await failure(short.prune.prune({ policies }));
            expect([error.code, error.rawMessage]).toEqual([
                Code.ResourceExhausted,
                `prune selection exceeds the store's query memory limit of ${SELECTION - 1} bytes`,
            ]);
            expect(deletes).not.toHaveBeenCalled();
            jest.restoreAllMocks();
            expect(await contentOf(filled.name)).toEqual(before);

            // At exactly the selection's cost, the Prune runs and leaves only the kept keys.
            const enough = (await openStore(filled.name, { maxQueryBytes: SELECTION })).client;
            await enough.prune.prune({ policies });
            expect((await contentOf(filled.name)).kv.map(([key]) => key)).toEqual(kept.map(hex).sort());
        });
    });

    describe('two connections to one database', () => {
        async function pair() {
            const first = await openStore();
            const second = await openStore(first.name);
            return { name: first.name, a: first.client, b: second.client };
        }

        it('numbers interleaved and concurrent Puts once each without a gap in the log', async () => {
            const { name, a, b } = await pair();
            const sequences: bigint[] = [];
            for (let i = 0; i < 6; i++) sequences.push(await putOne(i % 2 === 0 ? a : b, `serial-${i}`));
            const concurrent = Array.from({ length: 30 }, (_, i) => putOne(i % 2 === 0 ? a : b, `concurrent-${i}`));
            sequences.push(...(await Promise.all(concurrent)));

            const expected = Array.from({ length: 36 }, (_, i) => BigInt(i + 1));
            expect([...sequences].sort((x, y) => Number(x - y))).toEqual(expected);
            const { log, meta } = await contentOf(name);
            expect(log.map(([key]) => key)).toEqual(expected.map((n) => hex(be64(n))));
            expect(meta).toEqual([[hex(utf8('sequence')), hex(be64(36n))]]);
        });

        it('wakes a subscriber of one connection for a Put of the other', async () => {
            const { a, b } = await pair();
            const { waiting } = watchWaiters();
            const frames = subscribe(a, { selectors: [everyKey], sinceSequenceNumber: 1n });
            const next = nextFrame(frames);
            await waiting();
            await putOne(b, 'from-b', 'hello');
            const value = await next;
            expect(value.sequenceNumber).toBe(1n);
            expect(value.entries.map((entry) => hex(entry.key))).toEqual([hex(utf8('from-b'))]);
        });

        it('wakes subscribers for a well formed notification only', async () => {
            const { name, client } = await openStore();
            const wakes = jest.spyOn(Notifier.prototype, 'wake');
            const channel = openChannel(name);
            channel.postMessage(new Uint8Array(7));
            channel.postMessage('12345678');
            channel.postMessage(new Uint8Array(8).buffer);

            // A channel delivers its messages in order, so the three above have arrived when
            // the well formed one wakes the store.
            channel.postMessage(new Uint8Array(8));
            await until(() => wakes.mock.calls.length > 0);
            expect(wakes).toHaveBeenCalledTimes(1);
            expect(await sequenceOf(client)).toBe(0n);
        });

        it('announces each committed Put with its sequence number as 8 bytes', async () => {
            const { name, client } = await openStore();
            const channel = openChannel(name);
            const messages: unknown[] = [];
            channel.onmessage = (event) => messages.push(event.data);
            await putOne(client, 'a');
            await putOne(client, 'b');
            await until(() => messages.length >= 2);
            expect(messages.map((message) => hex(message as Uint8Array))).toEqual([hex(be64(1n)), hex(be64(2n))]);
        });

        it('applies a retention rule set through one connection to a Put of the other', async () => {
            const { a, b } = await pair();
            await putOne(a, 'first');
            await a.retention.setRetention({ policy: { kind: { case: 'keepLatest', value: { count: 1n } } } });
            await putOne(b, 'second');
            expect((await failure(b.stream.get({ sequenceNumber: 1n }))).code).toBe(Code.OutOfRange);
            await expect(a.stream.get({ sequenceNumber: 2n })).resolves.toMatchObject({ sequenceNumber: 2n });
        });

        it('shows a write of one connection to a query of the other with its sequence number', async () => {
            const { a, b } = await pair();
            const sequenceNumber = await putOne(a, 'shared', 'value');
            const got = await b.query.get({ key: utf8('shared'), minSequenceNumber: sequenceNumber });
            expect(got.value).toEqual(utf8('value'));
            expect(got.detail?.sequenceNumber).toBe(sequenceNumber);
        });
    });

    describe('subscriptions', () => {
        it('wakes a subscriber of the connection that commits a Put', async () => {
            const { client } = await openStore();
            const { waiting } = watchWaiters();
            const frames = subscribe(client, { selectors: [everyKey], sinceSequenceNumber: 1n });
            const next = nextFrame(frames);
            await waiting();
            await putOne(client, 'a');
            expect((await next).sequenceNumber).toBe(1n);
        });

        it('does not lose a wake that arrives while it reads the log', async () => {
            const { name, client } = await openStore();
            const raw = await openRaw(name);
            const { waiting } = watchWaiters();
            const next = nextFrame(subscribe(client, { selectors: [everyKey], sinceSequenceNumber: 1n }));
            const notifier = await waiting();

            // The subscriber's next read starts, a batch is written without an announcement, and
            // a wake for it arrives before the read returns. IndexedDB runs overlapping
            // transactions in the order they were created, and the write is created right after
            // the read, so this read misses the batch and every later read sees it. No further
            // wake follows.
            const { spy } = spyOnTransactions();
            spy.mockImplementationOnce(function (this: IDBDatabase, ...args) {
                spy.mockRestore();
                const tx = this.transaction(...args);
                const write = raw.transaction(STORES, 'readwrite');
                write.objectStore('log').put(exact(encodedBatch(1n, [[utf8('a'), utf8('b')]])), exact(be64(1n)));
                write.objectStore('meta').put(exact(be64(1n)), asciiKey('sequence'));
                notifier.wake();
                return tx;
            });
            notifier.wake();
            expect((await next).sequenceNumber).toBe(1n);
        });

        it('ends a waiting subscription with CANCELED when its call is aborted and keeps no waiter', async () => {
            const { client } = await openStore();
            const { waits, waiting } = watchWaiters();
            const { frames, controller } = subscriptions.open(client, { selectors: [everyKey] });
            const next = failure(nextWithTimeout(frames));
            const notifier = await waiting();
            expect(notifier.waiting).toBe(1);
            abortCall(controller);
            expect((await next).code).toBe(Code.Canceled);
            expect(notifier.waiting).toBe(0);
            await expect(waits.mock.results[0].value).rejects.toMatchObject({ code: Code.Canceled });
        });

        it('ends waiting subscriptions with UNAVAILABLE when the store closes', async () => {
            const { store, client } = await openStore();
            const { waiting } = watchWaiters();
            const next = failure(nextWithTimeout(subscribe(client, { selectors: [everyKey] })));
            const notifier = await waiting();
            store.close();
            const error = await next;
            expect([error.code, error.rawMessage]).toEqual([Code.Unavailable, 'store is closed']);
            expect(notifier.waiting).toBe(0);
        });

        // The value matches only at its last byte, after a search that takes many slices.
        const slowToMatch = () => {
            const value = new Uint8Array(1 << 20).fill(0x61);
            value[value.length - 1] = 0x62;
            return { value, pattern: '(?s-u)a.{200}b' };
        };

        it.each<[string, (store: IndexedDbStore, name: string) => unknown]>([
            ['the store closes', (store) => store.close()],
            ['another connection upgrades the database', (_, name) => openRaw(name, 2)],
            ['the database is deleted', (_, name) => deleteIndexedDbStore(name)],
        ])('ends a subscription that is matching a batch with UNAVAILABLE and no frame when %s', async (_, end) => {
            const { store, name, client } = await openStore();
            const { value, pattern } = slowToMatch();
            const sequenceNumber = await put(client, [[utf8('large'), value]]);
            const turns = jest.spyOn(Pacer.prototype, 'turn');
            const frames = subscribe(client, {
                selectors: [everyKey],
                valueFilters: [{ kind: { case: 'regex', value: pattern } }],
                sinceSequenceNumber: sequenceNumber,
            });
            const ended = failure(nextWithTimeout(frames, 60_000));
            await until(() => turns.mock.calls.length > 0, 60_000);
            await end(store, name);
            const error = await ended;
            expect([error.code, error.rawMessage]).toEqual([Code.Unavailable, 'store is closed']);
        });

        it('delivers the batch of a slow match when nothing ends the subscription', async () => {
            const { client } = await openStore();
            const { value, pattern } = slowToMatch();
            const sequenceNumber = await put(client, [[utf8('large'), value]]);
            const frames = subscribe(client, {
                selectors: [everyKey],
                valueFilters: [{ kind: { case: 'regex', value: pattern } }],
                sinceSequenceNumber: sequenceNumber,
            });
            expect((await nextFrame(frames, 60_000)).sequenceNumber).toBe(sequenceNumber);
        });

        it('delivers no frame of a batch whose match ends as the store closes', async () => {
            const { store, client } = await openStore();
            const sequenceNumber = await putOne(client, 'k');
            const isMatch = Regex.prototype.isMatch;
            jest.spyOn(Regex.prototype, 'isMatch').mockImplementation(function (this: Regex, haystack) {
                store.close();
                return isMatch.call(this, haystack);
            });
            const frames = subscribe(client, { selectors: [everyKey], sinceSequenceNumber: sequenceNumber });
            const error = await failure(nextWithTimeout(frames));
            expect([error.code, error.rawMessage]).toEqual([Code.Unavailable, 'store is closed']);
        });

        it('searches a value in slices whenever one call could pass the step budget', async () => {
            const { client } = await openStore();

            // The longest value that the store matches in one call. A program of the largest size
            // spends the whole step budget of a slice on it.
            const direct = (1 << 16) / MAX_INSTRUCTIONS;
            const sequenceNumber = await put(client, [
                [utf8('short'), new Uint8Array(direct).fill(0x61)],
                [utf8('long'), new Uint8Array(direct + 1).fill(0x61)],
            ]);
            const matches = jest.spyOn(Regex.prototype, 'isMatch');
            const searches = jest.spyOn(Regex.prototype, 'search');
            const frames = subscribe(client, {
                selectors: [everyKey],
                valueFilters: [{ kind: { case: 'regex', value: 'a$' } }],
                sinceSequenceNumber: sequenceNumber,
            });
            expect((await nextFrame(frames)).entries).toHaveLength(2);
            expect(matches.mock.calls.map(([haystack]) => haystack.byteLength).sort((a, b) => a - b)).toEqual(
                [utf8('long').byteLength, utf8('short').byteLength, direct],
            );
            expect(searches.mock.calls.map(([haystack]) => haystack.byteLength)).toEqual([direct + 1]);
        });

        it('asks whether to yield between the filters of one value', async () => {
            const { client } = await openStore();
            const sequenceNumber = await putOne(client, 'k', 'value');
            const asked = jest.spyOn(Pacer.prototype, 'due');
            const filters = Array.from({ length: 16 }, (_, i) => ({
                kind: { case: 'regex' as const, value: `never-${i}` },
            }));
            const frames = subscribe(client, {
                selectors: [everyKey],
                valueFilters: [...filters.slice(1), { kind: { case: 'regex', value: 'value' } }],
                sinceSequenceNumber: sequenceNumber,
            });
            expect((await nextFrame(frames)).sequenceNumber).toBe(sequenceNumber);

            // Once for the entry and once before each of its 16 filters.
            expect(asked).toHaveBeenCalledTimes(17);
        });

        it('asks whether to yield before every exact and prefix filter of one value', async () => {
            const { client } = await openStore();
            const sequenceNumber = await putOne(client, 'k', 'value');
            const asked = jest.spyOn(Pacer.prototype, 'due');
            const never = (kind: 'exact' | 'prefix') =>
                Array.from({ length: 8 }, (_, i) => ({ kind: { case: kind, value: utf8(`never-${i}`) } }));
            const frames = subscribe(client, {
                selectors: [everyKey],
                valueFilters: [
                    ...never('exact'),
                    ...never('prefix').slice(1),
                    { kind: { case: 'prefix', value: utf8('val') } },
                ],
                sinceSequenceNumber: sequenceNumber,
            });
            expect((await nextFrame(frames)).sequenceNumber).toBe(sequenceNumber);

            // Once for the entry and once before each of its 16 filters.
            expect(asked).toHaveBeenCalledTimes(17);
        });

        it('compares a filter of 3 MiB in pieces and yields between them', async () => {
            const { client } = await openStore();
            const value = new Uint8Array(3 << 20).fill(7);
            const other = value.slice();
            other[other.byteLength - 1] = 8;
            const sequenceNumber = await put(client, [[utf8('k'), value]]);

            // A pacer that is always due takes a turn wherever the matching asks it.
            jest.spyOn(Pacer.prototype, 'due').mockReturnValue(true);
            const turns = jest.spyOn(Pacer.prototype, 'turn');
            const frames = subscribe(client, {
                selectors: [everyKey],
                valueFilters: [
                    { kind: { case: 'exact', value: other } },
                    { kind: { case: 'prefix', value: other } },
                    { kind: { case: 'prefix', value } },
                ],
                sinceSequenceNumber: sequenceNumber,
            });
            expect((await nextFrame(frames, 60_000)).entries).toHaveLength(1);

            // One turn for the entry, one before each filter and one before each piece of 64 KiB.
            const pieces = value.byteLength / (1 << 16);
            expect(turns).toHaveBeenCalledTimes(1 + 3 + 3 * pieces);
        });

        it('keeps the event loop running while it matches a large value', async () => {
            const { client } = await openStore();

            // Every position of the large value starts a match thread that lives for 200 more
            // bytes, so the search runs long enough to show whether it yields to the event loop.
            const large = new Uint8Array(1 << 20).fill(0x61);
            const pattern = '(?s-u)a.{200}b';
            const first = await put(client, [[utf8('large'), large]]);
            await put(client, [[utf8('small'), utf8(`a${'x'.repeat(200)}b`)]]);

            let last = performance.now();
            let longestGap = 0;
            const timer = setInterval(() => {
                const now = performance.now();
                longestGap = Math.max(longestGap, now - last);
                last = now;
            }, 1);
            const started = performance.now();
            const frames = subscribe(client, {
                selectors: [everyKey],
                valueFilters: [{ kind: { case: 'regex', value: pattern } }],
                sinceSequenceNumber: first,
            });
            const value = await nextFrame(frames, 60_000).finally(() => clearInterval(timer));
            const elapsed = performance.now() - started;

            expect(value.entries.map((entry) => hex(entry.key))).toEqual([hex(utf8('small'))]);
            expect(longestGap).toBeLessThan(Math.max(100, elapsed / 4));
        });
    });

    describe('a Put that commits while the store closes or cannot announce', () => {
        it('announces its batch to other connections and then closes the channel', async () => {
            const { store, name, client } = await openStore();
            const messages: unknown[] = [];
            openChannel(name).onmessage = (event) => messages.push(event.data);
            const closes = jest.spyOn(BroadcastChannel.prototype, 'close');

            // The store closes when the last request of the Put has succeeded, before the commit.
            const original = IDBObjectStore.prototype.put;
            let closedDuringPut = false;
            jest.spyOn(IDBObjectStore.prototype, 'put').mockImplementation(function (
                this: IDBObjectStore,
                value: unknown,
                key?: IDBValidKey,
            ) {
                const request = original.call(this, value, key);
                if (this.name === 'meta') {
                    request.addEventListener('success', () => {
                        store.close();
                        closedDuringPut = closes.mock.calls.length === 0;
                    });
                }
                return request;
            });

            await expect(putOne(client, 'a')).resolves.toBe(1n);
            expect(closedDuringPut).toBe(true);
            expect(closes).toHaveBeenCalledTimes(1);
            await until(() => messages.length > 0);
            expect(messages.map((message) => hex(message as Uint8Array))).toEqual([hex(be64(1n))]);
            expect((await failure(putOne(client, 'b'))).code).toBe(Code.Unavailable);
        });

        it('answers and wakes its own subscribers when the announcement cannot be posted', async () => {
            const { client } = await openStore();
            const { waiting } = watchWaiters();
            const next = nextFrame(subscribe(client, { selectors: [everyKey], sinceSequenceNumber: 1n }));
            await waiting();
            jest.spyOn(BroadcastChannel.prototype, 'postMessage').mockImplementation(() => {
                throw new Error('cannot post');
            });
            await expect(putOne(client, 'a')).resolves.toBe(1n);
            expect((await next).sequenceNumber).toBe(1n);
        });
    });

    describe('cancellation', () => {
        it('writes nothing for a Put that is canceled before it starts', async () => {
            const { name, client } = await openStore();
            const before = await contentOf(name);
            const { calls } = spyOnTransactions();
            const controller = new AbortController();
            const call = failure(client.ingest.put({ kvs: [{ key: utf8('a'), value: utf8('b') }] }, { signal: controller.signal }));
            abortCall(controller);
            expect((await call).code).toBe(Code.Canceled);

            // A later read that completes shows that the canceled Put is done. A Put that had
            // started would have opened its transaction before the one of this read.
            expect(await sequenceOf(client)).toBe(0n);
            expect(calls()).toEqual([QUERY_SCOPE]);
            jest.restoreAllMocks();
            expect(await contentOf(name)).toEqual(before);
        });

        it('commits and announces a Put that is canceled after its transaction started', async () => {
            const { client } = await openStore();
            const { waiting } = watchWaiters();
            const frames = subscribe(client, { selectors: [everyKey], sinceSequenceNumber: 1n });
            const delivered = nextWithTimeout(frames);
            await waiting();

            const controller = new AbortController();
            const { spy } = spyOnTransactions();
            spy.mockImplementation(function (this: IDBDatabase, ...args) {
                spy.mockRestore();
                const tx = this.transaction(...args);
                if (tx.mode === 'readwrite') abortCall(controller);
                return tx;
            });
            const call = client.ingest.put({ kvs: [{ key: utf8('a'), value: utf8('b') }] }, { signal: controller.signal });
            expect((await failure(call)).code).toBe(Code.Canceled);
            expect((await delivered).value.sequenceNumber).toBe(1n);
            expect(await sequenceOf(client)).toBe(1n);
        });

        const dropUnder = (prefix: string): MessageInitShape<typeof PolicySchema> => ({
            keys: { selector: { prefix: utf8(prefix), payloadRegex: '(?s-u).*' } },
            retain: { kind: { case: 'dropAll', value: {} } },
        });

        /**
         * A store of three rows under a/, and a signal that aborts during the nth call of `method`
         * on an object store. `calls` spies on that method, `steps` on the steps of cursors and
         * `aborts` on the transactions that the store aborts.
         */
        async function canceledDuring(method: 'get' | 'openCursor' | 'openKeyCursor', nth: number) {
            const { name, client } = await openStore();
            await put(client, [1, 2, 3].map((i): Row => [utf8('a/' + i), utf8('v')]));
            const before = await contentOf(name);
            const controller = new AbortController();
            const calls = onCall(method, nth, (_, place) => {
                abortCall(controller);
                return place();
            });
            const steps = jest.spyOn(IDBCursor.prototype, 'continue');
            const aborts = jest.spyOn(IDBTransaction.prototype, 'abort');
            return { name, client, before, signal: controller.signal, calls, steps, aborts };
        }

        it('ends the transaction of a Range at the next row when its call is canceled', async () => {
            // The call is canceled as the scan opens its cursor, so the scan stops at the first row
            // and never steps the cursor.
            const { client, signal, steps, aborts } = await canceledDuring('openCursor', 1);
            expect((await failure(client.query.range({ batchSize: 10 }, { signal }))).code).toBe(Code.Canceled);
            await until(() => aborts.mock.calls.length > 0);
            expect(aborts).toHaveBeenCalledTimes(1);
            expect(steps).not.toHaveBeenCalled();
        });

        it('ends the transaction of a GetMany at the next key when its call is canceled', async () => {
            // Call 1 reads the sequence number and call 2 the first key. The call is canceled
            // during call 2, so no other key is read.
            const { client, signal, calls, aborts } = await canceledDuring('get', 2);
            const keys = [1, 2, 3].map((i) => utf8('a/' + i));
            expect((await failure(client.query.getMany({ keys, batchSize: 10 }, { signal }))).code).toBe(Code.Canceled);
            await until(() => aborts.mock.calls.length > 0);
            expect(aborts).toHaveBeenCalledTimes(1);
            expect(calls).toHaveBeenCalledTimes(2);
        });

        it('deletes nothing for a Prune that is canceled while it selects its keys', async () => {
            // The call is canceled as the key cursor opens, so the scan stops at the first key.
            const { name, client, before, signal, steps, aborts } = await canceledDuring('openKeyCursor', 1);
            const deletes = jest.spyOn(IDBObjectStore.prototype, 'delete');
            const call = client.prune.prune({ policies: [dropUnder('a/')] }, { signal });
            expect((await failure(call)).code).toBe(Code.Canceled);
            await until(() => aborts.mock.calls.length > 0);
            expect(aborts).toHaveBeenCalledTimes(1);
            expect(steps).not.toHaveBeenCalled();
            expect(deletes).not.toHaveBeenCalled();
            jest.restoreAllMocks();
            expect(await contentOf(name)).toEqual(before);
        });

        it('deletes nothing for a Prune that is canceled after its last key and before its first delete', async () => {
            // The second policy has no key. The call is canceled as the scan of that policy
            // starts, when the first policy has selected every row.
            const { name, client, before, signal, aborts } = await canceledDuring('openKeyCursor', 2);
            const deletes = jest.spyOn(IDBObjectStore.prototype, 'delete');
            const call = client.prune.prune({ policies: [dropUnder('a/'), dropUnder('b/')] }, { signal });
            expect((await failure(call)).code).toBe(Code.Canceled);
            await until(() => aborts.mock.calls.length > 0);
            expect(aborts).toHaveBeenCalledTimes(1);
            expect(deletes).not.toHaveBeenCalled();
            jest.restoreAllMocks();
            expect(await contentOf(name)).toEqual(before);
        });
    });

    describe('limits and hostile input', () => {
        it('refuses a request message above maxRequestBytes before the handler runs', async () => {
            const { client } = await openStore(undefined, { maxRequestBytes: 1024 });
            const { calls } = spyOnTransactions();
            const error = await failure(put(client, [[utf8('a'), new Uint8Array(2048)]]));
            expect(error.code).toBe(Code.ResourceExhausted);
            expect(error.rawMessage).toMatch(/readMaxBytes 1024/);
            expect(calls()).toEqual([]);
            await expect(put(client, [[utf8('a'), new Uint8Array(1000)]])).resolves.toBe(1n);
        });

        it('carries its request limit and its decoding options to a router that a caller builds', async () => {
            const { store } = await openStore(undefined, { maxRequestBytes: 1024 });
            const received: { $unknown?: unknown; kvs: { $unknown?: unknown }[] }[] = [];

            // A Put with a field that no message defines, in the request and in its entry.
            const undefinedField = bytes(0x78, 0x01);
            const entry = concat(bytes(0x0a, 0x01, 0x61), undefinedField);
            const request = fromBinary(
                PutRequestSchema,
                concat(bytes(0x0a, entry.byteLength), entry, undefinedField),
            );
            expect([request.$unknown?.length, request.kvs[0].$unknown?.length]).toEqual([1, 1]);

            mockEncoding.decoded = (typeName, message) => {
                if (typeName === PutRequestSchema.typeName) received.push(message as (typeof received)[0]);
            };
            for (const router of [undefined, { readMaxBytes: 1 << 30 }]) {
                const client = new Client(createRouterTransport(store.routes, { router }));
                received.length = 0;
                await client.ingest.put(request);
                expect(received).toHaveLength(1);
                expect([received[0].$unknown, received[0].kvs[0].$unknown]).toEqual([undefined, undefined]);

                const error = await failure(put(client, [[utf8('a'), new Uint8Array(2048)]]));
                expect(error.code).toBe(Code.ResourceExhausted);
                expect(error.rawMessage).toMatch(/readMaxBytes 1024/);
            }
        });

        it('refuses a Put whose entries exceed maxRequestBytes on a router that applies no message limit', async () => {
            const { store } = await openStore(undefined, { maxRequestBytes: 1024 });
            const client = new Client(withoutServiceOptions(store));

            // A request of one entry takes 3 bytes to frame the entry, 3 for a key of one byte and
            // 3 to frame the value, so a value of 1015 bytes makes a request of exactly 1024.
            await expect(put(client, [[utf8('a'), new Uint8Array(1015)]])).resolves.toBe(1n);
            const error = await failure(put(client, [[utf8('a'), new Uint8Array(1016)]]));
            expect([error.code, error.rawMessage]).toEqual([
                Code.ResourceExhausted,
                'put exceeds the request message size limit',
            ]);
        });

        it('counts the encoded entries of a Put exactly and stops at the entry that passes the limit', async () => {
            const rows: Row[] = [[bytes(), bytes()], [utf8('key'), new Uint8Array(300)], [utf8('k2'), bytes()]];
            const request = create(PutRequestSchema, { kvs: rows.map(([key, value]) => ({ key, value })) });
            const size = toBinary(PutRequestSchema, request).byteLength;
            const unlimited = async (maxRequestBytes: number) =>
                new Client(withoutServiceOptions((await openStore(undefined, { maxRequestBytes })).store));

            await expect(put(await unlimited(size), rows)).resolves.toBe(1n);
            const client = await unlimited(size - 1);
            const tooLarge = [Code.ResourceExhausted, 'put exceeds the request message size limit'];
            const error = await failure(put(client, rows));
            expect([error.code, error.rawMessage]).toEqual(tooLarge);

            // The size error comes from the entry that passes the limit, before the store checks
            // the key of a later entry.
            const later = await failure(put(client, [...rows, [new Uint8Array(255), bytes()]]));
            expect([later.code, later.rawMessage]).toEqual(tooLarge);
        });

        it('refuses a Put with more entries than maxPutEntries', async () => {
            const { client } = await openStore(undefined, { maxPutEntries: 3 });
            const rows = (count: number) => Array.from({ length: count }, (_, i): Row => [bytes(i), bytes()]);
            await expect(put(client, rows(3))).resolves.toBe(1n);
            expectFieldError(await failure(put(client, rows(4))), {
                message: 'put request exceeds size limits',
                field: 'kvs',
                description: 'put has 4 entries, exceeding the limit of 3',
                reason: 'PUT_TOO_LARGE',
                domain: 'log.ingest',
                metadata: { entries: '4', max_entries: '3' },
            });
        });

        it('refuses a value longer than maxValueLen and checks the key of an entry first', async () => {
            const { client } = await openStore(undefined, { maxValueLen: 4 });
            await expect(put(client, [[utf8('a'), new Uint8Array(4)]])).resolves.toBe(1n);
            expectFieldError(await failure(put(client, [[utf8('a'), bytes()], [utf8('b'), new Uint8Array(5)]])), {
                message: 'kvs[1].value value length is outside store limits',
                field: 'kvs[1].value',
                description: 'value length 5 exceeds maximum 4',
                reason: 'INVALID_VALUE_LENGTH',
                domain: 'log.ingest',
                metadata: { max_value_len: '4' },
            });
            const both = await failure(put(client, [[new Uint8Array(255), new Uint8Array(5)]]));
            expect(both.rawMessage).toBe('kvs[0].key key length is outside store limits');
        });

        it('opens no transaction for a request that it rejects', async () => {
            const { client } = await openStore();
            const { calls } = spyOnTransactions();
            const rejected: (() => Promise<unknown> | AsyncIterable<unknown>)[] = [
                () => client.ingest.put({ kvs: [] }),
                () => client.ingest.put({ kvs: [{ key: new Uint8Array(255) }] }),
                () => client.query.get({ key: new Uint8Array(255) }),
                () => client.query.getMany({ keys: [], batchSize: 1 }),
                () => client.query.getMany({ keys: [bytes()], batchSize: 0 }),
                () => client.query.range({ batchSize: 0 }),
                () => client.query.range({ batchSize: 1, mode: 99 as TraversalMode }),
                () => client.query.range({ batchSize: 1, end: new Uint8Array(255) }),
                () => client.query.reduce({}),
                () => client.query.reduce({ ...countRows, start: new Uint8Array(255) }),
                () => client.query.reduce({ ...countRows, end: new Uint8Array(255) }),
                () => client.stream.subscribe({}),
                () => client.stream.subscribe({ selectors: [{ payloadRegex: '(' }] }),
                () => client.stream.subscribe({ selectors: [everyKey], valueFilters: [{}] }),
                () => client.retention.setRetention({ policy: {} }),
                () => client.prune.prune({ policies: [] }),
                () => client.prune.prune({ policies: [{}] }),
            ];
            await expectEveryCallFails(rejected, Code.InvalidArgument);
            expect(calls()).toEqual([]);
        });

        const nested = (depth: number) => `${'('.repeat(depth)}a${')'.repeat(depth)}`;
        const counted = (count: number) => `a{${count}}`;
        const blocks = Math.floor(MAX_INSTRUCTIONS / MAX_REPEAT_COUNT);
        it.each<[string, string, string, string]>([
            [
                'a pattern of the longest length',
                'a pattern one character longer',
                'a'.repeat(MAX_PATTERN_CHARS),
                'a'.repeat(MAX_PATTERN_CHARS + 1),
            ],
            [
                'groups nested to the limit',
                'groups nested one deeper',
                nested(MAX_GROUP_DEPTH),
                nested(MAX_GROUP_DEPTH + 1),
            ],
            [
                'the largest repetition count',
                'a repetition count one larger',
                counted(MAX_REPEAT_COUNT),
                counted(MAX_REPEAT_COUNT + 1),
            ],
            [
                'a program within the size limit',
                'a program above the size limit',
                counted(MAX_REPEAT_COUNT).repeat(blocks),
                counted(MAX_REPEAT_COUNT).repeat(blocks + 1),
            ],
        ])('compiles %s and answers UNIMPLEMENTED for %s', async (_, __, accepted, refused) => {
            const { client } = await openStore();
            const sequenceNumber = await putOne(client, 'a'.repeat(254));
            const subscribeWith = (payloadRegex: string) =>
                nextFrame(subscribe(client, { selectors: [{ payloadRegex }, everyKey], sinceSequenceNumber: sequenceNumber }));
            const pruneWith = (payloadRegex: string) => client.prune.prune({
                policies: [{ keys: { selector: { prefix: utf8('none/'), payloadRegex } }, retain: { kind: { case: 'dropAll', value: {} } } }],
            });

            expect((await subscribeWith(accepted)).sequenceNumber).toBe(sequenceNumber);
            await pruneWith(accepted);
            const { calls } = spyOnTransactions();
            for (const call of [subscribeWith, pruneWith]) {
                const error = await failure(call(refused));
                expect(error.code).toBe(Code.Unimplemented);
                expect(error.rawMessage).toMatch(/^selector payload_regex uses regex syntax that this store does not support: /);
            }
            expect(calls()).toEqual([]);
        });

        it('answers UNIMPLEMENTED for a value filter outside the regex subset', async () => {
            const { client } = await openStore();
            const frames = subscribe(client, {
                selectors: [everyKey],
                valueFilters: [{ kind: { case: 'regex', value: '(?i)abc' } }],
            });
            const error = await failure(nextWithTimeout(frames));
            expect(error.code).toBe(Code.Unimplemented);
            expect(error.rawMessage).toMatch(/^value_filter regex uses regex syntax that this store does not support: /);
        });

        it('repeats at most 256 characters of a request in an error message', async () => {
            const { client } = await openStore();
            const policy = {
                keys: {
                    selector: { prefix: bytes(), payloadRegex: '(?P<a>.)' },
                    groupBy: { captureGroups: ['n'.repeat(100_000)] },
                },
                retain: { kind: { case: 'dropAll' as const, value: {} } },
            };
            const error = await failure(client.prune.prune({ policies: [policy] }));
            expect(error.code).toBe(Code.InvalidArgument);
            expect(error.rawMessage).toBe(
                `group_by capture_groups references unknown capture group Utf8("${'n'.repeat(256)}...")`,
            );
        });

        it('reads no more of a text than it quotes', () => {
            const iterate = String.prototype[Symbol.iterator];
            let read = 0;
            const iterator = jest.spyOn(String.prototype as never, Symbol.iterator as never);
            const spy = (iterator as unknown as jest.SpyInstance<IterableIterator<string>, []>)
                .mockImplementation(function (this: string) {
                    const characters = iterate.call(this);
                    const counted: IterableIterator<string> = {
                        next: () => {
                            read++;
                            return characters.next();
                        },
                        [Symbol.iterator]: () => counted,
                    };
                    return counted;
                });
            const text = quoted('n'.repeat(100_000));
            spy.mockRestore();
            expect(text).toBe(`"${'n'.repeat(256)}..."`);
            expect(read).toBe(257);
        });

        it('quotes up to 256 characters and counts a character outside the basic plane as one', () => {
            const smile = String.fromCodePoint(0x1f600);
            expect(quoted('n'.repeat(256))).toBe(`"${'n'.repeat(256)}"`);
            expect(quoted(`a${smile}"`)).toBe(`"a${smile}\\""`);
            expect(quoted(smile.repeat(256))).toBe(`"${smile.repeat(256)}"`);
            expect(quoted(smile.repeat(257))).toBe(`"${smile.repeat(256)}..."`);
        });

        it('refuses more Prune policies than it compiles for one request', async () => {
            const { client } = await openStore();
            await putOne(client, 'kept');
            const policies = (count: number) => Array.from({ length: count }, (_, i) => ({
                keys: { selector: { prefix: be64(BigInt(i)), payloadRegex: '.' } },
                retain: { kind: { case: 'dropAll' as const, value: {} } },
            }));
            await client.prune.prune({ policies: policies(MAX_PRUNE_POLICIES) });
            const error = await failure(client.prune.prune({ policies: policies(MAX_PRUNE_POLICIES + 1) }));
            expect(error.code).toBe(Code.ResourceExhausted);
            expect((await allRows(client)).rows).toHaveLength(1);
        });

        it('handles the highest sequence number in every request field', async () => {
            const { client } = await openStore();
            for (const key of ['a', 'b']) await putOne(client, key);

            // Reads and a subscription at the highest number treat it as a batch not yet written.
            expect((await failure(client.stream.get({ sequenceNumber: MAX_U64 }))).code).toBe(Code.NotFound);
            expect((await failure(client.query.get({ key: bytes(), minSequenceNumber: MAX_U64 }))).code).toBe(Code.Aborted);
            const watch = watchWaiters();
            const waiting = subscriptions.open(client, { selectors: [everyKey], sinceSequenceNumber: MAX_U64 });
            const ended = failure(nextWithTimeout(waiting.frames));
            await watch.waiting();
            abortCall(waiting.controller);
            expect((await ended).code).toBe(Code.Canceled);

            // A keep_latest count at the highest number keeps every batch. A threshold there keeps
            // no batch, including the next one written.
            const setRetention = async (kind: NonNullable<MessageInitShape<typeof RetentionPolicySchema>['kind']>) =>
                (await client.retention.setRetention({ policy: { kind } })).oldestRetainedSequence;
            await expect(setRetention({ case: 'keepLatest', value: { count: MAX_U64 } })).resolves.toBe(1n);
            await expect(setRetention({ case: 'greaterThanOrEqual', value: { threshold: MAX_U64 } })).resolves.toBeUndefined();
            await expect(putOne(client, 'c')).resolves.toBe(3n);
            await expect(setRetention({ case: 'greaterThan', value: { threshold: MAX_U64 } })).resolves.toBeUndefined();
            await expect(putOne(client, 'd')).resolves.toBe(4n);
            expect((await failure(client.stream.get({ sequenceNumber: 4n }))).code).toBe(Code.OutOfRange);

            // A keep_latest count at the highest number keeps every version, greater_than_or_equal
            // keeps only the highest version, and greater_than keeps none.
            const versions = [0n, 1n, MAX_U64].map((version) => be64(version));
            await put(client, versions.map((key): Row => [key, bytes()]));
            const pruneVersions = (retain: NonNullable<NonNullable<MessageInitShape<typeof PolicySchema>['retain']>['kind']>) =>
                client.prune.prune({
                    policies: [{
                        keys: {
                            selector: { prefix: bytes(), payloadRegex: '(?s-u)^(?P<v>.{8})$' },
                            orderBy: { captureGroup: 'v', encoding: PolicyOrderEncoding.U64_BE },
                        },
                        retain: { kind: retain },
                    }],
                });
            const versionsLeft = async () =>
                (await allRows(client)).rows.map(([key]) => hex(key)).filter((key) => key.length === 16);
            await pruneVersions({ case: 'keepLatest', value: { count: MAX_U64 } });
            expect(await versionsLeft()).toEqual(versions.map(hex));
            await pruneVersions({ case: 'greaterThanOrEqual', value: { threshold: MAX_U64 } });
            expect(await versionsLeft()).toEqual([hex(be64(MAX_U64))]);
            await pruneVersions({ case: 'greaterThan', value: { threshold: MAX_U64 } });
            expect(await versionsLeft()).toEqual([]);
        });

        it.each<[string, (stores: Record<string, IDBObjectStore>) => void, string]>([
            ['a sequence row of 9 bytes', ({ meta }) => meta.put(new ArrayBuffer(9), asciiKey('sequence')), 'store metadata is corrupt'],
            ['a sequence row that is an object', ({ meta }) => meta.put({ n: 1 }, asciiKey('sequence')), 'store metadata is corrupt'],
        ])('fails every read over %s', async (_, damage, message) => {
            const { name, client } = await openStore();
            await putOne(client, 'a');
            await withRaw(name, 'readwrite', damage);
            const calls: (() => Promise<unknown> | AsyncIterable<unknown>)[] = [
                () => client.query.get({ key: utf8('a') }),
                () => client.query.getMany({ keys: [utf8('a')], batchSize: 1 }),
                () => client.query.range({ batchSize: 1 }),
                () => client.query.reduce(countRows),
                () => client.stream.get({ sequenceNumber: 1n }),
                () => client.stream.subscribe({ selectors: [everyKey], sinceSequenceNumber: 1n }),
            ];
            await expectEveryCallFails(calls, Code.Internal, message);
        });

        it('fails a read of a row or a batch that is not in a form of the layout', async () => {
            const { name, client } = await openStore();
            await putOne(client, 'a');
            await putOne(client, 'b');
            await putOne(client, 'c');
            await withRaw(name, 'readwrite', ({ kv, log }) => {
                kv.put(7, exact(utf8('a')));
                kv.put('text', 'not a binary key');
                log.put(exact(bytes(0xff, 0xff, 0xff)), exact(be64(1n)));
                log.put(exact(encodedBatch(9n, [[utf8('b'), utf8('v')]])), exact(be64(2n)));
                log.put(exact(encodedBatch(3n, [])), exact(be64(3n)));
            });
            const calls: (() => Promise<unknown> | AsyncIterable<unknown>)[] = [
                () => client.query.get({ key: utf8('a') }),
                () => client.query.getMany({ keys: [utf8('b'), utf8('a')], batchSize: 1 }),
                () => client.query.range({ batchSize: 1 }),
                () => client.query.reduce(countRows),
                () => client.query.reduce({ ...countRows, start: utf8('a'), end: utf8('a') }),
                () => client.stream.get({ sequenceNumber: 1n }),
                () => client.stream.get({ sequenceNumber: 2n }),
                () => client.stream.get({ sequenceNumber: 3n }),
                () => client.stream.subscribe({ selectors: [everyKey], sinceSequenceNumber: 1n }),
            ];
            await expectEveryCallFails(calls, Code.Internal, 'store data is corrupt');
            expect((await client.query.get({ key: utf8('b') })).value).toEqual(utf8('v'));
        });

        it('treats a stored key longer than 254 bytes as corrupt data', async () => {
            const { name, client } = await openStore();
            await putOne(client, 'a');
            await putOne(client, 'b');
            const long = new Uint8Array(255);
            await withRaw(name, 'readwrite', ({ kv, log }) => {
                kv.put(new ArrayBuffer(0), exact(long));
                log.put(exact(encodedBatch(2n, [[utf8('b'), utf8('v')], [long, bytes()]])), exact(be64(2n)));
            });
            const before = await contentOf(name);
            const calls: (() => Promise<unknown> | AsyncIterable<unknown>)[] = [
                () => client.query.range({ batchSize: 1 }),
                () => client.query.reduce(countRows),
                () => client.prune.prune({
                    policies: [{ keys: { selector: everyKey }, retain: { kind: { case: 'dropAll', value: {} } } }],
                }),
                () => client.stream.get({ sequenceNumber: 2n }),
                () => client.stream.subscribe({ selectors: [everyKey], sinceSequenceNumber: 2n }),
            ];
            await expectEveryCallFails(calls, Code.Internal, 'store data is corrupt');
            expect(await contentOf(name)).toEqual(before);

            // Reads that do not reach the long key still succeed.
            await expect(client.stream.get({ sequenceNumber: 1n })).resolves.toMatchObject({ sequenceNumber: 1n });
            await expect(collect(client.query.range({ batchSize: 1, start: bytes(1) }))).resolves.toHaveLength(2);
        });

        it('treats a log row at 0 or above the sequence number as corrupt data', async () => {
            const { name, client } = await openStore();
            await putOne(client, 'a');
            await withRaw(name, 'readwrite', ({ log }) => {
                for (const sequenceNumber of [0n, 5n]) {
                    const row = encodedBatch(sequenceNumber, [[utf8('a'), utf8('v')]]);
                    log.put(exact(row), exact(be64(sequenceNumber)));
                }
            });
            const calls: (() => Promise<unknown> | AsyncIterable<unknown>)[] = [
                () => client.stream.get({ sequenceNumber: 0n }),
                () => client.stream.get({ sequenceNumber: 5n }),
                () => client.stream.subscribe({ selectors: [everyKey], sinceSequenceNumber: 5n }),
            ];
            await expectEveryCallFails(calls, Code.Internal, 'store data is corrupt');
            await expect(client.stream.get({ sequenceNumber: 1n })).resolves.toMatchObject({ sequenceNumber: 1n });
            expect((await failure(client.stream.get({ sequenceNumber: 4n }))).code).toBe(Code.NotFound);
        });

        it.each([0n, 2n])(
            'treats an oldest log key of %s in a store at sequence number 1 as corrupt data',
            async (key) => {
                const { name, client } = await openStore();
                await putOne(client, 'a');
                await withRaw(name, 'readwrite', ({ log }) => {
                    log.delete(exact(be64(1n)));
                    log.put(exact(encodedBatch(key, [[utf8('a'), utf8('v')]])), exact(be64(key)));
                });
                const before = await contentOf(name);
                const writes = [
                    jest.spyOn(IDBObjectStore.prototype, 'put'),
                    jest.spyOn(IDBObjectStore.prototype, 'delete'),
                ];

                // Batch 1 is gone, so each of these looks for the oldest batch that is left.
                const calls = [
                    () => client.stream.get({ sequenceNumber: 1n }),
                    () => client.stream.subscribe({ selectors: [everyKey], sinceSequenceNumber: 1n }),
                    () => client.retention.setRetention({}),
                    () => client.retention.setRetention({
                        policy: { kind: { case: 'keepLatest', value: { count: 5n } } },
                    }),
                ];
                await expectEveryCallFails(calls, Code.Internal, 'store data is corrupt');
                for (const write of writes) expect(write).not.toHaveBeenCalled();
                jest.restoreAllMocks();
                expect(await contentOf(name)).toEqual(before);
            },
        );

        const corrupt = 'store data is corrupt';
        const roomy = { maxRowBytes: 1 << 20, maxEntries: 100 };

        /**
         * What the reader makes of a row stored under sequence number 1. The result is its
         * entries as pairs of hex strings, or the message of the error it fails with.
         */
        const read = (row: Uint8Array, bounds = roomy, stored: unknown = exact(row)) => {
            try {
                return decodeBatch(stored, 1n, bounds).entries.map(({ key, value }) => [hex(key), hex(value)]);
            } catch (error) {
                return (error as { rawMessage: string }).rawMessage;
            }
        };
        const keyOnly = (key: string) => concat(bytes(0x12, 2 + key.length, 0x0a, key.length), utf8(key));

        it('reads exactly the fields that the two messages of a stored batch define', () => {
            const fields = (schema: typeof GetResponseSchema | typeof EntrySchema) =>
                schema.fields.map((field) => [
                    field.number,
                    field.name,
                    field.fieldKind === 'scalar' ? ScalarType[field.scalar] : field.fieldKind,
                    field.message?.typeName,
                ]);
            expect(GetResponseSchema.typeName).toBe('log.stream.v1.GetResponse');
            expect(fields(GetResponseSchema)).toEqual([
                [1, 'sequence_number', 'UINT64', undefined],
                [2, 'entries', 'list', 'common.kv.v1.Entry'],
            ]);
            expect(EntrySchema.typeName).toBe('common.kv.v1.Entry');
            expect(fields(EntrySchema)).toEqual([
                [1, 'key', 'BYTES', undefined],
                [2, 'value', 'BYTES', undefined],
            ]);
        });

        it('reads a stored batch up to the largest that a writer may store', () => {
            // At most 2,000,000 entries in 256 MiB of encoded entries, and 11 bytes for the
            // sequence number field.
            expect(LOG_BOUNDS).toEqual({ maxRowBytes: 256 * 1024 * 1024 + 11, maxEntries: 2_000_000 });
        });

        it('bounds the bytes and the entries of a stored batch as it reads it', () => {
            const rows: Row[] = [[utf8('a'), utf8('1')], [utf8('b'), utf8('2')], [utf8('c'), utf8('3')]];
            const row = encodedBatch(1n, rows);
            const fits = { maxRowBytes: row.byteLength, maxEntries: rows.length };
            expect(read(row, fits)).toEqual(rows.map(([key, value]) => [hex(key), hex(value)]));
            expect(read(row, { ...fits, maxRowBytes: row.byteLength - 1 })).toBe(corrupt);
            expect(read(row, { ...fits, maxEntries: 2 })).toBe(corrupt);
        });

        it('creates no entry beyond the bound on entries', () => {
            const stored = exact(concat(bytes(0x08, 0x01), keyOnly('a'), keyOnly('b'), keyOnly('c')));

            // The reader takes each field of an entry as a view of the row. These entries have a
            // key and no value, so the views it takes count the entries it reads.
            const views = jest.spyOn(Uint8Array.prototype, 'subarray');
            const outcome = read(bytes(), { ...roomy, maxEntries: 1 }, stored);
            const taken = views.mock.calls.length;
            views.mockRestore();
            expect(outcome).toBe(corrupt);
            expect(taken).toBe(1);
        });

        it('checks the form and the length of a stored batch before it copies it', () => {
            const row = encodedBatch(1n, [[utf8('a'), new Uint8Array(1000)]]);
            const copiesOf = (bounds: typeof roomy, stored: unknown) => {
                const copies = jest.spyOn(Uint8Array.prototype, 'set');
                const outcome = read(row, bounds, stored);
                const made = copies.mock.calls.filter(([source]) => (source as Uint8Array).byteLength === row.byteLength);
                copies.mockRestore();
                return [typeof outcome === 'string' ? outcome : outcome.length, made.length];
            };
            const tooLong = { ...roomy, maxRowBytes: row.byteLength - 1 };
            expect(copiesOf(tooLong, offsetView(row))).toEqual([corrupt, 0]);
            expect(copiesOf(roomy, 'not bytes')).toEqual([corrupt, 0]);

            // A view of part of a buffer is copied once. A value that owns its whole buffer is
            // read in place.
            expect(copiesOf(roomy, offsetView(row))).toEqual([1, 1]);
            expect(copiesOf(roomy, exact(row))).toEqual([1, 0]);
            expect(copiesOf(roomy, new Uint8Array(exact(row)))).toEqual([1, 0]);
        });

        const zeros = (count: number) => new Uint8Array(count);
        const one = { ...roomy, maxEntries: 1 };
        it.each<[string, Uint8Array, typeof roomy]>([
            ['the entries field as a varint', bytes(0x08, 0x01, 0x10, 0x00), roomy],
            ['the entries field as two varints where one entry is allowed', bytes(0x08, 0x01, 0x10, 0x00, 0x10, 0x00), one],
            ['the sequence number as a length delimited field', bytes(0x0a, 0x01, 0x12, 0x00), roomy],
            ['a key as a varint', bytes(0x08, 0x01, 0x12, 0x02, 0x08, 0x00), roomy],
            ['a value as a varint', bytes(0x08, 0x01, 0x12, 0x02, 0x10, 0x00), roomy],
            [
                'a key that runs past its entry where one entry is allowed',
                concat(bytes(0x08, 0x01, 0x12, 0x01, 0x0a, 0x1a, 0x1b), zeros(25), bytes(0x12, 0x00)),
                one,
            ],
            [
                'a key that runs past its entry',
                concat(bytes(0x08, 0x01, 0x12, 0x01, 0x0a, 0x1a, 0x1b), zeros(25), bytes(0x12, 0x00)),
                roomy,
            ],
            ['an entry that runs past the row', bytes(0x08, 0x01, 0x12, 0x05, 0x0a, 0x01), roomy],
            ['an undefined length delimited field that runs past the row', bytes(0x08, 0x01, 0x12, 0x00, 0x7a, 0x02, 0x00), roomy],
            ['an undefined fixed 64 bit field that runs past the row', bytes(0x08, 0x01, 0x12, 0x00, 0x79, 0, 0, 0), roomy],
            ['an undefined fixed 32 bit field that runs past its entry', bytes(0x08, 0x01, 0x12, 0x03, 0x7d, 0, 0, 0, 0), roomy],
            ['the field number 0', bytes(0x08, 0x01, 0x12, 0x00, 0x00, 0x00), roomy],
            ['the field number 0 inside an entry', bytes(0x08, 0x01, 0x12, 0x02, 0x02, 0x00), roomy],
            ['a group', bytes(0x08, 0x01, 0x12, 0x00, 0x1b, 0x1c), roomy],
            ['a group inside an entry', bytes(0x08, 0x01, 0x12, 0x02, 0x1b, 0x1c), roomy],
            ['a varint of 11 bytes', concat(bytes(0x08, 0x01, 0x12, 0x00, 0x78), new Uint8Array(10).fill(0x80), bytes(0x00)), roomy],
            ['a varint that the row cuts off', bytes(0x08, 0x01, 0x12, 0x00, 0x78, 0x80), roomy],
            ['a sequence number above 64 bits', concat(bytes(0x08), new Uint8Array(9).fill(0xff), bytes(0x02, 0x12, 0x00)), roomy],
            ['an undefined varint above 64 bits', concat(bytes(0x08, 0x01, 0x12, 0x00, 0x78), new Uint8Array(9).fill(0xff), bytes(0x02)), roomy],
            ['a tag above 32 bits', bytes(0x08, 0x01, 0x92, 0x80, 0x80, 0x80, 0x10, 0x00), roomy],
            ['a length above 32 bits', bytes(0x08, 0x01, 0x12, 0x80, 0x80, 0x80, 0x80, 0x10), roomy],
            ['no entry', bytes(0x08, 0x01), roomy],
            ['another sequence number than its key', bytes(0x08, 0x02, 0x12, 0x00), roomy],
            ['a key of 255 bytes', concat(bytes(0x08, 0x01, 0x12, 0x82, 0x02, 0x0a, 0xff, 0x01), zeros(255)), roomy],
        ])('treats a stored batch with %s as corrupt data', (_, row, bounds) => {
            expect(read(row, bounds)).toBe(corrupt);
        });

        it.each<[string, Uint8Array, string[][]]>([
            ['an entry without a key or a value', bytes(0x08, 0x01, 0x12, 0x00), [['', '']]],
            ['its fields in another order', bytes(0x12, 0x06, 0x12, 0x01, 0x31, 0x0a, 0x01, 0x61, 0x08, 0x01), [['61', '31']]],
            [
                'a sequence number, a key and a value that are written twice',
                bytes(0x08, 0x09, 0x12, 0x0c, 0x0a, 0x01, 0x61, 0x12, 0x01, 0x31, 0x0a, 0x01, 0x62, 0x12, 0x01, 0x32, 0x08, 0x01),
                [['62', '32']],
            ],
            [
                'undefined fields of every wire type in the batch and in an entry',
                concat(
                    bytes(0x78, 0x05, 0x79), zeros(8), bytes(0x7a, 0x02, 0xff, 0xff, 0x7d), zeros(4),
                    bytes(0x08, 0x01, 0x12, 0x17, 0x78, 0x05, 0x79), zeros(8), bytes(0x7a, 0x02, 0xff, 0xff, 0x7d), zeros(4),
                    bytes(0x0a, 0x01, 0x61),
                ),
                [['61', '']],
            ],
            [
                'varints that are longer than they need to be',
                bytes(0x88, 0x80, 0x00, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00, 0x92, 0x00, 0x86, 0x00, 0x8a, 0x80, 0x00, 0x81, 0x00, 0x61),
                [['61', '']],
            ],
            ['a key of 254 bytes', concat(bytes(0x08, 0x01, 0x12, 0x81, 0x02, 0x0a, 0xfe, 0x01), zeros(254)), [[hex(zeros(254)), '']]],
        ])('reads a stored batch with %s', (_, row, entries) => {
            expect(read(row)).toEqual(entries);
            const decoded = fromBinary(GetResponseSchema, row);
            expect(decoded.entries.map(({ key, value }) => [hex(key), hex(value)])).toEqual(entries);
        });

        it('reads valid batches of any encoding as a protobuf decoder does', () => {
            // A fixed generator makes a failure repeatable.
            let state = 0x1234abcd;
            const random = (bound: number) => {
                state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
                return Math.floor((state / 0x100000000) * bound);
            };
            const randomBytes = (count: number) => Array.from({ length: count }, () => random(256));

            // A varint with up to `padding` bytes more than it needs.
            const varint = (value: number, padding: number): number[] => {
                const encoded: number[] = [];
                for (; value >= 0x80; value = Math.floor(value / 128)) encoded.push((value % 128) | 0x80);
                encoded.push(value);
                for (let extra = random(padding + 1); extra > 0; extra--) {
                    encoded[encoded.length - 1] |= 0x80;
                    encoded.push(0);
                }
                return encoded;
            };
            const tag = (field: number, wireType: number) => varint(field * 8 + wireType, 2);
            const lengthDelimited = (field: number, content: number[]) =>
                [...tag(field, 2), ...varint(content.length, 2), ...content];
            const undefinedField = (): number[] => {
                const field = 3 + random(500);
                switch (random(4)) {
                    case 0:
                        return [...tag(field, 0), ...varint(random(1 << 30), 4)];
                    case 1:
                        return [...tag(field, 1), ...randomBytes(8)];
                    case 2:
                        return lengthDelimited(field, randomBytes(random(6)));
                    default:
                        return [...tag(field, 5), ...randomBytes(4)];
                }
            };
            const pick = (parts: (() => number[])[]) => parts[random(parts.length)]();
            const entry = () => lengthDelimited(2, Array.from({ length: random(6) }, () => pick([
                () => lengthDelimited(1, randomBytes(random(5))),
                () => lengthDelimited(2, randomBytes(random(5))),
                undefinedField,
            ])).flat());
            const sequenceNumber = () => [...tag(1, 0), ...varint(random(1 << 30), 5)];

            for (let round = 0; round < 300; round++) {
                const parts = [entry(), ...Array.from({ length: random(8) }, () => pick([entry, sequenceNumber, undefinedField]))];

                // The first part moves to a random place, so an entry is not always in front.
                const place = random(parts.length);
                [parts[0], parts[place]] = [parts[place], parts[0]];
                const row = Uint8Array.from(parts.flat());

                const expected = fromBinary(GetResponseSchema, row);
                const batch = decodeBatch(exact(row), expected.sequenceNumber, roomy);
                expect(batch.sequenceNumber).toBe(expected.sequenceNumber);
                expect(batch.entries.map(({ key, value }) => [hex(key), hex(value)])).toEqual(
                    expected.entries.map(({ key, value }) => [hex(key), hex(value)]),
                );
            }
        });

        it.each([
            ['entries of 2 bytes each', bytes(0x12, 0x00)],
            ['varints under the number of the entries field', bytes(0x10, 0x00)],
        ])('refuses a stored batch with more %s than any Put can write entries', async (_, repetition) => {
            const { name, client } = await openStore();
            await putOne(client, 'a');
            const row = concat(bytes(0x08, 0x01), repeated(repetition, MAX_PUT_ENTRIES + 1));
            await withRaw(name, 'readwrite', ({ log }) => {
                log.put(exact(row), exact(be64(1n)));
            });
            const calls = [
                () => client.stream.get({ sequenceNumber: 1n }),
                () => client.stream.subscribe({ selectors: [everyKey], sinceSequenceNumber: 1n }),
            ];
            await expectEveryCallFails(calls, Code.Internal, corrupt);
        });

        it('reads a large stored batch and keeps no field that a batch does not define', async () => {
            const { name, client } = await openStore();
            await putOne(client, 'a');
            const ENTRIES = 50_000;
            const UNDEFINED_FIELDS = 200_000;
            const undefinedField = bytes(0x78, 0x01);
            const entry = concat(bytes(0x12, 0x05, 0x0a, 0x01, 0x6b), undefinedField);
            const row = concat(
                bytes(0x08, 0x01),
                repeated(entry, ENTRIES),
                repeated(undefinedField, UNDEFINED_FIELDS),
            );
            await withRaw(name, 'readwrite', ({ log }) => {
                log.put(exact(row), exact(be64(1n)));
            });

            // The batch as the handler hands it to the encoder of the answer.
            const answered: { $unknown?: unknown; entries: { $unknown?: unknown }[] }[] = [];
            mockEncoding.observe = (typeName, message) => {
                if (typeName === GetResponseSchema.typeName) answered.push(message as (typeof answered)[0]);
            };

            const batch = await client.stream.get({ sequenceNumber: 1n });
            expect(batch.entries).toHaveLength(ENTRIES);
            expect(batch.entries.every(({ key, value }) => hex(key) === '6b' && value.byteLength === 0)).toBe(true);
            const replayed = await nextFrame(subscribe(client, { selectors: [everyKey], sinceSequenceNumber: 1n }));
            expect(replayed.entries).toHaveLength(ENTRIES);

            expect(answered).toHaveLength(1);
            expect(answered[0].$unknown).toBeUndefined();
            expect(answered[0].entries).toHaveLength(ENTRIES);
            expect(answered[0].entries.every((each) => each.$unknown === undefined)).toBe(true);
        });

        // Encodings of the rule that keeps the latest batch. Each writes the count field one or
        // more times inside the rule, always with the value 1, and a decoder keeps the last one.
        const keepLatestOne = (counts: Uint8Array) => {
            const length = counts.byteLength < 128 ? [counts.byteLength] : [(counts.byteLength & 0x7f) | 0x80, counts.byteLength >> 7];
            return concat(bytes(0x0a, ...length), counts);
        };
        const count = bytes(0x08, 0x01);
        const validRules: [string, Uint8Array, number][] = [
            ['66 bytes that repeat the count', keepLatestOne(repeated(count, 32)), 66],
            [
                '1024 bytes, the longest the layout allows',
                keepLatestOne(concat(bytes(0x08, 0x81, 0x00), repeated(count, 509))),
                1024,
            ],
            [
                '10 bytes with fields that a rule does not define',
                concat(keepLatestOne(count), repeated(bytes(0x78, 0x01), 3)),
                10,
            ],
        ];

        it.each(validRules)('reads a stored retention rule of %s and applies it', async (_, rule, length) => {
            expect(rule.byteLength).toBe(length);
            const { name, client } = await openStore();
            await putOne(client, 'a');
            await putOne(client, 'b');
            await withRaw(name, 'readwrite', ({ meta }) => {
                meta.put(exact(rule), asciiKey('retention'));
            });
            const rules: { $unknown?: unknown; kind: unknown }[] = [];
            mockEncoding.decoded = (typeName, message) => {
                if (typeName === RetentionPolicySchema.typeName) rules.push(message as (typeof rules)[0]);
            };

            await expect(putOne(client, 'c')).resolves.toBe(3n);
            expect((await failure(client.stream.get({ sequenceNumber: 2n }))).code).toBe(Code.OutOfRange);
            await expect(client.stream.get({ sequenceNumber: 3n })).resolves.toMatchObject({ sequenceNumber: 3n });
            expect(rules).toHaveLength(1);
            expect(rules[0].kind).toMatchObject({ case: 'keepLatest', value: { count: 1n } });
            expect(rules[0].$unknown).toBeUndefined();
        });

        it('treats a stored retention rule of 1025 bytes as corrupt before it copies or decodes it', async () => {
            const { name, client } = await openStore();
            await putOne(client, 'a');
            const rule = keepLatestOne(repeated(count, 511));
            expect(rule.byteLength).toBe(1025);
            await withRaw(name, 'readwrite', ({ meta }) => {
                meta.put(offsetView(rule), asciiKey('retention'));
            });
            const before = await contentOf(name);
            let decoded = 0;
            mockEncoding.decoded = (typeName) => {
                if (typeName === RetentionPolicySchema.typeName) decoded++;
            };

            // A copy of the row would pass its 1025 bytes to this method.
            const copies = jest.spyOn(Uint8Array.prototype, 'set');

            const error = await failure(putOne(client, 'b'));
            const copied = copies.mock.calls.filter(([source]) => (source as Uint8Array).byteLength === 1025);
            jest.restoreAllMocks();
            expect([error.code, error.rawMessage]).toEqual([Code.Internal, 'store metadata is corrupt']);
            expect(decoded).toBe(0);
            expect(copied).toEqual([]);
            expect(await contentOf(name)).toEqual(before);
        });

        it('ends a subscription normally when no sequence number is left to deliver', async () => {
            const { name, client } = await openStore();
            await withRaw(name, 'readwrite', ({ log, meta }) => {
                log.put(exact(encodedBatch(MAX_U64, [[utf8('last'), utf8('v')]])), exact(be64(MAX_U64)));
                meta.put(exact(be64(MAX_U64)), asciiKey('sequence'));
            });
            const waits = jest.spyOn(Notifier.prototype, 'after');
            const reads = spyOnTransactions();

            const live = subscribe(client, { selectors: [everyKey] });
            await expect(nextWithTimeout(live)).resolves.toMatchObject({ done: true });
            expect(reads.calls()).toEqual([LOG_SCOPE]);

            const replay = subscribe(client, { selectors: [everyKey], sinceSequenceNumber: MAX_U64 });
            expect((await nextFrame(replay)).sequenceNumber).toBe(MAX_U64);
            await expect(nextWithTimeout(replay)).resolves.toMatchObject({ done: true });
            expect(waits).not.toHaveBeenCalled();
        });

        it('reports the sequence number of a store at the highest number and refuses its next Put', async () => {
            const { name, client } = await openStore();
            await withRaw(name, 'readwrite', ({ meta }) => {
                meta.put(exact(be64(MAX_U64)), asciiKey('sequence'));
            });
            expect(await sequenceOf(client)).toBe(MAX_U64);
            expect((await failure(putOne(client, 'a'))).code).toBe(Code.Internal);
            expect((await contentOf(name)).kv).toEqual([]);
        });

        it('maps an exception inside a transaction to INTERNAL without its text', async () => {
            const { client } = await openStore();
            jest.spyOn(IDBObjectStore.prototype, 'get').mockImplementation(() => {
                throw new TypeError('secret detail');
            });
            await expectEveryCallFails(
                [() => client.query.get({ key: bytes() }), () => client.stream.get({ sequenceNumber: 1n })],
                Code.Internal,
                'internal error',
            );
        });
    });
});
