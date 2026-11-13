/**
 * Opening, closing and deleting a store, and the wiring of its handlers into a Connect router.
 */

import { createRouterTransport, type ConnectRouter, type Transport } from '@connectrpc/connect';
import { Service as IngestService } from '../gen/ts/log/v1/ingest_pb.js';
import { Service as RetentionService } from '../gen/ts/log/v1/retention_pb.js';
import { Service as StreamService } from '../gen/ts/log/v1/stream_pb.js';
import { Service as PruneService } from '../gen/ts/store/v1/prune_pb.js';
import { Service as QueryService } from '../gen/ts/store/v1/query_pb.js';
import { MAX_PUT_ENTRIES, MAX_REQUEST_MESSAGE_BYTES, MAX_VALUE_LEN } from '../limits.js';
import { serverStream, unary } from './errors.js';
import { KV, LAYOUT_VERSION, LOG, MAX_SEQUENCE, META, be64 } from './idb.js';
import { putHandler } from './ingest.js';
import { Notifier } from './notifier.js';
import { pruneHandler } from './prune.js';
import { getHandler, getManyHandler, rangeHandler } from './query.js';
import { reduceHandler } from './reduce/handler.js';
import { setRetentionHandler } from './retention.js';
import { getBatchHandler, subscribeHandler } from './stream.js';

// Defaults of `maxRequestBytes` and `maxQueryBytes`.
const DEFAULT_MAX_REQUEST_BYTES = 64 * 1024 * 1024;
const DEFAULT_MAX_QUERY_BYTES = 64 * 1024 * 1024;

/**
 * The largest setting of each write limit. These are the limits of the Store API, and the
 * database layout lets no writer store more.
 */
const WRITE_LIMIT_CEILINGS = {
    maxPutEntries: MAX_PUT_ENTRIES,
    maxValueLen: MAX_VALUE_LEN,
    maxRequestBytes: MAX_REQUEST_MESSAGE_BYTES,
} as const;

/**
 * Limits of one store. Every field is optional and defaults to the value given with it. The
 * three limits on a Put can be lowered and cannot be set above the limits of the Store API.
 */
export interface IndexedDbStoreOptions {
    /** Maximum number of entries in one Put. Defaults to 2,000,000, which is also the most. */
    maxPutEntries?: number;
    /** Longest value in bytes. Defaults to 32 MiB, which is also the most. */
    maxValueLen?: number;
    /**
     * Largest request message in bytes, and largest sum of the encoded entries of one Put.
     * Defaults to 64 MiB and is at most 256 MiB. The default is lower because a Put writes its
     * payload twice in one transaction, as rows and as a log batch.
     */
    maxRequestBytes?: number;
    /**
     * Maximum memory in bytes that one query, Prune or Reduce may hold, 64 MiB by default. It
     * bounds the answer of a query (key and value bytes plus 64 bytes per row), the keys a Prune
     * selects together with the matcher of one pattern at a time, and the aggregation state of a
     * Reduce together with the expression results of one batch of rows.
     */
    maxQueryBytes?: number;
}

/** An Exoware Store kept in one IndexedDB database of the current origin. */
export interface IndexedDbStore {
    /** Name of the IndexedDB database. */
    readonly name: string;
    /**
     * True when this open created the database. A browser can delete a damaged or evicted
     * database without an error, so an application that expected data should check this.
     */
    readonly created: boolean;
    /**
     * Registers the handlers of the Store services on a Connect router. Each service carries the
     * store's request byte limit, and the router applies it whatever its own options are.
     */
    readonly routes: (router: ConnectRouter) => void;
    /** An in-process transport over the same handlers, for `new Client(store.transport)`. */
    readonly transport: Transport;
    /** Ends subscriptions, stops accepting calls and closes the database connection. */
    close(): void;
}

function resolveOptions(options: IndexedDbStoreOptions): Required<IndexedDbStoreOptions> {
    const resolved = {
        maxPutEntries: options.maxPutEntries ?? MAX_PUT_ENTRIES,
        maxValueLen: options.maxValueLen ?? MAX_VALUE_LEN,
        maxRequestBytes: options.maxRequestBytes ?? DEFAULT_MAX_REQUEST_BYTES,
        maxQueryBytes: options.maxQueryBytes ?? DEFAULT_MAX_QUERY_BYTES,
    };
    for (const [name, value] of Object.entries(resolved)) {
        const least = name === 'maxValueLen' ? 0 : 1;
        if (!Number.isSafeInteger(value) || value < least) {
            throw new RangeError(`${name} must be a safe integer of at least ${least}`);
        }
    }
    for (const [name, most] of Object.entries(WRITE_LIMIT_CEILINGS)) {
        if (resolved[name as keyof typeof WRITE_LIMIT_CEILINGS] > most) {
            throw new RangeError(`${name} must be at most ${most}`);
        }
    }
    return resolved;
}

/**
 * Opens the database at the layout version this store implements, creating it when it does not
 * exist. A database with a newer version or with other object stores is refused. It is left
 * unchanged, and this store keeps no connection to it.
 */
function openDatabase(name: string): Promise<{ db: IDBDatabase; created: boolean }> {
    return new Promise((resolve, reject) => {
        let created = false;
        const opening = indexedDB.open(name, LAYOUT_VERSION);
        const detach = () => {
            opening.onupgradeneeded = opening.onerror = opening.onsuccess = null;
        };
        opening.onupgradeneeded = (event) => {
            if (event.oldVersion !== 0) return;
            for (const store of [KV, LOG, META]) opening.result.createObjectStore(store);
            created = true;
        };
        opening.onerror = () => {
            detach();
            const reason = opening.error?.name === 'VersionError'
                ? 'has a layout version that this store does not implement'
                : `could not be opened (${opening.error?.name ?? 'unknown error'})`;
            reject(new Error(`IndexedDB database "${name}" ${reason}`));
        };
        opening.onsuccess = () => {
            detach();
            const db = opening.result;
            const stores = [...db.objectStoreNames].sort();
            if (stores.join() !== [KV, LOG, META].join()) {
                db.close();
                reject(new Error(`IndexedDB database "${name}" does not have the layout of an Exoware store`));
                return;
            }
            resolve({ db, created });
        };
    });
}

/**
 * The channel on which every connection to a database announces the batches it commits.
 * Undefined where the environment has no BroadcastChannel.
 */
function openChannel(name: string): BroadcastChannel | undefined {
    if (typeof BroadcastChannel === 'undefined') return undefined;
    const channel = new BroadcastChannel(`exoware-store:${name}`);

    // In Node an open channel would keep the process alive.
    (channel as { unref?: () => void }).unref?.();
    return channel;
}

/**
 * Opens the store in the IndexedDB database `name`, creating the database when it does not exist.
 * The database layout is specified in indexeddb/README.md at the repository root. Other pages and
 * workers of the origin may have the same database open, through this module or another
 * implementation of the layout.
 *
 * Reduce is evaluated in this process, and the README of this package lists the expressions that
 * answer UNIMPLEMENTED.
 */
export async function openIndexedDbStore(
    name: string,
    options: IndexedDbStoreOptions = {},
): Promise<IndexedDbStore> {
    const limits = resolveOptions(options);
    const { db, created } = await openDatabase(name);
    let channel: BroadcastChannel | undefined;
    try {
        channel = openChannel(name);
    } catch (error) {
        db.close();
        throw error;
    }
    const notifier = new Notifier();
    let open = true;
    const isOpen = () => open;

    // Puts that have started and not yet answered. Each of them may still commit and announce
    // its batch, so the channel stays open for them after close().
    let runningPuts = 0;

    const close = () => {
        if (!open) return;
        open = false;
        db.onversionchange = db.onclose = null;
        if (channel !== undefined) channel.onmessage = null;
        notifier.close();
        db.close();
        if (runningPuts === 0) channel?.close();
    };

    // Another connection that deletes or upgrades the database waits until this one closes.
    db.onversionchange = close;

    // The browser closes the connection itself when the origin's storage is cleared.
    db.onclose = close;

    if (channel !== undefined) {
        // A message is a hint that some connection committed a batch. Only its form is checked.
        channel.onmessage = (event: MessageEvent) => {
            const data: unknown = event.data;
            const isBytes = Object.prototype.toString.call(data) === '[object Uint8Array]';
            if (isBytes && (data as Uint8Array).byteLength === 8) notifier.wake();
        };
    }
    const committed = (sequenceNumber: bigint) => {
        notifier.wake(sequenceNumber);
        try {
            channel?.postMessage(new Uint8Array(be64(sequenceNumber)));
        } catch {
            // The batch is committed whether or not other connections can be told. They learn of
            // it from the next announcement or the next time they read.
        }
    };
    const expectedSequence = () => (notifier.hint < MAX_SEQUENCE ? notifier.hint + 1n : MAX_SEQUENCE);
    const put = putHandler(db, limits, expectedSequence, committed);
    const countedPut: typeof put = async (request, context) => {
        runningPuts++;
        try {
            return await put(request, context);
        } finally {
            if (--runningPuts === 0 && !open) channel?.close();
        }
    };

    // Every service is registered with these options, so the limits travel with the routes and
    // hold on any router. The router refuses a request message above the byte limit before a
    // handler runs, and it drops fields that the request messages do not define.
    const serviceOptions = {
        readMaxBytes: limits.maxRequestBytes,
        binaryOptions: { readUnknownFields: false },
    };

    const routes = (router: ConnectRouter) => {
        router.service(IngestService, {
            put: unary(isOpen, countedPut),
        }, serviceOptions);
        router.service(QueryService, {
            get: unary(isOpen, getHandler(db, limits.maxQueryBytes)),
            getMany: serverStream(isOpen, getManyHandler(db, limits.maxQueryBytes)),
            range: serverStream(isOpen, rangeHandler(db, limits.maxQueryBytes)),
            reduce: serverStream(isOpen, reduceHandler(db, limits.maxQueryBytes)),
        }, serviceOptions);
        router.service(PruneService, {
            prune: unary(isOpen, pruneHandler(db, limits.maxQueryBytes)),
        }, serviceOptions);
        router.service(StreamService, {
            get: unary(isOpen, getBatchHandler(db)),
            subscribe: serverStream(isOpen, subscribeHandler(db, notifier, isOpen)),
        }, serviceOptions);
        router.service(RetentionService, {
            setRetention: unary(isOpen, setRetentionHandler(db)),
        }, serviceOptions);
    };
    return { name, created, routes, transport: createRouterTransport(routes), close };
}

/**
 * Deletes the database `name` with everything in it. Every store that has it open, in this page
 * or another, closes itself. The promise resolves once the database is gone.
 */
export function deleteIndexedDbStore(name: string): Promise<void> {
    return new Promise((resolve, reject) => {
        const deleting = indexedDB.deleteDatabase(name);
        const detach = () => {
            deleting.onsuccess = deleting.onerror = null;
        };
        deleting.onsuccess = () => {
            detach();
            resolve();
        };
        deleting.onerror = () => {
            detach();
            reject(new Error(`IndexedDB database "${name}" could not be deleted (${deleting.error?.name ?? 'unknown error'})`));
        };
    });
}
