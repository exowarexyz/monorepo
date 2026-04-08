import { create } from '@bufbuild/protobuf';
import { Code, ConnectError } from '@connectrpc/connect';
import type { Client } from './client.js';
import { HttpError } from './error.js';
import { PutRequestSchema, KvPairSchema } from './gen/ts/store/v1/ingest_pb.js';
import {
    GetRequestSchema,
    GetManyRequestSchema,
    RangeRequestSchema,
    TraversalMode,
} from './gen/ts/store/v1/query_pb.js';

/**
 * The result of a `get` operation.
 */
export interface GetResult {
    /** The retrieved value. */
    value: Uint8Array;
}

/**
 * An item in the result of a `getMany` operation.
 */
export interface GetManyResultItem {
    /** The key that was looked up. */
    key: Uint8Array;
    /** The value, or undefined if the key was not found. */
    value: Uint8Array | undefined;
}

/**
 * An item in the result of a `query` operation.
 */
export interface QueryResultItem {
    /** The key of the item. */
    key: Uint8Array;
    /** The value of the item. */
    value: Uint8Array;
}

/**
 * The result of a `query` operation.
 */
export interface QueryResult {
    /** A list of key-value pairs. */
    results: QueryResultItem[];
}

function toUint8Array(value: Uint8Array | Buffer): Uint8Array {
    return value instanceof Uint8Array ? value : new Uint8Array(value);
}

function mapConnectToHttpError(err: unknown): never {
    if (err instanceof ConnectError) {
        const status = connectCodeToHttpStatus(err.code);
        throw new HttpError(status, err.message || String(err.code));
    }
    throw err;
}

/** Best-effort mapping for tests and HTTP-oriented callers; prefer `ConnectError` in new code. */
function connectCodeToHttpStatus(code: Code): number {
    switch (code) {
        case Code.Canceled:
            return 499;
        case Code.Unknown:
            return 500;
        case Code.InvalidArgument:
            return 400;
        case Code.DeadlineExceeded:
            return 504;
        case Code.NotFound:
            return 404;
        case Code.AlreadyExists:
            return 409;
        case Code.PermissionDenied:
            return 403;
        case Code.ResourceExhausted:
            return 429;
        case Code.FailedPrecondition:
            return 400;
        case Code.Aborted:
            return 409;
        case Code.OutOfRange:
            return 400;
        case Code.Unimplemented:
            return 501;
        case Code.Internal:
            return 500;
        case Code.Unavailable:
            return 503;
        case Code.DataLoss:
            return 500;
        case Code.Unauthenticated:
            return 401;
        default:
            return 500;
    }
}

/**
 * A client for the key-value store API.
 */
export class StoreClient {
    constructor(private readonly client: Client) {}

    /**
     * Sets a key-value pair in the store.
     * @param key The key to set.
     * @param value The value to set.
     */
    async set(key: Uint8Array, value: Uint8Array | Buffer): Promise<void> {
        const req = create(PutRequestSchema, {
            kvs: [
                create(KvPairSchema, {
                    key,
                    value: toUint8Array(value),
                }),
            ],
        });
        try {
            await this.client.ingest.put(req);
        } catch (e) {
            mapConnectToHttpError(e);
        }
    }

    /**
     * Retrieves a value from the store by its key.
     * @param key The key to retrieve.
     * @returns The value, or `null` if the key does not exist.
     */
    async get(key: Uint8Array): Promise<GetResult | null> {
        const req = create(GetRequestSchema, { key });
        try {
            const res = await this.client.query.get(req);
            if (!res.found || res.value === undefined) {
                return null;
            }
            return { value: res.value };
        } catch (e) {
            mapConnectToHttpError(e);
        }
    }

    /**
     * Retrieves multiple values from the store by their keys in a single streaming RPC.
     * Results stream back as frames; each entry includes its key so results may arrive
     * in any order. Use the callback to process entries incrementally, or omit it to
     * collect all results.
     * @param keys The keys to look up.
     * @param batchSize Maximum entries per streamed frame; must be positive. Defaults to keys.length.
     * @param onChunk Optional callback invoked per frame for incremental processing.
     * @returns All results collected (after all frames have been processed).
     */
    async getMany(
        keys: Uint8Array[],
        batchSize?: number,
        onChunk?: (entries: GetManyResultItem[]) => void,
    ): Promise<GetManyResultItem[]> {
        const req = create(GetManyRequestSchema, {
            keys,
            batchSize: batchSize ?? keys.length,
        });
        const results: GetManyResultItem[] = [];
        try {
            const stream = this.client.query.getMany(req);
            for await (const frame of stream) {
                const chunk: GetManyResultItem[] = [];
                for (const entry of frame.results) {
                    chunk.push({
                        key: entry.key,
                        value: entry.value,
                    });
                }
                if (onChunk) {
                    onChunk(chunk);
                }
                results.push(...chunk);
            }
            return results;
        } catch (e) {
            mapConnectToHttpError(e);
        }
    }

    /**
     * Queries for a range of key-value pairs (forward scan via `Range` streaming RPC).
     * @param start The key to start the query from (inclusive). If omitted, starts at the empty key.
     * @param end The key to end the query at (inclusive when provided). If omitted, ends at the empty key (full range semantics match the server).
     * @param limit The maximum number of results to return. If omitted, no limit is applied.
     * @param batchSize Maximum rows per streamed frame; must be positive. Defaults to `4096`.
     */
    async query(
        start?: Uint8Array,
        end?: Uint8Array,
        limit?: number,
        batchSize: number = 4096,
    ): Promise<QueryResult> {
        const req = create(RangeRequestSchema, {
            start: start ?? new Uint8Array(),
            end: end ?? new Uint8Array(),
            batchSize,
            mode: TraversalMode.FORWARD,
            ...(limit !== undefined ? { limit } : {}),
        });
        const results: QueryResultItem[] = [];
        try {
            const stream = this.client.query.range(req);
            for await (const frame of stream) {
                for (const row of frame.results) {
                    results.push({ key: row.key, value: row.value });
                }
            }
            return { results };
        } catch (e) {
            mapConnectToHttpError(e);
        }
    }
}
