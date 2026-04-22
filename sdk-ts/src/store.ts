import { create, fromBinary, type MessageInitShape } from '@bufbuild/protobuf';
import { Code, ConnectError } from '@connectrpc/connect';
import type { CallOptions } from '@connectrpc/connect';
import type { Client } from './client.js';
import { HttpError } from './error.js';
import { PruneRequestSchema } from './gen/ts/store/v1/compact_pb.js';
import type { Policy } from './gen/ts/store/v1/compact_pb.js';
import { KvEntrySchema, MatchKeySchema } from './gen/ts/store/v1/common_pb.js';
import { ErrorInfoSchema } from './gen/ts/google/rpc/error_details_pb.js';
import { PutRequestSchema } from './gen/ts/store/v1/ingest_pb.js';
import {
    DetailSchema,
    GetManyRequestSchema,
    GetRequestSchema as QueryGetRequestSchema,
    RangeRequestSchema,
    ReduceRequestSchema,
    TraversalMode,
} from './gen/ts/store/v1/query_pb.js';
import type { Detail, ReduceParams, ReduceResponse } from './gen/ts/store/v1/query_pb.js';
import {
    GetRequestSchema as StreamGetRequestSchema,
    SubscribeRequestSchema,
} from './gen/ts/store/v1/stream_pb.js';

const QUERY_DETAIL_HEADER = 'x-store-query-detail-bin';

type DetailObserver = (detail: Detail) => void;

export { TraversalMode };

export type { ReduceParams, ReduceResponse };

export interface GetResult {
    value: Uint8Array;
}

export interface GetManyResultItem {
    key: Uint8Array;
    value: Uint8Array | undefined;
}

export interface QueryResultItem {
    key: Uint8Array;
    value: Uint8Array;
}

export interface QueryResult {
    results: QueryResultItem[];
}

export interface StoreBatchEntry {
    key: Uint8Array;
    value: Uint8Array;
}

export interface StoreBatch {
    sequenceNumber: bigint;
    entries: StoreBatchEntry[];
}

function toUint8Array(value: Uint8Array | Buffer): Uint8Array {
    return value instanceof Uint8Array ? value : new Uint8Array(value);
}

function normalizeMinSequenceNumber(value?: bigint): bigint | undefined {
    return value !== undefined && value > 0n ? value : undefined;
}

function mapConnectToHttpError(err: unknown): never {
    if (err instanceof ConnectError) {
        const status = connectCodeToHttpStatus(err.code);
        throw new HttpError(status, err.message || String(err.code), err.code, err);
    }
    throw err;
}

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

function parseDetailFromHeaders(headers: Headers): Detail | undefined {
    const raw = headers.get(QUERY_DETAIL_HEADER);
    if (!raw) return undefined;
    try {
        const binaryStr = atob(raw);
        const bytes = new Uint8Array(binaryStr.length);
        for (let i = 0; i < binaryStr.length; i++) {
            bytes[i] = binaryStr.charCodeAt(i);
        }
        return fromBinary(DetailSchema, bytes);
    } catch {
        return undefined;
    }
}

function mergeCallOptionsWithDetailObserver(
    detailObserver?: DetailObserver,
    options?: CallOptions,
): CallOptions | undefined {
    if (!detailObserver) {
        return options;
    }
    return {
        ...options,
        onHeader: (headers) => {
            options?.onHeader?.(headers);
            const detail = parseDetailFromHeaders(headers);
            if (detail) {
                detailObserver(detail);
            }
        },
        onTrailer: (trailers) => {
            options?.onTrailer?.(trailers);
            const detail = parseDetailFromHeaders(trailers);
            if (detail) {
                detailObserver(detail);
            }
        },
    };
}

function isMissingBatchError(err: ConnectError): boolean {
    return err.findDetails(ErrorInfoSchema).some(
        (detail) =>
            detail.domain === 'store.stream' &&
            (detail.reason === 'BATCH_EVICTED' || detail.reason === 'BATCH_NOT_FOUND'),
    );
}

function toStoreBatch(
    response: {
        sequenceNumber: bigint;
        entries: { key: Uint8Array; value: Uint8Array }[];
    },
): StoreBatch {
    return {
        sequenceNumber: response.sequenceNumber,
        entries: response.entries.map((entry) => ({
            key: entry.key,
            value: entry.value,
        })),
    };
}

async function performGet(
    client: Client,
    key: Uint8Array,
    minSequenceNumber?: bigint,
    detailObserver?: DetailObserver,
): Promise<GetResult | null> {
    const effective = normalizeMinSequenceNumber(minSequenceNumber);
    const req = create(QueryGetRequestSchema, {
        key,
        ...(effective !== undefined ? { minSequenceNumber: effective } : {}),
    });
    try {
        const res = await client.query.get(req, mergeCallOptionsWithDetailObserver(detailObserver));
        if (res.value === undefined) {
            return null;
        }
        return { value: res.value };
    } catch (e) {
        mapConnectToHttpError(e);
    }
}

async function performGetMany(
    client: Client,
    keys: Uint8Array[],
    batchSize?: number,
    onChunk?: (entries: GetManyResultItem[]) => void,
    minSequenceNumber?: bigint,
    detailObserver?: DetailObserver,
): Promise<GetManyResultItem[]> {
    const effective = normalizeMinSequenceNumber(minSequenceNumber);
    const req = create(GetManyRequestSchema, {
        keys,
        batchSize: batchSize ?? keys.length,
        ...(effective !== undefined ? { minSequenceNumber: effective } : {}),
    });
    const results: GetManyResultItem[] = [];
    try {
        const stream = client.query.getMany(req, mergeCallOptionsWithDetailObserver(detailObserver));
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

async function performQuery(
    client: Client,
    start?: Uint8Array,
    end?: Uint8Array,
    limit?: number,
    batchSize: number = 4096,
    mode: TraversalMode = TraversalMode.FORWARD,
    minSequenceNumber?: bigint,
    detailObserver?: DetailObserver,
): Promise<QueryResult> {
    const effective = normalizeMinSequenceNumber(minSequenceNumber);
    const req = create(RangeRequestSchema, {
        start: start ?? new Uint8Array(),
        end: end ?? new Uint8Array(),
        batchSize,
        mode,
        ...(limit !== undefined ? { limit } : {}),
        ...(effective !== undefined ? { minSequenceNumber: effective } : {}),
    });
    const results: QueryResultItem[] = [];
    try {
        const stream = client.query.range(req, mergeCallOptionsWithDetailObserver(detailObserver));
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

async function performReduce(
    client: Client,
    start: Uint8Array,
    end: Uint8Array,
    params: ReduceParams,
    minSequenceNumber?: bigint,
    detailObserver?: DetailObserver,
): Promise<ReduceResponse> {
    const effective = normalizeMinSequenceNumber(minSequenceNumber);
    const req = create(ReduceRequestSchema, {
        start,
        end,
        params,
        ...(effective !== undefined ? { minSequenceNumber: effective } : {}),
    });
    try {
        return await client.query.reduce(req, mergeCallOptionsWithDetailObserver(detailObserver));
    } catch (e) {
        mapConnectToHttpError(e);
    }
}

async function performGetBatch(
    client: Client,
    sequenceNumber: bigint,
    options?: CallOptions,
): Promise<StoreBatch | null> {
    const req = create(StreamGetRequestSchema, { sequenceNumber });
    try {
        const res = await client.stream.get(req, options);
        return toStoreBatch(res);
    } catch (e) {
        if (
            e instanceof ConnectError &&
            (isMissingBatchError(e) || e.code === Code.NotFound || e.code === Code.OutOfRange)
        ) {
            return null;
        }
        mapConnectToHttpError(e);
    }
}

async function* performSubscribe(
    client: Client,
    matchKeys: MessageInitShape<typeof MatchKeySchema>[],
    sinceSequenceNumber?: bigint,
    options?: CallOptions,
): AsyncIterable<StoreBatch> {
    const req = create(SubscribeRequestSchema, {
        matchKeys,
        ...(sinceSequenceNumber !== undefined ? { sinceSequenceNumber } : {}),
    });
    try {
        const stream = client.stream.subscribe(req, options);
        for await (const frame of stream) {
            yield toStoreBatch(frame);
        }
    } catch (e) {
        mapConnectToHttpError(e);
    }
}

export class SerializableReadSession {
    private sequence: bigint;
    private initGate = Promise.resolve();
    private gateLocked = false;

    constructor(private readonly client: Client, initialSequence: bigint = 0n) {
        this.sequence = normalizeMinSequenceNumber(initialSequence) ?? 0n;
    }

    fixedSequence(): bigint | undefined {
        return normalizeMinSequenceNumber(this.sequence);
    }

    private async acquireInitGate(): Promise<() => void> {
        while (this.gateLocked) {
            await this.initGate;
        }
        this.gateLocked = true;
        let release!: () => void;
        this.initGate = new Promise<void>((resolve) => {
            release = resolve;
        });
        return () => {
            this.gateLocked = false;
            release();
        };
    }

    private async runRead<T>(
        seededCall: (sequence: bigint) => Promise<T>,
        unseededCall: (detailObserver: DetailObserver) => Promise<T>,
    ): Promise<T> {
        const fixed = this.fixedSequence();
        if (fixed !== undefined) {
            return seededCall(fixed);
        }

        const release = await this.acquireInitGate();
        try {
            const rechecked = this.fixedSequence();
            if (rechecked !== undefined) {
                return await seededCall(rechecked);
            }

            let observed = this.sequence;
            const result = await unseededCall((detail) => {
                if (detail.sequenceNumber > observed) {
                    observed = detail.sequenceNumber;
                }
            });
            if (observed > this.sequence) {
                this.sequence = observed;
            }
            return result;
        } finally {
            release();
        }
    }

    async get(key: Uint8Array): Promise<GetResult | null> {
        return this.runRead(
            (sequence) => performGet(this.client, key, sequence),
            (detailObserver) => performGet(this.client, key, undefined, detailObserver),
        );
    }

    async getMany(
        keys: Uint8Array[],
        batchSize?: number,
        onChunk?: (entries: GetManyResultItem[]) => void,
    ): Promise<GetManyResultItem[]> {
        return this.runRead(
            (sequence) => performGetMany(this.client, keys, batchSize, onChunk, sequence),
            (detailObserver) =>
                performGetMany(this.client, keys, batchSize, onChunk, undefined, detailObserver),
        );
    }

    async query(
        start?: Uint8Array,
        end?: Uint8Array,
        limit?: number,
        batchSize: number = 4096,
        mode: TraversalMode = TraversalMode.FORWARD,
    ): Promise<QueryResult> {
        return this.runRead(
            (sequence) => performQuery(this.client, start, end, limit, batchSize, mode, sequence),
            (detailObserver) =>
                performQuery(
                    this.client,
                    start,
                    end,
                    limit,
                    batchSize,
                    mode,
                    undefined,
                    detailObserver,
                ),
        );
    }

    async reduce(
        start: Uint8Array,
        end: Uint8Array,
        params: ReduceParams,
    ): Promise<ReduceResponse> {
        return this.runRead(
            (sequence) => performReduce(this.client, start, end, params, sequence),
            (detailObserver) =>
                performReduce(this.client, start, end, params, undefined, detailObserver),
        );
    }
}

export class StoreClient {
    constructor(private readonly client: Client) {}

    createSession(): SerializableReadSession {
        return new SerializableReadSession(this.client);
    }

    createSessionWithSequence(sequence: bigint): SerializableReadSession {
        return new SerializableReadSession(this.client, sequence);
    }

    async set(key: Uint8Array, value: Uint8Array | Buffer): Promise<bigint> {
        const req = create(PutRequestSchema, {
            kvs: [
                create(KvEntrySchema, {
                    key,
                    value: toUint8Array(value),
                }),
            ],
        });
        try {
            const res = await this.client.ingest.put(req);
            return res.sequenceNumber;
        } catch (e) {
            mapConnectToHttpError(e);
        }
    }

    async setMany(kvs: { key: Uint8Array; value: Uint8Array | Buffer }[]): Promise<bigint> {
        const req = create(PutRequestSchema, {
            kvs: kvs.map((kv) =>
                create(KvEntrySchema, {
                    key: kv.key,
                    value: toUint8Array(kv.value),
                }),
            ),
        });
        try {
            const res = await this.client.ingest.put(req);
            return res.sequenceNumber;
        } catch (e) {
            mapConnectToHttpError(e);
        }
    }

    async get(key: Uint8Array, minSequenceNumber?: bigint): Promise<GetResult | null> {
        return performGet(this.client, key, minSequenceNumber);
    }

    async getMany(
        keys: Uint8Array[],
        batchSize?: number,
        onChunk?: (entries: GetManyResultItem[]) => void,
        minSequenceNumber?: bigint,
    ): Promise<GetManyResultItem[]> {
        return performGetMany(this.client, keys, batchSize, onChunk, minSequenceNumber);
    }

    async query(
        start?: Uint8Array,
        end?: Uint8Array,
        limit?: number,
        batchSize: number = 4096,
        mode: TraversalMode = TraversalMode.FORWARD,
        minSequenceNumber?: bigint,
    ): Promise<QueryResult> {
        return performQuery(
            this.client,
            start,
            end,
            limit,
            batchSize,
            mode,
            minSequenceNumber,
        );
    }

    async prune(policies: Policy[]): Promise<void> {
        const req = create(PruneRequestSchema, { policies });
        try {
            await this.client.compact.prune(req);
        } catch (e) {
            mapConnectToHttpError(e);
        }
    }

    async reduce(
        start: Uint8Array,
        end: Uint8Array,
        params: ReduceParams,
        minSequenceNumber?: bigint,
    ): Promise<ReduceResponse> {
        return performReduce(this.client, start, end, params, minSequenceNumber);
    }

    async getBatch(sequenceNumber: bigint, options?: CallOptions): Promise<StoreBatch | null> {
        return performGetBatch(this.client, sequenceNumber, options);
    }

    async *subscribe(
        matchKeys: MessageInitShape<typeof MatchKeySchema>[],
        sinceSequenceNumber?: bigint,
        options?: CallOptions,
    ): AsyncIterable<StoreBatch> {
        yield* performSubscribe(this.client, matchKeys, sinceSequenceNumber, options);
    }
}
