import { create, fromBinary } from '@bufbuild/protobuf';
import { Code, ConnectError } from '@connectrpc/connect';
import type { CallOptions } from '@connectrpc/connect';
import type { Client } from './client.js';
import { HttpError } from './error.js';
import { PruneRequestSchema } from './gen/ts/store/v1/compact_pb.js';
import type { Policy } from './gen/ts/store/v1/compact_pb.js';
import { PutRequestSchema, KvPairSchema } from './gen/ts/store/v1/ingest_pb.js';
import {
    GetRequestSchema,
    GetManyRequestSchema,
    RangeRequestSchema,
    ReduceRequestSchema,
    DetailSchema,
    TraversalMode,
} from './gen/ts/store/v1/query_pb.js';
import type {
    ReduceParams,
    ReduceResponse,
    Detail,
} from './gen/ts/store/v1/query_pb.js';

const QUERY_DETAIL_HEADER = 'x-store-query-detail-bin';

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

function toUint8Array(value: Uint8Array | Buffer): Uint8Array {
    return value instanceof Uint8Array ? value : new Uint8Array(value);
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

export class StoreClient {
    private _sequenceNumber = 0n;

    constructor(private readonly client: Client) {}

    get sequenceNumber(): bigint {
        return this._sequenceNumber;
    }

    observeSequenceNumber(sn: bigint): void {
        if (sn > this._sequenceNumber) {
            this._sequenceNumber = sn;
        }
    }

    private effectiveMinSequenceNumber(override?: bigint): bigint | undefined {
        const sn = override ?? this._sequenceNumber;
        return sn > 0n ? sn : undefined;
    }

    private observeDetailFromHeaders(headers: Headers): void {
        const detail = parseDetailFromHeaders(headers);
        if (detail) {
            this.observeSequenceNumber(detail.sequenceNumber);
        }
    }

    async set(key: Uint8Array, value: Uint8Array | Buffer): Promise<bigint> {
        const req = create(PutRequestSchema, {
            kvs: [
                create(KvPairSchema, {
                    key,
                    value: toUint8Array(value),
                }),
            ],
        });
        try {
            const res = await this.client.ingest.put(req);
            this.observeSequenceNumber(res.sequenceNumber);
            return res.sequenceNumber;
        } catch (e) {
            mapConnectToHttpError(e);
        }
    }

    async setMany(kvs: { key: Uint8Array; value: Uint8Array | Buffer }[]): Promise<bigint> {
        const req = create(PutRequestSchema, {
            kvs: kvs.map((kv) =>
                create(KvPairSchema, {
                    key: kv.key,
                    value: toUint8Array(kv.value),
                }),
            ),
        });
        try {
            const res = await this.client.ingest.put(req);
            this.observeSequenceNumber(res.sequenceNumber);
            return res.sequenceNumber;
        } catch (e) {
            mapConnectToHttpError(e);
        }
    }

    async get(
        key: Uint8Array,
        minSequenceNumber?: bigint,
    ): Promise<GetResult | null> {
        const effective = this.effectiveMinSequenceNumber(minSequenceNumber);
        const req = create(GetRequestSchema, {
            key,
            ...(effective !== undefined ? { minSequenceNumber: effective } : {}),
        });
        try {
            const callOpts: CallOptions = {
                onHeader: (h) => this.observeDetailFromHeaders(h),
                onTrailer: (t) => this.observeDetailFromHeaders(t),
            };
            const res = await this.client.query.get(req, callOpts);
            if (res.value === undefined) {
                return null;
            }
            return { value: res.value };
        } catch (e) {
            mapConnectToHttpError(e);
        }
    }

    async getMany(
        keys: Uint8Array[],
        batchSize?: number,
        onChunk?: (entries: GetManyResultItem[]) => void,
        minSequenceNumber?: bigint,
    ): Promise<GetManyResultItem[]> {
        const effective = this.effectiveMinSequenceNumber(minSequenceNumber);
        const req = create(GetManyRequestSchema, {
            keys,
            batchSize: batchSize ?? keys.length,
            ...(effective !== undefined ? { minSequenceNumber: effective } : {}),
        });
        const results: GetManyResultItem[] = [];
        try {
            const callOpts: CallOptions = {
                onHeader: (h) => this.observeDetailFromHeaders(h),
                onTrailer: (t) => this.observeDetailFromHeaders(t),
            };
            const stream = this.client.query.getMany(req, callOpts);
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

    async query(
        start?: Uint8Array,
        end?: Uint8Array,
        limit?: number,
        batchSize: number = 4096,
        mode: TraversalMode = TraversalMode.FORWARD,
        minSequenceNumber?: bigint,
    ): Promise<QueryResult> {
        const effective = this.effectiveMinSequenceNumber(minSequenceNumber);
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
            const callOpts: CallOptions = {
                onHeader: (h) => this.observeDetailFromHeaders(h),
                onTrailer: (t) => this.observeDetailFromHeaders(t),
            };
            const stream = this.client.query.range(req, callOpts);
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
        const effective = this.effectiveMinSequenceNumber(minSequenceNumber);
        const req = create(ReduceRequestSchema, {
            start,
            end,
            params,
            ...(effective !== undefined ? { minSequenceNumber: effective } : {}),
        });
        try {
            const callOpts: CallOptions = {
                onHeader: (h) => this.observeDetailFromHeaders(h),
                onTrailer: (t) => this.observeDetailFromHeaders(t),
            };
            return await this.client.query.reduce(req, callOpts);
        } catch (e) {
            mapConnectToHttpError(e);
        }
    }
}
