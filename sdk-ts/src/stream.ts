import { create } from '@bufbuild/protobuf';
import { Code, ConnectError } from '@connectrpc/connect';
import type { Client } from './client.js';
import { HttpError } from './error.js';
import type { MatchKey } from './gen/ts/store/v1/common_pb.js';
import { GetRequestSchema, SubscribeRequestSchema } from './gen/ts/store/v1/stream_pb.js';

export interface StreamBatchEntry {
    key: Uint8Array;
    value: Uint8Array;
}

export interface StreamBatch {
    sequenceNumber: bigint;
    entries: StreamBatchEntry[];
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

function toStreamBatch(sequenceNumber: bigint, entries: { key: Uint8Array; value: Uint8Array }[]): StreamBatch {
    return {
        sequenceNumber,
        entries: entries.map((entry) => ({
            key: entry.key,
            value: entry.value,
        })),
    };
}

export class StoreStreamClient {
    constructor(private readonly client: Client) {}

    async get(sequenceNumber: bigint): Promise<StreamBatch> {
        const req = create(GetRequestSchema, { sequenceNumber });
        try {
            const res = await this.client.streamService.get(req);
            return toStreamBatch(res.sequenceNumber, res.entries);
        } catch (e) {
            mapConnectToHttpError(e);
        }
    }

    async *subscribe(
        matchKeys: MatchKey[],
        sinceSequenceNumber?: bigint,
    ): AsyncGenerator<StreamBatch, void, void> {
        const req = create(SubscribeRequestSchema, {
            matchKeys,
            ...(sinceSequenceNumber !== undefined ? { sinceSequenceNumber } : {}),
        });
        try {
            const stream = this.client.streamService.subscribe(req);
            for await (const frame of stream) {
                yield toStreamBatch(frame.sequenceNumber, frame.entries);
            }
        } catch (e) {
            mapConnectToHttpError(e);
        }
    }
}
