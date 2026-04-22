import { create } from '@bufbuild/protobuf';
import type { Client } from './client.js';
import { mapConnectToHttpError } from './error.js';
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

export class StoreStreamClient {
    constructor(private readonly client: Client) {}

    async get(sequenceNumber: bigint): Promise<StreamBatch> {
        const req = create(GetRequestSchema, { sequenceNumber });
        try {
            const res = await this.client.streamService.get(req);
            return { sequenceNumber: res.sequenceNumber, entries: res.entries };
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
                yield { sequenceNumber: frame.sequenceNumber, entries: frame.entries };
            }
        } catch (e) {
            mapConnectToHttpError(e);
        }
    }
}
