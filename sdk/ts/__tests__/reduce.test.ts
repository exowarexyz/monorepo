import { create } from '@bufbuild/protobuf';
import { Code, ConnectError } from '@connectrpc/connect';
import type { Client } from '../src/client';
import { HttpError } from '../src/error';
import {
    ReduceParamsSchema,
    ReduceResponseSchema,
    type ReduceRequest,
} from '../src/gen/ts/store/v1/query_pb';
import { SerializableReadSession, StoreClient } from '../src/store';

const start = new Uint8Array([1]);
const end = new Uint8Array([2]);
const params = create(ReduceParamsSchema);

function frame(group: bigint, sequenceNumber: bigint = 7n) {
    return create(ReduceResponseSchema, {
        groups: [{
            groupValues: [{ value: { case: 'uint64Value', value: group } }],
            groupValuesPresent: [true],
        }],
        detail: { sequenceNumber },
    });
}

function clientWithReduce(reduce: Client['query']['reduce']): Client {
    return { query: { reduce }, credential: 'absent' } as unknown as Client;
}

test('reduce yields frames on demand and returning cancels the underlying stream', async () => {
    let secondPolled = false;
    let cancelled = false;
    const client = clientWithReduce(async function* () {
        try {
            yield frame(1n);
            secondPolled = true;
            yield frame(2n, 7n);
        } finally {
            cancelled = true;
        }
    });
    const stream = new StoreClient(client).reduce(start, end, params)[Symbol.asyncIterator]();
    expect((await stream.next()).value).toEqual(frame(1n));
    expect(secondPolled).toBe(false);
    expect(cancelled).toBe(false);
    await stream.return?.();
    expect(cancelled).toBe(true);
    expect(secondPolled).toBe(false);
});

test('reduce observes metadata on frame consumption and sends the fixed session floor', async () => {
    const floors: Array<bigint | undefined> = [];
    const client = clientWithReduce(async function* (request) {
        floors.push((request as ReduceRequest).minSequenceNumber);
        yield frame(1n);
        yield frame(2n, 7n);
    });
    const session = new SerializableReadSession(client);
    const stream = session.reduce(start, end, params)[Symbol.asyncIterator]();
    expect(session.fixedSequence()).toBeUndefined();
    await stream.next();
    expect(session.fixedSequence()).toBe(7n);
    await stream.next();
    expect(session.fixedSequence()).toBe(7n);
    expect((await stream.next()).done).toBe(true);
    const second = session.reduce(start, end, params)[Symbol.asyncIterator]();
    await second.next();
    await second.return?.();
    expect(floors).toEqual([undefined, 7n]);
});

test('reduce returns a midstream error without replaying delivered groups', async () => {
    const reduce = jest.fn(async function* () {
        yield frame(1n);
        throw new ConnectError('failed after groups', Code.Unavailable);
    });
    const stream = new StoreClient(clientWithReduce(reduce))
        .reduce(start, end, params)[Symbol.asyncIterator]();
    expect((await stream.next()).value).toEqual(frame(1n));
    await expect(stream.next()).rejects.toBeInstanceOf(HttpError);
    expect(reduce).toHaveBeenCalledTimes(1);
});
