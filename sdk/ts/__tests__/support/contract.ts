import {
    create,
    fromBinary,
    type DescMessage,
    type MessageInitShape,
    type MessageShape,
} from '@bufbuild/protobuf';
import { Code, ConnectError } from '@connectrpc/connect';
import type { Client } from '../../src/client';
import { BadRequestSchema, ErrorInfoSchema } from '../../src/gen/ts/google/rpc/error_details_pb';
import type { SubscribeRequestSchema, SubscribeResponse } from '../../src/gen/ts/log/v1/stream_pb';

export const bytes = (...values: number[]): Uint8Array => new Uint8Array(values);
export const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);
export const hex = (data: Uint8Array): string => Buffer.from(data).toString('hex');
export const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** The 8 byte big endian form of an unsigned integer. */
export function be64(value: bigint): Uint8Array {
    const encoded = new Uint8Array(8);
    new DataView(encoded.buffer).setBigUint64(0, value);
    return encoded;
}

/** The bytes of the parts in order. A part is a byte array or a list of byte values. */
export function concat(...parts: ArrayLike<number>[]): Uint8Array {
    const out = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}

/** Waits until `condition` holds. Fails when it does not hold within the timeout. */
export async function until(condition: () => boolean, timeoutMs: number = 5_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (!condition()) {
        if (Date.now() > deadline) throw new Error('the condition must hold within the timeout');
        await sleep(2);
    }
}

/** A selector that accepts every key. */
export const everyKey = { prefix: new Uint8Array(), payloadRegex: '(?s-u).*' };

export async function collect<T>(stream: AsyncIterable<T>): Promise<T[]> {
    const items: T[] = [];
    for await (const item of stream) items.push(item);
    return items;
}

/** The ConnectError that a call or a stream ends with. Fails when it ends without one. */
export async function failure(call: Promise<unknown> | AsyncIterable<unknown>): Promise<ConnectError> {
    try {
        await (Symbol.asyncIterator in call ? collect(call) : call);
    } catch (error) {
        expect(error).toBeInstanceOf(ConnectError);
        return error as ConnectError;
    }
    throw new Error('the call must fail');
}

function bareTypeName(type: string): string {
    return type.replace(/^type\.googleapis\.com\//, '');
}

/** Type names of the error's details in order. */
export function detailTypes(error: ConnectError): string[] {
    return error.details.map((detail) =>
        'desc' in detail ? detail.desc.typeName : bareTypeName(detail.type));
}

/** The decoded details of one type. */
export function details<S extends DescMessage>(error: ConnectError, schema: S): MessageShape<S>[] {
    return error.details.flatMap((detail) => {
        if ('desc' in detail) {
            return detail.desc.typeName === schema.typeName
                ? [create(schema, detail.value as MessageInitShape<S>)]
                : [];
        }
        return bareTypeName(detail.type) === schema.typeName ? [fromBinary(schema, detail.value)] : [];
    });
}

/** Checks that each call, run in turn, fails with the code and, when given, the message. */
export async function expectEveryCallFails(
    calls: (() => Promise<unknown> | AsyncIterable<unknown>)[],
    code: Code,
    message?: string,
): Promise<void> {
    for (const call of calls) {
        const error = await failure(call());
        expect(error.code).toBe(code);
        if (message !== undefined) expect(error.rawMessage).toBe(message);
    }
}

export interface FieldError {
    message: string;
    field: string;
    description: string;
    reason: string;
    domain: string;
    metadata?: Record<string, string>;
}

/** Checks an INVALID_ARGUMENT error about one request field, with its two details in order. */
export function expectFieldError(error: ConnectError, expected: FieldError): void {
    expect(error.code).toBe(Code.InvalidArgument);
    expect(error.rawMessage).toBe(expected.message);
    expect(detailTypes(error)).toEqual([BadRequestSchema.typeName, ErrorInfoSchema.typeName]);
    const [badRequest] = details(error, BadRequestSchema);
    expect(badRequest.fieldViolations).toHaveLength(1);
    expect(badRequest.fieldViolations[0]).toMatchObject({
        field: expected.field,
        description: expected.description,
    });
    const [info] = details(error, ErrorInfoSchema);
    expect(info.reason).toBe(expected.reason);
    expect(info.domain).toBe(expected.domain);
    expect(info.metadata).toEqual({ ...expected.metadata, description: expected.description });
}

/** Checks an INVALID_ARGUMENT error that carries only a message. */
export function expectInvalidArgument(error: ConnectError, message: string | RegExp): void {
    expect(error.code).toBe(Code.InvalidArgument);
    expect(error.rawMessage).toMatch(typeof message === 'string' ? new RegExp(`^${escapeRegExp(message)}$`) : message);
    expect(error.details).toHaveLength(0);
}

function escapeRegExp(text: string): string {
    return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Checks the error of a log read for a batch that is not there. */
export function expectLogError(
    error: ConnectError,
    expected: { code: Code; reason: string; oldestRetained?: bigint },
): void {
    expect(error.code).toBe(expected.code);
    expect(detailTypes(error)).toEqual([ErrorInfoSchema.typeName]);
    const [info] = details(error, ErrorInfoSchema);
    expect(info.reason).toBe(expected.reason);
    expect(info.domain).toBe('log.stream');
    expect(info.metadata).toEqual(
        expected.oldestRetained === undefined ? {} : { oldest_retained: expected.oldestRetained.toString() },
    );
}

export async function nextWithTimeout<T>(
    iterator: AsyncIterator<T>,
    timeoutMs: number = 5_000,
): Promise<IteratorResult<T>> {
    let timeout: NodeJS.Timeout | undefined;
    try {
        return await Promise.race([
            iterator.next(),
            new Promise<IteratorResult<T>>((_, reject) => {
                timeout = setTimeout(() => reject(new Error('timed out waiting for stream')), timeoutMs);
            }),
        ]);
    } finally {
        if (timeout) {
            clearTimeout(timeout);
        }
    }
}

/** The next frame of a subscription. Fails when it ends or no frame arrives within the timeout. */
export async function nextFrame(
    frames: AsyncIterator<SubscribeResponse>,
    timeoutMs?: number,
): Promise<SubscribeResponse> {
    const next = await nextWithTimeout(frames, timeoutMs);
    if (next.done) throw new Error('the subscription must yield another frame');
    return next.value;
}

export type Row = [key: Uint8Array, value: Uint8Array];

/** Writes one batch through the generated ingest client, so no StoreClient check runs first. */
export async function put(client: Client, rows: Row[]): Promise<bigint> {
    const response = await client.ingest.put({ kvs: rows.map(([key, value]) => ({ key, value })) });
    return response.sequenceNumber;
}

/** Every row of the store in key order, with the sequence number of the read. */
export async function allRows(client: Client): Promise<{ sequenceNumber: bigint; rows: Row[] }> {
    const frames = await collect(client.query.range({ batchSize: 4096 }));
    return {
        sequenceNumber: frames[0].detail!.sequenceNumber,
        rows: frames.flatMap((frame) => frame.results.map(({ key, value }): Row => [key, value])),
    };
}

/**
 * Aborts a call with an Error named AbortError so that Connect reports CANCELED. Under jest the
 * default reason of an AbortController comes from another realm, so Connect does not take it for
 * an Error and reports UNKNOWN.
 */
export function abortCall(controller: AbortController): void {
    controller.abort(Object.assign(new Error('This operation was aborted'), { name: 'AbortError' }));
}

/** Subscriptions opened by a test, ended together when it finishes. */
export class Subscriptions {
    private readonly controllers: AbortController[] = [];

    /** Opens a subscription and returns its frames with the controller that ends it. */
    open(
        client: Client,
        request: MessageInitShape<typeof SubscribeRequestSchema>,
    ): { frames: AsyncIterator<SubscribeResponse>; controller: AbortController } {
        const controller = new AbortController();
        this.controllers.push(controller);
        const stream = client.stream.subscribe(request, { signal: controller.signal });
        return { frames: stream[Symbol.asyncIterator](), controller };
    }

    closeAll(): void {
        for (const controller of this.controllers.splice(0)) abortCall(controller);
    }
}
