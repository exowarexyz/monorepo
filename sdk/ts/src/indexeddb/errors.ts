/**
 * The errors of the store's handlers. Codes, detail messages and their order follow the Rust
 * server, so a client reads a failure the same way from either implementation.
 */

import { Code, ConnectError, type HandlerContext } from '@connectrpc/connect';
import {
    BadRequestSchema,
    ErrorInfoSchema,
    RetryInfoSchema,
} from '../gen/ts/google/rpc/error_details_pb.js';
import { DetailSchema } from '../gen/ts/store/v1/query_pb.js';
import { MAX_KEY_LEN } from '../limits.js';

// Domains of the ErrorInfo details that query and stream failures carry.
const QUERY_DOMAIN = 'store.query';
const STREAM_DOMAIN = 'log.stream';

/** Longest piece of request text that an error message repeats. */
const MAX_QUOTED_CHARS = 256;

/**
 * An INVALID_ARGUMENT error about one request field. It carries a BadRequest with the violation
 * and an ErrorInfo whose metadata repeats the description, in that order.
 */
export function fieldError(
    domain: string,
    field: string,
    description: string,
    reason: string,
    message: string,
    metadata: Record<string, string> = {},
): ConnectError {
    return new ConnectError(message, Code.InvalidArgument, undefined, [
        { desc: BadRequestSchema, value: { fieldViolations: [{ field, description }] } },
        { desc: ErrorInfoSchema, value: { reason, domain, metadata: { ...metadata, description } } },
    ]);
}

/** Rejects a key or range bound longer than the Store allows. */
export function checkKeyLength(domain: string, field: string, key: Uint8Array): void {
    if (key.byteLength <= MAX_KEY_LEN) return;
    throw fieldError(
        domain,
        field,
        `key length ${key.byteLength} exceeds max ${MAX_KEY_LEN}`,
        'INVALID_KEY_LENGTH',
        `${field} key length is outside store limits`,
        { max_key_len: String(MAX_KEY_LEN) },
    );
}

export function invalidArgument(message: string): ConnectError {
    return new ConnectError(message, Code.InvalidArgument);
}

/**
 * The failure of a query whose minimum sequence number is above the store's sequence number. The
 * client may retry, and the Detail carries the store's current sequence number.
 */
export function consistencyNotReady(required: bigint, current: bigint): ConnectError {
    return new ConnectError('minimum consistency token is not yet visible', Code.Aborted, undefined, [
        { desc: RetryInfoSchema, value: { retryDelay: { seconds: 1n } } },
        {
            desc: ErrorInfoSchema,
            value: {
                reason: 'CONSISTENCY_NOT_READY',
                domain: QUERY_DOMAIN,
                metadata: {
                    required_sequence_number: required.toString(),
                    current_sequence_number: current.toString(),
                },
            },
        },
        { desc: DetailSchema, value: { sequenceNumber: current } },
    ]);
}

/** A batch above the store's sequence number. No Put has written it yet. */
export function batchNotFound(): ConnectError {
    return new ConnectError('batch not found', Code.NotFound, undefined, [
        { desc: ErrorInfoSchema, value: { reason: 'BATCH_NOT_FOUND', domain: STREAM_DOMAIN } },
    ]);
}

/** A batch that retention removed. `oldestRetained` is absent when the log is empty. */
export function batchEvicted(oldestRetained: bigint | undefined): ConnectError {
    const metadata: Record<string, string> = {};
    if (oldestRetained !== undefined) metadata.oldest_retained = oldestRetained.toString();
    return new ConnectError('batch has been evicted from the log', Code.OutOfRange, undefined, [
        { desc: ErrorInfoSchema, value: { reason: 'BATCH_EVICTED', domain: STREAM_DOMAIN, metadata } },
    ]);
}

export function storeClosed(): ConnectError {
    return new ConnectError('store is closed', Code.Unavailable);
}

/** A meta row that does not have the form the layout defines. */
export function metadataCorrupt(): ConnectError {
    return new ConnectError('store metadata is corrupt', Code.Internal);
}

/** A stored key, value or batch that does not have the form the layout defines. */
export function dataCorrupt(): ConnectError {
    return new ConnectError('store data is corrupt', Code.Internal);
}

/**
 * The error of a call whose signal aborted. It is the signal's reason when that is a ConnectError,
 * such as a deadline error, and CANCELED otherwise.
 */
export function canceled(signal: AbortSignal): ConnectError {
    return ConnectError.from(signal.reason, Code.Canceled);
}

function escaped(char: string): string {
    switch (char) {
        case '"':
            return '\\"';
        case '\\':
            return '\\\\';
        case '\n':
            return '\\n';
        case '\r':
            return '\\r';
        case '\t':
            return '\\t';
        case '\0':
            return '\\0';
    }
    const code = char.codePointAt(0)!;
    return code < 0x20 || code === 0x7f ? `\\u{${code.toString(16)}}` : char;
}

/**
 * Request text as it appears inside an error message. It stands in double quotes with quotes,
 * backslashes and control characters escaped, and it is cut after `MAX_QUOTED_CHARS` characters so
 * a message stays small whatever the request holds. It reads at most one character past what it
 * shows, to tell whether the text was cut.
 */
export function quoted(text: string): string {
    let shown = '';
    let count = 0;
    for (const char of text) {
        if (count === MAX_QUOTED_CHARS) return `"${shown}..."`;
        shown += escaped(char);
        count++;
    }
    return `"${shown}"`;
}

/**
 * The name of an error that IndexedDB reports, undefined for any other value. Browsers report a
 * DOMException, and some report an exceeded quota as a QuotaExceededError object with a tag of
 * its own. The tag is read because an error can come from another realm, where instanceof does
 * not hold.
 */
export function domExceptionName(error: unknown): string | undefined {
    const tag = Object.prototype.toString.call(error).slice(8, -1);
    const reported = tag === 'DOMException' || tag === 'QuotaExceededError';
    return reported ? (error as DOMException).name : undefined;
}

/**
 * Maps whatever a handler throws to the error the client sees. A ConnectError passes through.
 * An exceeded storage quota is RESOURCE_EXHAUSTED. Any other IndexedDB failure is INTERNAL and
 * names only the kind of failure, and anything else is INTERNAL without detail.
 */
export function toConnectError(error: unknown): ConnectError {
    if (error instanceof ConnectError) return error;
    const name = domExceptionName(error);
    if (name === undefined) return new ConnectError('internal error', Code.Internal);
    if (name === 'QuotaExceededError') {
        return new ConnectError('store is out of space', Code.ResourceExhausted);
    }
    const shown = /^[A-Za-z]{1,64}$/.test(name) ? name : 'UnknownError';
    return new ConnectError(`indexeddb transaction failed: ${shown}`, Code.Internal);
}

/**
 * A unary handler that refuses calls on a closed store and reports every failure as a
 * ConnectError.
 */
export function unary<I, O>(
    isOpen: () => boolean,
    handler: (request: I, context: HandlerContext) => Promise<O>,
): (request: I, context: HandlerContext) => Promise<O> {
    return async (request, context) => {
        try {
            if (!isOpen()) throw storeClosed();
            return await handler(request, context);
        } catch (error) {
            throw toConnectError(error);
        }
    };
}

/** The same as `unary` for a handler that streams its answer. */
export function serverStream<I, O>(
    isOpen: () => boolean,
    handler: (request: I, context: HandlerContext) => AsyncIterable<O>,
): (request: I, context: HandlerContext) => AsyncGenerator<O> {
    return async function* (request, context) {
        try {
            if (!isOpen()) throw storeClosed();
            yield* handler(request, context);
        } catch (error) {
            throw toConnectError(error);
        }
    };
}
