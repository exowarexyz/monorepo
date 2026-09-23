import { create, type MessageInitShape } from '@bufbuild/protobuf';
import { Code, ConnectError } from '@connectrpc/connect';
import type { CallOptions } from '@connectrpc/connect';
import type { Client } from './client.js';
import { credentialRemedy, withoutHtmlBody, type Credential } from './credential.js';
import { HttpError } from './error.js';
import { PruneRequestSchema } from './gen/ts/store/v1/prune_pb.js';
import type { Policy } from './gen/ts/store/v1/prune_pb.js';
import {
    FilterSchema,
    EntrySchema,
    SelectorSchema,
} from './gen/ts/common/v1/kv_pb.js';
import type { Selector } from './gen/ts/common/v1/kv_pb.js';
import { ErrorInfoSchema } from './gen/ts/google/rpc/error_details_pb.js';
import { PutRequestSchema } from './gen/ts/log/v1/ingest_pb.js';
import { MAX_KEY_LEN } from './limits.js';
import {
    GetManyRequestSchema,
    GetRequestSchema as QueryGetRequestSchema,
    RangeRequestSchema,
    ReduceRequestSchema,
    TraversalMode,
} from './gen/ts/store/v1/query_pb.js';
import type {
    Detail,
    KvExpr,
    KvFieldRef,
    KvPredicate,
    RangeReducerSpec,
    ReduceParams,
    ReduceResponse,
} from './gen/ts/store/v1/query_pb.js';
import {
    GetRequestSchema as StreamGetRequestSchema,
    SubscribeRequestSchema,
} from './gen/ts/log/v1/stream_pb.js';

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
    sequenceNumber: bigint;
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

export class StoreKeyPrefix {
    public readonly prefix: Uint8Array;

    constructor(prefix: Uint8Array) {
        if (prefix.length > MAX_KEY_LEN) {
            throw new RangeError(
                `store key prefix length ${prefix.length} exceeds ${MAX_KEY_LEN}`,
            );
        }
        // Copy so the namespace cannot alias a caller-owned mutable buffer.
        this.prefix = prefix.slice();
    }

    maxLogicalKeyLen(): number {
        return MAX_KEY_LEN - this.prefix.length;
    }

    encodeKey(key: Uint8Array): Uint8Array {
        const maxPayloadLen = this.maxLogicalKeyLen();
        if (key.length > maxPayloadLen) {
            throw new RangeError(
                `logical key length ${key.length} exceeds prefixed capacity ${maxPayloadLen}`,
            );
        }
        const out = new Uint8Array(this.prefix.length + key.length);
        out.set(this.prefix, 0);
        out.set(key, this.prefix.length);
        return out;
    }

    decodeKey(key: Uint8Array): Uint8Array {
        if (!this.matches(key)) {
            throw new RangeError('key does not belong to this store prefix');
        }
        // Copy so decoded keys do not alias the shared transport frame.
        return key.slice(this.prefix.length);
    }

    matches(key: Uint8Array): boolean {
        if (key.length < this.prefix.length) {
            return false;
        }
        for (let i = 0; i < this.prefix.length; i++) {
            if (key[i] !== this.prefix[i]) {
                return false;
            }
        }
        return true;
    }

    prefixBounds(): { start: Uint8Array; end: Uint8Array } {
        const start = this.prefix.slice();
        const end = new Uint8Array(MAX_KEY_LEN);
        end.fill(0xff);
        end.set(this.prefix, 0);
        return { start, end };
    }

    encodeRange(start?: Uint8Array, end?: Uint8Array): { start: Uint8Array; end: Uint8Array } {
        const physicalStart = this.encodeKey(start ?? new Uint8Array());
        let physicalEnd: Uint8Array;
        if (end === undefined || end.length === 0) {
            physicalEnd = this.prefixBounds().end;
        } else {
            const maxLen = this.maxLogicalKeyLen();
            physicalEnd = this.encodeKey(end.length > maxLen ? end.subarray(0, maxLen) : end);
        }
        return { start: physicalStart, end: physicalEnd };
    }

    // The selector's payloadRegex is forwarded verbatim and compiled
    // server-side by Rust's regex crate, so JS-only syntax (lookaround,
    // backreferences) is rejected by the server.
    prefixSelector(selector: MessageInitShape<typeof SelectorSchema>): Selector {
        const logicalPrefix = selector.prefix ?? new Uint8Array();
        const prefix = new Uint8Array(this.prefix.length + logicalPrefix.length);
        prefix.set(this.prefix, 0);
        prefix.set(logicalPrefix, this.prefix.length);
        if (prefix.length > MAX_KEY_LEN) {
            throw new RangeError(
                `combined key prefix length ${prefix.length} exceeds ${MAX_KEY_LEN}`,
            );
        }
        return create(SelectorSchema, {
            prefix,
            payloadRegex: selector.payloadRegex ?? '',
        });
    }
}

function toUint8Array(value: Uint8Array | Buffer): Uint8Array {
    return value instanceof Uint8Array ? value : new Uint8Array(value);
}

function copyBytes(value: Uint8Array | Buffer): Uint8Array {
    return new Uint8Array(toUint8Array(value));
}

function encodeStoreKey(prefix: StoreKeyPrefix | undefined, key: Uint8Array): Uint8Array {
    return prefix ? prefix.encodeKey(key) : key;
}

function decodeStoreKey(prefix: StoreKeyPrefix | undefined, key: Uint8Array): Uint8Array {
    return prefix ? prefix.decodeKey(key) : key;
}

function encodeStoreRange(
    prefix: StoreKeyPrefix | undefined,
    start?: Uint8Array,
    end?: Uint8Array,
): { start: Uint8Array; end: Uint8Array } {
    if (prefix) {
        return prefix.encodeRange(start, end);
    }
    return {
        start: start ?? new Uint8Array(),
        end: end ?? new Uint8Array(),
    };
}

export class StoreWriteBatch {
    private readonly kvs: StoreBatchEntry[] = [];

    push(client: StoreClient, key: Uint8Array, value: Uint8Array | Buffer): this {
        this.kvs.push({
            key: client.encodeStoreKey(key),
            value: copyBytes(value),
        });
        return this;
    }

    entries(): readonly StoreBatchEntry[] {
        return this.kvs;
    }

    get length(): number {
        return this.kvs.length;
    }

    clear(): void {
        this.kvs.length = 0;
    }

    async commit(client: StoreClient): Promise<bigint> {
        return client.putPrepared(this);
    }
}

function normalizeMinSequenceNumber(value?: bigint): bigint | undefined {
    return value !== undefined && value >= 0n ? value : undefined;
}

function maxSequenceNumber(
    left: bigint | undefined,
    right: bigint | undefined,
): bigint | undefined {
    if (left === undefined) return right;
    if (right === undefined) return left;
    return left > right ? left : right;
}

/**
 * Presents an RPC failure to the caller, dropping any page a proxy answered with and telling a
 * rejected caller what to do about their credential.
 */
function mapConnectToHttpError(err: unknown, credential: Credential): never {
    if (err instanceof ConnectError) {
        const status = connectCodeToHttpStatus(err.code);
        let message = withoutHtmlBody(err.message);
        if (err.code === Code.Unauthenticated) {
            const remedy = credentialRemedy(credential);
            message = message === undefined ? remedy : `${message}. ${remedy}`;
        }
        throw new HttpError(status, message || String(err.code), err.code, err);
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

function isMissingBatchError(err: ConnectError): boolean {
    return err.findDetails(ErrorInfoSchema).some(
        (detail) =>
            detail.domain === 'log.stream' &&
            (detail.reason === 'BATCH_EVICTED' || detail.reason === 'BATCH_NOT_FOUND'),
    );
}

function toStoreBatch(
    response: {
        sequenceNumber: bigint;
        entries: { key: Uint8Array; value: Uint8Array }[];
    },
    prefix?: StoreKeyPrefix,
): StoreBatch {
    return {
        sequenceNumber: response.sequenceNumber,
        entries: response.entries.flatMap((entry) => {
            if (prefix && !prefix.matches(entry.key)) {
                return [];
            }
            return [
                {
                    key: decodeStoreKey(prefix, entry.key),
                    value: entry.value,
                },
            ];
        }),
    };
}

function prefixPolicies(policies: Policy[], prefix?: StoreKeyPrefix): Policy[] {
    if (!prefix) return policies;
    return policies.map((policy) => {
        const scope = policy.keys;
        if (!scope) {
            return policy;
        }
        return {
            ...policy,
            keys: {
                ...scope,
                selector: scope.selector ? prefix.prefixSelector(scope.selector) : undefined,
            },
        } as Policy;
    });
}

function prefixSubscribeFilters(
    filters: SubscribeFilters,
    prefix?: StoreKeyPrefix,
): SubscribeFilters {
    if (!prefix) return filters;
    return {
        ...filters,
        selectors: filters.selectors.map((selector) => prefix.prefixSelector(selector)),
    };
}

function shiftOffset(offset: number, shift: number, unit: 'byte' | 'bit'): number {
    const shifted = offset + shift;
    if (shifted > 0xffff) {
        throw new RangeError(
            `key ${unit} offset ${offset} plus prefix ${unit}s ${shift} exceeds u16`,
        );
    }
    return shifted;
}

function prefixFieldRef(field: KvFieldRef, prefixBytes: number): KvFieldRef {
    switch (field.field.case) {
        case 'key':
            return {
                ...field,
                field: {
                    case: 'key',
                    value: {
                        ...field.field.value,
                        byteOffset: shiftOffset(field.field.value.byteOffset, prefixBytes, 'byte'),
                    },
                },
            } as KvFieldRef;
        case 'zOrderKey':
            return {
                ...field,
                field: {
                    case: 'zOrderKey',
                    value: {
                        ...field.field.value,
                        bitOffset: shiftOffset(field.field.value.bitOffset, prefixBytes * 8, 'bit'),
                    },
                },
            } as KvFieldRef;
        case 'value':
        case undefined:
            return field;
    }
}

function prefixExpr(expr: KvExpr, prefixBytes: number): KvExpr {
    switch (expr.expr.case) {
        case 'field':
            return {
                ...expr,
                expr: {
                    case: 'field',
                    value: prefixFieldRef(expr.expr.value, prefixBytes),
                },
            } as KvExpr;
        case 'add':
        case 'sub':
        case 'mul':
        case 'div':
            return {
                ...expr,
                expr: {
                    case: expr.expr.case,
                    value: {
                        ...expr.expr.value,
                        left: expr.expr.value.left
                            ? prefixExpr(expr.expr.value.left, prefixBytes)
                            : undefined,
                        right: expr.expr.value.right
                            ? prefixExpr(expr.expr.value.right, prefixBytes)
                            : undefined,
                    },
                },
            } as KvExpr;
        case 'lower':
        case 'dateTruncDay':
        case 'castFloat64':
            return {
                ...expr,
                expr: {
                    case: expr.expr.case,
                    value: prefixExpr(expr.expr.value, prefixBytes),
                },
            } as KvExpr;
        case 'literal':
        case undefined:
            return expr;
    }
}

function prefixPredicate(predicate: KvPredicate, prefixBytes: number): KvPredicate {
    return {
        ...predicate,
        checks: predicate.checks.map((check) => ({
            ...check,
            field: check.field ? prefixFieldRef(check.field, prefixBytes) : undefined,
        })),
    } as KvPredicate;
}

function prefixReducer(reducer: RangeReducerSpec, prefixBytes: number): RangeReducerSpec {
    return {
        ...reducer,
        expr: reducer.expr ? prefixExpr(reducer.expr, prefixBytes) : undefined,
        filter: reducer.filter ? prefixPredicate(reducer.filter, prefixBytes) : undefined,
    } as RangeReducerSpec;
}

function prefixReduceParams(params: ReduceParams, prefix?: StoreKeyPrefix): ReduceParams {
    if (!prefix) return params;
    const prefixBytes = prefix.prefix.length;
    return {
        ...params,
        reducers: params.reducers.map((reducer) => prefixReducer(reducer, prefixBytes)),
        groupBy: params.groupBy.map((expr) => prefixExpr(expr, prefixBytes)),
        filter: params.filter ? prefixPredicate(params.filter, prefixBytes) : undefined,
    } as ReduceParams;
}

async function performGet(
    client: Client,
    key: Uint8Array,
    minSequenceNumber?: bigint,
    detailObserver?: DetailObserver,
    prefix?: StoreKeyPrefix,
    options?: CallOptions,
): Promise<GetResult | null> {
    const effective = normalizeMinSequenceNumber(minSequenceNumber);
    const req = create(QueryGetRequestSchema, {
        key: encodeStoreKey(prefix, key),
        ...(effective !== undefined ? { minSequenceNumber: effective } : {}),
    });
    try {
        const res = await client.query.get(req, options);
        if (res.detail) {
            detailObserver?.(res.detail);
        }
        if (res.value === undefined) {
            return null;
        }
        return { value: res.value };
    } catch (e) {
        mapConnectToHttpError(e, client.credential);
    }
}

async function performGetMany(
    client: Client,
    keys: Uint8Array[],
    batchSize?: number,
    onChunk?: (entries: GetManyResultItem[]) => void,
    minSequenceNumber?: bigint,
    detailObserver?: DetailObserver,
    prefix?: StoreKeyPrefix,
): Promise<GetManyResultItem[]> {
    const effective = normalizeMinSequenceNumber(minSequenceNumber);
    const req = create(GetManyRequestSchema, {
        keys: keys.map((key) => encodeStoreKey(prefix, key)),
        batchSize: batchSize ?? keys.length,
        ...(effective !== undefined ? { minSequenceNumber: effective } : {}),
    });
    const results: GetManyResultItem[] = [];
    try {
        const stream = client.query.getMany(req);
        for await (const frame of stream) {
            if (frame.detail) {
                detailObserver?.(frame.detail);
            }
            const chunk: GetManyResultItem[] = [];
            for (const entry of frame.results) {
                chunk.push({
                    key: decodeStoreKey(prefix, entry.key),
                    value: entry.value,
                });
            }
            if (onChunk && chunk.length > 0) {
                onChunk(chunk);
            }
            results.push(...chunk);
        }
        return results;
    } catch (e) {
        mapConnectToHttpError(e, client.credential);
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
    prefix?: StoreKeyPrefix,
    options?: CallOptions,
): Promise<QueryResult> {
    const effective = normalizeMinSequenceNumber(minSequenceNumber);
    const physicalRange = encodeStoreRange(prefix, start, end);
    const req = create(RangeRequestSchema, {
        start: physicalRange.start,
        end: physicalRange.end,
        batchSize,
        mode,
        ...(limit !== undefined ? { limit } : {}),
        ...(effective !== undefined ? { minSequenceNumber: effective } : {}),
    });
    const results: QueryResultItem[] = [];
    let sequenceNumber = 0n;
    try {
        const stream = client.query.range(req, options);
        for await (const frame of stream) {
            for (const row of frame.results) {
                results.push({ key: decodeStoreKey(prefix, row.key), value: row.value });
            }
            if (frame.detail) {
                sequenceNumber = frame.detail.sequenceNumber;
                detailObserver?.(frame.detail);
            }
        }
        return { sequenceNumber, results };
    } catch (e) {
        mapConnectToHttpError(e, client.credential);
    }
}

async function* performReduce(
    client: Client,
    start: Uint8Array,
    end: Uint8Array,
    params: ReduceParams,
    minSequenceNumber?: bigint,
    detailObserver?: DetailObserver,
    prefix?: StoreKeyPrefix,
): AsyncIterable<ReduceResponse> {
    const effective = normalizeMinSequenceNumber(minSequenceNumber);
    const physicalRange = encodeStoreRange(prefix, start, end);
    const req = create(ReduceRequestSchema, {
        start: physicalRange.start,
        end: physicalRange.end,
        params: prefixReduceParams(params, prefix),
        ...(effective !== undefined ? { minSequenceNumber: effective } : {}),
    });
    const controller = new AbortController();
    try {
        for await (const frame of client.query.reduce(req, { signal: controller.signal })) {
            if (frame.detail) {
                detailObserver?.(frame.detail);
            }
            yield frame;
        }
    } catch (e) {
        mapConnectToHttpError(e, client.credential);
    } finally {
        controller.abort();
    }
}

async function prefetchFirst<T>(iterable: AsyncIterable<T>): Promise<AsyncIterable<T>> {
    const iterator = iterable[Symbol.asyncIterator]();
    const first = await iterator.next();
    return (async function* () {
        try {
            if (!first.done) {
                yield first.value;
                yield* { [Symbol.asyncIterator]: () => iterator };
            }
        } finally {
            await iterator.return?.();
        }
    })();
}

async function performGetBatch(
    client: Client,
    sequenceNumber: bigint,
    prefix?: StoreKeyPrefix,
    options?: CallOptions,
): Promise<StoreBatch | null> {
    const req = create(StreamGetRequestSchema, { sequenceNumber });
    try {
        const res = await client.stream.get(req, options);
        return toStoreBatch(res, prefix);
    } catch (e) {
        if (
            e instanceof ConnectError &&
            (isMissingBatchError(e) || e.code === Code.NotFound || e.code === Code.OutOfRange)
        ) {
            return null;
        }
        mapConnectToHttpError(e, client.credential);
    }
}

export interface SubscribeFilters {
    selectors: MessageInitShape<typeof SelectorSchema>[];
    valueFilters?: MessageInitShape<typeof FilterSchema>[];
    sinceSequenceNumber?: bigint;
}

async function* performSubscribe(
    client: Client,
    filters: SubscribeFilters,
    prefix?: StoreKeyPrefix,
    options?: CallOptions,
): AsyncIterable<StoreBatch> {
    const prefixed = prefixSubscribeFilters(filters, prefix);
    const req = create(SubscribeRequestSchema, {
        selectors: prefixed.selectors,
        valueFilters: prefixed.valueFilters ?? [],
        ...(prefixed.sinceSequenceNumber !== undefined
            ? { sinceSequenceNumber: prefixed.sinceSequenceNumber }
            : {}),
    });
    try {
        const stream = client.stream.subscribe(req, options);
        for await (const frame of stream) {
            const batch = toStoreBatch(frame, prefix);
            if (batch.entries.length === 0) {
                continue;
            }
            yield batch;
        }
    } catch (e) {
        mapConnectToHttpError(e, client.credential);
    }
}

type ReadPolicy = 'fixed' | 'monotonic';

interface ReadSessionState {
    sequence: bigint | undefined;
    initGate: Promise<void>;
    gateLocked: boolean;
}

interface StoreClientBinding {
    client: Client;
    keyPrefix?: StoreKeyPrefix;
}

const storeClientBindings = new WeakMap<StoreClient, StoreClientBinding>();

/**
 * A read session with a fixed or monotonic minimum Store sequence.
 *
 * Fixed sessions keep their configured floor. Monotonic sessions raise their floor to the highest
 * sequence observed by any clone. An absent floor sends no requirement; zero is an explicit floor.
 * An initial floor is a requirement, not an observation.
 */
export class ReadSession {
    private policy: ReadPolicy = 'monotonic';
    private configuredFloor: bigint | undefined;
    private state: ReadSessionState = {
        sequence: undefined,
        initGate: Promise.resolve(),
        gateLocked: false,
    };

    /** Create a monotonic session from the low-level client. */
    constructor(
        private client: Client,
        private keyPrefix?: StoreKeyPrefix,
        initialSequence?: bigint,
    ) {
        this.configuredFloor = normalizeMinSequenceNumber(initialSequence);
    }

    /** Create a session whose floor advances to the highest observed read sequence. */
    static monotonic(client: StoreClient, initialFloor?: bigint): ReadSession {
        return ReadSession.fromStoreClient(client, initialFloor, 'monotonic');
    }

    /** Create a session whose read floor stays fixed as responses are observed. */
    static fixed(client: StoreClient, floor?: bigint): ReadSession {
        return ReadSession.fromStoreClient(client, floor, 'fixed');
    }

    private static fromStoreClient(
        storeClient: StoreClient,
        configuredFloor: bigint | undefined,
        policy: ReadPolicy,
    ): ReadSession {
        const binding = storeClientBindings.get(storeClient);
        if (!binding) {
            throw new TypeError('invalid StoreClient');
        }
        const session = new ReadSession(binding.client, binding.keyPrefix, configuredFloor);
        session.policy = policy;
        return session;
    }

    /** Minimum Store sequence requested by subsequent reads. */
    minSequenceNumber(): bigint | undefined {
        return this.policy === 'fixed'
            ? this.configuredFloor
            : maxSequenceNumber(this.configuredFloor, this.state.sequence);
    }

    /** Highest Store sequence reported by a read in this session. */
    evaluatedSequence(): bigint | undefined {
        return this.state.sequence;
    }

    /** Return a handle that shares observations and retains this handle's policy and floor. */
    clone(): ReadSession {
        const session = new ReadSession(this.client, this.keyPrefix, this.configuredFloor);
        session.policy = this.policy;
        session.state = this.state;
        return session;
    }

    /**
     * Derive a reader with at least the requested minimum sequence.
     *
     * The derived handle's floor is at least `sequence`. The parent floor is unchanged, and the
     * requirement does not count as an observation.
     */
    withMinSequenceNumber(sequence: bigint): ReadSession {
        const session = this.clone();
        const requested = normalizeMinSequenceNumber(sequence);
        if (requested === undefined) {
            return session;
        }
        const current = this.minSequenceNumber();
        if (current === undefined || requested > current) {
            session.configuredFloor = requested;
        }
        return session;
    }

    /** Share this session's observations with another logical client for the same Store. */
    withClient(client: StoreClient): ReadSession {
        const binding = storeClientBindings.get(client);
        if (!binding) {
            throw new TypeError('invalid StoreClient');
        }
        const session = this.clone();
        session.client = binding.client;
        session.keyPrefix = binding.keyPrefix;
        return session;
    }

    private observe(detail: Detail): void {
        if (this.state.sequence === undefined || detail.sequenceNumber > this.state.sequence) {
            this.state.sequence = detail.sequenceNumber;
        }
    }

    private async acquireInitGate(): Promise<() => void> {
        while (this.state.gateLocked) {
            await this.state.initGate;
        }
        this.state.gateLocked = true;
        let release!: () => void;
        this.state.initGate = new Promise<void>((resolve) => {
            release = resolve;
        });
        return () => {
            this.state.gateLocked = false;
            release();
        };
    }

    private async runRead<T>(
        call: (sequence: bigint | undefined, detailObserver: DetailObserver) => Promise<T>,
    ): Promise<T> {
        const observer = (detail: Detail) => this.observe(detail);
        const minimum = this.minSequenceNumber();
        if (this.policy === 'fixed' || minimum !== undefined) {
            return call(minimum, observer);
        }

        const release = await this.acquireInitGate();
        try {
            const rechecked = this.minSequenceNumber();
            if (rechecked !== undefined) {
                return await call(rechecked, observer);
            }
            return await call(undefined, observer);
        } finally {
            release();
        }
    }

    async get(key: Uint8Array): Promise<GetResult | null> {
        return this.runRead((sequence, detailObserver) =>
            performGet(this.client, key, sequence, detailObserver, this.keyPrefix),
        );
    }

    async getMany(
        keys: Uint8Array[],
        batchSize?: number,
        onChunk?: (entries: GetManyResultItem[]) => void,
    ): Promise<GetManyResultItem[]> {
        return this.runRead((sequence, detailObserver) =>
            performGetMany(
                this.client,
                keys,
                batchSize,
                onChunk,
                sequence,
                detailObserver,
                this.keyPrefix,
            ),
        );
    }

    async query(
        start?: Uint8Array,
        end?: Uint8Array,
        limit?: number,
        batchSize: number = 4096,
        mode: TraversalMode = TraversalMode.FORWARD,
    ): Promise<QueryResult> {
        return this.runRead((sequence, detailObserver) =>
            performQuery(
                this.client,
                start,
                end,
                limit,
                batchSize,
                mode,
                sequence,
                detailObserver,
                this.keyPrefix,
            ),
        );
    }

    async *reduce(
        start: Uint8Array,
        end: Uint8Array,
        params: ReduceParams,
    ): AsyncIterable<ReduceResponse> {
        yield* await this.runRead(async (sequence, detailObserver) => {
            const stream = performReduce(
                this.client,
                start,
                end,
                params,
                sequence,
                detailObserver,
                this.keyPrefix,
            );
            return sequence === undefined && this.policy === 'monotonic'
                ? prefetchFirst(stream)
                : stream;
        });
    }

}

export class StoreClient {
    constructor(
        private readonly client: Client,
        private readonly keyPrefix?: StoreKeyPrefix,
    ) {
        storeClientBindings.set(this, { client, keyPrefix });
    }

    withKeyPrefix(prefix: StoreKeyPrefix): StoreClient {
        return new StoreClient(this.client, prefix);
    }

    withoutKeyPrefix(): StoreClient {
        return new StoreClient(this.client);
    }

    encodeStoreKey(key: Uint8Array): Uint8Array {
        return encodeStoreKey(this.keyPrefix, key);
    }

    decodeStoreKey(key: Uint8Array): Uint8Array {
        return decodeStoreKey(this.keyPrefix, key);
    }

    createSession(): ReadSession {
        return ReadSession.monotonic(this);
    }

    createSessionWithSequence(sequence: bigint): ReadSession {
        return ReadSession.monotonic(this, sequence);
    }

    async set(key: Uint8Array, value: Uint8Array | Buffer): Promise<bigint> {
        const req = create(PutRequestSchema, {
            kvs: [
                create(EntrySchema, {
                    key: this.encodeStoreKey(key),
                    value: toUint8Array(value),
                }),
            ],
        });
        try {
            const res = await this.client.ingest.put(req);
            return res.sequenceNumber;
        } catch (e) {
            mapConnectToHttpError(e, this.client.credential);
        }
    }

    async setMany(kvs: { key: Uint8Array; value: Uint8Array | Buffer }[]): Promise<bigint> {
        const req = create(PutRequestSchema, {
            kvs: kvs.map((kv) =>
                create(EntrySchema, {
                    key: this.encodeStoreKey(kv.key),
                    value: toUint8Array(kv.value),
                }),
            ),
        });
        try {
            const res = await this.client.ingest.put(req);
            return res.sequenceNumber;
        } catch (e) {
            mapConnectToHttpError(e, this.client.credential);
        }
    }

    async putPrepared(batch: StoreWriteBatch): Promise<bigint> {
        const req = create(PutRequestSchema, {
            kvs: batch.entries().map((kv) =>
                create(EntrySchema, {
                    key: kv.key,
                    value: kv.value,
                }),
            ),
        });
        try {
            const res = await this.client.ingest.put(req);
            return res.sequenceNumber;
        } catch (e) {
            mapConnectToHttpError(e, this.client.credential);
        }
    }

    async get(
        key: Uint8Array,
        minSequenceNumber?: bigint,
        options?: CallOptions,
    ): Promise<GetResult | null> {
        return performGet(this.client, key, minSequenceNumber, undefined, this.keyPrefix, options);
    }

    async getMany(
        keys: Uint8Array[],
        batchSize?: number,
        onChunk?: (entries: GetManyResultItem[]) => void,
        minSequenceNumber?: bigint,
    ): Promise<GetManyResultItem[]> {
        return performGetMany(
            this.client,
            keys,
            batchSize,
            onChunk,
            minSequenceNumber,
            undefined,
            this.keyPrefix,
        );
    }

    async query(
        start?: Uint8Array,
        end?: Uint8Array,
        limit?: number,
        batchSize: number = 4096,
        mode: TraversalMode = TraversalMode.FORWARD,
        minSequenceNumber?: bigint,
        options?: CallOptions,
    ): Promise<QueryResult> {
        return performQuery(
            this.client,
            start,
            end,
            limit,
            batchSize,
            mode,
            minSequenceNumber,
            undefined,
            this.keyPrefix,
            options,
        );
    }

    async prune(policies: Policy[]): Promise<void> {
        const req = create(PruneRequestSchema, { policies: prefixPolicies(policies, this.keyPrefix) });
        try {
            await this.client.prune.prune(req);
        } catch (e) {
            mapConnectToHttpError(e, this.client.credential);
        }
    }

    reduce(
        start: Uint8Array,
        end: Uint8Array,
        params: ReduceParams,
        minSequenceNumber?: bigint,
    ): AsyncIterable<ReduceResponse> {
        return performReduce(
            this.client,
            start,
            end,
            params,
            minSequenceNumber,
            undefined,
            this.keyPrefix,
        );
    }

    async getBatch(sequenceNumber: bigint, options?: CallOptions): Promise<StoreBatch | null> {
        return performGetBatch(this.client, sequenceNumber, this.keyPrefix, options);
    }

    async *subscribe(
        filters: SubscribeFilters,
        options?: CallOptions,
    ): AsyncIterable<StoreBatch> {
        yield* performSubscribe(this.client, filters, this.keyPrefix, options);
    }
}
