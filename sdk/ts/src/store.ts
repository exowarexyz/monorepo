import { create, type MessageInitShape } from '@bufbuild/protobuf';
import { Code, ConnectError } from '@connectrpc/connect';
import type { CallOptions } from '@connectrpc/connect';
import type { StoreClient } from './client.js';
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
import {
    MAX_KEY_LEN,
    normalizePutLimits,
    putEncodedLen,
    putEntryEncodedLen,
    validatePut,
    validatePutEntry,
    type PutLimits,
} from './limits.js';
import {
    GetManyRequestSchema,
    GetRequestSchema as QueryGetRequestSchema,
    RangeRequestSchema,
    ReduceRequestSchema,
    TraversalMode as RangeMode,
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

// Range traversal direction: the generated `store.query.v1.TraversalMode` enum.
export { RangeMode };

export type { ReduceParams, ReduceResponse };

export interface GetResult {
    value: Uint8Array;
}

export interface GetManyResultItem {
    key: Uint8Array;
    value: Uint8Array | undefined;
}

export interface RangeResultItem {
    key: Uint8Array;
    value: Uint8Array;
}

export interface RangeResult {
    sequenceNumber: bigint;
    results: RangeResultItem[];
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

    push(store: PrefixedStoreClient, key: Uint8Array, value: Uint8Array | Buffer): this {
        this.kvs.push({
            key: store.encodeStoreKey(key),
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

    encodedLen(): number {
        return putEncodedLen(this.kvs);
    }

    validate(limits: PutLimits): void {
        validatePut(this.kvs, limits);
    }

    /** Each returned batch is a separate atomic Put. Payload buffers remain shared. */
    split(limits: PutLimits): StoreWriteBatch[] {
        const normalized = normalizePutLimits(limits);
        const batches: StoreWriteBatch[] = [];
        let batch = new StoreWriteBatch();
        let entryBytes = 0;
        for (const [index, entry] of this.kvs.entries()) {
            validatePutEntry(entry, index, normalized.maxValueLen);
            const length = putEntryEncodedLen(entry);
            if (length > normalized.maxEncodedBytes) {
                throw new RangeError(`Put entry ${index} encoded size ${length} exceeds ${normalized.maxEncodedBytes}`);
            }
            if (batch.length === normalized.maxEntries
                || entryBytes + length > normalized.maxEncodedBytes) {
                batches.push(batch);
                batch = new StoreWriteBatch();
                entryBytes = 0;
            }
            batch.kvs.push({ key: entry.key, value: entry.value });
            entryBytes += length;
        }
        if (batch.length > 0) batches.push(batch);
        return batches;
    }

    /**
     * Send every staged entry in one atomic Put through the physical client. Keys were encoded
     * under their owning store's prefix by {@link StoreWriteBatch.push}.
     */
    async commit(client: StoreClient, options?: CallOptions): Promise<bigint> {
        return performPut(client, this.kvs, options);
    }
}

async function performPut(
    client: StoreClient,
    entries: readonly StoreBatchEntry[],
    options?: CallOptions,
): Promise<bigint> {
    validatePut(entries, client.putLimits);
    const req = create(PutRequestSchema, {
        kvs: entries.map((entry) => create(EntrySchema, entry)),
    });
    try {
        const res = await client.ingest.put(req, options);
        return res.sequenceNumber;
    } catch (e) {
        mapConnectToHttpError(e, client.credential);
    }
}

const MAX_U64 = (1n << 64n) - 1n;

function normalizeMinSequenceNumber(value?: bigint): bigint | undefined {
    if (value === undefined) return undefined;
    if (typeof value !== 'bigint') {
        throw new TypeError('minimum sequence number must be a bigint');
    }
    if (value < 0n || value > MAX_U64) {
        throw new RangeError('minimum sequence number must fit in u64');
    }
    return value;
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

function prefixStreamFilter(
    filter: StreamFilter,
    prefix?: StoreKeyPrefix,
): StreamFilter {
    if (!prefix) return filter;
    return {
        ...filter,
        selectors: filter.selectors.map((selector) => prefix.prefixSelector(selector)),
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
    client: StoreClient,
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
    client: StoreClient,
    keys: Uint8Array[],
    batchSize?: number,
    onChunk?: (entries: GetManyResultItem[]) => void,
    minSequenceNumber?: bigint,
    detailObserver?: DetailObserver,
    prefix?: StoreKeyPrefix,
    options?: CallOptions,
): Promise<GetManyResultItem[]> {
    const effective = normalizeMinSequenceNumber(minSequenceNumber);
    const req = create(GetManyRequestSchema, {
        keys: keys.map((key) => encodeStoreKey(prefix, key)),
        batchSize: batchSize ?? keys.length,
        ...(effective !== undefined ? { minSequenceNumber: effective } : {}),
    });
    const results: GetManyResultItem[] = [];
    try {
        const stream = client.query.getMany(req, options);
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

async function performRange(
    client: StoreClient,
    start?: Uint8Array,
    end?: Uint8Array,
    limit?: number,
    batchSize: number = 4096,
    mode: RangeMode = RangeMode.FORWARD,
    minSequenceNumber?: bigint,
    detailObserver?: DetailObserver,
    prefix?: StoreKeyPrefix,
    options?: CallOptions,
): Promise<RangeResult> {
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
    const results: RangeResultItem[] = [];
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
    client: StoreClient,
    start: Uint8Array,
    end: Uint8Array,
    params: ReduceParams,
    minSequenceNumber?: bigint,
    detailObserver?: DetailObserver,
    prefix?: StoreKeyPrefix,
    options?: CallOptions,
): AsyncIterable<ReduceResponse> {
    const effective = normalizeMinSequenceNumber(minSequenceNumber);
    const physicalRange = encodeStoreRange(prefix, start, end);
    const req = create(ReduceRequestSchema, {
        start: physicalRange.start,
        end: physicalRange.end,
        params: prefixReduceParams(params, prefix),
        ...(effective !== undefined ? { minSequenceNumber: effective } : {}),
    });

    // The local controller ends the RPC when the consumer stops iterating, and a
    // caller-supplied signal aborts it as well.
    const controller = new AbortController();
    const callerSignal = options?.signal;
    const abortFromCaller = () => controller.abort(callerSignal?.reason);
    if (callerSignal?.aborted) {
        abortFromCaller();
    } else {
        callerSignal?.addEventListener('abort', abortFromCaller, { once: true });
    }
    try {
        for await (const frame of client.query.reduce(req, { ...options, signal: controller.signal })) {
            if (frame.detail) {
                detailObserver?.(frame.detail);
            }
            yield frame;
        }
    } catch (e) {
        mapConnectToHttpError(e, client.credential);
    } finally {
        callerSignal?.removeEventListener('abort', abortFromCaller);
        controller.abort();
    }
}

async function performGetBatch(
    client: StoreClient,
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

/** Selects the log batches a subscription delivers. */
export interface StreamFilter {
    selectors: MessageInitShape<typeof SelectorSchema>[];
    valueFilters?: MessageInitShape<typeof FilterSchema>[];
    sinceSequenceNumber?: bigint;
}

async function* performSubscribe(
    client: StoreClient,
    filter: StreamFilter,
    prefix?: StoreKeyPrefix,
    options?: CallOptions,
): AsyncIterable<StoreBatch> {
    const prefixed = prefixStreamFilter(filter, prefix);
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
}

interface PrefixedClientBinding {
    client: StoreClient;
    keyPrefix?: StoreKeyPrefix;
}

const prefixedClientBindings = new WeakMap<PrefixedStoreClient, PrefixedClientBinding>();

/**
 * A read session with a fixed or monotonic minimum Store sequence.
 *
 * Fixed sessions keep their configured floor. Monotonic sessions raise their floor to the highest
 * sequence observed by any clone. An absent floor sends no requirement, and zero is an explicit
 * floor. An initial floor is a requirement, not an observation. A write is observed only when its
 * commit sequence is recorded with `observeWrite`.
 */
export class ReadSession {
    private policy: ReadPolicy = 'monotonic';
    private configuredFloor: bigint | undefined;
    private state: ReadSessionState = {
        sequence: undefined,
    };

    private constructor(
        private client: StoreClient,
        private keyPrefix?: StoreKeyPrefix,
        initialFloor?: bigint,
    ) {
        this.configuredFloor = normalizeMinSequenceNumber(initialFloor);
    }

    /** Create a session whose floor advances to the highest observed sequence. */
    static monotonic(store: PrefixedStoreClient, initialFloor?: bigint): ReadSession {
        return ReadSession.fromStore(store, initialFloor, 'monotonic');
    }

    /** Create a session whose read floor stays fixed as sequences are observed. */
    static fixed(store: PrefixedStoreClient, floor?: bigint): ReadSession {
        return ReadSession.fromStore(store, floor, 'fixed');
    }

    private static fromStore(
        store: PrefixedStoreClient,
        configuredFloor: bigint | undefined,
        policy: ReadPolicy,
    ): ReadSession {
        const binding = prefixedClientBindings.get(store);
        if (!binding) {
            throw new TypeError('invalid PrefixedStoreClient');
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

    /** Highest Store sequence observed by this session. */
    evaluatedSequence(): bigint | undefined {
        return this.state.sequence;
    }

    /**
     * Record the sequence a write committed at, with the same effect as a read observation.
     *
     * A monotonic session requires the sequence for reads started afterwards. A fixed session keeps
     * its floor and reports the sequence through `evaluatedSequence()`. Clones share the
     * observation.
     */
    observeWrite(sequenceNumber: bigint): void {
        if (typeof sequenceNumber !== 'bigint') {
            throw new TypeError('write sequence number must be a bigint');
        }
        if (sequenceNumber < 0n || sequenceNumber > MAX_U64) {
            throw new RangeError('write sequence number must fit in u64');
        }
        this.observeSequence(sequenceNumber);
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
     * The derived handle's floor is at least `minSequenceNumber`. The parent floor is unchanged,
     * and the requirement does not count as an observation.
     */
    withMinSequenceNumber(minSequenceNumber: bigint): ReadSession {
        const session = this.clone();
        const requested = normalizeMinSequenceNumber(minSequenceNumber);
        if (requested === undefined) {
            return session;
        }
        const current = this.minSequenceNumber();
        if (current === undefined || requested > current) {
            session.configuredFloor = requested;
        }
        return session;
    }

    /** Share this session's observations with another store handle for the same Store. */
    withStore(store: PrefixedStoreClient): ReadSession {
        const binding = prefixedClientBindings.get(store);
        if (!binding) {
            throw new TypeError('invalid PrefixedStoreClient');
        }
        const session = this.clone();
        session.client = binding.client;
        session.keyPrefix = binding.keyPrefix;
        return session;
    }

    private observe(detail: Detail): void {
        this.observeSequence(detail.sequenceNumber);
    }

    private observeSequence(sequenceNumber: bigint): void {
        if (this.state.sequence === undefined || sequenceNumber > this.state.sequence) {
            this.state.sequence = sequenceNumber;
        }
    }

    async get(key: Uint8Array, options?: CallOptions): Promise<GetResult | null> {
        return performGet(
            this.client,
            key,
            this.minSequenceNumber(),
            (detail) => this.observe(detail),
            this.keyPrefix,
            options,
        );
    }

    async getMany(
        keys: Uint8Array[],
        batchSize?: number,
        onChunk?: (entries: GetManyResultItem[]) => void,
        options?: CallOptions,
    ): Promise<GetManyResultItem[]> {
        return performGetMany(
            this.client,
            keys,
            batchSize,
            onChunk,
            this.minSequenceNumber(),
            (detail) => this.observe(detail),
            this.keyPrefix,
            options,
        );
    }

    async range(
        start?: Uint8Array,
        end?: Uint8Array,
        limit?: number,
        batchSize: number = 4096,
        mode: RangeMode = RangeMode.FORWARD,
        options?: CallOptions,
    ): Promise<RangeResult> {
        return performRange(
            this.client,
            start,
            end,
            limit,
            batchSize,
            mode,
            this.minSequenceNumber(),
            (detail) => this.observe(detail),
            this.keyPrefix,
            options,
        );
    }

    async *rangeReduce(
        start: Uint8Array,
        end: Uint8Array,
        params: ReduceParams,
        options?: CallOptions,
    ): AsyncIterable<ReduceResponse> {
        yield* performReduce(
            this.client,
            start,
            end,
            params,
            this.minSequenceNumber(),
            (detail) => this.observe(detail),
            this.keyPrefix,
            options,
        );
    }

    /** Read a historical batch. */
    async getBatch(sequenceNumber: bigint, options?: CallOptions): Promise<StoreBatch | null> {
        const batch = await performGetBatch(this.client, sequenceNumber, this.keyPrefix, options);
        if (batch !== null) {
            this.observeSequence(batch.sequenceNumber);
        }
        return batch;
    }

    /** Subscribe to log batches, recording each batch's sequence before delivery. */
    async *subscribe(
        filter: StreamFilter,
        options?: CallOptions,
    ): AsyncIterable<StoreBatch> {
        for await (const batch of performSubscribe(
            this.client,
            filter,
            this.keyPrefix,
            options,
        )) {
            this.observeSequence(batch.sequenceNumber);
            yield batch;
        }
    }
}

export class PrefixedStoreClient {
    constructor(
        private readonly client: StoreClient,
        private readonly keyPrefix?: StoreKeyPrefix,
    ) {
        prefixedClientBindings.set(this, { client, keyPrefix });
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

    createSessionWithMinSequenceNumber(minSequenceNumber: bigint): ReadSession {
        return ReadSession.monotonic(this, minSequenceNumber);
    }

    /** Limits used by this client's Put validation and batch splitting. */
    get putLimits(): Readonly<Required<PutLimits>> {
        return this.client.putLimits;
    }

    async put(key: Uint8Array, value: Uint8Array | Buffer, options?: CallOptions): Promise<bigint> {
        return this.putMany([{ key, value }], options);
    }

    async putMany(
        kvs: { key: Uint8Array; value: Uint8Array | Buffer }[],
        options?: CallOptions,
    ): Promise<bigint> {
        return performPut(this.client, kvs.map((kv) => create(EntrySchema, {
            key: this.encodeStoreKey(kv.key),
            value: toUint8Array(kv.value),
        })), options);
    }

    async putPrepared(batch: StoreWriteBatch, options?: CallOptions): Promise<bigint> {
        return performPut(this.client, batch.entries(), options);
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
        options?: CallOptions,
    ): Promise<GetManyResultItem[]> {
        return performGetMany(
            this.client,
            keys,
            batchSize,
            onChunk,
            minSequenceNumber,
            undefined,
            this.keyPrefix,
            options,
        );
    }

    async range(
        start?: Uint8Array,
        end?: Uint8Array,
        limit?: number,
        batchSize: number = 4096,
        mode: RangeMode = RangeMode.FORWARD,
        minSequenceNumber?: bigint,
        options?: CallOptions,
    ): Promise<RangeResult> {
        return performRange(
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

    async prune(policies: Policy[], options?: CallOptions): Promise<void> {
        const req = create(PruneRequestSchema, { policies: prefixPolicies(policies, this.keyPrefix) });
        try {
            await this.client.prune.prune(req, options);
        } catch (e) {
            mapConnectToHttpError(e, this.client.credential);
        }
    }

    rangeReduce(
        start: Uint8Array,
        end: Uint8Array,
        params: ReduceParams,
        minSequenceNumber?: bigint,
        options?: CallOptions,
    ): AsyncIterable<ReduceResponse> {
        return performReduce(
            this.client,
            start,
            end,
            params,
            minSequenceNumber,
            undefined,
            this.keyPrefix,
            options,
        );
    }

    async getBatch(sequenceNumber: bigint, options?: CallOptions): Promise<StoreBatch | null> {
        return performGetBatch(this.client, sequenceNumber, this.keyPrefix, options);
    }

    async *subscribe(
        filter: StreamFilter,
        options?: CallOptions,
    ): AsyncIterable<StoreBatch> {
        yield* performSubscribe(this.client, filter, this.keyPrefix, options);
    }
}
