import { createClient, type Client as ConnectClient, type Interceptor, Code, ConnectError } from '@connectrpc/connect';
import { createConnectTransport } from '@connectrpc/connect-web';
import { CookieJar, fetchWithCookieJar } from './cookies.js';
import { environmentApiKey, resolveCredential, type Credential } from './credential.js';
import { StoreClient, type StoreKeyPrefix } from './store.js';
import { normalizePutOptions, type PutBatchOptions, type PutLimits } from './limits.js';
import { Service as IngestService } from './gen/ts/log/v1/ingest_pb.js';
import { Service as PruneService } from './gen/ts/store/v1/prune_pb.js';
import { Service as QueryService } from './gen/ts/store/v1/query_pb.js';
import { Service as RetentionService } from './gen/ts/log/v1/retention_pb.js';
import { Service as StreamService } from './gen/ts/log/v1/stream_pb.js';
import { ErrorInfoSchema, RetryInfoSchema } from './gen/ts/google/rpc/error_details_pb.js';

export type RetryConfig = {
    maxAttempts: number;
    initialBackoffMs: number;
    maxBackoffMs: number;
};

const DEFAULT_RETRY_CONFIG: RetryConfig = {
    maxAttempts: 3,
    initialBackoffMs: 100,
    maxBackoffMs: 2000,
};

const RETRYABLE_CODES = new Set<Code>([
    Code.Aborted,
    Code.Unavailable,
    Code.ResourceExhausted,
]);

function retryBackoffDelay(attempt: number, config: RetryConfig): number {
    const exponent = Math.min(Math.max(attempt - 1, 0), 20);
    const baseMs = config.initialBackoffMs * (1 << exponent);
    const cappedMs = Math.min(baseMs, config.maxBackoffMs);
    const jitter = cappedMs * (0.5 + 0.5 * Math.random());
    return Math.round(jitter);
}

function putRetryHint(err: unknown): number | undefined {
    if (!(err instanceof ConnectError) || err.code !== Code.ResourceExhausted) return undefined;

    // findDetails skips undecodable details, so reject duplicate hints before decoding.
    const types = err.details.map((detail) => {
        const type = 'desc' in detail ? detail.desc.typeName : detail.type;
        return type.replace(/^type\.googleapis\.com\//, '');
    });
    if (
        types.filter((type) => type === ErrorInfoSchema.typeName).length !== 1 ||
        types.filter((type) => type === RetryInfoSchema.typeName).length !== 1
    ) return undefined;

    const errors = err.findDetails(ErrorInfoSchema);
    const retries = err.findDetails(RetryInfoSchema);
    if (
        errors.length !== 1 ||
        errors[0].domain !== 'log.ingest' ||
        errors[0].reason !== 'INGEST_ADMISSION_EXHAUSTED' ||
        retries.length !== 1
    ) return undefined;

    const duration = retries[0].retryDelay;
    if (
        duration === undefined ||
        duration.seconds < 0n ||
        duration.seconds > 315_576_000_000n ||
        !Number.isInteger(duration.nanos) ||
        duration.nanos < 0 ||
        duration.nanos >= 1_000_000_000 ||
        (duration.seconds === 0n && duration.nanos === 0)
    ) return undefined;

    // Rounding up preserves the server's minimum even for submillisecond hints.
    return Number(duration.seconds * 1000n) + Math.ceil(duration.nanos / 1_000_000);
}

function putDeadline(header: Headers): number | undefined {
    const timeout = header.get('connect-timeout-ms');
    if (timeout === null || !/^\d+$/.test(timeout)) return undefined;
    const timeoutMs = Number(timeout);
    return Number.isFinite(timeoutMs) && timeoutMs >= 0 ? performance.now() + timeoutMs : undefined;
}

function checkPutCancellation(signal: AbortSignal, deadline: number | undefined): void {
    if (signal.aborted) throw ConnectError.from(signal.reason, Code.Canceled);
    if (deadline !== undefined && performance.now() >= deadline) {
        throw new ConnectError('the operation timed out', Code.DeadlineExceeded);
    }
}

function waitForPutRetry(delay: number, signal: AbortSignal, deadline: number | undefined): Promise<void> {
    return new Promise((resolve, reject) => {
        const retryAt = performance.now() + delay;
        let timer: ReturnType<typeof setTimeout>;
        const cleanup = () => {
            clearTimeout(timer);
            signal.removeEventListener('abort', abort);
        };
        const wake = () => {
            try {
                checkPutCancellation(signal, deadline);
                const remaining = retryAt - performance.now();
                if (remaining > 0) {
                    // Timers can fire early or overflow for long hints. Recheck before retrying.
                    const budget = deadline === undefined ? Infinity : deadline - performance.now();
                    timer = setTimeout(wake, Math.min(Math.ceil(Math.min(remaining, budget)), 2_147_483_647));
                    return;
                }
                cleanup();
                resolve();
            } catch (err) {
                cleanup();
                reject(err);
            }
        };
        const abort = () => {
            cleanup();
            reject(ConnectError.from(signal.reason, Code.Canceled));
        };
        signal.addEventListener('abort', abort, { once: true });
        wake();
    });
}

function makeRetryInterceptor(config: RetryConfig): Interceptor {
    const maxAttempts = Math.max(config.maxAttempts, 1);
    return (next) => async (req) => {
        const isPut = req.service.typeName === IngestService.typeName && req.method.name === IngestService.method.put.name;
        const deadline = isPut ? putDeadline(req.header) : undefined;
        if (req.stream && req.method === QueryService.method.reduce) {
            // Each retry must serialize the same input after Connect consumes its request iterator.
            const input = await req.message[Symbol.asyncIterator]().next();
            req = {
                ...req,
                message: {
                    async *[Symbol.asyncIterator]() {
                        if (!input.done) yield input.value;
                    },
                },
            };
        }
        let attempt = 1;
        for (;;) {
            if (isPut) {
                checkPutCancellation(req.signal, deadline);
                if (deadline !== undefined) {
                    const remaining = deadline - performance.now();
                    if (remaining <= 0) throw new ConnectError('the operation timed out', Code.DeadlineExceeded);
                    req.header.set('connect-timeout-ms', String(Math.ceil(remaining)));
                }
            }
            if (req.signal.aborted) throw ConnectError.from(req.signal.reason, Code.Canceled);
            try {
                const response = await next(req);
                if (response.stream && response.method === QueryService.method.reduce) {
                    // Before any result is exposed, a retry cannot duplicate delivered groups.
                    const iterator = response.message[Symbol.asyncIterator]();
                    const first = await iterator.next();
                    if (first.done) throw new ConnectError('reduction stream returned no frames', Code.Internal);
                    return {
                        ...response,
                        message: (async function* () {
                            yield first.value;
                            yield* { [Symbol.asyncIterator]: () => iterator };
                        })(),
                    };
                }
                return response;
            } catch (err) {
                if (isPut) {
                    checkPutCancellation(req.signal, deadline);
                    const hint = putRetryHint(err);
                    if (!(attempt < maxAttempts) || hint === undefined || !(hint <= config.maxBackoffMs)) throw err;

                    const exponent = Math.min(Math.max(attempt - 1, 0), 20);
                    const backoff = Math.min(config.initialBackoffMs * (1 << exponent), config.maxBackoffMs);
                    if (!Number.isFinite(backoff) || backoff < 0) throw err;

                    const minimum = Math.max(hint, backoff);
                    const maximum = Math.min(config.maxBackoffMs, minimum + backoff);
                    const delay = minimum + (maximum - minimum) * Math.random();
                    if (!Number.isFinite(delay)) throw err;

                    await waitForPutRetry(delay, req.signal, deadline);
                    attempt++;
                    continue;
                }
                if (
                    attempt < maxAttempts &&
                    err instanceof ConnectError &&
                    RETRYABLE_CODES.has(err.code)
                ) {
                    const delay = retryBackoffDelay(attempt, config);
                    await new Promise((resolve) => setTimeout(resolve, delay));
                    attempt++;
                    continue;
                }
                throw err;
            }
        }
    };
}

export type ClientOptions = {
    token?: string;
    retry?: RetryConfig;
    useBinaryFormat?: boolean;
    putLimits?: PutLimits;
};

function normalizeClientOptions(tokenOrOptions?: string | ClientOptions): ClientOptions {
    return typeof tokenOrOptions === 'string' ? { token: tokenOrOptions } : tokenOrOptions ?? {};
}

// Both transports from one factory share credential resolution, retry policy, and cookies.
function transportFactory(opts: ClientOptions): {
    create: (baseUrl: string, useBinaryFormat?: boolean) => ReturnType<typeof createConnectTransport>;
    credential: Credential;
} {
    const retryConfig = opts.retry ?? DEFAULT_RETRY_CONFIG;
    const { token, credential } = resolveCredential(opts.token, environmentApiKey());
    const interceptors: Interceptor[] = [];
    if (token !== undefined) {
        interceptors.push((next) => async (req) => {
            // Connect seeds req.header from CallOptions.headers before interceptors run, so a
            // caller-supplied credential is already here and takes precedence.
            if (!req.header.has('Authorization')) {
                req.header.set('Authorization', `Bearer ${token}`);
            }
            return next(req);
        });
    }
    interceptors.push(makeRetryInterceptor(retryConfig));
    const fetch = fetchWithCookieJar(new CookieJar());
    return {
        create: (baseUrl, useBinaryFormat) => createConnectTransport({
            baseUrl: baseUrl.replace(/\/$/, ''),
            useBinaryFormat,
            interceptors,
            fetch,
        }),
        credential,
    };
}

/**
 * Takes the API key from `EXOWARE_API_KEY` when running under Node and no `token` is given, and
 * throws `InvalidApiKeyError` if either cannot be an HTTP header.
 * Custom ingest clients must pass `useBinaryFormat: true` because Put requires protobuf.
 */
export function createTransport(baseUrl: string, tokenOrOptions?: string | ClientOptions) {
    const opts = normalizeClientOptions(tokenOrOptions);
    return transportFactory(opts).create(baseUrl, opts.useBinaryFormat);
}

export class Client {
    public readonly baseUrl: string;
    public readonly ingest: ConnectClient<typeof IngestService>;
    public readonly prune: ConnectClient<typeof PruneService>;
    public readonly query: ConnectClient<typeof QueryService>;
    public readonly retention: ConnectClient<typeof RetentionService>;
    public readonly stream: ConnectClient<typeof StreamService>;
    public readonly retryConfig: RetryConfig;
    public readonly putOptions: Readonly<Required<PutBatchOptions>>;
    /** Whether this client sends a credential, which is what makes a 401 explicable. */
    public readonly credential: Credential;

    constructor(baseUrl: string, tokenOrOptions?: string | ClientOptions) {
        const opts = normalizeClientOptions(tokenOrOptions);
        this.baseUrl = baseUrl.replace(/\/$/, '');
        this.retryConfig = opts.retry ?? DEFAULT_RETRY_CONFIG;
        this.putOptions = Object.freeze(normalizePutOptions(opts.putLimits));
        const { create, credential } = transportFactory(opts);
        const transport = create(this.baseUrl, opts.useBinaryFormat);
        this.credential = credential;
        this.ingest = createClient(IngestService, create(this.baseUrl, true));
        this.prune = createClient(PruneService, transport);
        this.query = createClient(QueryService, transport);
        this.retention = createClient(RetentionService, transport);
        this.stream = createClient(StreamService, transport);
    }

    public store(prefix?: StoreKeyPrefix): StoreClient {
        return new StoreClient(this, prefix);
    }
}
