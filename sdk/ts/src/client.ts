import { createClient, type Client as ConnectClient, type Interceptor, Code, ConnectError } from '@connectrpc/connect';
import { createConnectTransport } from '@connectrpc/connect-web';
import { CookieJar, fetchWithCookieJar } from './cookies.js';
import { environmentApiKey, resolveCredential, type Credential } from './credential.js';
import { StoreClient, type StoreKeyPrefix } from './store.js';
import { Service as IngestService } from './gen/ts/log/v1/ingest_pb.js';
import { Service as PruneService } from './gen/ts/store/v1/prune_pb.js';
import { Service as QueryService } from './gen/ts/store/v1/query_pb.js';
import { Service as RetentionService } from './gen/ts/log/v1/retention_pb.js';
import { Service as StreamService } from './gen/ts/log/v1/stream_pb.js';

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

function makeRetryInterceptor(config: RetryConfig): Interceptor {
    const maxAttempts = Math.max(config.maxAttempts, 1);
    return (next) => async (req) => {
        let attempt = 1;
        for (;;) {
            try {
                return await next(req);
            } catch (err) {
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
};

function normalizeClientOptions(tokenOrOptions?: string | ClientOptions): ClientOptions {
    return typeof tokenOrOptions === 'string' ? { token: tokenOrOptions } : tokenOrOptions ?? {};
}

/**
 * Builds the transport and reports whether it carries a credential, so a `Client` resolves the
 * token once rather than reading the environment again.
 */
function transportWithCredential(
    baseUrl: string,
    opts: ClientOptions,
): { transport: ReturnType<typeof createConnectTransport>; credential: Credential } {
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
    return {
        transport: createConnectTransport({
            baseUrl: baseUrl.replace(/\/$/, ''),
            interceptors,
            fetch: fetchWithCookieJar(new CookieJar()),
        }),
        credential,
    };
}

/**
 * Takes the API key from `EXOWARE_API_KEY` when running under Node and no `token` is given, and
 * throws `InvalidApiKeyError` if either cannot be an HTTP header.
 */
export function createTransport(baseUrl: string, tokenOrOptions?: string | ClientOptions) {
    return transportWithCredential(baseUrl, normalizeClientOptions(tokenOrOptions)).transport;
}

export class Client {
    public readonly baseUrl: string;
    public readonly ingest: ConnectClient<typeof IngestService>;
    public readonly prune: ConnectClient<typeof PruneService>;
    public readonly query: ConnectClient<typeof QueryService>;
    public readonly retention: ConnectClient<typeof RetentionService>;
    public readonly stream: ConnectClient<typeof StreamService>;
    public readonly retryConfig: RetryConfig;
    /** Whether this client sends a credential, which is what makes a 401 explicable. */
    public readonly credential: Credential;

    constructor(baseUrl: string, tokenOrOptions?: string | ClientOptions) {
        const opts = normalizeClientOptions(tokenOrOptions);
        this.baseUrl = baseUrl.replace(/\/$/, '');
        this.retryConfig = opts.retry ?? DEFAULT_RETRY_CONFIG;
        const { transport, credential } = transportWithCredential(this.baseUrl, opts);
        this.credential = credential;
        this.ingest = createClient(IngestService, transport);
        this.prune = createClient(PruneService, transport);
        this.query = createClient(QueryService, transport);
        this.retention = createClient(RetentionService, transport);
        this.stream = createClient(StreamService, transport);
    }

    public store(prefix?: StoreKeyPrefix): StoreClient {
        return new StoreClient(this, prefix);
    }
}
