import { createClient, type Client as ConnectClient, type Interceptor } from '@connectrpc/connect';
import { createConnectTransport } from '@connectrpc/connect-web';
import { StoreClient } from './store.js';
import { Service as IngestService } from './gen/ts/store/v1/ingest_pb.js';
import { Service as QueryService } from './gen/ts/store/v1/query_pb.js';

export type ClientOptions = {
    /**
     * Optional bearer token sent as `Authorization: Bearer ...` on every RPC.
     */
    token?: string;
};

/**
 * Client for the Exoware store API (ingest + query on one base URL).
 */
export class Client {
    /**
     * Base URL of the server (e.g. `http://127.0.0.1:8080`).
     */
    public readonly baseUrl: string;

    /**
     * Ingest RPC client (`Put`).
     */
    public readonly ingest: ConnectClient<typeof IngestService>;

    /**
     * Query RPC client (`Get`, `Range`, `Reduce`).
     */
    public readonly query: ConnectClient<typeof QueryService>;

    /**
     * @param baseUrl The base URL of the Exoware server (e.g. `http://localhost:8080`).
     * @param tokenOrOptions Legacy second argument: a bearer token string, or options with `token`.
     */
    constructor(baseUrl: string, tokenOrOptions?: string | ClientOptions) {
        const opts: ClientOptions =
            typeof tokenOrOptions === 'string' ? { token: tokenOrOptions } : tokenOrOptions ?? {};
        this.baseUrl = baseUrl.replace(/\/$/, '');
        const interceptors: Interceptor[] =
            opts.token === undefined
                ? []
                : [
                      (next) => async (req) => {
                          req.header.set('Authorization', `Bearer ${opts.token}`);
                          return next(req);
                      },
                  ];
        const transport = createConnectTransport({
            baseUrl: this.baseUrl,
            interceptors,
        });
        this.ingest = createClient(IngestService, transport);
        this.query = createClient(QueryService, transport);
    }

    /**
     * Returns a `StoreClient` for interacting with the key-value store.
     */
    public store(): StoreClient {
        return new StoreClient(this);
    }
}
