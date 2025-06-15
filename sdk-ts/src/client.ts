import { StoreClient } from './store';
import { StreamClient } from './stream';
import axios, { AxiosInstance } from 'axios';

/**
 * Client for interacting with the Exoware API.
 */
export class Client {
    /**
     * The underlying HTTP client.
     */
    public readonly httpClient: AxiosInstance;
    private readonly token: string;
    /**
     * The base URL of the Exoware server.
     */
    public readonly baseUrl: string;

    /**
     * Creates a new `Client`.
     * @param baseUrl The base URL of the Exoware server (e.g., `http://localhost:8080`).
     * @param token The token to use for bearer authentication.
     */
    constructor(baseUrl: string, token: string) {
        this.baseUrl = baseUrl;
        this.token = token;
        this.httpClient = axios.create({
            headers: {
                'Authorization': `Bearer ${this.token}`
            }
        });
    }

    /**
     * Returns a `StoreClient` for interacting with the key-value store.
     */
    public store(): StoreClient {
        return new StoreClient(this);
    }

    /**
     * Returns a `StreamClient` for interacting with real-time streams.
     */
    public stream(): StreamClient {
        return new StreamClient(this);
    }
}