import type { Client } from './client';
import { HttpError } from './error';
import { Base64 } from 'js-base64';
import { AxiosError } from 'axios';

/**
 * The result of a `get` operation.
 */
export interface GetResult {
    /** The retrieved value. */
    value: Uint8Array;
}

/**
 * An item in the result of a `query` operation.
 */
export interface QueryResultItem {
    /** The key of the item. */
    key: string;
    /** The value of the item. */
    value: Uint8Array;
}

/**
 * The result of a `query` operation.
 */
export interface QueryResult {
    /** A list of key-value pairs. */
    results: QueryResultItem[];
}

/**
 * A client for interacting with the key-value store.
 */
export class StoreClient {
    constructor(private client: Client) { }

    /**
     * Sets a key-value pair in the store.
     * @param key The key to set.
     * @param value The value to set.
     */
    async set(key: string, value: Uint8Array | Buffer): Promise<void> {
        const url = `${this.client.baseUrl}/store/${key}`;
        try {
            await this.client.httpClient.post(url, value, {
                headers: { 'Content-Type': 'application/octet-stream' },
            });
        } catch (error) {
            if (error instanceof AxiosError && error.response) {
                throw new HttpError(error.response.status, error.response.statusText);
            }
            throw error;
        }
    }

    /**
     * Retrieves a value from the store by its key.
     * @param key The key to retrieve.
     * @returns The value, or `null` if the key does not exist.
     */
    async get(key: string): Promise<GetResult | null> {
        const url = `${this.client.baseUrl}/store/${key}`;
        try {
            const response = await this.client.httpClient.get<{ value: string }>(url);
            const value = Base64.toUint8Array(response.data.value);
            return { value };
        } catch (error) {
            if (error instanceof AxiosError && error.response) {
                if (error.response.status === 404) {
                    return null;
                }
                throw new HttpError(error.response.status, error.response.statusText);
            }
            throw error;
        }
    }

    /**
     * Queries for a range of key-value pairs.
     * @param start The key to start the query from (inclusive). If `undefined`, the query starts from the first key.
     * @param end The key to end the query at (exclusive). If `undefined`, the query continues to the last key.
     * @param limit The maximum number of results to return. If `undefined`, all results are returned.
     */
    async query(start?: string, end?: string, limit?: number): Promise<QueryResult> {
        const url = new URL(`${this.client.baseUrl}/store`);
        if (start) url.searchParams.append('start', start);
        if (end) url.searchParams.append('end', end);
        if (limit) url.searchParams.append('limit', limit.toString());

        try {
            const response = await this.client.httpClient.get<{ results: { key: string, value: string }[] }>(url.toString());
            const results = response.data.results.map(item => ({
                key: item.key,
                value: Base64.toUint8Array(item.value),
            }));
            return { results };
        } catch (error) {
            if (error instanceof AxiosError && error.response) {
                throw new HttpError(error.response.status, error.response.statusText);
            }
            throw error;
        }
    }
}