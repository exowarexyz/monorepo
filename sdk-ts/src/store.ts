import { Client } from './index';
import { HttpError } from './error';
import { Base64 } from 'js-base64';
import { AxiosError } from 'axios';

export interface GetResult {
    value: Uint8Array;
}

export interface QueryResultItem {
    key: string;
    value: Uint8Array;
}

export interface QueryResult {
    results: QueryResultItem[];
}

export class StoreClient {
    constructor(private client: Client) { }

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