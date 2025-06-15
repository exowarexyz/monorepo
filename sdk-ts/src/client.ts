import { StoreClient } from './store';
import { StreamClient } from './stream';
import axios, { AxiosInstance } from 'axios';

export class Client {
    public readonly httpClient: AxiosInstance;
    private readonly token: string;
    public readonly baseUrl: string;

    constructor(baseUrl: string, token: string) {
        this.baseUrl = baseUrl;
        this.token = token;
        this.httpClient = axios.create({
            headers: {
                'Authorization': `Bearer ${this.token}`
            }
        });
    }

    public store(): StoreClient {
        return new StoreClient(this);
    }

    public stream(): StreamClient {
        return new StreamClient(this);
    }
}