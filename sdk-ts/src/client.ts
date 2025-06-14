import { StoreClient } from './store';
import { StreamClient } from './stream';
import axios, { AxiosInstance } from 'axios';

export class Client {
    public readonly httpClient: AxiosInstance;
    private readonly authToken: string;
    public readonly baseUrl: string;

    constructor(baseUrl: string, authToken: string) {
        this.baseUrl = baseUrl;
        this.authToken = authToken;
        this.httpClient = axios.create({
            headers: {
                'Authorization': `Bearer ${this.authToken}`
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