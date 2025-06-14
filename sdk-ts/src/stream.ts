import { Client } from './index';
import { HttpError, WebSocketError } from './error';
import WebSocket, { Data } from 'ws';
import { AxiosError } from 'axios';
import { IncomingMessage } from 'http';

export class Subscription {
    constructor(public readonly ws: WebSocket) { }

    onMessage(listener: (data: Data) => void) {
        this.ws.on('message', listener);
    }

    onError(listener: (err: Error) => void) {
        this.ws.on('error', listener);
    }

    onClose(listener: (code: number, reason: Buffer) => void) {
        this.ws.on('close', listener);
    }

    close(code?: number, reason?: string): void {
        this.ws.close(code, reason);
    }
}

export class StreamClient {
    constructor(private client: Client) { }

    async publish(name: string, data: Uint8Array | Buffer): Promise<void> {
        const url = `${this.client.baseUrl}/stream/${name}`;
        try {
            await this.client.httpClient.post(url, data, {
                headers: { 'Content-Type': 'application/octet-stream' },
            });
        } catch (error) {
            if (error instanceof AxiosError && error.response) {
                throw new HttpError(error.response.status, error.response.statusText);
            }
            throw error;
        }
    }

    subscribe(name: string): Promise<Subscription> {
        return new Promise((resolve, reject) => {
            const url = `${this.client.baseUrl}/stream/${name}`.replace(/^http/, 'ws');
            const authToken = (this.client as any).authToken;
            const ws = new WebSocket(url, {
                headers: {
                    'Authorization': `Bearer ${authToken}`
                }
            });

            const onOpen = () => {
                cleanup();
                resolve(new Subscription(ws));
            };

            const onError = (err: Error) => {
                cleanup();
                reject(new WebSocketError(err.message));
            };

            const onUnexpectedResponse = (req: unknown, res: IncomingMessage) => {
                cleanup();
                reject(new HttpError(res.statusCode || 500, res.statusMessage || 'Unexpected response'));
            };

            const cleanup = () => {
                ws.removeListener('open', onOpen);
                ws.removeListener('error', onError);
                ws.removeListener('unexpected-response', onUnexpectedResponse);
            };

            ws.on('open', onOpen);
            ws.on('error', onError);
            ws.on('unexpected-response', onUnexpectedResponse);
        });
    }
}