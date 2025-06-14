import type { Client } from './client';
import { HttpError, WebSocketError } from './error';
import { AxiosError } from 'axios';
import WebSocket, { Data } from 'isomorphic-ws';

export class Subscription {
    constructor(public readonly ws: WebSocket) { }

    onMessage(listener: (data: Data) => void) {
        this.ws.onmessage = (event: { data: any; }) => {
            if (typeof event.data === 'string' || event.data instanceof ArrayBuffer || event.data instanceof Buffer) {
                listener(event.data);
            } else if (event.data instanceof Blob) {
                // If it's a blob, we convert it to a Buffer
                event.data.arrayBuffer().then((buffer: ArrayBuffer) => listener(Buffer.from(buffer)));
            }
        };
    }

    onError(listener: (err: WebSocket.ErrorEvent) => void) {
        this.ws.onerror = listener;
    }

    onClose(listener: (ev: WebSocket.CloseEvent) => void) {
        this.ws.onclose = listener;
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
            const urlStr = `${this.client.baseUrl}/stream/${name}`.replace(/^http/, 'ws');
            const url = new URL(urlStr);
            const authToken = (this.client as any).authToken;
            if (authToken) {
                url.searchParams.set('auth_token', authToken);
            }

            const ws = new WebSocket(url.toString());

            const onOpen = () => {
                cleanup();
                resolve(new Subscription(ws));
            };

            const onError = (err: WebSocket.ErrorEvent) => {
                cleanup();
                reject(new WebSocketError('WebSocket connection failed'));
            };

            const onClose = (event: WebSocket.CloseEvent) => {
                cleanup();
                if (!event.wasClean) {
                    reject(new HttpError(event.code, event.reason || 'WebSocket connection closed unexpectedly'));
                }
            };

            const cleanup = () => {
                ws.removeEventListener('open', onOpen);
                ws.removeEventListener('error', onError as any);
                ws.removeEventListener('close', onClose as any);
            };

            ws.addEventListener('open', onOpen);
            ws.addEventListener('error', onError as any);
            ws.addEventListener('close', onClose as any);
        });
    }
}