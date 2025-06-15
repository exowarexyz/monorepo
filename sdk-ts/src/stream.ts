import type { Client } from './client';
import { HttpError, WebSocketError } from './error';
import { AxiosError } from 'axios';
import WebSocket, { Data } from 'isomorphic-ws';

/**
 * A subscription to a realtime stream.
 */
export class Subscription {
    /**
     * @param ws The underlying WebSocket connection.
     */
    constructor(public readonly ws: WebSocket) { }

    /**
     * Sets a listener for incoming messages.
     * @param listener The listener to call with incoming data.
     */
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

    /**
     * Sets a listener for WebSocket errors.
     * @param listener The listener to call with an error.
     */
    onError(listener: (err: WebSocket.ErrorEvent) => void) {
        this.ws.onerror = listener;
    }

    /**
     * Sets a listener for when the WebSocket connection is closed.
     * @param listener The listener to call with a close event.
     */
    onClose(listener: (ev: WebSocket.CloseEvent) => void) {
        this.ws.onclose = listener;
    }

    /**
     * Closes the WebSocket connection.
     * @param code An optional close code.
     * @param reason An optional close reason.
     */
    close(code?: number, reason?: string): void {
        this.ws.close(code, reason);
    }
}

/**
 * A client for interacting with realtime streams.
 */
export class StreamClient {
    constructor(private client: Client) { }

    /**
     * Publishes a message to a stream.
     * @param name The name of the stream to publish to.
     * @param data The data to publish.
     */
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

    /**
     * Subscribes to a stream.
     *
     * This function opens a WebSocket connection and returns a `Subscription` object,
     * which can be used to receive messages and manage the connection.
     * @param name The name of the stream to subscribe to.
     * @returns A `Subscription` object.
     */
    subscribe(name: string): Promise<Subscription> {
        return new Promise((resolve, reject) => {
            const urlStr = `${this.client.baseUrl}/stream/${name}`.replace(/^http/, 'ws');
            const url = new URL(urlStr);
            const token = (this.client as any).token;
            if (token) {
                url.searchParams.set('token', token);
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