/**
 * The base error type for the SDK.
 */
export class ExowareError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'ExowareError';
    }
}

/**
 * An error representing an HTTP error response from the server.
 */
export class HttpError extends ExowareError {
    /**
     * @param status The HTTP status code.
     * @param message The HTTP status message.
     */
    constructor(public status: number, message: string) {
        super(`HTTP error: ${status} ${message}`);
        this.name = 'HttpError';
    }
}

/**
 * An error representing a WebSocket error.
 */
export class WebSocketError extends ExowareError {
    constructor(message: string) {
        super(`WebSocket error: ${message}`);
        this.name = 'WebSocketError';
    }
}