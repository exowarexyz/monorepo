export class ExowareError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'ExowareError';
    }
}

export class HttpError extends ExowareError {
    constructor(public status: number, message: string) {
        super(`HTTP error: ${status} ${message}`);
        this.name = 'HttpError';
    }
}

export class WebSocketError extends ExowareError {
    constructor(message: string) {
        super(`WebSocket error: ${message}`);
        this.name = 'WebSocketError';
    }
}