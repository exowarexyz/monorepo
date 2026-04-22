import { Code, ConnectError } from '@connectrpc/connect';

/**
 * The base error type for the SDK.
 */
export class ExowareError extends Error {
    constructor(message: string, options?: ErrorOptions) {
        super(message, options);
        this.name = 'ExowareError';
    }
}

/**
 * An error representing an HTTP error response from the server.
 * Access `.connectCode` for the original connect-rpc error code
 * and `.cause` for the full `ConnectError` with structured details.
 */
export class HttpError extends ExowareError {
    public readonly connectCode: Code;

    constructor(public status: number, message: string, connectCode: Code, cause: ConnectError) {
        super(`HTTP error: ${status} ${message}`, { cause });
        this.name = 'HttpError';
        this.connectCode = connectCode;
    }
}

export function mapConnectToHttpError(err: unknown): never {
    if (err instanceof ConnectError) {
        const status = connectCodeToHttpStatus(err.code);
        throw new HttpError(status, err.message || String(err.code), err.code, err);
    }
    throw err;
}

function connectCodeToHttpStatus(code: Code): number {
    switch (code) {
        case Code.Canceled:
            return 499;
        case Code.Unknown:
            return 500;
        case Code.InvalidArgument:
            return 400;
        case Code.DeadlineExceeded:
            return 504;
        case Code.NotFound:
            return 404;
        case Code.AlreadyExists:
            return 409;
        case Code.PermissionDenied:
            return 403;
        case Code.ResourceExhausted:
            return 429;
        case Code.FailedPrecondition:
            return 400;
        case Code.Aborted:
            return 409;
        case Code.OutOfRange:
            return 400;
        case Code.Unimplemented:
            return 501;
        case Code.Internal:
            return 500;
        case Code.Unavailable:
            return 503;
        case Code.DataLoss:
            return 500;
        case Code.Unauthenticated:
            return 401;
        default:
            return 500;
    }
}
