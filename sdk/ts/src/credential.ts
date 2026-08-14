/**
 * The API key a client presents, and what a rejection tells the caller to do about it.
 *
 * A client cannot tell from its configuration whether the endpoint requires a credential, since a
 * deployment behind a load balancer authenticates every RPC and one without authenticates none. It
 * sends whatever it has and explains itself when a call is rejected.
 */

import { ExowareError } from './error.js';

/** Environment variable read for the API key, in Node, when no token is passed to the client. */
export const API_KEY_ENV = 'EXOWARE_API_KEY';

/**
 * Whether a client sends a credential with every request. A rejection reads the same either way,
 * so only the client can tell a missing credential from a refused one.
 */
export type Credential = 'sent' | 'absent';

/** Thrown when a configured API key cannot be sent as an HTTP header. */
export class InvalidApiKeyError extends ExowareError {
    constructor(message: string) {
        super(message);
        this.name = 'InvalidApiKeyError';
    }
}

export type ResolvedCredential = {
    token?: string;
    credential: Credential;
};

/** Header field values are tab and visible ASCII, so anything else cannot be sent. */
const USABLE_HEADER_VALUE = /^[\t\x20-\x7e]*$/;

/**
 * Reads the API key from the environment, or `undefined` in a browser.
 *
 * A browser has no environment, so this is the Node half of the same split `cookies.ts` makes for
 * cookie jars.
 */
export function environmentApiKey(): string | undefined {
    if (typeof process === 'undefined') {
        return undefined;
    }
    return process.env?.[API_KEY_ENV];
}

/**
 * Chooses between an explicitly configured token and one found in the environment, and throws
 * `InvalidApiKeyError` if the chosen one cannot be an HTTP header.
 *
 * Takes the environment lookup as an argument rather than reading it, so that every case is
 * reachable without touching a process-wide variable.
 */
export function resolveCredential(
    explicit: string | undefined,
    fromEnvironment: string | undefined,
): ResolvedCredential {
    const isFromEnvironment = explicit === undefined;
    const candidate = explicit ?? fromEnvironment;

    // Surrounding whitespace is trimmed rather than rejected. A key routinely arrives as
    // EXOWARE_API_KEY=$(cat token), which carries a trailing newline that is no part of it.
    const token = candidate?.trim();
    if (token === undefined || token === '') {
        return { credential: 'absent' };
    }

    if (!USABLE_HEADER_VALUE.test(token)) {
        throw new InvalidApiKeyError(
            isFromEnvironment
                ? `${API_KEY_ENV} is set to a value that cannot be an HTTP header. Remove any control or non-ASCII characters from it`
                : 'The API key given to this client cannot be an HTTP header (check for control or non-ASCII characters)',
        );
    }

    return { token, credential: 'sent' };
}

/**
 * Advice for an unauthenticated rejection.
 *
 * Neither case names a symbol, because whoever reads this may not be whoever wrote the call.
 */
export function credentialRemedy(credential: Credential): string {
    return credential === 'absent'
        ? `This endpoint requires a credential and none was sent. Supply one when constructing the client, or in Node through the ${API_KEY_ENV} environment variable`
        : 'The credential sent with this request was refused. It may have expired, or been issued for a different deployment, or lack the scope this call needs';
}

/**
 * Drops an HTML error page from a message, keeping whatever preceded it.
 *
 * A proxy that rejects a request before it reaches a service answers with a page rather than a
 * ConnectRPC error, and the whole page arrives in the message. Returns `undefined` when nothing but
 * markup was there.
 */
export function withoutHtmlBody(message: string): string | undefined {
    const lowercase = message.toLowerCase();
    const starts = ['<html', '<!doctype']
        .map((marker) => lowercase.indexOf(marker))
        .filter((index) => index >= 0);
    if (starts.length === 0) {
        return message;
    }

    const kept = message
        .slice(0, Math.min(...starts))
        .trimEnd()
        .replace(/:+$/, '')
        .trimEnd();
    return kept === '' ? undefined : kept;
}
