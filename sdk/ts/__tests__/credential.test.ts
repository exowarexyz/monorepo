import { Code, ConnectError } from '@connectrpc/connect';

import { Client } from '../src/client';
import {
    API_KEY_ENV,
    InvalidApiKeyError,
    credentialRemedy,
    resolveCredential,
    withoutHtmlBody,
} from '../src/credential';
import { HttpError } from '../src/error';
import { StoreClient } from '../src/store';

/** The 401 body an ALB serves when it rejects a token, verbatim. */
const PROXY_REJECTION =
    'HTTP error 401: <html>\r\n<head><title>401 Authorization Required</title></head>\r\n<body>\r\n<center><h1>401 Authorization Required</h1></center>\r\n</body>\r\n</html>\r\n';

/** A byte no base64url token contains, so the value is broken config rather than a near-miss. */
const UNUSABLE = 'has\nnewline';

describe('resolveCredential', () => {
    test('an explicit token wins over the environment', () => {
        expect(resolveCredential('explicit', 'from-env')).toEqual({
            token: 'explicit',
            credential: 'sent',
        });
    });

    test('the environment supplies one when no token is given', () => {
        expect(resolveCredential(undefined, 'from-env')).toEqual({
            token: 'from-env',
            credential: 'sent',
        });
    });

    test('no token anywhere sends no header', () => {
        // A deployment with no load balancer in front of it authenticates nothing, so this has to
        // keep working rather than demand a credential.
        expect(resolveCredential(undefined, undefined)).toEqual({ credential: 'absent' });
    });

    test('surrounding whitespace is trimmed rather than rejected', () => {
        // A key reaching the environment through $(cat token) carries a trailing newline.
        expect(resolveCredential(undefined, '  padded-token\n')).toEqual({
            token: 'padded-token',
            credential: 'sent',
        });
    });

    test.each([
        ['empty', ''],
        ['only whitespace', '   \n'],
    ])('a variable that is %s is an unset one', (_label, value) => {
        expect(resolveCredential(undefined, value)).toEqual({ credential: 'absent' });
    });

    test('an unusable environment value names the variable', () => {
        expect(() => resolveCredential(undefined, UNUSABLE)).toThrow(InvalidApiKeyError);
        expect(() => resolveCredential(undefined, UNUSABLE)).toThrow(API_KEY_ENV);
    });

    test('an unusable explicit token does not blame the environment', () => {
        expect(() => resolveCredential(UNUSABLE, undefined)).toThrow(InvalidApiKeyError);
        expect(() => resolveCredential(UNUSABLE, undefined)).not.toThrow(API_KEY_ENV);
    });

    test('a non-ASCII token is rejected', () => {
        expect(() => resolveCredential('tokén', undefined)).toThrow(InvalidApiKeyError);
    });
});

describe('credentialRemedy', () => {
    test('a missing credential is told how to supply one', () => {
        const remedy = credentialRemedy('absent');
        expect(remedy).toContain('none was sent');
        expect(remedy).toContain(API_KEY_ENV);
    });

    test('a refused credential is told why rather than how to set one', () => {
        // A caller that sent a credential must not be told to supply the one it already sent.
        const remedy = credentialRemedy('sent');
        expect(remedy).toContain('refused');
        expect(remedy).toContain('expired');
        expect(remedy).not.toContain(API_KEY_ENV);
    });
});

describe('withoutHtmlBody', () => {
    test('keeps the status and drops the page', () => {
        expect(withoutHtmlBody(PROXY_REJECTION)).toBe('HTTP error 401');
    });

    test('recognizes a doctype and a message that is only markup', () => {
        expect(withoutHtmlBody('HTTP error 502: <!DOCTYPE html><html></html>')).toBe(
            'HTTP error 502',
        );
        expect(withoutHtmlBody('<html>bare</html>')).toBeUndefined();
    });

    test('a service message survives untouched', () => {
        // Service errors are the common case, and nothing about them should be trimmed.
        const message = 'key not found: a < b';
        expect(withoutHtmlBody(message)).toBe(message);
    });
});

describe('Client credential', () => {
    test('records whether a credential will be sent', () => {
        expect(new Client('http://localhost:10000', 'token-abc').credential).toBe('sent');
        expect(new Client('http://localhost:10000').credential).toBe('absent');
    });

    test('an unusable token fails construction', () => {
        expect(() => new Client('http://localhost:10000', UNUSABLE)).toThrow(InvalidApiKeyError);
    });
});

describe('a rejected request', () => {
    /**
     * Drives the real error path by making the transport reject, which is the only way a
     * `ConnectError` reaches `mapConnectToHttpError`.
     */
    async function rejectionFrom(client: Client, message: string): Promise<HttpError> {
        client.query.get = () => {
            throw new ConnectError(message, Code.Unauthenticated);
        };
        try {
            await new StoreClient(client).get(new Uint8Array([1]));
        } catch (err) {
            return err as HttpError;
        }
        throw new Error('the call should have thrown');
    }

    test('drops the proxy page and explains a missing credential', async () => {
        const err = await rejectionFrom(new Client('http://localhost:10000'), PROXY_REJECTION);

        expect(err).toBeInstanceOf(HttpError);
        expect(err.connectCode).toBe(Code.Unauthenticated);
        expect(err.message).not.toContain('<');
        expect(err.message).toContain('HTTP error 401');
        expect(err.message).toContain(API_KEY_ENV);
    });

    test('tells a client that sent one that it was refused', async () => {
        const err = await rejectionFrom(
            new Client('http://localhost:10000', 'token-abc'),
            PROXY_REJECTION,
        );

        expect(err.message).toContain('refused');
        expect(err.message).not.toContain(API_KEY_ENV);
    });

    test('other codes carry no credential remedy', async () => {
        const client = new Client('http://localhost:10000');
        client.query.get = () => {
            throw new ConnectError('no such key', Code.NotFound);
        };

        await expect(new StoreClient(client).get(new Uint8Array([1]))).rejects.toThrow(
            /no such key$/,
        );
    });
});
