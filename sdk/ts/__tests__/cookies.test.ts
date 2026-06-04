import { CookieJar, fetchWithCookieJar, mergeCookieValues, parseSetCookie } from '../src/cookies';

const MAX_COOKIES_PER_HOST = 16;
const MAX_COOKIE_BYTES = 4096;
const MAX_COOKIE_HEADER_BYTES = 8192;
const MAX_HOSTS = 256;

function setCookieHeaders(values: string[]): Headers {
    const headers = new Headers();
    for (const v of values) {
        headers.append('set-cookie', v);
    }
    return headers;
}

describe('parseSetCookie', () => {
    test('extracts name/value ignoring attributes', () => {
        expect(parseSetCookie('affinity="Zm9vYmFy"; Path=/; HttpOnly')).toEqual({
            kind: 'store',
            name: 'affinity',
            value: 'Zm9vYmFy',
        });
        expect(parseSetCookie('AWSALB=abc.def.ghi; Path=/')).toEqual({
            kind: 'store',
            name: 'AWSALB',
            value: 'abc.def.ghi',
        });
        // Empty values are valid cookies; deletion is signaled by lifetime attributes.
        expect(parseSetCookie('AWSALB=; Path=/')).toEqual({
            kind: 'store',
            name: 'AWSALB',
            value: '',
        });
    });

    test('trims quoted values without regex backtracking', () => {
        expect(parseSetCookie(`affinity=${'"'.repeat(1024)}value${'"'.repeat(1024)}; Path=/`)).toEqual({
            kind: 'store',
            name: 'affinity',
            value: 'value',
        });
    });

    test('marks expired cookies for deletion', () => {
        expect(parseSetCookie('AWSALB=abc; Max-Age=0; Path=/')).toEqual({ kind: 'delete', name: 'AWSALB' });
        expect(parseSetCookie('AWSALB=abc; Max-Age=-1; Path=/')).toEqual({ kind: 'delete', name: 'AWSALB' });
        expect(parseSetCookie('AWSALB=abc; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/')).toEqual({
            kind: 'delete',
            name: 'AWSALB',
        });
    });

    test('max-age takes precedence over expires and sets a future expiry', () => {
        const update = parseSetCookie(
            'AWSALB=abc; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/',
        );
        expect(update?.kind).toBe('store');
        if (update?.kind === 'store') {
            expect(update.name).toBe('AWSALB');
            expect(update.value).toBe('abc');
            expect(update.expires).toBeGreaterThan(Date.now());
        }
    });

    test('returns null when there is no name/value pair', () => {
        expect(parseSetCookie('; Path=/')).toBeNull();
        expect(parseSetCookie('=value; Path=/')).toBeNull();
    });
});

describe('CookieJar', () => {
    test('scopes cookies per host', () => {
        const jar = new CookieJar();
        jar.storeSetCookies('query.internal:80', ['AWSALB=hostA; Path=/']);
        jar.storeSetCookies('ingest.internal:80', ['AWSALB=hostB; Path=/']);

        expect(jar.cookieHeaderFor('query.internal:80')).toBe('AWSALB=hostA');
        expect(jar.cookieHeaderFor('ingest.internal:80')).toBe('AWSALB=hostB');
        expect(jar.cookieHeaderFor('other.internal:80')).toBeUndefined();
    });

    test('normalizes host key case', () => {
        const jar = new CookieJar();
        jar.storeSetCookies('API.example.com:443', ['AWSALB=stick; Path=/']);

        expect(jar.cookieHeaderFor('api.example.com:443')).toBe('AWSALB=stick');
    });

    test('merges multiple cookies for one host deterministically', () => {
        const jar = new CookieJar();
        jar.storeSetCookies('edge.internal:443', [
            'AWSALBCORS=abc; Path=/; SameSite=None',
            'AWSALB=abc; Path=/',
        ]);
        // Sorted by name regardless of insertion order.
        expect(jar.cookieHeaderFor('edge.internal:443')).toBe('AWSALB=abc; AWSALBCORS=abc');
    });

    test('does not store oversized cookies', () => {
        const jar = new CookieJar();
        jar.storeSetCookies('edge.internal:443', [`AWSALB=${'x'.repeat(MAX_COOKIE_BYTES)}; Path=/`]);
        expect(jar.cookieHeaderFor('edge.internal:443')).toBeUndefined();
    });

    test('count cap rejects new names but allows replacement', () => {
        const jar = new CookieJar();
        const setCookies: string[] = [];
        for (let idx = 0; idx < MAX_COOKIES_PER_HOST; idx++) {
            setCookies.push(`c${idx.toString().padStart(2, '0')}=v; Path=/`);
        }
        setCookies.push('extra=v; Path=/');
        jar.storeSetCookies('edge.internal:443', setCookies);

        const header = jar.cookieHeaderFor('edge.internal:443')!;
        expect(header.split('; ')).toHaveLength(MAX_COOKIES_PER_HOST);
        expect(header).not.toContain('extra=');

        jar.storeSetCookies('edge.internal:443', ['c00=rotated; Path=/']);
        expect(jar.cookieHeaderFor('edge.internal:443')).toContain('c00=rotated');
    });

    test('host cap evicts to bound total hosts', () => {
        const jar = new CookieJar();
        for (let idx = 0; idx < MAX_HOSTS; idx++) {
            jar.storeSetCookies(`h${idx.toString().padStart(4, '0')}.internal:443`, ['AWSALB=v; Path=/']);
        }
        jar.storeSetCookies('new.internal:443', ['AWSALB=v; Path=/']);
        expect(jar.cookieHeaderFor('new.internal:443')).toBe('AWSALB=v');
        // The very first host was evicted to make room.
        expect(jar.cookieHeaderFor('h0000.internal:443')).toBeUndefined();
    });

    test('header size cap rejects an insert that would overflow', () => {
        const jar = new CookieJar();
        const first = 'a'.repeat(MAX_COOKIE_BYTES - 'a='.length);
        const second = 'b'.repeat(MAX_COOKIE_BYTES - 'b='.length);
        jar.storeSetCookies('edge.internal:443', [`a=${first}; Path=/`, `b=${second}; Path=/`]);

        const header = jar.cookieHeaderFor('edge.internal:443')!;
        expect(header.length).toBeLessThanOrEqual(MAX_COOKIE_HEADER_BYTES);
        expect(header.split('; ')).toHaveLength(1);
        expect(header.startsWith('a=')).toBe(true);
    });

    test('expired set-cookie removes cookie from host jar', () => {
        const jar = new CookieJar();
        jar.storeSetCookies('edge.internal:443', ['AWSALB=abc; Path=/', 'AWSALBCORS=def; Path=/']);
        jar.storeSetCookies('edge.internal:443', ['AWSALB=; Max-Age=0; Path=/']);
        expect(jar.cookieHeaderFor('edge.internal:443')).toBe('AWSALBCORS=def');
    });

    test('expired set-cookie clears an empty host jar', () => {
        const jar = new CookieJar();
        jar.storeSetCookies('edge.internal:443', ['AWSALB=abc; Path=/']);
        jar.storeSetCookies('edge.internal:443', ['AWSALB=; Max-Age=0; Path=/']);
        expect(jar.cookieHeaderFor('edge.internal:443')).toBeUndefined();
    });

    test('prunes lapsed cookies lazily on read', () => {
        const jar = new CookieJar();
        jar.storeSetCookies('edge.internal:443', ['live=1; Path=/', 'dead=2; Max-Age=1; Path=/']);
        // Advance past the 1s lifetime.
        const realNow = Date.now;
        jest.spyOn(Date, 'now').mockReturnValue(realNow() + 2000);
        try {
            expect(jar.cookieHeaderFor('edge.internal:443')).toBe('live=1');
        } finally {
            (Date.now as jest.Mock).mockRestore();
        }
    });
});

describe('mergeCookieValues', () => {
    test('appends jar cookies to existing cookies', () => {
        expect(mergeCookieValues(['caller=token'], 'AWSALB=abc; AWSALBCORS=def')).toBe(
            'caller=token; AWSALB=abc; AWSALBCORS=def',
        );
    });

    test('keeps existing cookie on name collision', () => {
        expect(mergeCookieValues(['AWSALB=caller; app=session'], 'AWSALB=jar; AWSALBCORS=jarcors')).toBe(
            'AWSALB=caller; app=session; AWSALBCORS=jarcors',
        );
    });
});

describe('fetchWithCookieJar', () => {
    test('replays stored cookies to the same host and not to others', async () => {
        const jar = new CookieJar();
        const seen: Array<{ url: string; cookie: string | null }> = [];
        const baseFetch: typeof fetch = async (input, init) => {
            const headers = new Headers(init?.headers);
            seen.push({ url: new URL(typeof input === 'string' ? input : (input as URL).href).host, cookie: headers.get('cookie') });
            return new Response('ok', { headers: { 'set-cookie': 'AWSALB=stick; Path=/' } });
        };
        const wrapped = fetchWithCookieJar(jar, baseFetch);

        // First call has no cookie and the response sets one.
        await wrapped('https://edge.internal/rpc');
        // Second call to the same host replays it.
        await wrapped('https://edge.internal/rpc');
        // A different host does not get it.
        await wrapped('https://other.internal/rpc');

        expect(seen[0].cookie).toBeNull();
        expect(seen[1].cookie).toBe('AWSALB=stick');
        expect(seen[2].cookie).toBeNull();
    });

    test('preserves a caller-supplied cookie header', async () => {
        const jar = new CookieJar();
        jar.storeSetCookies('edge.internal', ['AWSALB=jar; Path=/']);
        let observed: string | null = null;
        const baseFetch: typeof fetch = async (_input, init) => {
            observed = new Headers(init?.headers).get('cookie');
            return new Response('ok');
        };
        const wrapped = fetchWithCookieJar(jar, baseFetch);

        await wrapped('https://edge.internal/rpc', { headers: { cookie: 'caller=token' } });
        expect(observed).toBe('caller=token; AWSALB=jar');
    });
});
