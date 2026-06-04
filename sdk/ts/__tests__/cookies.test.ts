import { CookieJar, fetchWithCookieJar } from '../src/cookies';

function responseFor(url: string, init?: ResponseInit): Response {
    const response = new Response('ok', init);
    Object.defineProperty(response, 'url', { value: url });
    return response;
}

describe('fetchWithCookieJar', () => {
    test('replays host cookies to the same host and not to others', async () => {
        const jar = new CookieJar();
        const seen: Array<{ url: string; cookie: string | null }> = [];
        const baseFetch: typeof fetch = async (input, init) => {
            const url = typeof input === 'string' ? input : (input as URL).href;
            const headers = new Headers(init?.headers);
            seen.push({ url: new URL(url).host, cookie: headers.get('cookie') });
            return responseFor(url, { headers: { 'set-cookie': 'AWSALB=stick; Path=/' } });
        };
        const wrapped = fetchWithCookieJar(jar, baseFetch);

        await wrapped('https://edge.internal/rpc');
        await wrapped('https://edge.internal/rpc');
        await wrapped('https://other.internal/rpc');

        expect(seen[0].cookie).toBeNull();
        expect(seen[1].cookie).toBe('AWSALB=stick');
        expect(seen[2].cookie).toBeNull();
    });

    test('honors domain and path matching', async () => {
        const jar = new CookieJar();
        const seen: Array<{ path: string; cookie: string | null }> = [];
        const baseFetch: typeof fetch = async (input, init) => {
            const url = typeof input === 'string' ? input : (input as URL).href;
            const parsed = new URL(url);
            seen.push({ path: parsed.pathname, cookie: new Headers(init?.headers).get('cookie') });
            return responseFor(url, {
                headers: {
                    'set-cookie': 'session=one; Domain=example.com; Path=/rpc',
                },
            });
        };
        const wrapped = fetchWithCookieJar(jar, baseFetch);

        await wrapped('https://api.example.com/rpc/create');
        await wrapped('https://query.example.com/rpc/read');
        await wrapped('https://query.example.com/other');

        expect(seen[0].cookie).toBeNull();
        expect(seen[1].cookie).toBe('session=one');
        expect(seen[2].cookie).toBeNull();
    });

    test('rejects public suffix domain cookies', async () => {
        const jar = new CookieJar();
        const seen: Array<{ host: string; cookie: string | null }> = [];
        const baseFetch: typeof fetch = async (input, init) => {
            const url = typeof input === 'string' ? input : (input as URL).href;
            seen.push({ host: new URL(url).host, cookie: new Headers(init?.headers).get('cookie') });
            return responseFor(url, {
                headers: {
                    'set-cookie': 'leak=1; Domain=com; Path=/',
                },
            });
        };
        const wrapped = fetchWithCookieJar(jar, baseFetch);

        await wrapped('https://api.example.com/rpc');
        await wrapped('https://api.example.com/rpc');
        await wrapped('https://other.com/rpc');

        expect(seen).toEqual([
            { host: 'api.example.com', cookie: null },
            { host: 'api.example.com', cookie: null },
            { host: 'other.com', cookie: null },
        ]);
    });

    test('removes cookies expired by the server', async () => {
        const jar = new CookieJar();
        const seen: Array<string | null> = [];
        let calls = 0;
        const baseFetch: typeof fetch = async (input, init) => {
            calls++;
            const url = typeof input === 'string' ? input : (input as URL).href;
            seen.push(new Headers(init?.headers).get('cookie'));
            return responseFor(url, {
                headers: {
                    'set-cookie': calls === 1 ? 'AWSALB=stick; Path=/' : 'AWSALB=; Max-Age=0; Path=/',
                },
            });
        };
        const wrapped = fetchWithCookieJar(jar, baseFetch);

        await wrapped('https://edge.internal/rpc');
        await wrapped('https://edge.internal/rpc');
        await wrapped('https://edge.internal/rpc');

        expect(seen).toEqual([null, 'AWSALB=stick', null]);
    });

    test('preserves caller cookies when adding jar cookies', async () => {
        const jar = new CookieJar();
        await jar.setCookie('AWSALB=jar; Path=/', 'https://edge.internal/rpc');
        await jar.setCookie('other=jar; Path=/', 'https://edge.internal/rpc');
        let observed: string | null = null;
        const baseFetch: typeof fetch = async (input, init) => {
            const url = typeof input === 'string' ? input : (input as URL).href;
            observed = new Headers(init?.headers).get('cookie');
            return responseFor(url);
        };
        const wrapped = fetchWithCookieJar(jar, baseFetch);

        await wrapped('https://edge.internal/rpc', { headers: { cookie: 'caller=token; AWSALB=caller' } });

        expect(observed).toBe('caller=token; AWSALB=caller; other=jar');
    });

    test('captures cookies across redirects', async () => {
        const jar = new CookieJar();
        const seen: Array<{ path: string; cookie: string | null }> = [];
        const baseFetch: typeof fetch = async (input, init) => {
            const url = typeof input === 'string' ? input : (input as URL).href;
            const parsed = new URL(url);
            seen.push({ path: parsed.pathname, cookie: new Headers(init?.headers).get('cookie') });
            if (parsed.pathname === '/start') {
                return responseFor(url, {
                    status: 302,
                    headers: {
                        Location: '/final',
                        'set-cookie': 'redirected=1; Path=/',
                    },
                });
            }
            return responseFor(url);
        };
        const wrapped = fetchWithCookieJar(jar, baseFetch);

        await wrapped('https://edge.internal/start');

        expect(seen).toEqual([
            { path: '/start', cookie: null },
            { path: '/final', cookie: 'redirected=1' },
        ]);
    });
});
