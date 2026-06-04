import { CookieJar, fetchWithCookieJar } from '../src/cookies';

function responseFor(url: string, init?: ResponseInit): Response {
    const response = new Response('ok', init);
    Object.defineProperty(response, 'url', { value: url });
    return response;
}

describe('fetchWithCookieJar', () => {
    test('top-level sdk import does not load node cookie packages', () => {
        jest.resetModules();
        jest.doMock('fetch-cookie', () => {
            throw new Error('fetch-cookie should not be loaded by sdk index import');
        });
        jest.doMock('tough-cookie', () => {
            throw new Error('tough-cookie should not be loaded by sdk index import');
        });
        try {
            expect(() => require('../src/index')).not.toThrow();
        } finally {
            jest.dontMock('fetch-cookie');
            jest.dontMock('tough-cookie');
            jest.resetModules();
        }
    });

    test('browser runtimes use native credentials without node cookie packages', async () => {
        jest.resetModules();
        jest.doMock('fetch-cookie', () => {
            throw new Error('fetch-cookie should not be loaded in browser runtimes');
        });
        jest.doMock('tough-cookie', () => {
            throw new Error('tough-cookie should not be loaded in browser runtimes');
        });

        const globals = globalThis as typeof globalThis & {
            window?: unknown;
            document?: unknown;
        };
        const hadWindow = 'window' in globals;
        const hadDocument = 'document' in globals;
        const previousWindow = globals.window;
        const previousDocument = globals.document;
        Object.defineProperty(globals, 'window', { value: {}, configurable: true });
        Object.defineProperty(globals, 'document', { value: {}, configurable: true });

        try {
            const { CookieJar: BrowserCookieJar, fetchWithCookieJar: fetchWithBrowserCookieJar } = require('../src/cookies') as typeof import('../src/cookies');
            let observedCredentials: RequestCredentials | undefined;
            const baseFetch: typeof fetch = async (input, init) => {
                observedCredentials = init?.credentials;
                const url = input instanceof Request ? input.url : typeof input === 'string' ? input : input.href;
                return responseFor(url);
            };
            const wrapped = fetchWithBrowserCookieJar(new BrowserCookieJar(), baseFetch);

            await wrapped('https://edge.internal/rpc');

            expect(observedCredentials).toBe('include');
        } finally {
            if (hadWindow) {
                Object.defineProperty(globals, 'window', { value: previousWindow, configurable: true });
            } else {
                Reflect.deleteProperty(globals, 'window');
            }
            if (hadDocument) {
                Object.defineProperty(globals, 'document', { value: previousDocument, configurable: true });
            } else {
                Reflect.deleteProperty(globals, 'document');
            }
            jest.dontMock('fetch-cookie');
            jest.dontMock('tough-cookie');
            jest.resetModules();
        }
    });

    test('shares one backend during concurrent first cookie writes', async () => {
        jest.resetModules();

        const instances: MockToughCookieJar[] = [];
        class MockToughCookieJar {
            private readonly cookies = new Map<string, string>();

            public constructor() {
                instances.push(this);
            }

            public getCookieString(_currentUrl: string): string {
                return Array.from(this.cookies.values()).join('; ');
            }

            public setCookie(cookieString: string, _currentUrl: string): void {
                const [pair] = cookieString.split(';', 1);
                const eq = pair.indexOf('=');
                this.cookies.set(pair.slice(0, eq), pair);
            }
        }

        jest.doMock('tough-cookie', () => ({ CookieJar: MockToughCookieJar }));
        try {
            const { CookieJar: MockedCookieJar } = require('../src/cookies') as typeof import('../src/cookies');
            const jar = new MockedCookieJar();

            await Promise.all([
                jar.setCookie('first=1; Path=/', 'https://edge.internal/rpc'),
                jar.setCookie('second=2; Path=/', 'https://edge.internal/rpc'),
            ]);

            expect(instances).toHaveLength(1);
            expect(await jar.getCookieString('https://edge.internal/rpc')).toBe('first=1; second=2');
        } finally {
            jest.dontMock('tough-cookie');
            jest.resetModules();
        }
    });

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

    test('preserves jar cookies for Request inputs with init headers', async () => {
        const jar = new CookieJar();
        await jar.setCookie('AWSALB=jar; Path=/', 'https://edge.internal/rpc');
        let observed: { cookie: string | null; initHeader: string | null; requestHeader: string | null } | null = null;
        const baseFetch: typeof fetch = async (input, init) => {
            const url = input instanceof Request ? input.url : typeof input === 'string' ? input : input.href;
            const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
            observed = {
                cookie: headers.get('cookie'),
                initHeader: headers.get('x-init'),
                requestHeader: headers.get('x-request'),
            };
            return responseFor(url);
        };
        const wrapped = fetchWithCookieJar(jar, baseFetch);
        const request = new Request('https://edge.internal/rpc', {
            headers: {
                cookie: 'stale=request',
                'x-request': 'request',
            },
        });

        await wrapped(request, {
            headers: {
                cookie: 'caller=token',
                'x-init': 'init',
            },
        });

        expect(observed).toEqual({
            cookie: 'caller=token; AWSALB=jar',
            initHeader: 'init',
            requestHeader: null,
        });
    });

    test('preserves jar cookies for Request inputs with caller cookies', async () => {
        const jar = new CookieJar();
        await jar.setCookie('AWSALB=jar; Path=/', 'https://edge.internal/rpc');
        let observed: string | null = null;
        const baseFetch: typeof fetch = async (input, init) => {
            const url = input instanceof Request ? input.url : typeof input === 'string' ? input : input.href;
            const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
            observed = headers.get('cookie');
            return responseFor(url);
        };
        const wrapped = fetchWithCookieJar(jar, baseFetch);
        const request = new Request('https://edge.internal/rpc', {
            headers: {
                cookie: 'caller=token',
            },
        });

        await wrapped(request);

        expect(observed).toBe('caller=token; AWSALB=jar');
    });

    test('does not send or store jar cookies when credentials are omitted', async () => {
        const jar = new CookieJar();
        await jar.setCookie('AWSALB=jar; Path=/', 'https://edge.internal/rpc');
        const seen: Array<string | null> = [];
        let calls = 0;
        const baseFetch: typeof fetch = async (input, init) => {
            calls++;
            const url = typeof input === 'string' ? input : input instanceof Request ? input.url : input.href;
            const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
            seen.push(headers.get('cookie'));
            return responseFor(url, {
                headers: calls === 1 ? { 'set-cookie': 'omitted=stored; Path=/' } : undefined,
            });
        };
        const wrapped = fetchWithCookieJar(jar, baseFetch);

        await wrapped('https://edge.internal/rpc', {
            credentials: 'omit',
            headers: {
                cookie: 'caller=token',
            },
        });
        await wrapped('https://edge.internal/rpc');

        expect(seen).toEqual([null, 'AWSALB=jar']);
    });

    test('does not mutate caller Request headers with jar cookies', async () => {
        const jar = new CookieJar();
        await jar.setCookie('AWSALB=jar; Path=/', 'https://edge.internal/rpc');
        const seen: Array<string | null> = [];
        let calls = 0;
        const baseFetch: typeof fetch = async (input, init) => {
            calls++;
            const url = input instanceof Request ? input.url : typeof input === 'string' ? input : input.href;
            const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
            seen.push(headers.get('cookie'));
            return responseFor(url, {
                headers: calls === 1 ? { 'set-cookie': 'AWSALB=; Max-Age=0; Path=/' } : undefined,
            });
        };
        const wrapped = fetchWithCookieJar(jar, baseFetch);
        const request = new Request('https://edge.internal/rpc');

        await wrapped(request);
        expect(request.headers.get('cookie')).toBeNull();
        await wrapped(request);

        expect(seen).toEqual(['AWSALB=jar', null]);
        expect(request.headers.get('cookie')).toBeNull();
    });

    test('does not mutate caller init Headers with jar cookies', async () => {
        const jar = new CookieJar();
        await jar.setCookie('AWSALB=jar; Path=/', 'https://edge.internal/rpc');
        const seen: Array<string | null> = [];
        let calls = 0;
        const baseFetch: typeof fetch = async (input, init) => {
            calls++;
            const url = typeof input === 'string' ? input : input instanceof Request ? input.url : input.href;
            seen.push(new Headers(init?.headers).get('cookie'));
            return responseFor(url, {
                headers: calls === 1 ? { 'set-cookie': 'AWSALB=; Max-Age=0; Path=/' } : undefined,
            });
        };
        const wrapped = fetchWithCookieJar(jar, baseFetch);
        const headers = new Headers();

        await wrapped('https://edge.internal/rpc', { headers });
        expect(headers.get('cookie')).toBeNull();
        await wrapped('https://edge.internal/rpc', { headers });

        expect(seen).toEqual(['AWSALB=jar', null]);
        expect(headers.get('cookie')).toBeNull();
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

    test('does not replay caller cookies when redirect init omits redirect count', async () => {
        jest.resetModules();
        const makeFetchCookie = jest.fn((fetchImpl: typeof fetch) => {
            return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
                const response = await fetchImpl(input, init);
                await fetchImpl('https://other.internal/final', {
                    ...init,
                    headers: new Headers(init?.headers),
                });
                return response;
            };
        });
        jest.doMock('fetch-cookie', () => ({ __esModule: true, default: makeFetchCookie }));
        try {
            const { CookieJar: MockedCookieJar, fetchWithCookieJar: fetchWithMockedCookieJar } = require('../src/cookies') as typeof import('../src/cookies');
            const jar = new MockedCookieJar();
            const seen: Array<{ host: string; cookie: string | null }> = [];
            const baseFetch: typeof fetch = async (input, init) => {
                const url = typeof input === 'string' ? input : (input as URL).href;
                seen.push({
                    host: new URL(url).host,
                    cookie: new Headers(init?.headers).get('cookie'),
                });
                return responseFor(url);
            };
            const wrapped = fetchWithMockedCookieJar(jar, baseFetch);

            await wrapped('https://edge.internal/start', { headers: { cookie: 'caller=token' } });

            expect(seen).toEqual([
                { host: 'edge.internal', cookie: 'caller=token' },
                { host: 'other.internal', cookie: null },
            ]);
        } finally {
            jest.dontMock('fetch-cookie');
            jest.resetModules();
        }
    });
});
