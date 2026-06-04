import makeFetchCookie from 'fetch-cookie';
import { CookieJar } from 'tough-cookie';

export { CookieJar } from 'tough-cookie';

type FetchCookieRequestInit = RequestInit & {
    maxRedirect?: number;
    redirectCount?: number;
};

type PreparedFetchCookieRequest = {
    input: RequestInfo | URL;
    init?: FetchCookieRequestInit;
};

function requestHeaders(input: RequestInfo | URL, init?: RequestInit): Headers {
    return new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
}

function mergeCookieValues(callerHeader: string, jarHeader: string | null): string {
    if (!jarHeader) {
        return callerHeader;
    }

    const merged = splitCookies(callerHeader);
    const callerNames = new Set(merged.map(cookieName).filter((name): name is string => name !== null));
    for (const cookie of splitCookies(jarHeader)) {
        const name = cookieName(cookie);
        if (name === null || !callerNames.has(name)) {
            merged.push(cookie);
        }
    }
    return merged.join('; ');
}

function splitCookies(value: string): string[] {
    return value
        .split(';')
        .map((s) => s.trim())
        .filter((s) => s !== '');
}

function cookieName(cookie: string): string | null {
    const eq = cookie.indexOf('=');
    if (eq < 0) {
        return null;
    }
    const name = cookie.slice(0, eq).trim();
    return name === '' ? null : name;
}

// Appends jar cookies without replacing caller cookies with the same names.
function addCookieHeader(headers: Headers, cookie: string): void {
    const existing = headers.get('cookie');
    headers.set('cookie', existing ? mergeCookieValues(existing, cookie) : cookie);
}

// Resolves credentials from init first, matching fetch's RequestInit override rules.
function effectiveCredentials(input: RequestInfo | URL, init?: RequestInit): RequestCredentials | undefined {
    return init?.credentials ?? (input instanceof Request ? input.credentials : undefined);
}

// Normalizes caller input before fetch-cookie can add jar cookies to mutable headers.
function prepareRequestForCookieJar(input: RequestInfo | URL, init?: RequestInit): PreparedFetchCookieRequest {
    const headers = requestHeaders(input, init);
    const hasCookie = headers.has('cookie');
    headers.delete('cookie');

    if (input instanceof Request) {
        const request = new Request(input, { ...init, headers });
        const requestInit: FetchCookieRequestInit = {
            headers: new Headers(request.headers),
            redirect: request.redirect,
        };
        const { maxRedirect, redirectCount } = (init ?? {}) as FetchCookieRequestInit;
        if (maxRedirect !== undefined) {
            requestInit.maxRedirect = maxRedirect;
        }
        if (redirectCount !== undefined) {
            requestInit.redirectCount = redirectCount;
        }
        return { input: request, init: requestInit };
    }

    if (!hasCookie && init?.headers === undefined) {
        return { input, init: init as FetchCookieRequestInit | undefined };
    }
    return { input, init: { ...init, headers } };
}

// Wrap a fetch implementation with a real RFC6265 cookie jar. Browsers still use their native jar
// through `credentials: 'include'`; Node fetch uses the explicit jar because it has no ambient one.
export function fetchWithCookieJar(jar: CookieJar = new CookieJar(), baseFetch: typeof fetch = fetch): typeof fetch {
    return (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const callerCookie = requestHeaders(input, init).get('cookie');
        if (effectiveCredentials(input, init) === 'omit') {
            const headers = requestHeaders(input, init);
            headers.delete('cookie');
            if (input instanceof Request) {
                const request = new Request(input, { ...init, headers });
                return baseFetch(request, {
                    headers,
                    credentials: 'omit',
                });
            }
            return baseFetch(input, {
                ...init,
                headers,
                credentials: 'omit',
            });
        }

        let forwardedCallerCookie = false;
        const fetchWithCredentials = async (
            currentInput: RequestInfo | URL,
            currentInit?: FetchCookieRequestInit,
        ): Promise<Response> => {
            const headers = requestHeaders(currentInput, currentInit);
            if (currentInput instanceof Request) {
                const requestCookie = currentInput.headers.get('cookie');
                if (requestCookie) {
                    addCookieHeader(headers, requestCookie);
                }
            }
            if (callerCookie && !forwardedCallerCookie) {
                forwardedCallerCookie = true;
                headers.set('cookie', mergeCookieValues(callerCookie, headers.get('cookie')));
            }
            return baseFetch(currentInput, {
                ...currentInit,
                headers,
                credentials: currentInit?.credentials ?? 'include',
            });
        };
        const fetchWithCookies = makeFetchCookie<RequestInfo | URL, FetchCookieRequestInit, Response>(
            fetchWithCredentials,
            jar,
        );

        const request = prepareRequestForCookieJar(input, init);
        return fetchWithCookies(request.input, request.init);
    };
}
