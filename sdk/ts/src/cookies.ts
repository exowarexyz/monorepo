// Edge upstream affinity (cookie) for the Node fetch transport.
//
// Deployments behind a load balancer or proxy may use HTTP sticky sessions: the edge sets a
// `Set-Cookie` so each client session sticks to one backend (cache locality). The cookie name is
// the edge's concern, not ours. In the browser the platform already keeps a native cookie jar, so
// `fetchWithCookieJar` only sets `credentials: 'include'` and lets the browser do the rest (JS
// cannot read `Set-Cookie` there anyway). Under Node there is no ambient jar, so we keep a small
// one here, mirroring the Rust SDK: every `Set-Cookie` is stored and replayed as `Cookie`, but only
// to the host that set it, so a single client targeting several upstreams never sends one
// upstream's affinity token to another.
//
// The jar is bounded so a broken or compromised edge cannot amplify memory usage or outbound
// request headers, and so a client fanning out to many upstreams cannot grow it without limit.

const MAX_HOSTS = 256;
const MAX_COOKIES_PER_HOST = 16;
const MAX_COOKIE_BYTES = 4096;
const MAX_COOKIE_HEADER_BYTES = 8192;

type Cookie = {
    value: string;
    // Absolute expiry in epoch milliseconds. Undefined is a session cookie, kept until overwritten
    // or explicitly deleted.
    expires?: number;
};

type SetCookieUpdate =
    | { kind: 'store'; name: string; value: string; expires?: number }
    | { kind: 'delete'; name: string };

// 'expired' -> delete now; 'session' -> no expiry; number -> absolute expiry in epoch ms.
type Lifetime = 'expired' | 'session' | number;

export class CookieJar {
    // Partitioned by request authority (`host` or `host:port`) -> that host's cookies (name -> value).
    private readonly hosts = new Map<string, Map<string, Cookie>>();

    // Render the `Cookie` header value for `authority`, or undefined if it holds none. Expired
    // cookies are pruned here so a lapsed cookie is dropped even without a deletion from the edge.
    cookieHeaderFor(authority: string): string | undefined {
        const origin = this.hosts.get(authority);
        if (!origin) {
            return undefined;
        }
        const now = Date.now();
        for (const [name, cookie] of origin) {
            if (cookie.expires !== undefined && cookie.expires <= now) {
                origin.delete(name);
            }
        }
        if (origin.size === 0) {
            this.hosts.delete(authority);
            return undefined;
        }
        return [...origin.keys()]
            .sort()
            .map((name) => `${name}=${origin.get(name)!.value}`)
            .join('; ');
    }

    // Store every `Set-Cookie` value under `authority`, so each is only replayed to that host.
    storeSetCookies(authority: string, setCookies: readonly string[]): void {
        for (const raw of setCookies) {
            const update = parseSetCookie(raw);
            if (!update) {
                continue;
            }
            if (update.kind === 'delete') {
                const origin = this.hosts.get(authority);
                if (origin) {
                    origin.delete(update.name);
                    if (origin.size === 0) {
                        this.hosts.delete(authority);
                    }
                }
            } else {
                this.store(authority, update.name, update.value, update.expires);
            }
        }
    }

    private store(authority: string, name: string, value: string, expires?: number): void {
        if (cookiePairLen(name, value) > MAX_COOKIE_BYTES) {
            return;
        }

        // Evict an arbitrary existing host to make room for a new one rather than rejecting it, so a
        // long-lived client that rotates through upstreams keeps affinity for whatever it talks to now.
        if (!this.hosts.has(authority) && this.hosts.size >= MAX_HOSTS) {
            const victim = this.hosts.keys().next().value;
            if (victim !== undefined) {
                this.hosts.delete(victim);
            }
        }

        let origin = this.hosts.get(authority);
        if (!origin) {
            origin = new Map();
            this.hosts.set(authority, origin);
        }
        if (!origin.has(name) && origin.size >= MAX_COOKIES_PER_HOST) {
            return;
        }

        const previous = origin.get(name);
        origin.set(name, { value, expires });
        if (renderedCookieHeaderLen(origin) > MAX_COOKIE_HEADER_BYTES) {
            if (previous) {
                origin.set(name, previous);
            } else {
                origin.delete(name);
            }
        }
    }
}

function cookiePairLen(name: string, value: string): number {
    return name.length + 1 + value.length;
}

function renderedCookieHeaderLen(cookies: Map<string, Cookie>): number {
    let pairBytes = 0;
    for (const [name, cookie] of cookies) {
        pairBytes += cookiePairLen(name, cookie.value);
    }
    return pairBytes + Math.max(cookies.size - 1, 0) * 2;
}

// From one `Set-Cookie` header value, extract the cookie update, honoring expiry/deletion
// attributes while ignoring non-lifetime attributes (`Path`, `Domain`, ...).
export function parseSetCookie(setCookie: string): SetCookieUpdate | null {
    const segments = setCookie.split(';');
    const first = (segments.shift() ?? '').trim();
    const eq = first.indexOf('=');
    if (eq < 0) {
        return null;
    }
    const name = first.slice(0, eq).trim();
    const value = first
        .slice(eq + 1)
        .trim()
        .replace(/^"+|"+$/g, '');
    if (name === '') {
        return null;
    }

    const lifetime = cookieLifetime(segments);
    if (lifetime === 'expired') {
        return { kind: 'delete', name };
    }
    if (lifetime === 'session') {
        return { kind: 'store', name, value };
    }
    return { kind: 'store', name, value, expires: lifetime };
}

function cookieLifetime(attributes: readonly string[]): Lifetime {
    const now = Date.now();
    let expires: number | undefined;

    for (const attr of attributes) {
        const trimmed = attr.trim();
        const eq = trimmed.indexOf('=');
        if (eq < 0) {
            continue;
        }
        const name = trimmed.slice(0, eq).trim().toLowerCase();
        const value = trimmed.slice(eq + 1).trim();

        if (name === 'max-age') {
            // Max-Age takes precedence over Expires per RFC 6265.
            const seconds = parseIntStrict(value);
            if (seconds === null) {
                continue;
            }
            if (seconds <= 0) {
                return 'expired';
            }
            return now + seconds * 1000;
        }

        if (name === 'expires') {
            const parsed = parseCookieExpires(value);
            if (parsed !== null) {
                expires = parsed;
            }
        }
    }

    if (expires !== undefined) {
        return expires <= now ? 'expired' : expires;
    }
    return 'session';
}

function parseIntStrict(value: string): number | null {
    if (!/^-?\d+$/.test(value)) {
        return null;
    }
    return Number(value);
}

function parseCookieExpires(value: string): number | null {
    const ms = Date.parse(value);
    return Number.isNaN(ms) ? null : ms;
}

function mergeCookieHeader(headers: Headers, jarHeader: string): void {
    const existing = headers.get('cookie');
    if (!existing) {
        headers.set('cookie', jarHeader);
        return;
    }
    headers.set('cookie', mergeCookieValues([existing], jarHeader));
}

// Append jar cookies to caller-supplied ones; jar names never override existing names.
export function mergeCookieValues(existingValues: readonly string[], jarHeader: string): string {
    const merged: string[] = [];
    const existingNames = new Set<string>();

    for (const value of existingValues) {
        for (const cookie of splitCookies(value)) {
            const name = cookieName(cookie);
            if (name !== null) {
                existingNames.add(name);
            }
            merged.push(cookie);
        }
    }

    for (const cookie of splitCookies(jarHeader)) {
        const name = cookieName(cookie);
        if (name === null || !existingNames.has(name)) {
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

function readSetCookies(headers: Headers): string[] {
    const withGetSetCookie = headers as Headers & { getSetCookie?: () => string[] };
    if (typeof withGetSetCookie.getSetCookie === 'function') {
        return withGetSetCookie.getSetCookie();
    }
    const single = headers.get('set-cookie');
    return single ? [single] : [];
}

function requestUrl(input: RequestInfo | URL): string {
    if (typeof input === 'string') {
        return input;
    }
    if (input instanceof URL) {
        return input.href;
    }
    return input.url;
}

// Wrap a fetch implementation so sticky-session cookies are replayed per host. Always sends
// credentials so the browser's native jar also carries affinity cross-origin; the explicit jar is
// what makes affinity work under Node, where there is no ambient cookie store.
export function fetchWithCookieJar(jar: CookieJar, baseFetch: typeof fetch = fetch): typeof fetch {
    return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const authority = new URL(requestUrl(input)).host;

        const headers = new Headers(
            init?.headers ?? (input instanceof Request ? input.headers : undefined),
        );
        const jarHeader = jar.cookieHeaderFor(authority);
        if (jarHeader) {
            mergeCookieHeader(headers, jarHeader);
        }

        const response = await baseFetch(input, { ...init, headers, credentials: 'include' });

        const setCookies = readSetCookies(response.headers);
        if (setCookies.length > 0) {
            jar.storeSetCookies(authority, setCookies);
        }
        return response;
    };
}
