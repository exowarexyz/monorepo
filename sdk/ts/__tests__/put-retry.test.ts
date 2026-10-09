import { create, toBinary } from '@bufbuild/protobuf';
import { Code, ConnectError, createClient } from '@connectrpc/connect';
import { Client, createTransport, type RetryConfig } from '../src/client';
import { ErrorInfoSchema, RetryInfoSchema } from '../src/gen/ts/google/rpc/error_details_pb';
import { PutRequestSchema, PutResponseSchema, Service as IngestService } from '../src/gen/ts/log/v1/ingest_pb';
import { GetRequestSchema, GetResponseSchema } from '../src/gen/ts/store/v1/query_pb';

type Detail = { type: string; value: string };

function errorInfo(domain = 'log.ingest', reason = 'INGEST_ADMISSION_EXHAUSTED'): Detail {
    return {
        type: 'google.rpc.ErrorInfo',
        value: Buffer.from(toBinary(ErrorInfoSchema, create(ErrorInfoSchema, { domain, reason }))).toString('base64'),
    };
}

function retryInfo(seconds = 0n, nanos = 20_000_000): Detail {
    return {
        type: 'google.rpc.RetryInfo',
        value: Buffer.from(toBinary(RetryInfoSchema, create(RetryInfoSchema, {
            retryDelay: { seconds, nanos },
        }))).toString('base64'),
    };
}

function rejected(details: Detail[] = [errorInfo(), retryInfo()], code = 'resource_exhausted'): Response {
    return new Response(JSON.stringify({ code, message: 'rejected', details }), {
        status: code === 'resource_exhausted' ? 429 : 503,
        headers: { 'content-type': 'application/json' },
    });
}

function accepted(): Response {
    return new Response(toBinary(PutResponseSchema, create(PutResponseSchema, { sequenceNumber: 7n })), {
        headers: { 'content-type': 'application/proto' },
    });
}

function client(retry: Partial<RetryConfig> = {}): Client {
    return new Client('http://put-retry.test', {
        token: '',
        retry: { maxAttempts: 3, initialBackoffMs: 10, maxBackoffMs: 100, ...retry },
    });
}

function customIngest(typeName = IngestService.typeName, retry: Partial<RetryConfig> = {}) {
    const service = { ...IngestService, typeName };
    const put = { ...IngestService.method.put, parent: service };
    service.methods = [put];
    service.method = { put };
    expect(service).not.toBe(IngestService);
    expect(put).not.toBe(IngestService.method.put);
    return createClient(service, createTransport('http://put-retry.test', {
        token: '',
        useBinaryFormat: true,
        retry: { maxAttempts: 3, initialBackoffMs: 10, maxBackoffMs: 100, ...retry },
    }));
}

const request = create(PutRequestSchema, {
    kvs: [
        { key: new Uint8Array([1]), value: new Uint8Array([2, 3]) },
        { key: new Uint8Array([4]), value: new Uint8Array([5, 6]) },
    ],
});

// Preserve Rust's serialized bytes to expose Connect detail type-name incompatibilities.
const serverAdmissionBody = '{"code":"resource_exhausted","message":"ingest admission exhausted","details":[{"type":"google.rpc.ErrorInfo","value":"ChpJTkdFU1RfQURNSVNTSU9OX0VYSEFVU1RFRBIKbG9nLmluZ2VzdA"},{"type":"google.rpc.RetryInfo","value":"CgUQgMLXLw"}]}';

beforeEach(() => {
    jest.useFakeTimers();
    jest.spyOn(Math, 'random').mockReturnValue(0);
});

afterEach(() => {
    jest.restoreAllMocks();
    jest.useRealTimers();
});

test('admission retry preserves every byte and waits for the hint minimum', async () => {
    const fetch = jest.spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(rejected())
        .mockResolvedValueOnce(accepted());
    const pending = client().ingest.put(request);
    await jest.advanceTimersByTimeAsync(19);
    expect(fetch).toHaveBeenCalledTimes(1);
    await jest.advanceTimersByTimeAsync(1);
    await expect(pending).resolves.toMatchObject({ sequenceNumber: 7n });
    expect(fetch).toHaveBeenCalledTimes(2);
    for (const [, init] of fetch.mock.calls) {
        expect(init?.body).toEqual(toBinary(PutRequestSchema, request));
        expect(new Headers(init?.headers).has('connect-timeout-ms')).toBe(false);
    }
});

test.each(['SDK', 'custom'])('Rust-serialized admission errors retry through the %s transport', async (kind) => {
    const fetch = jest.spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(new Response(serverAdmissionBody, {
            status: 429,
            headers: { 'content-type': 'application/json' },
        }))
        .mockResolvedValueOnce(accepted());
    const retry = { initialBackoffMs: 10, maxBackoffMs: 2000 };
    const ingest = kind === 'custom' ? customIngest(IngestService.typeName, retry) : client(retry).ingest;
    const pending = ingest.put(request);
    await jest.advanceTimersByTimeAsync(99);
    expect(fetch).toHaveBeenCalledTimes(1);
    await jest.advanceTimersByTimeAsync(1);
    await expect(pending).resolves.toMatchObject({ sequenceNumber: 7n });
    expect(fetch).toHaveBeenCalledTimes(2);
    for (const [, init] of fetch.mock.calls) {
        expect(init?.body).toEqual(toBinary(PutRequestSchema, request));
    }
});

test.each([
    ['missing details', []],
    ['missing ErrorInfo', [retryInfo()]],
    ['missing RetryInfo', [errorInfo()]],
    ['wrong domain', [errorInfo('store'), retryInfo()]],
    ['permanent rejection', [errorInfo('log.ingest', 'PUT_TOO_LARGE'), retryInfo()]],
    ['missing duration', [errorInfo(), { type: 'google.rpc.RetryInfo', value: '' }]],
    ['zero duration', [errorInfo(), retryInfo(0n, 0)]],
    ['negative seconds', [errorInfo(), retryInfo(-1n, 1)]],
    ['negative nanos', [errorInfo(), retryInfo(1n, -1)]],
    ['nanos out of range', [errorInfo(), retryInfo(0n, 1_000_000_000)]],
    ['seconds out of range', [errorInfo(), retryInfo(315_576_000_001n, 0)]],
    ['malformed RetryInfo', [errorInfo(), { type: 'google.rpc.RetryInfo', value: '/w==' }]],
    ['duplicate RetryInfo', [errorInfo(), retryInfo(), retryInfo()]],
    ['duplicate ErrorInfo', [errorInfo(), errorInfo(), retryInfo()]],
    ['bare and prefixed ErrorInfo', [errorInfo(), { ...errorInfo(), type: 'type.googleapis.com/google.rpc.ErrorInfo' }, retryInfo()]],
    ['bare and prefixed RetryInfo', [errorInfo(), retryInfo(), { ...retryInfo(), type: 'type.googleapis.com/google.rpc.RetryInfo' }]],
    ['valid and malformed RetryInfo', [errorInfo(), retryInfo(), { type: 'google.rpc.RetryInfo', value: '/w==' }]],
    ['valid and malformed ErrorInfo', [errorInfo(), retryInfo(), { type: 'google.rpc.ErrorInfo', value: '/w==' }]],
] satisfies Array<[string, Detail[]]>)('Put does not retry %s', async (_name, details) => {
    const fetch = jest.spyOn(globalThis, 'fetch').mockResolvedValueOnce(rejected(details));
    await expect(client().ingest.put(request)).rejects.toMatchObject({ code: Code.ResourceExhausted });
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(jest.getTimerCount()).toBe(0);
});

test.each(['unavailable', 'internal', 'aborted'])('Put does not retry %s even with admission details', async (code) => {
    const fetch = jest.spyOn(globalThis, 'fetch').mockResolvedValueOnce(rejected(undefined, code));
    await expect(client().ingest.put(request)).rejects.toBeInstanceOf(ConnectError);
    expect(fetch).toHaveBeenCalledTimes(1);
});

test.each(['unavailable', 'aborted', 'resource_exhausted'])('custom Ingest descriptors do not replay generic %s', async (code) => {
    const fetch = jest.spyOn(globalThis, 'fetch').mockImplementation(async () => rejected([], code));
    const pending = customIngest().put(request);
    const result = expect(pending).rejects.toBeInstanceOf(ConnectError);
    await jest.advanceTimersByTimeAsync(100);
    await result;
    expect(fetch).toHaveBeenCalledTimes(1);
});

test('custom Ingest descriptors can retry explicit admission rejection', async () => {
    const fetch = jest.spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(rejected())
        .mockResolvedValueOnce(accepted());
    const pending = customIngest().put(request);
    await jest.advanceTimersByTimeAsync(19);
    expect(fetch).toHaveBeenCalledTimes(1);
    await jest.advanceTimersByTimeAsync(1);
    await expect(pending).resolves.toMatchObject({ sequenceNumber: 7n });
    expect(fetch).toHaveBeenCalledTimes(2);
});

test('Put methods on another service retain the generic retry policy', async () => {
    const fetch = jest.spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(rejected([], 'unavailable'))
        .mockResolvedValueOnce(accepted());
    const pending = customIngest('other.Service').put(request);
    await jest.advanceTimersByTimeAsync(5);
    await expect(pending).resolves.toMatchObject({ sequenceNumber: 7n });
    expect(fetch).toHaveBeenCalledTimes(2);
});

test.each([
    new TypeError('fetch failed'),
    new ConnectError('connection lost', Code.Unavailable),
    new ConnectError('unknown transport failure', Code.Internal),
])('Put does not replay an ambiguous transport error %s', async (error) => {
    const fetch = jest.spyOn(globalThis, 'fetch').mockRejectedValueOnce(error);
    await expect(client().ingest.put(request)).rejects.toBeInstanceOf(ConnectError);
    expect(fetch).toHaveBeenCalledTimes(1);
});

test.each([0, 1])('maxAttempts %s disables admission retries', async (maxAttempts) => {
    const fetch = jest.spyOn(globalThis, 'fetch').mockResolvedValueOnce(rejected());
    await expect(client({ maxAttempts }).ingest.put(request)).rejects.toMatchObject({ code: Code.ResourceExhausted });
    expect(fetch).toHaveBeenCalledTimes(1);
});

test('admission retries stop at maxAttempts', async () => {
    const fetch = jest.spyOn(globalThis, 'fetch').mockImplementation(async () => rejected());
    const pending = client().ingest.put(request);
    const result = expect(pending).rejects.toMatchObject({ code: Code.ResourceExhausted });
    await jest.advanceTimersByTimeAsync(40);
    await result;
    expect(fetch).toHaveBeenCalledTimes(3);
});

test('hints above maxBackoffMs are not shortened into retries', async () => {
    const fetch = jest.spyOn(globalThis, 'fetch').mockResolvedValueOnce(rejected([errorInfo(), retryInfo(0n, 100_000_001)]));
    await expect(client().ingest.put(request)).rejects.toMatchObject({ code: Code.ResourceExhausted });
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(jest.getTimerCount()).toBe(0);
});

test('submillisecond hints round up instead of retrying early', async () => {
    const fetch = jest.spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(rejected([errorInfo(), retryInfo(0n, 1)]))
        .mockResolvedValueOnce(accepted());
    const pending = client({ initialBackoffMs: 0 }).ingest.put(request);
    await jest.advanceTimersByTimeAsync(0);
    expect(fetch).toHaveBeenCalledTimes(1);
    await jest.advanceTimersByTimeAsync(1);
    await expect(pending).resolves.toMatchObject({ sequenceNumber: 7n });
});

test('long hints do not overflow the timer into an early retry', async () => {
    const fetch = jest.spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(rejected([errorInfo(), retryInfo(2_147_483n, 648_000_000)]))
        .mockResolvedValueOnce(accepted());
    const pending = client({ maxBackoffMs: 2_147_483_648 }).ingest.put(request);
    await jest.advanceTimersByTimeAsync(2_147_483_647);
    expect(fetch).toHaveBeenCalledTimes(1);
    await jest.advanceTimersByTimeAsync(1);
    await expect(pending).resolves.toMatchObject({ sequenceNumber: 7n });
});

test('jittered exponential backoff can exceed the hint but remains bounded', async () => {
    jest.mocked(Math.random).mockReturnValue(1);
    const fetch = jest.spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(rejected([errorInfo(), retryInfo(0n, 1_000_000)]))
        .mockResolvedValueOnce(rejected([errorInfo(), retryInfo(0n, 1_000_000)]))
        .mockResolvedValueOnce(accepted());
    const pending = client({ initialBackoffMs: 80 }).ingest.put(request);
    await jest.advanceTimersByTimeAsync(99);
    expect(fetch).toHaveBeenCalledTimes(1);
    await jest.advanceTimersByTimeAsync(1);
    expect(fetch).toHaveBeenCalledTimes(2);
    await jest.advanceTimersByTimeAsync(99);
    expect(fetch).toHaveBeenCalledTimes(2);
    await jest.advanceTimersByTimeAsync(1);
    await expect(pending).resolves.toMatchObject({ sequenceNumber: 7n });
});

test.each([
    [0, 1000],
    [0.5, 1050],
    [1, 1100],
])('dominant server hints retain jitter with random %s', async (random, expectedDelay) => {
    jest.mocked(Math.random).mockReturnValue(random);
    const fetch = jest.spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(rejected([errorInfo(), retryInfo(1n, 0)]))
        .mockResolvedValueOnce(accepted());
    const pending = client({ initialBackoffMs: 100, maxBackoffMs: 2000 }).ingest.put(request);
    await jest.advanceTimersByTimeAsync(expectedDelay - 1);
    expect(fetch).toHaveBeenCalledTimes(1);
    await jest.advanceTimersByTimeAsync(1);
    await expect(pending).resolves.toMatchObject({ sequenceNumber: 7n });
});

test.each([
    { maxAttempts: NaN },
    { maxBackoffMs: NaN },
    { initialBackoffMs: NaN },
])('invalid retry settings do not bypass the hint floor %s', async (retry) => {
    const fetch = jest.spyOn(globalThis, 'fetch').mockResolvedValueOnce(rejected());
    await expect(client(retry).ingest.put(request)).rejects.toMatchObject({ code: Code.ResourceExhausted });
    expect(fetch).toHaveBeenCalledTimes(1);
});

test('aborting backoff rejects promptly and prevents another attempt', async () => {
    const controller = new AbortController();
    const fetch = jest.spyOn(globalThis, 'fetch').mockResolvedValueOnce(rejected());
    const pending = client().ingest.put(request, { signal: controller.signal });
    const result = expect(pending).rejects.toMatchObject({ code: Code.Canceled });
    await jest.advanceTimersByTimeAsync(1);
    controller.abort();
    await result;
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(jest.getTimerCount()).toBe(0);
});

test('an already canceled Put is never sent', async () => {
    const controller = new AbortController();
    controller.abort();
    const fetch = jest.spyOn(globalThis, 'fetch');
    await expect(client().ingest.put(request, { signal: controller.signal }))
        .rejects.toMatchObject({ code: Code.Canceled });
    expect(fetch).not.toHaveBeenCalled();
});

test.each(['timeout', 'header'])('the original %s deadline expires during backoff', async (kind) => {
    const fetch = jest.spyOn(globalThis, 'fetch').mockResolvedValueOnce(rejected());
    const options = kind === 'timeout' ? { timeoutMs: 10 } : { headers: { 'connect-timeout-ms': '10' } };
    const pending = client().ingest.put(request, options);
    const result = expect(pending).rejects.toMatchObject({ code: Code.DeadlineExceeded });
    await jest.advanceTimersByTimeAsync(10);
    await result;
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(jest.getTimerCount()).toBe(0);
});

test('an explicit zero timeout header expires before sending Put', async () => {
    const fetch = jest.spyOn(globalThis, 'fetch').mockImplementation(async () => rejected());
    await expect(client().ingest.put(request, { headers: { 'connect-timeout-ms': '0' } }))
        .rejects.toMatchObject({ code: Code.DeadlineExceeded });
    expect(fetch).not.toHaveBeenCalled();
    expect(jest.getTimerCount()).toBe(0);
});

test('Connect timeoutMs zero still omits the timeout header', async () => {
    const fetch = jest.spyOn(globalThis, 'fetch').mockResolvedValueOnce(accepted());
    await expect(client().ingest.put(request, { timeoutMs: 0 }))
        .resolves.toMatchObject({ sequenceNumber: 7n });
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(new Headers(fetch.mock.calls[0][1]?.headers).has('connect-timeout-ms')).toBe(false);
});

test('remaining timeout decreases across attempts and includes upload and backoff', async () => {
    const timeouts: Array<string | null> = [];
    const fetch = jest.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
        timeouts.push(new Headers(init?.headers).get('connect-timeout-ms'));
        if (timeouts.length === 1) {
            await new Promise((resolve) => setTimeout(resolve, 30));
            return rejected();
        }
        return accepted();
    });
    const pending = client().ingest.put(request, { timeoutMs: 100 });
    await jest.advanceTimersByTimeAsync(50);
    await expect(pending).resolves.toMatchObject({ sequenceNumber: 7n });
    expect(timeouts).toEqual(['100', '50']);
    expect(fetch).toHaveBeenCalledTimes(2);
});

test('Store writes without a timeout retain their uncapped upload budget', async () => {
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
        expect(new Headers(init?.headers).has('connect-timeout-ms')).toBe(false);
        await new Promise((resolve) => setTimeout(resolve, 60_000));
        expect(init?.signal?.aborted).toBe(false);
        return accepted();
    });
    const pending = client().store().set(new Uint8Array([1]), new Uint8Array([2]));
    await jest.advanceTimersByTimeAsync(60_000);
    await expect(pending).resolves.toBe(7n);
});

test('deadline during a later upload uses the original budget', async () => {
    let attempts = 0;
    const fetch = jest.spyOn(globalThis, 'fetch').mockImplementation(async (_input, init) => {
        if (++attempts === 1) return rejected();
        return new Promise((_resolve, reject) => {
            init?.signal?.addEventListener('abort', () => reject(init.signal?.reason), { once: true });
        });
    });
    const pending = client().ingest.put(request, { timeoutMs: 30 });
    const result = expect(pending).rejects.toMatchObject({ code: Code.DeadlineExceeded });
    await jest.advanceTimersByTimeAsync(30);
    await result;
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(jest.getTimerCount()).toBe(0);
});

test.each(['unavailable', 'aborted', 'resource_exhausted'])('Get retains retries for generic %s', async (code) => {
    const fetch = jest.spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(rejected([], code))
        .mockResolvedValueOnce(new Response(JSON.stringify({}), { headers: { 'content-type': 'application/json' } }));
    const pending = client().query.get(create(GetRequestSchema));
    await jest.advanceTimersByTimeAsync(5);
    await expect(pending).resolves.toEqual(create(GetResponseSchema));
    expect(fetch).toHaveBeenCalledTimes(2);
});
