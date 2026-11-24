import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { create, fromBinary } from '@bufbuild/protobuf';
import { Code, ConnectError } from '@connectrpc/connect';
import * as portfinder from 'portfinder';

jest.mock('../src/credential', () => ({
    ...jest.requireActual('../src/credential'),
    environmentApiKey: () => undefined,
}));

import { Client, type ClientOptions } from '../src/client';
import { HttpError } from '../src/error';
import { SelectorSchema } from '../src/gen/ts/common/v1/kv_pb';
import { ErrorInfoSchema } from '../src/gen/ts/google/rpc/error_details_pb';
import { SetRetentionRequestSchema } from '../src/gen/ts/log/v1/retention_pb';
import type { StoreBatch } from '../src/store';
import { Simulator } from '../test-support/simulator';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

let directory: string;
let simulator: Simulator | undefined;

beforeEach(() => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), 'exoware-ts-resume-'));
});

afterEach(async () => {
    await simulator?.stop('SIGKILL');
    simulator = undefined;
    fs.rmSync(directory, { recursive: true, force: true });
});

async function startSimulator(extra: string[] = []): Promise<Simulator> {
    const port = await portfinder.getPortPromise({ port: 20_000 + Math.floor(Math.random() * 20_000) });
    simulator = new Simulator(port, directory, extra);
    await simulator.start();
    return simulator;
}

function client(url: string, subscriptionRetry: ClientOptions['subscriptionRetry'] = {}): Client {
    return new Client(url, { token: '', subscriptionRetry });
}

function selector(prefix: string) {
    return create(SelectorSchema, { payloadRegex: `(?s-u)^${prefix}.*$` });
}

async function write(target: Client, key: string): Promise<bigint> {
    return target.store().set(encoder.encode(key), Buffer.from(key));
}

/** Pulls batches on demand so a test can interleave writes, restarts, and reads. */
class Reader {
    private readonly iterator: AsyncIterator<StoreBatch>;

    constructor(stream: AsyncIterable<StoreBatch>) {
        this.iterator = stream[Symbol.asyncIterator]();
    }

    async next(timeoutMs = 20_000): Promise<{ sequence: bigint; keys: string[] }> {
        let timer: ReturnType<typeof setTimeout> | undefined;
        const timeout = new Promise<never>((_, reject) => {
            timer = setTimeout(() => reject(new Error('timed out waiting for a batch')), timeoutMs);
        });
        try {
            const next = await Promise.race([this.iterator.next(), timeout]);
            if (next.done) throw new Error('subscription ended');
            return {
                sequence: next.value.sequenceNumber,
                keys: next.value.entries.map((entry) => decoder.decode(entry.key)),
            };
        } finally {
            clearTimeout(timer);
        }
    }

    async close(): Promise<void> {
        await this.iterator.return?.();
    }
}

// The server sends type URLs with the type.googleapis.com prefix, which findDetails does not match.
function errorReason(err: unknown): string | undefined {
    const cause = err instanceof HttpError ? err.cause : err;
    if (!(cause instanceof ConnectError)) return undefined;
    for (const detail of cause.details) {
        if ('desc' in detail) continue;
        if (detail.type.replace(/^type\.googleapis\.com\//, '') === ErrorInfoSchema.typeName) {
            return fromBinary(ErrorInfoSchema, detail.value).reason;
        }
    }
    return undefined;
}

test('a subscriber stays continuous across a simulator restart', async () => {
    const server = await startSimulator();
    const writer = client(server.url);
    const prefix = 'restart-';
    const first = await write(writer, `${prefix}1`);

    // Reconnects wait until the restarted server has taken writes, so those writes land during the outage.
    let writesDone!: () => void;
    const outageWrites = new Promise<void>((resolve) => {
        writesDone = resolve;
    });
    const subscriber = client(server.url, { initialBackoffMs: 50, maxBackoffMs: 200 });
    const subscribe = subscriber.stream.subscribe.bind(subscriber.stream);
    const cursors: Array<bigint | undefined> = [];
    subscriber.stream.subscribe = ((request, options) => {
        cursors.push(request.sinceSequenceNumber);
        if (cursors.length === 1) return subscribe(request, options);
        return (async function* () {
            await outageWrites;
            yield* subscribe(request, options);
        })();
    }) as typeof subscriber.stream.subscribe;
    const resumed = new Reader(subscriber.store()
        .subscribe({ selectors: [selector(prefix)], sinceSequenceNumber: first }));
    const legacy = client(server.url, { enabled: false }).store()
        .subscribe({ selectors: [selector(prefix)], sinceSequenceNumber: first })[Symbol.asyncIterator]();

    const delivered = [await resumed.next()];
    expect((await legacy.next()).value?.sequenceNumber).toBe(first);
    const second = await write(writer, `${prefix}2`);
    delivered.push(await resumed.next());
    expect((await legacy.next()).value?.sequenceNumber).toBe(second);

    const legacyEnd = legacy.next().then(
        () => undefined,
        (err: unknown) => err,
    );
    await server.stop('SIGTERM');
    const shutdown = await legacyEnd;
    expect(shutdown).toBeInstanceOf(HttpError);
    expect(shutdown).toMatchObject({ connectCode: Code.Unavailable });
    expect(errorReason(shutdown)).toBe('SERVER_SHUTDOWN');

    await server.start();
    const restarted = client(server.url);
    const during = [await write(restarted, `${prefix}3`), await write(restarted, `${prefix}4`)];
    writesDone();
    delivered.push(await resumed.next(), await resumed.next());
    const after = await write(restarted, `${prefix}5`);
    delivered.push(await resumed.next());
    await resumed.close();

    expect(delivered.map((batch) => batch.sequence)).toEqual([first, second, ...during, after]);
    expect(delivered.map((batch) => batch.keys)).toEqual(
        [1, 2, 3, 4, 5].map((index) => [`${prefix}${index}`]),
    );
    expect(after - first).toBe(4n);
    expect(cursors).toEqual([first, second + 1n]);
});

test('a subscriber resumes across forced closes at the maximum subscription duration', async () => {
    const server = await startSimulator([
        '--subscription-max-duration-ms',
        '300',
        '--subscription-lifetime-jitter',
        '0',
    ]);
    const writer = client(server.url);
    const prefix = 'expiry-';
    const first = await write(writer, `${prefix}0`);

    const legacy = client(server.url, { enabled: false }).store()
        .subscribe({ selectors: [selector(prefix)], sinceSequenceNumber: first });
    const legacyStarted = performance.now();
    const expired = await (async () => {
        for await (const _batch of legacy) {
            // Drain until the server closes the subscription.
        }
    })().then(() => undefined, (err: unknown) => err);
    expect(expired).toMatchObject({ connectCode: Code.Unavailable });
    expect(errorReason(expired)).toBe('SUBSCRIPTION_EXPIRED');
    expect(performance.now() - legacyStarted).toBeLessThan(5_000);

    const subscriber = client(server.url, { initialBackoffMs: 10, maxBackoffMs: 50 });
    const subscribe = subscriber.stream.subscribe.bind(subscriber.stream);
    let attempts = 0;
    subscriber.stream.subscribe = ((request, options) => {
        attempts++;
        return subscribe(request, options);
    }) as typeof subscriber.stream.subscribe;
    const resumed = new Reader(subscriber.store()
        .subscribe({ selectors: [selector(prefix)], sinceSequenceNumber: first }));
    const sequences = [(await resumed.next()).sequence];
    let index = 1;

    // Keep writing until the subscription has been force-closed and reopened several times.
    while (attempts < 5) {
        const sequence = await write(writer, `${prefix}${index++}`);
        const batch = await resumed.next();
        expect(batch.sequence).toBe(sequence);
        sequences.push(batch.sequence);
        await new Promise((resolve) => setTimeout(resolve, 50));
    }
    await resumed.close();

    expect(sequences).toEqual(sequences.map((_, offset) => first + BigInt(offset)));
});

test('an evicted cursor is surfaced without retrying', async () => {
    const server = await startSimulator();
    const target = client(server.url);
    const prefix = 'evicted-';
    const first = await write(target, `${prefix}1`);
    await write(target, `${prefix}2`);
    await write(target, `${prefix}3`);
    await target.retention.setRetention(create(SetRetentionRequestSchema, {
        policy: { kind: { case: 'keepLatest', value: { count: 1n } } },
    }));

    let attempts = 0;
    const subscribe = target.stream.subscribe.bind(target.stream);
    target.stream.subscribe = ((request, options) => {
        attempts++;
        return subscribe(request, options);
    }) as typeof target.stream.subscribe;

    const error = await (async () => {
        for await (const _batch of target.store().subscribe({
            selectors: [selector(prefix)],
            sinceSequenceNumber: first,
        })) {
            // An evicted cursor must fail before any delivery.
        }
    })().then(() => undefined, (err: unknown) => err);

    expect(error).toMatchObject({ connectCode: Code.OutOfRange });
    expect(errorReason(error)).toBe('BATCH_EVICTED');
    expect(attempts).toBe(1);
});
