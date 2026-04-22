import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execFileSync } from 'child_process';
import { Client } from '../src/client';
import {
    ImmutableQmdbClient,
    KeylessQmdbClient,
    OrderedQmdbClient,
    type ImmutableQmdbOperation,
    type KeylessQmdbOperation,
    type OrderedQmdbOperation,
    UnorderedQmdbClient,
    type UnorderedQmdbOperation,
} from '../../qmdb/web/src/node';

const tempDir = path.join(os.tmpdir(), 'exoware-ts-sdk-tests');
const configFile = path.join(tempDir, 'config.json');

type TestConfig = {
    port: number;
    cargoTargetDir: string;
};

jest.setTimeout(180000);

function parseFixtureOutput(output: string): Record<string, string> {
    const entries = output
        .trim()
        .split(/\r?\n/)
        .filter(Boolean)
        .map((line) => {
            const [key, ...rest] = line.split('=');
            return [key, rest.join('=')];
        });
    return Object.fromEntries(entries);
}

function runFixture(
    fixturePath: string,
    baseUrl: string,
    command:
        | 'seed-ordered'
        | 'seed-unordered'
        | 'seed-immutable'
        | 'seed-keyless'
        | 'tamper-immutable',
): Record<string, string> {
    const stdout = execFileSync(
        fixturePath,
        [
            '--base-url',
            baseUrl,
            command,
        ],
        {
            encoding: 'utf-8',
        },
    );
    return parseFixtureOutput(stdout);
}

function decodeUtf8(bytes: Uint8Array | undefined | null): string | null {
    if (bytes === undefined || bytes === null) {
        return null;
    }
    return Buffer.from(bytes).toString('utf-8');
}

function decodeHex(hex: string): Uint8Array {
    return Uint8Array.from(Buffer.from(hex, 'hex'));
}

async function nextWithTimeout<T>(
    iterator: AsyncIterator<T>,
    label: string,
    timeoutMs = 10000,
): Promise<IteratorResult<T>> {
    let timeout: ReturnType<typeof setTimeout> | undefined;
    try {
        return await Promise.race([
            iterator.next(),
            new Promise<IteratorResult<T>>((_, reject) => {
                timeout = setTimeout(() => reject(new Error(`timed out waiting for ${label}`)), timeoutMs);
            }),
        ]);
    } finally {
        if (timeout !== undefined) {
            clearTimeout(timeout);
        }
    }
}

async function closeIterator<T>(iterator: AsyncIterator<T>, timeoutMs = 1000): Promise<void> {
    const close = iterator.return?.();
    if (close === undefined) {
        return;
    }
    await Promise.race([
        Promise.resolve(close).then(() => undefined).catch(() => undefined),
        new Promise<void>((resolve) => setTimeout(resolve, timeoutMs)),
    ]);
}

describe('qmdb-web', () => {
    let client: Client;
    let baseUrl: string;
    let fixturePath: string;

    beforeAll(() => {
        const config = JSON.parse(fs.readFileSync(configFile, 'utf-8')) as TestConfig;
        baseUrl = `http://127.0.0.1:${config.port}`;
        fixturePath = path.join(config.cargoTargetDir, 'debug', 'examples', 'qmdb_web_fixture');
        client = new Client(baseUrl);
    });

    it('verifies ordered get/proof/stream end-to-end through wasm', async () => {
        const ordered = new OrderedQmdbClient(client.store(), client.stream());
        const stream = ordered.streamBatches();

        try {
            const nextBatch = nextWithTimeout(stream, 'ordered batch');

            await new Promise((resolve) => setTimeout(resolve, 100));
            const fixture = runFixture(fixturePath, baseUrl, 'seed-ordered');
            const result = await nextBatch;

            expect(result.done).toBe(false);
            const batch = result.value!;
            const updates = batch.operations.filter(
                (operation: OrderedQmdbOperation): operation is Extract<OrderedQmdbOperation, { kind: 'update' }> =>
                    operation.kind === 'update',
            );

            expect(batch.watermark).toBe(BigInt(fixture.ordered_watermark));
            expect(batch.startLocation).toBe(BigInt(fixture.ordered_start_location));
            expect(
                updates.some(
                    (operation: Extract<OrderedQmdbOperation, { kind: 'update' }>) =>
                        decodeUtf8(operation.key) === 'alpha' &&
                        decodeUtf8(operation.value) === 'one',
                ),
            ).toBe(true);
            expect(
                updates.some(
                    (operation: Extract<OrderedQmdbOperation, { kind: 'update' }>) =>
                        decodeUtf8(operation.key) === 'beta' &&
                        decodeUtf8(operation.value) === 'two',
                ),
            ).toBe(true);
            expect(batch.operations.some((operation: OrderedQmdbOperation) => operation.kind === 'commitFloor')).toBe(true);

            await expect(ordered.rootAt(batch.watermark)).resolves.toEqual(batch.root);
            await expect(
                ordered.operationRangeProof(
                    batch.watermark,
                    batch.startLocation,
                    batch.operations.length,
                ),
            ).resolves.toMatchObject({
                watermark: batch.watermark,
                startLocation: batch.startLocation,
                operations: batch.operations,
            });
        } finally {
            await closeIterator(stream);
            ordered.free();
        }
    });

    it('verifies unordered get/proof/stream end-to-end through wasm', async () => {
        const unordered = new UnorderedQmdbClient(client.store(), client.stream());
        const stream = unordered.streamBatches();

        try {
            const nextBatch = nextWithTimeout(stream, 'unordered batch');

            await new Promise((resolve) => setTimeout(resolve, 100));
            const fixture = runFixture(fixturePath, baseUrl, 'seed-unordered');
            const result = await nextBatch;

            expect(result.done).toBe(false);
            const batch = result.value!;
            const updates = batch.operations.filter(
                (operation: UnorderedQmdbOperation): operation is Extract<UnorderedQmdbOperation, { kind: 'update' }> =>
                    operation.kind === 'update',
            );

            expect(batch.watermark).toBe(BigInt(fixture.unordered_watermark));
            expect(batch.startLocation).toBe(BigInt(fixture.unordered_start_location));
            expect(
                updates.some(
                    (operation: Extract<UnorderedQmdbOperation, { kind: 'update' }>) =>
                        decodeUtf8(operation.key) === 'alpha' &&
                        decodeUtf8(operation.value) === 'one',
                ),
            ).toBe(true);
            expect(
                updates.some(
                    (operation: Extract<UnorderedQmdbOperation, { kind: 'update' }>) =>
                        decodeUtf8(operation.key) === 'beta' &&
                        decodeUtf8(operation.value) === 'two',
                ),
            ).toBe(true);
            expect(batch.operations.some((operation: UnorderedQmdbOperation) => operation.kind === 'commitFloor')).toBe(true);

            await expect(unordered.rootAt(batch.watermark)).resolves.toEqual(batch.root);
            await expect(
                unordered.operationRangeProof(
                    batch.watermark,
                    batch.startLocation,
                    batch.operations.length,
                ),
            ).resolves.toMatchObject({
                watermark: batch.watermark,
                startLocation: batch.startLocation,
                operations: batch.operations,
            });
        } finally {
            await closeIterator(stream);
            unordered.free();
        }
    });

    it('verifies immutable get/proof/stream end-to-end through wasm', async () => {
        const immutable = new ImmutableQmdbClient(client.store(), client.stream(), 20);
        const stream = immutable.streamBatches();

        try {
            const nextBatch = nextWithTimeout(stream, 'immutable batch');

            await new Promise((resolve) => setTimeout(resolve, 100));
            const fixture = runFixture(fixturePath, baseUrl, 'seed-immutable');
            const result = await nextBatch;

            expect(result.done).toBe(false);
            const batch = result.value!;
            const sets = batch.operations.filter(
                (operation: ImmutableQmdbOperation): operation is Extract<ImmutableQmdbOperation, { kind: 'set' }> =>
                    operation.kind === 'set',
            );

            expect(batch.watermark).toBe(BigInt(fixture.immutable_watermark));
            expect(batch.startLocation).toBe(BigInt(fixture.immutable_start_location));
            expect(sets).toHaveLength(2);
            expect(Buffer.from(sets[0]!.key)).toEqual(Buffer.from(decodeHex(fixture.immutable_key_hex)));
            expect(decodeUtf8(sets[0]!.value)).toBe('alpha');
            expect(decodeUtf8(sets[1]!.value)).toBe('beta');

            await expect(immutable.rootAt(batch.watermark)).resolves.toEqual(batch.root);
            await expect(
                immutable.operationRangeProof(
                    batch.watermark,
                    batch.startLocation,
                    batch.operations.length,
                ),
            ).resolves.toMatchObject({
                watermark: batch.watermark,
                startLocation: batch.startLocation,
                operations: batch.operations,
            });
            await expect(immutable.writerLocationWatermark()).resolves.toBe(batch.watermark);

            const got = await immutable.getAt(
                decodeHex(fixture.immutable_key_hex),
                batch.watermark,
            );
            expect(got).not.toBeNull();
            expect(Buffer.from(got!.key)).toEqual(Buffer.from(decodeHex(fixture.immutable_key_hex)));
            const alphaIndex = batch.operations.findIndex(
                (operation: ImmutableQmdbOperation) =>
                    operation.kind === 'set' &&
                    Buffer.from(operation.key).equals(Buffer.from(decodeHex(fixture.immutable_key_hex))),
            );
            expect(alphaIndex).toBeGreaterThanOrEqual(0);
            expect(got!.location).toBe(batch.startLocation + BigInt(alphaIndex));
            expect(decodeUtf8(got!.value ?? undefined)).toBe('alpha');
        } finally {
            await closeIterator(stream);
            immutable.free();
        }
    });

    it('verifies keyless get/proof/stream end-to-end through wasm', async () => {
        const keyless = new KeylessQmdbClient(client.store(), client.stream());
        const stream = keyless.streamBatches();

        try {
            const nextBatch = nextWithTimeout(stream, 'keyless batch');

            await new Promise((resolve) => setTimeout(resolve, 100));
            const fixture = runFixture(fixturePath, baseUrl, 'seed-keyless');
            const result = await nextBatch;

            expect(result.done).toBe(false);
            const batch = result.value!;
            const appends = batch.operations.filter(
                (operation: KeylessQmdbOperation): operation is Extract<KeylessQmdbOperation, { kind: 'append' }> =>
                    operation.kind === 'append',
            );

            expect(batch.watermark).toBe(BigInt(fixture.keyless_watermark));
            expect(batch.startLocation).toBe(BigInt(fixture.keyless_start_location));
            expect(appends).toHaveLength(2);
            expect(decodeUtf8(appends[0]!.value)).toBe('first-value');
            expect(decodeUtf8(appends[1]!.value)).toBe('second-value');
            expect(batch.operations.some((operation: KeylessQmdbOperation) => operation.kind === 'commit')).toBe(true);

            await expect(keyless.rootAt(batch.watermark)).resolves.toEqual(batch.root);
            await expect(
                keyless.operationRangeProof(
                    batch.watermark,
                    batch.startLocation,
                    batch.operations.length,
                ),
            ).resolves.toMatchObject({
                watermark: batch.watermark,
                startLocation: batch.startLocation,
                operations: batch.operations,
            });
        } finally {
            await closeIterator(stream);
            keyless.free();
        }
    });

    it('rejects tampered immutable proofs through the wasm verifier', async () => {
        const immutable = new ImmutableQmdbClient(client.store(), client.stream(), 20);
        const stream = immutable.streamBatches();

        try {
            const nextBatch = nextWithTimeout(stream, 'tampered immutable batch');

            await new Promise((resolve) => setTimeout(resolve, 100));
            const fixture = runFixture(fixturePath, baseUrl, 'tamper-immutable');

            await expect(nextBatch).rejects.toThrow(/corrupt/i);
            await expect(
                immutable.operationRangeProof(
                    BigInt(fixture.immutable_watermark),
                    BigInt(fixture.immutable_start_location),
                    2,
                ),
            ).rejects.toThrow(/corrupt/i);
        } finally {
            await closeIterator(stream);
            immutable.free();
        }
    });
});
