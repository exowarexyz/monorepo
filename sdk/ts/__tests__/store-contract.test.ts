import type { Client } from '../src/client';
import { ReadSession } from '../src/store';
import { isolatedSimulator, type Backend, type RestartableBackend } from './support/backends';

const backends: Backend<RestartableBackend>[] = [isolatedSimulator];

const encoder = new TextEncoder();

describe.each(backends)('store contract on $name', (backend) => {
    let store: RestartableBackend;
    let client: Client;

    beforeEach(async () => {
        store = await backend.open();
        client = store.client;
    });

    afterEach(async () => {
        await store.close();
    });

    describe('sequence numbers', () => {
        it('numbers sequential Puts from 1 on a fresh store', async () => {
            const writer = client.store();
            for (const expected of [1n, 2n, 3n]) {
                await expect(
                    writer.set(encoder.encode(`key-${expected}`), encoder.encode('value')),
                ).resolves.toBe(expected);
            }
        });

        it('keeps the sequence number, rows and the next number across reopen', async () => {
            const key = encoder.encode('durable');
            const value = encoder.encode('kept');
            const writer = client.store();
            await writer.set(encoder.encode('first'), encoder.encode('1'));
            await expect(writer.set(key, value)).resolves.toBe(2n);

            const reopened = (await store.reopen()).store();
            const session = ReadSession.monotonic(reopened);
            await expect(session.get(key)).resolves.toMatchObject({ value });
            expect(session.evaluatedSequence()).toBe(2n);
            await expect(reopened.set(encoder.encode('next'), value)).resolves.toBe(3n);
        });
    });
});
