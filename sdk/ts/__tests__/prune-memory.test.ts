import type { MessageInitShape } from '@bufbuild/protobuf';
import { Code } from '@connectrpc/connect';
import { Client } from '../src/client';
import type { PolicySchema } from '../src/gen/ts/store/v1/prune_pb';
import { deleteIndexedDbStore, openIndexedDbStore, type IndexedDbStore } from '../src/indexeddb';
import { Regex } from '../src/indexeddb/regex';
import { freshDatabaseName } from './support/backends';
import { allRows, bytes, failure, put, utf8 } from './support/contract';

// A pattern of 100 named groups, each matching one byte of a 100 byte payload. A matcher that
// records all of them holds about 165 KiB, one that records 20 of them about 37 KiB, and one that
// records a single group about 7 KiB.
const GROUPS = Array.from({ length: 100 }, (_, i) => 'g' + i);
const PATTERN = '(?s-u)^' + GROUPS.map((name) => `(?P<${name}>a)`).join('') + '$';
const BUDGET = 64 * 1024;
const PREFIXES = [utf8('j/'), utf8('k/')];
const PAYLOAD = new Uint8Array(100).fill(0x61);

const policy = (prefix: Uint8Array, captureGroups: string[]): MessageInitShape<typeof PolicySchema> => ({
    keys: { selector: { prefix, payloadRegex: PATTERN }, groupBy: { captureGroups } },
    retain: { kind: { case: 'dropAll', value: {} } },
});

describe('memory of a Prune pattern', () => {
    let store: IndexedDbStore;
    let client: Client;

    beforeEach(async () => {
        store = await openIndexedDbStore(freshDatabaseName(), { maxQueryBytes: BUDGET });
        client = new Client(store.transport);
        await put(client, PREFIXES.map((prefix) => [new Uint8Array([...prefix, ...PAYLOAD]), bytes(1)]));
    });

    afterEach(async () => {
        jest.restoreAllMocks();
        store.close();
        await deleteIndexedDbStore(store.name);
    });

    const prune = (...policies: MessageInitShape<typeof PolicySchema>[]) => client.prune.prune({ policies });

    async function expectExhaustedWithoutDeletes(captureGroups: string[], message: string): Promise<void> {
        const deletes = jest.spyOn(IDBObjectStore.prototype, 'delete');
        const error = await failure(prune(policy(PREFIXES[0], captureGroups)));
        expect([error.code, error.rawMessage]).toEqual([Code.ResourceExhausted, message]);
        expect(deletes).not.toHaveBeenCalled();
        expect((await allRows(client)).rows).toHaveLength(PREFIXES.length);
    }

    it('is charged to the query budget before it is built', async () => {
        const built = jest.spyOn(Regex.prototype, 'capturer');
        expect(Regex.compile(PATTERN).capturerBytes(GROUPS)).toBeGreaterThan(BUDGET);
        await expectExhaustedWithoutDeletes(GROUPS, `prune selection exceeds the store's query memory limit of ${BUDGET} bytes`);
        expect(built).not.toHaveBeenCalled();

        // The same pattern grouped by one of its groups records only that group and fits.
        await prune(policy(PREFIXES[0], ['g0']));
        expect((await allRows(client)).rows).toHaveLength(PREFIXES.length - 1);
    });

    it('holds the matcher of one policy at a time', async () => {
        const groups = GROUPS.slice(0, 20);
        const matcherBytes = Regex.compile(PATTERN).capturerBytes(groups);
        expect(matcherBytes).toBeLessThan(BUDGET);
        expect(matcherBytes * PREFIXES.length).toBeGreaterThan(BUDGET);
        await prune(...PREFIXES.map((prefix) => policy(prefix, groups)));
        expect((await allRows(client)).rows).toHaveLength(0);
    });

    it('answers RESOURCE_EXHAUSTED when the engine cannot allocate it', async () => {
        jest.spyOn(Regex.prototype, 'capturer').mockImplementation(() => {
            throw new RangeError('Array buffer allocation failed');
        });
        await expectExhaustedWithoutDeletes(['g0'], 'prune pattern needs more memory than is available');
    });
});
