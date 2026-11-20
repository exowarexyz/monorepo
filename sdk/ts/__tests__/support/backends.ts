import 'fake-indexeddb/auto';
import { Client } from '../../src/client';
import { deleteIndexedDbStore, openIndexedDbStore } from '../../src/indexeddb';
import { readSharedSimulatorConfig, startPrivateSimulator } from './simulator';

/** A store opened for one suite. */
export interface OpenBackend {
    client: Client;
    close(): Promise<void>;
}

/** An opened store that a suite can stop and start again. */
export interface RestartableBackend extends OpenBackend {
    /** Stops the store and starts it again on the same data. */
    reopen(): Promise<Client>;
}

/** A kind of store that the suites run against. */
export interface Backend<Opened extends OpenBackend = OpenBackend> {
    /** Label of the backend in suite titles. */
    name: string;
    /** Whether selectors accept every pattern of the Rust regex crate. */
    fullRegex: boolean;
    /** Whether Puts that queue together may commit as one batch with one sequence number. */
    mergesConcurrentPuts: boolean;
    /** Whether retention trims the log in a separate step after a Put commits. */
    trimsAfterCommit: boolean;
    /** Opens a store of this kind with a client connected to it. */
    open(): Promise<Opened>;
}

// An empty token stops the client from sending the EXOWARE_API_KEY of the developer's environment
// to a local store.
function connect(url: string): Client {
    return new Client(url, { token: '' });
}

const simulatorBehavior = {
    fullRegex: true,
    mergesConcurrentPuts: true,
    trimsAfterCommit: true,
};

/** The simulator started by jest.globalSetup, shared with every suite of the run. */
export const sharedSimulator: Backend = {
    name: 'shared simulator',
    ...simulatorBehavior,
    async open() {
        const url = `http://127.0.0.1:${readSharedSimulatorConfig().port}`;
        return { client: connect(url), close: async () => {} };
    },
};

/** A fresh simulator process and directory for each open, restarted by reopen. */
export const isolatedSimulator: Backend<RestartableBackend> = {
    name: 'isolated simulator',
    ...simulatorBehavior,
    async open() {
        const simulator = await startPrivateSimulator(readSharedSimulatorConfig().simulatorPath);
        return {
            client: connect(simulator.url),
            async reopen() {
                await simulator.restart();
                return connect(simulator.url);
            },
            close: () => simulator.close(),
        };
    },
};

let indexedDbStores = 0;

/** A fresh database name for a test, unique across the workers of a run. */
export function freshDatabaseName(): string {
    return `exoware-test-${process.pid}-${indexedDbStores++}`;
}

/** The IndexedDB store on fake-indexeddb, in a fresh database for each open. */
export const indexedDb: Backend<RestartableBackend> = {
    name: 'IndexedDB',
    fullRegex: false,
    mergesConcurrentPuts: false,
    trimsAfterCommit: false,
    async open() {
        const name = freshDatabaseName();
        let store = await openIndexedDbStore(name);
        return {
            client: new Client(store.transport),
            async reopen() {
                store.close();
                store = await openIndexedDbStore(name);
                return new Client(store.transport);
            },
            async close() {
                store.close();
                await deleteIndexedDbStore(name);
            },
        };
    },
};
