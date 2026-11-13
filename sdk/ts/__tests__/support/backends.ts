import { Client } from '../../src/client';
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
    /** Opens a store of this kind with a client connected to it. */
    open(): Promise<Opened>;
}

// An empty token stops the client from sending the EXOWARE_API_KEY of the developer's environment
// to a local store.
function connect(url: string): Client {
    return new Client(url, { token: '' });
}

/** The simulator started by jest.globalSetup, shared with every suite of the run. */
export const sharedSimulator: Backend = {
    name: 'shared simulator',
    async open() {
        const url = `http://127.0.0.1:${readSharedSimulatorConfig().port}`;
        return { client: connect(url), close: async () => {} };
    },
};

/** A fresh simulator process and directory for each open, restarted by reopen. */
export const isolatedSimulator: Backend<RestartableBackend> = {
    name: 'isolated simulator',
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
