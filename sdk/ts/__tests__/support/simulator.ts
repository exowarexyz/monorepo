import { spawn, type ChildProcess } from 'child_process';
import * as fs from 'fs';
import { createConnection, createServer } from 'net';
import * as os from 'os';
import * as path from 'path';

/** Directory that holds the config file and storage of the simulator jest.globalSetup starts. */
export const sharedTempDir = path.join(os.tmpdir(), 'exoware-ts-sdk-tests');

/** File in which jest.globalSetup records the shared simulator's port, process and binary. */
export const sharedConfigFile = path.join(sharedTempDir, 'config.json');

/** What jest.globalSetup records about the shared simulator. */
export interface SharedSimulatorConfig {
    port: number;
    pid?: number;
    simulatorPath: string;
}

export function readSharedSimulatorConfig(): SharedSimulatorConfig {
    return JSON.parse(fs.readFileSync(sharedConfigFile, 'utf-8')) as SharedSimulatorConfig;
}

export async function waitForSimulator(port: number, simulatorProcess: ChildProcess): Promise<void> {
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
        if (simulatorProcess.exitCode !== null || simulatorProcess.signalCode !== null) {
            throw new Error('Simulator exited before accepting connections');
        }
        const ready = await new Promise<boolean>((resolve) => {
            const socket = createConnection({ host: '127.0.0.1', port });
            const finish = (connected: boolean) => {
                socket.destroy();
                resolve(connected);
            };
            socket.once('connect', () => finish(true));
            socket.once('error', () => finish(false));
            socket.setTimeout(1000, () => finish(false));
        });
        if (ready) {
            return;
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
    }
    simulatorProcess.kill('SIGTERM');
    throw new Error('Simulator did not start listening within 30 seconds');
}

/** A simulator process owned by one suite, with its own port and storage directory. */
export interface PrivateSimulator {
    /** Base URL that clients of this simulator connect to. */
    url: string;
    /** Stops the process and starts a new one on the same port and directory. */
    restart(): Promise<void>;
    /** Stops the process and removes its directory. */
    close(): Promise<void>;
}

// A port that the operating system reports as unused, so simulators of parallel workers start
// on different ports.
function freePort(): Promise<number> {
    return new Promise((resolve, reject) => {
        const server = createServer();
        server.once('error', reject);
        server.listen(0, '127.0.0.1', () => {
            const { port } = server.address() as { port: number };
            server.close(() => resolve(port));
        });
    });
}

async function launch(simulatorPath: string, port: number, directory: string): Promise<ChildProcess> {
    const child = spawn(
        simulatorPath,
        ['server', 'run', '--port', port.toString(), '--directory', directory],
        { stdio: 'ignore' },
    );
    await waitForSimulator(port, child);
    return child;
}

function stop(child: ChildProcess): Promise<void> {
    if (child.exitCode !== null || child.signalCode !== null) {
        return Promise.resolve();
    }
    return new Promise((resolve) => {
        child.once('exit', () => resolve());
        process.kill(child.pid!, 'SIGTERM');
    });
}

export async function startPrivateSimulator(simulatorPath: string): Promise<PrivateSimulator> {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'exoware-ts-sdk-private-'));
    const remove = () => fs.rmSync(directory, { recursive: true, force: true });
    let port: number;
    let child: ChildProcess;
    try {
        port = await freePort();
        child = await launch(simulatorPath, port, directory);
    } catch (e) {
        remove();
        throw e;
    }
    return {
        url: `http://127.0.0.1:${port}`,
        async restart() {
            await stop(child);
            child = await launch(simulatorPath, port, directory);
        },
        async close() {
            await stop(child);
            remove();
        },
    };
}
