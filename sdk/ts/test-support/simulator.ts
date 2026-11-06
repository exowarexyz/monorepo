import { execSync, spawn, type ChildProcess } from 'child_process';
import { createConnection } from 'net';
import * as path from 'path';

const repoRoot = path.join(__dirname, '..', '..', '..');

function cargoTargetDir(): string {
    if (process.env.CARGO_TARGET_DIR) {
        return process.env.CARGO_TARGET_DIR;
    }
    try {
        const meta = JSON.parse(
            execSync('cargo metadata --format-version 1 --no-deps', {
                cwd: repoRoot,
                encoding: 'utf-8',
            }),
        ) as { target_directory: string };
        return meta.target_directory;
    } catch {
        return path.join(repoRoot, 'target');
    }
}

export function buildSimulator(): void {
    execSync('cargo build --package exoware-simulator', { stdio: 'inherit', cwd: repoRoot });
}

export function simulatorPath(): string {
    return path.join(cargoTargetDir(), 'debug', 'simulator');
}

function exited(child: ChildProcess): boolean {
    return child.exitCode !== null || child.signalCode !== null;
}

export async function waitForSimulator(port: number, child: ChildProcess): Promise<void> {
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
        if (exited(child)) {
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
    child.kill('SIGTERM');
    throw new Error('Simulator did not start listening within 30 seconds');
}

export function simulatorArgs(port: number, directory: string, extra: string[] = []): string[] {
    return ['--verbose', 'server', 'run', '--port', port.toString(), '--directory', directory, ...extra];
}

/** A simulator owned by one test, so it can be stopped and restarted on the same port and data. */
export class Simulator {
    private child: ChildProcess | undefined;

    constructor(
        public readonly port: number,
        private readonly directory: string,
        private readonly extra: string[] = [],
    ) {}

    get url(): string {
        return `http://127.0.0.1:${this.port}`;
    }

    async start(): Promise<void> {
        const child = spawn(simulatorPath(), simulatorArgs(this.port, this.directory, this.extra), {
            stdio: 'ignore',
        });
        this.child = child;
        await waitForSimulator(this.port, child);
    }

    async stop(signal: NodeJS.Signals = 'SIGTERM'): Promise<void> {
        const child = this.child;
        this.child = undefined;
        if (child === undefined || exited(child)) return;

        const done = new Promise<void>((resolve) => child.once('exit', () => resolve()));
        child.kill(signal);

        // A graceful stop that hangs would hold the port, so escalate after a grace period.
        const timer = setTimeout(() => child.kill('SIGKILL'), 10_000);
        await done;
        clearTimeout(timer);
    }
}
