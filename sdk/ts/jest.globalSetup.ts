import { execSync, spawn, type ChildProcess } from 'child_process';
import { createConnection } from 'net';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import * as portfinder from 'portfinder';

const tempDir = path.join(os.tmpdir(), 'exoware-ts-sdk-tests');
const configFile = path.join(tempDir, 'config.json');

function cargoTargetDir(repoRoot: string): string {
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

async function waitForSimulator(port: number, simulatorProcess: ChildProcess): Promise<void> {
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

const setup = async () => {
    if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir, { recursive: true });
    }

    const repoRoot = path.join(__dirname, '..', '..');
    console.log('Building simulator...');
    execSync('cargo build --package exoware-simulator', { stdio: 'inherit', cwd: repoRoot });

    const port = await portfinder.getPortPromise();
    const storageDir = path.join(tempDir, 'storage');
    if (!fs.existsSync(storageDir)) {
        fs.mkdirSync(storageDir, { recursive: true });
    }

    const simulatorPath = path.join(cargoTargetDir(repoRoot), 'debug', 'simulator');
    const args = ['--verbose', 'server', 'run', '--port', port.toString(), '--directory', storageDir];

    console.log(`Starting simulator on port ${port}...`);
    const simulatorProcess = spawn(simulatorPath, args, {
        detached: true,
        stdio: 'ignore',
    });
    simulatorProcess.unref();

    const config = {
        port,
        pid: simulatorProcess.pid,
    };

    fs.writeFileSync(configFile, JSON.stringify(config));
    await waitForSimulator(port, simulatorProcess);
    console.log('Simulator started.');
};

export default setup;
