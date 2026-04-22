import { execSync, spawn } from 'child_process';
import * as net from 'net';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';

const tempDir = path.join(os.tmpdir(), 'exoware-ts-sdk-tests');
const configFile = path.join(tempDir, 'config.json');

async function findOpenPort(host: string = '127.0.0.1'): Promise<number> {
    return await new Promise((resolve, reject) => {
        const server = net.createServer();
        server.unref();
        server.on('error', reject);
        server.listen(0, host, () => {
            const address = server.address();
            if (address && typeof address === 'object') {
                const { port } = address;
                server.close((err) => {
                    if (err) {
                        reject(err);
                        return;
                    }
                    resolve(port);
                });
                return;
            }
            server.close();
            reject(new Error('unable to allocate test port'));
        });
    });
}

async function waitForPort(host: string, port: number, timeoutMs: number): Promise<void> {
    const started = Date.now();
    while ((Date.now() - started) < timeoutMs) {
        const connected = await new Promise<boolean>((resolve) => {
            const socket = net.createConnection({ host, port });
            socket.once('connect', () => {
                socket.destroy();
                resolve(true);
            });
            socket.once('error', () => {
                socket.destroy();
                resolve(false);
            });
        });
        if (connected) {
            return;
        }
        await new Promise((resolve) => setTimeout(resolve, 250));
    }
    throw new Error(`simulator did not start listening on ${host}:${port} within ${timeoutMs}ms`);
}

const setup = async () => {
    if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir, { recursive: true });
    }

    const repoRoot = path.join(__dirname, '..');
    const cargoTargetDir = path.join(tempDir, 'cargo-target');
    const cargoEnv = {
        ...process.env,
        CARGO_TARGET_DIR: cargoTargetDir,
    };

    console.log('Building simulator...');
    execSync('cargo build --package exoware-simulator', {
        stdio: 'inherit',
        cwd: repoRoot,
        env: cargoEnv,
    });
    console.log('Building qmdb-web node wasm package...');
    execSync('wasm-pack build qmdb/web --target nodejs --out-dir pkg-node', {
        stdio: 'inherit',
        cwd: repoRoot,
        env: cargoEnv,
    });
    console.log('Building qmdb-web fixture...');
    execSync('cargo build -p exoware-qmdb --features test-utils --example qmdb_web_fixture', {
        stdio: 'inherit',
        cwd: repoRoot,
        env: cargoEnv,
    });

    const port = await findOpenPort();
    const storageDir = path.join(tempDir, 'storage');
    fs.rmSync(storageDir, { recursive: true, force: true });
    fs.mkdirSync(storageDir, { recursive: true });

    const simulatorPath = path.join(cargoTargetDir, 'debug', 'simulator');
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
        cargoTargetDir,
    };

    fs.writeFileSync(configFile, JSON.stringify(config));
    console.log('Simulator started.');

    await waitForPort('127.0.0.1', port, 10000);
};

export default setup;
