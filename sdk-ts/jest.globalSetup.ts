import { execSync, spawn } from 'child_process';
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

const setup = async () => {
    if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir, { recursive: true });
    }

    const repoRoot = path.join(__dirname, '..');
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
    console.log('Simulator started.');

    await new Promise((resolve) => setTimeout(resolve, 2000));
};

export default setup;
