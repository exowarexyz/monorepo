import { execSync, spawn } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import * as portfinder from 'portfinder';
import ws from 'ws';

Object.assign(global, { WebSocket: ws });

const tempDir = path.join(os.tmpdir(), 'exoware-ts-sdk-tests');
const configFile = path.join(tempDir, 'config.json');

const randomString = () => Math.random().toString(36).substring(7);

const setup = async () => {
    if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir, { recursive: true });
    }

    console.log('Building simulator...');
    execSync('cargo build --package exoware-simulator', { stdio: 'inherit', cwd: path.join(__dirname, '..') });

    const port = await portfinder.getPortPromise();
    const token = randomString();
    const storageDir = path.join(tempDir, 'storage');
    if (!fs.existsSync(storageDir)) {
        fs.mkdirSync(storageDir, { recursive: true });
    }

    const simulatorPath = path.join(__dirname, '..', 'target', 'debug', 'simulator');
    const args = [
        '--verbose',
        'server',
        'run',
        '--port', port.toString(),
        '--token', token,
        '--directory', storageDir,
        '--consistency-bound-min', '0',
        '--consistency-bound-max', '0',
    ];

    console.log(`Starting simulator on port ${port}...`);
    const simulatorProcess = spawn(simulatorPath, args, {
        detached: true,
        stdio: 'ignore',
    });
    simulatorProcess.unref();

    const config = {
        port,
        token,
        pid: simulatorProcess.pid,
    };

    fs.writeFileSync(configFile, JSON.stringify(config));
    console.log('Simulator started.');

    // A small delay to allow the server to fully start
    await new Promise(resolve => setTimeout(resolve, 2000));
};

export default setup;