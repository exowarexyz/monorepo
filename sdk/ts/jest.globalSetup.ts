import { spawn } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import * as portfinder from 'portfinder';
import { buildSimulator, simulatorArgs, simulatorPath, waitForSimulator } from './test-support/simulator';

const tempDir = path.join(os.tmpdir(), 'exoware-ts-sdk-tests');
const configFile = path.join(tempDir, 'config.json');

const setup = async () => {
    if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir, { recursive: true });
    }

    console.log('Building simulator...');
    buildSimulator();

    const port = await portfinder.getPortPromise();
    const storageDir = path.join(tempDir, 'storage');
    if (!fs.existsSync(storageDir)) {
        fs.mkdirSync(storageDir, { recursive: true });
    }

    console.log(`Starting simulator on port ${port}...`);
    const simulatorProcess = spawn(simulatorPath(), simulatorArgs(port, storageDir), {
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
