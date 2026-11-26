import * as fs from 'fs';
import { sharedConfigFile as configFile, sharedTempDir as tempDir } from './__tests__/support/simulator';

const teardown = async () => {
    if (fs.existsSync(configFile)) {
        const config = JSON.parse(fs.readFileSync(configFile, 'utf-8'));
        if (config.pid) {
            try {
                console.log(`Stopping simulator with PID: ${config.pid}...`);
                process.kill(config.pid, 'SIGTERM');
                console.log('Simulator stopped.');
            } catch (e) {
                // Ignore errors if the process is already gone
            }
        }
        fs.unlinkSync(configFile);
    }

    if (fs.existsSync(tempDir)) {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
};

export default teardown;
