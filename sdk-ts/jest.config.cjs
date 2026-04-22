/** @type {import('jest').Config} */
module.exports = {
    preset: 'ts-jest/presets/default-esm',
    testEnvironment: 'node',
    extensionsToTreatAsEsm: ['.ts'],
    globalSetup: '<rootDir>/jest.globalSetup.ts',
    globalTeardown: '<rootDir>/jest.globalTeardown.ts',
    testTimeout: 60000,
    transform: {
        '^.+\\.tsx?$': ['ts-jest', {
            useESM: true,
            tsconfig: '<rootDir>/tsconfig.jest.json',
            diagnostics: {
                ignoreCodes: [1343],
            },
        }],
    },
    moduleNameMapper: {
        '^exoware-sdk-ts$': '<rootDir>/src/index.ts',
        '^(\\.{1,2}/.*)\\.js$': '$1',
    },
};
