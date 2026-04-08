/** @type {import('jest').Config} */
module.exports = {
    preset: 'ts-jest',
    testEnvironment: 'node',
    globalSetup: '<rootDir>/jest.globalSetup.ts',
    globalTeardown: '<rootDir>/jest.globalTeardown.ts',
    testTimeout: 60000,
    moduleNameMapper: {
        '^(\\.{1,2}/.*)\\.js$': '$1',
    },
};
