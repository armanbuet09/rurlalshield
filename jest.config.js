module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/test'],
  testMatch: ['**/*.test.ts'],
  moduleFileExtensions: ['ts', 'tsx', 'js', 'json', 'node'],
  transform: { '^.+\\.tsx?$': 'ts-jest' },
  testTimeout: 120000,
};
