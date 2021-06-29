module.exports = {
  collectCoverage: true,
  // Ensures that we collect coverage from all source files, not just tested
  // ones.
  collectCoverageFrom: ['./index.js'],
  coverageReporters: ['text', 'html'],
  coverageThreshold: {
    global: {
      branches: 38,
      functions: 66,
      lines: 68,
      statements: 68,
    },
  },
  moduleFileExtensions: ['js', 'json', 'jsx', 'ts', 'tsx', 'node'],
  // "resetMocks" resets all mocks, including mocked modules, to jest.fn(),
  // between each test case.
  resetMocks: true,
  // "restoreMocks" restores all mocks created using jest.spyOn to their
  // original implementations, between each test. It does not affect mocked
  // modules.
  restoreMocks: true,
  testEnvironment: 'node',
  testMatch: ['**/test/index.js'],
  testTimeout: 2500,
};
