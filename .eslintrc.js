module.exports = {
  root: true,
  extends: ['@metamask/eslint-config'],
  env: {
    commonjs: true,
  },
  overrides: [
    {
      files: ['test/**/*.js'],
      extends: ['@metamask/eslint-config-mocha', '@metamask/eslint-config-nodejs'],
    },
  ],
};
