module.exports = {
  root: true,
  extends: ['@metamask/eslint-config', '@metamask/eslint-config-mocha'],
  env: {
    commonjs: true,
  },
  overrides: [
    {
      files: ['test/**/*.js'],
      extends: ['@metamask/eslint-config-nodejs'],
    },
  ],
};
