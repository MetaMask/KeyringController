module.exports = {
  root: true,
  parserOptions: {
    ecmaVersion: 2018, // to support object rest spread, e.g. {...x, ...y}
  },
  extends: ['@metamask/eslint-config'],
  env: {
    commonjs: true,
  },
  overrides: [
    {
      files: ['test/**/*.js'],
      extends: [
        '@metamask/eslint-config-jest',
        '@metamask/eslint-config-nodejs',
      ],
    },
  ],
};
