module.exports = {
  root: true,
  extends: ['@metamask/eslint-config'],
  globals: {
    window: 'readonly',
  },
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
