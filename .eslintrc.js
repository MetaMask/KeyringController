module.exports = {
  root: true,
  extends: ['@metamask/eslint-config'],
  env: {
    commonjs: true,
  },
  overrides: [
    {
      files: ['test/**/*.ts'],
      extends: [
        '@metamask/eslint-config-jest',
        '@metamask/eslint-config-nodejs',
      ],
    },
    {
      files: ['*.ts'],
      extends: ['@metamask/eslint-config-typescript'],
    },
  ],
};
