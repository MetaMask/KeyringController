module.exports = {
  root: true,
  extends: ['@metamask/eslint-config', '@metamask/eslint-config-commonjs'],
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
