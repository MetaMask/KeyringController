module.exports = {

  root: true,

  parserOptions: {
    'ecmaVersion': 2017,
  },

  extends: [
    '@metamask/eslint-config',
    '@metamask/eslint-config/config/nodejs',
    '@metamask/eslint-config/config/mocha',
  ],

  plugins: [
    'json',
  ],

  globals: {
    'window': true,
  },

  overrides: [{
    files: [
      '.eslintrc.js',
    ],
    parserOptions: {
      sourceType: 'script',
    },
  }],
}
