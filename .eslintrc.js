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

  overrides: [{
    files: [
      '.eslintrc.js',
    ],
    parserOptions: {
      sourceType: 'script',
    },
  }],
}
