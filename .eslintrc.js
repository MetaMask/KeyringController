module.exports = {

  root: true,

  parser: 'babel-eslint',

  parserOptions: {
    'classes': true,
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
