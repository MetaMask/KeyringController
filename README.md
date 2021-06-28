# Eth Keyring Controller

A module for managing groups of Ethereum accounts called "Keyrings", defined originally for MetaMask's multiple-account-type feature.

To add new account types to a `KeyringController`, just make sure it follows [The Keyring Class Protocol](./docs/keyring.md).

The KeyringController has three main responsibilities:

- Initializing & using (signing with) groups of Ethereum accounts ("keyrings").
- Keeping track of local nicknames for those individual accounts.
- Providing password-encryption persisting & restoring of secret information.

## Installation

`yarn install eth-keyring-controller --save`

## Usage

```javascript
const KeyringController = require('eth-keyring-controller');
const SimpleKeyring = require('eth-simple-keyring');

const keyringController = new KeyringController({
  keyringTypes: [SimpleKeyring], // optional array of types to support.
  initState: initState.KeyringController, // Last emitted persisted state.
  encryptor: {
    // An optional object for defining encryption schemes:
    // Defaults to Browser-native SubtleCrypto.
    encrypt(password, object) {
      return new Promise('encrypted!');
    },
    decrypt(password, encryptedString) {
      return new Promise({ foo: 'bar' });
    },
  },
});

// The KeyringController is also an event emitter:
this.keyringController.on('newAccount', (address) => {
  console.log(`New account created: ${address}`);
});
this.keyringController.on('removedAccount', handleThat);
```

## Methods

Currently the methods are heavily commented in [the source code](./index.js), so it's the best place to look until we aggregate it here as well.

## Contributing

### Setup

- Install [Node.js](https://nodejs.org) version 12
  - If you are using [nvm](https://github.com/creationix/nvm#installation) (recommended) running `nvm use` will automatically choose the right node version for you.
- Install [Yarn v1](https://yarnpkg.com/en/docs/install)
- Run `yarn setup` to install dependencies and run any requried post-install scripts
  - **Warning:** Do not use the `yarn` / `yarn install` command directly. Use `yarn setup` instead. The normal install command will skip required post-install scripts, leaving your development environment in an invalid state.

### Testing and Linting

Run `yarn test` to run the tests once.

Run `yarn lint` to run the linter, or run `yarn lint:fix` to run the linter and fix any automatically fixable issues.
