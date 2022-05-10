# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [7.0.2]
### Uncategorized
- Patch KeyringController to accept seedphrases passed as buffers/arrays of numbers ([#138](https://github.com/MetaMask/KeyringController/pull/138))
- 7.0.1 ([#137](https://github.com/MetaMask/KeyringController/pull/137))
- Bump ajv from 6.12.0 to 6.12.6 ([#133](https://github.com/MetaMask/KeyringController/pull/133))
- 7.0.0 ([#135](https://github.com/MetaMask/KeyringController/pull/135))
- Create create-release-pr.yml ([#134](https://github.com/MetaMask/KeyringController/pull/134))
- Bump minimist from 1.2.5 to 1.2.6 ([#131](https://github.com/MetaMask/KeyringController/pull/131))
- docs: typo ([#126](https://github.com/MetaMask/KeyringController/pull/126))
- Refactor getKeyringForAccount error flow ([#125](https://github.com/MetaMask/KeyringController/pull/125))
- Bump tmpl from 1.0.4 to 1.0.5 ([#123](https://github.com/MetaMask/KeyringController/pull/123))
- Bump tar from 6.1.5 to 6.1.11 ([#122](https://github.com/MetaMask/KeyringController/pull/122))
- Bump path-parse from 1.0.6 to 1.0.7 ([#120](https://github.com/MetaMask/KeyringController/pull/120))
- Bump tar from 6.1.0 to 6.1.5 ([#119](https://github.com/MetaMask/KeyringController/pull/119))
- Bump @metamask/auto-changelog from 2.4.0 to 2.5.0 ([#118](https://github.com/MetaMask/KeyringController/pull/118))
- Switch from mocha to Jest ([#114](https://github.com/MetaMask/KeyringController/pull/114))
- Bump @metamask/eslint-config from 6.0.0 to 7.0.1 ([#115](https://github.com/MetaMask/KeyringController/pull/115))
- Add `prettier-plugin-packagejson` ([#113](https://github.com/MetaMask/KeyringController/pull/113))
- Migrate from CircleCI to GitHub Actions ([#110](https://github.com/MetaMask/KeyringController/pull/110))
- Bump @metamask/auto-changelog from 2.3.0 to 2.4.0 ([#112](https://github.com/MetaMask/KeyringController/pull/112))
- Add changelog ([#108](https://github.com/MetaMask/KeyringController/pull/108))
- Update ESLint config and dependencies ([#107](https://github.com/MetaMask/KeyringController/pull/107))
- Remove `bluebird` ([#104](https://github.com/MetaMask/KeyringController/pull/104))
- Remove browser-related test dependencies ([#103](https://github.com/MetaMask/KeyringController/pull/103))
- Update `bip39` from v2.4 to v3.0.4 ([#102](https://github.com/MetaMask/KeyringController/pull/102))
- Update `ethereumjs-wallet` to v1.0.1 ([#105](https://github.com/MetaMask/KeyringController/pull/105))
- Update `sinon` to the latest version ([#106](https://github.com/MetaMask/KeyringController/pull/106))
- Remove unused `sinon` sandbox ([#101](https://github.com/MetaMask/KeyringController/pull/101))
- Update `mocha` from v7 to v9 ([#100](https://github.com/MetaMask/KeyringController/pull/100))
- Remove `ethereumjs-util` dependency ([#96](https://github.com/MetaMask/KeyringController/pull/96))
- Remove `loglevel` dependency ([#99](https://github.com/MetaMask/KeyringController/pull/99))
- Remove unused `@babel/core` dependency ([#98](https://github.com/MetaMask/KeyringController/pull/98))
- Remove unused test files ([#97](https://github.com/MetaMask/KeyringController/pull/97))
- Remove unused `addGasBuffer` method ([#95](https://github.com/MetaMask/KeyringController/pull/95))
- Bump ws from 5.2.2 to 5.2.3 ([#94](https://github.com/MetaMask/KeyringController/pull/94))
- Bump glob-parent from 5.1.0 to 5.1.2 ([#93](https://github.com/MetaMask/KeyringController/pull/93))
- Bump hosted-git-info from 2.8.8 to 2.8.9 ([#92](https://github.com/MetaMask/KeyringController/pull/92))
- Bump lodash from 4.17.19 to 4.17.21 ([#91](https://github.com/MetaMask/KeyringController/pull/91))

## [7.0.1]
### Fixed
- Fix breaking change in `addNewKeyring` function that was accidentally introduced in v7.0.0 ([#136](https://github.com/MetaMask/KeyringController/pull/136))
  - We updated the method such that keyrings were always constructed with constructor arguments, defaulting to an empty object if none were provided. But some keyrings ([such as the QR Keyring](https://github.com/KeystoneHQ/keystone-airgaped-base/blob/c5e2d06892118265ec2ee613b543095276d5b208/packages/base-eth-keyring/src/BaseKeyring.ts#L290)) relied upon the options being undefined in some cases.

## [7.0.0]
### Added
- Add forget Keyring method for some hardware devices ([#124](https://github.com/MetaMask/KeyringController/pull/124))
- Add `@lavamoat/allow-scripts` ([#109](https://github.com/MetaMask/KeyringController/pull/109))

### Changed
- **BREAKING**: Bump eth-hd-keyring to latest version ([#132](https://github.com/MetaMask/KeyringController/pull/132))
    - When calling the `addNewKeyring` method, an options object can no longer be passed containing a `numberOfAccounts` property without also including a `mnemonic`. Not adding any option argument will result in the generation of a new mnemonic and the addition of 1 account derived from that mnemonic to the keyring.
- When calling `createNewVaultAndKeychain` all keyrings are cleared first thing ([#129](https://github.com/MetaMask/KeyringController/pull/129))
- Validate user imported seedphrase across all bip39 wordlists ([#77](https://github.com/MetaMask/KeyringController/pull/77))


[Unreleased]: https://github.com/MetaMask/KeyringController/compare/v7.0.2...HEAD
[7.0.2]: https://github.com/MetaMask/KeyringController/compare/v7.0.1...v7.0.2
[7.0.1]: https://github.com/MetaMask/KeyringController/compare/v7.0.0...v7.0.1
[7.0.0]: https://github.com/MetaMask/KeyringController/releases/tag/v7.0.0
