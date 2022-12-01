# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [8.1.0]
### Changed
- Allow deserializing vaults with unrecognized keyrings ([#169](https://github.com/MetaMask/KeyringController/pull/169))
  - When deserializing a vault with an unrecognized keyring, the controller will no longer crash. The unrecognized keyring vault data will be preserved in the vault for future use, but will otherwise be ignored.

## [8.0.1]
### Fixed
- Restore full state return value ([#161](https://github.com/MetaMask/KeyringController/pull/161))
  - Some methods were accidentally changed in v8.0.0 to return nothing, where previously they returned the full KeyringController state.
  - The affected methods were:
    - `createNewVaultAndKeychain`
    - `submitPassword`
    - `submitEncryptionKey`
    - `addNewAccount`
    - `removeAccount`
  - They now all return the full state, just as they did in earlier versions.

## [8.0.0] [DEPRECATED]
### Added
- Allow login with encryption key rather than password ([#152](https://github.com/MetaMask/KeyringController/pull/152))
  - This is required to support MetaMask extension builds using manifest v3.
  - This is enabled via the option `cacheEncryptionKey`.
  - The encryption key and salt have been added to the `memStore` as `encryptionKey` and `encryptionSalt`. The salt is used to verify that the key matches the vault being decrypted.
  - If the `cacheEncryptionKey` option is enabled, the encryption key and salt get cached in the `memStore` whenever the password is submitted.
  - The encryption key can be submitted with the new method `submitEncryptionKey`.
  - The `unlockKeyrings` method now accepts additional parameters for the encryption key and salt, though we don't recommend using this method directly.

### Changed
- **BREAKING:** Update minimum Node.js version to v14 ([#146](https://github.com/MetaMask/KeyringController/pull/146))
- **BREAKING:**: Remove password parameter from `persistAllKeyrings` and `createFirstKeyTree` ([#154](https://github.com/MetaMask/KeyringController/pull/154))
  - The password or encryption key must now be set already before these method are called. It is set by `createNewVaultAndKeychain`, `createNewVaultAndRestore`, and `submitPassword`/`submitEncryptionKey`.
  - This change was made to reduce redundant state changes.

### Fixed
- Fix a typo in the duplicate account import error ([#153](https://github.com/MetaMask/KeyringController/pull/153))

## [7.0.2]
### Fixed
- `createNewVaultAndRestore` now accepts a seedphrase formatted as an array of numbers ([#138](https://github.com/MetaMask/KeyringController/pull/138))

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


[Unreleased]: https://github.com/MetaMask/KeyringController/compare/v8.1.0...HEAD
[8.1.0]: https://github.com/MetaMask/KeyringController/compare/v8.0.1...v8.1.0
[8.0.1]: https://github.com/MetaMask/KeyringController/compare/v8.0.0...v8.0.1
[8.0.0]: https://github.com/MetaMask/KeyringController/compare/v7.0.2...v8.0.0
[7.0.2]: https://github.com/MetaMask/KeyringController/compare/v7.0.1...v7.0.2
[7.0.1]: https://github.com/MetaMask/KeyringController/compare/v7.0.0...v7.0.1
[7.0.0]: https://github.com/MetaMask/KeyringController/releases/tag/v7.0.0
