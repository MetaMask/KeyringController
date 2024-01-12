# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [16.0.0]
### Changed
- **BREAKING**: Bump `@metamask/obs-store` from `^8.1.0` to `^9.0.0` ([#306](https://github.com/MetaMask/KeyringController/pull/306))
  - The `store` and `memStore` properties now expose streams confirming to `readable-stream@^3.6.2`
- **BREAKING**: Replace `GenericEncryptor.updateVault` with `GenericEncryptor.isVaultUpdated` ([#310](https://github.com/MetaMask/KeyringController/pull/310)))
- Bump `@metamask/browser-passworder` from `^4.2.0` to `^4.3.0` ([#310](https://github.com/MetaMask/KeyringController/pull/310) [#311](https://github.com/MetaMask/KeyringController/pull/311))

### Fixed
- Prefer cached `encryptionKey` over password when possible ([#307](https://github.com/MetaMask/KeyringController/pull/307))

## [15.1.0]
### Added
- Added optional `isVaultUpdated` property to `GenericEncryptor` type ([#312](https://github.com/MetaMask/KeyringController/pull/312))

### Changed
- Bump `@metamask/browser-passworder` to `^4.3.0` ([#312](https://github.com/MetaMask/KeyringController/pull/312))

### Removed
- Removed `updateVault` optional property from `GenericEncryptor` type ([#312](https://github.com/MetaMask/KeyringController/pull/312))

### Fixed
- Improved encryption performance when the controller is constructed with `cacheEncryptionKey: true` ([#312](https://github.com/MetaMask/KeyringController/pull/312))

## [15.0.0]
### Changed
- **BREAKING** Removed `encryptor` class variable ([#293](https://github.com/MetaMask/KeyringController/pull/293))
- **BREAKING** Removed `cacheEncryptionKey` class variable ([#293](https://github.com/MetaMask/KeyringController/pull/293))
- **BREAKING** Changed `encryptor` constructor option property type to `GenericEncryptor | ExportableKeyEncryptor | undefined` ([#293](https://github.com/MetaMask/KeyringController/pull/293))
  - When the controller is instantiated with `cacheEncryptionKey = true`, the `encryptor` type is restricted to `ExportableKeyEncryptor | undefined`

## [14.0.1]
### Fixed
- Fix `removeAccount` to await the account removal in order to account for Snaps keyrings ([#280](https://github.com/MetaMask/KeyringController/pull/280))
- Bump `@metamask/eth-simple-keyring` from `^6.0.0` to `^6.0.1` ([#287](https://github.com/MetaMask/KeyringController/pull/287))

## [14.0.0]
### Changed
- **BREAKING:** Bump `@metamask/eth-sig-util` from `^6.0.0` to `^7.0.0` ([#269](https://github.com/MetaMask/KeyringController/pull/269))
- **BREAKING:** Bump `@metamask/eth-hd-keyring` from `^6.0.0` to `^7.0.1` ([#275](https://github.com/MetaMask/KeyringController/pull/275))
- **BREAKING:** Bump `@metamask/eth-simple-keyring` from `^5.0.0` to `^6.0.0` ([#273](https://github.com/MetaMask/KeyringController/pull/273))

## [13.0.1]
### Changed
- Bump `@metamask/utils` from `^6.2.0` to `^8.1.0` ([#261](https://github.com/MetaMask/KeyringController/pull/261))

## [13.0.0]
### Added
- Added `KeyringControllerPersistentState` type which includes only persistent state, an optional string property with key `vault` ([#247](https://github.com/MetaMask/KeyringController/pull/247))
- Added `KeyringObject` type for how keyrings are represented in `memStore` ([#247](https://github.com/MetaMask/KeyringController/pull/247))

### Changed
- **BREAKING**: Add types for store and fix type discrepancies ([#247](https://github.com/MetaMask/KeyringController/pull/247))
- **BREAKING**: Constructor parameter `KeyringControllerArgs` fields changed ([#247](https://github.com/MetaMask/KeyringController/pull/247)):
- **BREAKING**: type of `store` and `memStore` public properties changed ([#247](https://github.com/MetaMask/KeyringController/pull/247)):
  - `KeyringController.store` is now an `ObservableStore<KeyringControllerPersistentState>`
  - `KeyringController.memStore` is now an `ObservableStore<KeyringControllerState>`
- **BREAKING**: `updateMemStoreKeyrings` method return type changed to `Promise<void>` ([#247](https://github.com/MetaMask/KeyringController/pull/247))
- **BREAKING**: `KeyringControllerState` type changed to include only non-persistent state ([#247](https://github.com/MetaMask/KeyringController/pull/247)):
  - Now `undefined` is used instead of `null` when `encryptionKey` and `encryptionSalt` are unset
  - `keyrings` is now of type `KeyringObject[]` instead of `Keyring<Json>`
  - `password`, `store`, `memStore` have been removed - note that in practice this change only affects types
  - This changes cause the following methods also to change the return type:
    - `createNewVaultAndKeychain`
    - `createNewVaultAndRestore`
    - `setLocked`
    - `submitPassword`
    - `submitEncryptionKey`
    - `addNewAccount`
    - `removeAccount`
    - `fullUpdate`
- **BREAKING**: When constructing a simple keyring with `addNewKeyring`, the second parameter (`opts`) is now expected to be an array of private keys rather than an object with a `privateKeys` property ([#253](https://github.com/MetaMask/KeyringController/pull/253))
- Restored support for keyrings with non-object serialized state ([#253](https://github.com/MetaMask/KeyringController/pull/253))
- Narrow return type of `signTypedMessage` and encryption methods ([#249](https://github.com/MetaMask/KeyringController/pull/249))
  - The methods `signTypedMessage`, `getEncryptionPublicKey`, and `decryptMessage` now return `string` rather than `Bytes`

### Fixed
- Fix `signTypedMessage` parameter types ([#250](https://github.com/MetaMask/KeyringController/pull/250))
- Restore compatibility with QR Keyring ([#252](https://github.com/MetaMask/KeyringController/pull/252))
  - An empty object is no longer used as a default when deserialized state was not provided to the `addNewKeyring` method. This default empty object was breaking the QR keyring.


## [12.0.1]
### Fixed
- Improved error handling when calling `getKeyringForAccount` with empty or invalid address ([#238](https://github.com/MetaMask/KeyringController/pull/238))

## [12.0.0]
### Changed
- **BREAKING**: Update `@metamask/eth-sig-util` to version `^6` ([#235](https://github.com/MetaMask/KeyringController/pull/235))
  - `signPersonalMessage` now normalizes `msgParams.data` in a different way for `0` and empty strings inputs. `0` will be normalized to `0x00` and empty strings to `0x`
- **BREAKING**: Update Node.js min version to 16.0.0 ([#236](https://github.com/MetaMask/KeyringController/pull/236))
- Update `@metamask/utils` package ([#234](https://github.com/MetaMask/KeyringController/pull/234))
- Destroy keyrings on reference drop ([#233](https://github.com/MetaMask/KeyringController/pull/233))

## [11.0.0]
### Changed
- **BREAKING**: The addNewKeyring method now expects an object containing the property `privateKeys` of type `string[]` in case the supplied keyring is a "Simple Keyring". ([#202](https://github.com/MetaMask/KeyringController/pull/202)), ([#228](https://github.com/MetaMask/KeyringController/pull/228))
- Migrate the project to TypeScript ([#202](https://github.com/MetaMask/KeyringController/pull/202))
  - Methods that started with an underscore are now `#` private methods
  - Additional validation has been added to most methods
- deps: Unpin and bump @metamask/eth-sig-utils@5.0.2->^5.1.0 ([#224](https://github.com/MetaMask/KeyringController/pull/224))

## [10.0.1]
### Fixed
- Save encryption salt when `persistAllKeyrings` yields a new encryption key ([#203](https://github.com/MetaMask/KeyringController/pull/203))

## [10.0.0]
### Changed
- **BREAKING:** Update module name to use `@metamask` scope ([#187](https://github.com/MetaMask/KeyringController/pull/187))
  - Consumers will now need to import this package as `@metamask/eth-keyring-controller`
- **BREAKING:**  @metamask/eth-hd-keyring to v6.0.0 ([#193](https://github.com/MetaMask/KeyringController/pull/193))
  - Reverts the serialization format of mnemonics on HDKeyrings from `Uint8Arrays` back to an untyped array of UTF8 encoded bytes, which was the format prior to v9.0.0 of this package.

## [9.0.0] [DEPRECATED]
### Added
- Add support for keyring `init` method ([#163](https://github.com/MetaMask/KeyringController/pull/163)).
  - If a keyring has an `init` method, it will be called automatically upon construction. It is called with `await`, so it can be asynchronous.

### Changed
- **BREAKING:** Replace constructor option and public property `keyringTypes` with `keyringBuilders` ([#163](https://github.com/MetaMask/KeyringController/pull/163)).
  - The constructor now takes keyring builder functions rather than classes. Each builder function should return a keyring instance when called, and it must have a `type` string property set to the keyring type name. See the newly exported `keyringBuilderFactory` function for an example. The builder functions must be synchronous; use an `init` method for asynchronous initialization steps.
- **BREAKING:** `KeyringController` is now a named export instead of a default export ([#163](https://github.com/MetaMask/KeyringController/pull/163)).
- **BREAKING:** Update `@metamask/eth-simple-keyring` from v4 to v5 ([#171](https://github.com/MetaMask/KeyringController/pull/171)).
  - This keyring type is included as a default. If you are using this keyring API directly, see [the `@metamask/eth-simple-keyring` release notes](https://github.com/MetaMask/eth-simple-keyring/releases/tag/v5.0.0) for details on required changes.
- **BREAKING:** Replace `getKeyringClassForType` method with `getKeyringBuilderForType` ([#163](https://github.com/MetaMask/KeyringController/pull/163)).
- **BREAKING:** Update `@metamask/eth-hd-keyring` to v5 ([#177](https://github.com/MetaMask/KeyringController/pull/177))
  - This keyring type is included as a default. If you are using this keyring API directly, see [the `@metamask/eth-hd-keyring` release notes](https://github.com/MetaMask/eth-hd-keyring/releases/tag/v5.0.0) for details on required changes.
- **BREAKING:** Require support for ES2020 ([#177](https://github.com/MetaMask/KeyringController/pull/177), [#180](https://github.com/MetaMask/KeyringController/pull/180))
  - As a result of some dependency updates made in this release, this package now requires ES2020 support. If using this package in an environment that does not support ES2020 completely, consider investigating these two dependency changes and transpiling any packages using ES2020 syntax.
- Update `@metamask/eth-sig-util` to v5 ([#180](https://github.com/MetaMask/KeyringController/pull/180))
- Update minimum supported version of `@metamask/browser-passworder` from v4.0.1 to v4.0.2 ([#182](https://github.com/MetaMask/KeyringController/pull/182))
- Remove `bip39` dependency ([#179](https://github.com/MetaMask/KeyringController/pull/179))

### Fixed
- Fix support for asynchronous `addAccounts` HD Keyring method ([#176](https://github.com/MetaMask/KeyringController/pull/176))
  - This method was asynchronous, but was called synchronously. Currently the method does not do anything asynchronous so this should have no functional impact, but this ensures any future errors or asynchronous steps added to that method work correctly in the future.

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


[Unreleased]: https://github.com/MetaMask/KeyringController/compare/v16.0.0...HEAD
[16.0.0]: https://github.com/MetaMask/KeyringController/compare/v15.1.0...v16.0.0
[15.1.0]: https://github.com/MetaMask/KeyringController/compare/v15.0.0...v15.1.0
[15.0.0]: https://github.com/MetaMask/KeyringController/compare/v14.0.1...v15.0.0
[14.0.1]: https://github.com/MetaMask/KeyringController/compare/v14.0.0...v14.0.1
[14.0.0]: https://github.com/MetaMask/KeyringController/compare/v13.0.1...v14.0.0
[13.0.1]: https://github.com/MetaMask/KeyringController/compare/v13.0.0...v13.0.1
[13.0.0]: https://github.com/MetaMask/KeyringController/compare/v12.0.1...v13.0.0
[12.0.1]: https://github.com/MetaMask/KeyringController/compare/v12.0.0...v12.0.1
[12.0.0]: https://github.com/MetaMask/KeyringController/compare/v11.0.0...v12.0.0
[11.0.0]: https://github.com/MetaMask/KeyringController/compare/v10.0.1...v11.0.0
[10.0.1]: https://github.com/MetaMask/KeyringController/compare/v10.0.0...v10.0.1
[10.0.0]: https://github.com/MetaMask/KeyringController/compare/v9.0.0...v10.0.0
[9.0.0]: https://github.com/MetaMask/KeyringController/compare/v8.1.0...v9.0.0
[8.1.0]: https://github.com/MetaMask/KeyringController/compare/v8.0.1...v8.1.0
[8.0.1]: https://github.com/MetaMask/KeyringController/compare/v8.0.0...v8.0.1
[8.0.0]: https://github.com/MetaMask/KeyringController/compare/v7.0.2...v8.0.0
[7.0.2]: https://github.com/MetaMask/KeyringController/compare/v7.0.1...v7.0.2
[7.0.1]: https://github.com/MetaMask/KeyringController/compare/v7.0.0...v7.0.1
[7.0.0]: https://github.com/MetaMask/KeyringController/releases/tag/v7.0.0
