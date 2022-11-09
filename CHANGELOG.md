# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [8.0.0]
### Uncategorized
- Update GitHub actions to match module template ([#158](https://github.com/MetaMask/KeyringController/pull/158))
- Bump @metamask/eth-sig-util from 4.0.0 to 4.0.1 ([#159](https://github.com/MetaMask/KeyringController/pull/159))
- Migrate to Yarn v3 ([#157](https://github.com/MetaMask/KeyringController/pull/157))
- Keep User Logged In: Export key for encrypted key login ([#152](https://github.com/MetaMask/KeyringController/pull/152))
- Bump @metamask/auto-changelog from 2.5.0 to 3.0.0 ([#156](https://github.com/MetaMask/KeyringController/pull/156))
- Set password sooner to avoid redundant persistance ([#154](https://github.com/MetaMask/KeyringController/pull/154))
- Ensure newly created vaults are unlocked ([#155](https://github.com/MetaMask/KeyringController/pull/155))
- Fixed a typo in the duplicate account import error ([#153](https://github.com/MetaMask/KeyringController/pull/153))
- README cleanup ([#151](https://github.com/MetaMask/KeyringController/pull/151))
- Use async/await instead of then ([#148](https://github.com/MetaMask/KeyringController/pull/148))
- Bump Node to v14 ([#146](https://github.com/MetaMask/KeyringController/pull/146))
- Updated Readme ([#143](https://github.com/MetaMask/KeyringController/pull/143))

### Changed
- **BREAKING:** Removed support for Node v12 in favor of v14 ([#137](https://github.com/MetaMask/eth-json-rpc-middleware/pull/137))

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


[Unreleased]: https://github.com/MetaMask/KeyringController/compare/v8.0.0...HEAD
[8.0.0]: https://github.com/MetaMask/KeyringController/compare/v7.0.2...v8.0.0
[7.0.2]: https://github.com/MetaMask/KeyringController/compare/v7.0.1...v7.0.2
[7.0.1]: https://github.com/MetaMask/KeyringController/compare/v7.0.0...v7.0.1
[7.0.0]: https://github.com/MetaMask/KeyringController/releases/tag/v7.0.0
