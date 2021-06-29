import { strict as assert } from 'assert';
import sigUtil from 'eth-sig-util';

import sinon from 'sinon';
import Wallet from 'ethereumjs-wallet';

import KeyringController from '../src';
import mockEncryptor from './lib/mock-encryptor';

const normalizeAddress = sigUtil.normalize;

const mockAddress = '0xeF35cA8EbB9669A35c31b5F6f249A9941a812AC1'.toLowerCase();

describe('KeyringController', function () {
  let keyringController;
  const password = 'password123';
  const seedWords =
    'puzzle seed penalty soldier say clay field arctic metal hen cage runway';
  const addresses = [mockAddress];

  beforeEach(async function () {
    keyringController = new KeyringController({
      encryptor: mockEncryptor,
    });

    await keyringController.createNewVaultAndKeychain(password);
  });

  afterEach(function () {
    sinon.restore();
  });

  describe('setLocked', function () {
    it('setLocked correctly sets lock state', async function () {
      assert.notDeepEqual(
        keyringController.keyrings,
        [],
        'keyrings should not be empty',
      );

      await keyringController.setLocked();

      expect(keyringController.password).toBeNull();
      expect(keyringController.memStore.getState().isUnlocked).toBe(false);
      expect(keyringController.keyrings).toHaveLength(0);
    });

    it('emits "lock" event', async function () {
      const spy = sinon.spy();
      keyringController.on('lock', spy);

      await keyringController.setLocked();

      expect(spy.calledOnce).toBe(true);
    });
  });

  describe('submitPassword', function () {
    it('should not create new keyrings when called in series', async function () {
      await keyringController.createNewVaultAndKeychain(password);
      await keyringController.persistAllKeyrings();
      expect(keyringController.keyrings).toHaveLength(1);

      await keyringController.submitPassword(`${password}a`);
      expect(keyringController.keyrings).toHaveLength(1);

      await keyringController.submitPassword('');
      expect(keyringController.keyrings).toHaveLength(1);
    });

    it('emits "unlock" event', async function () {
      await keyringController.setLocked();

      const spy = sinon.spy();
      keyringController.on('unlock', spy);

      await keyringController.submitPassword(password);
      expect(spy.calledOnce).toBe(true);
    });
  });

  describe('createNewVaultAndKeychain', function () {
    it('should set a vault on the configManager', async function () {
      keyringController.store.updateState({ vault: null });
      assert(!keyringController.store.getState().vault, 'no previous vault');

      await keyringController.createNewVaultAndKeychain(password);
      const { vault } = keyringController.store.getState();
      // eslint-disable-next-line jest/no-restricted-matchers
      expect(vault).toBeTruthy();
    });

    it('should encrypt keyrings with the correct password each time they are persisted', async function () {
      keyringController.store.updateState({ vault: null });
      assert(!keyringController.store.getState().vault, 'no previous vault');

      await keyringController.createNewVaultAndKeychain(password);
      const { vault } = keyringController.store.getState();
      // eslint-disable-next-line jest/no-restricted-matchers
      expect(vault).toBeTruthy();
      keyringController.encryptor.encrypt.args.forEach(([actualPassword]) => {
        expect(actualPassword).toBe(password);
      });
    });
  });

  describe('addNewKeyring', function () {
    it('should add simple key pair', async function () {
      const privateKey =
        'c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3';
      const previousAccounts = await keyringController.getAccounts();
      const keyring = await keyringController.addNewKeyring('Simple Key Pair', [
        privateKey,
      ]);
      const keyringAccounts = await keyring.getAccounts();
      const expectedKeyringAccounts = [
        '0x627306090abab3a6e1400e9345bc60c78a8bef57',
      ];
      expect(keyringAccounts).toStrictEqual(expectedKeyringAccounts);

      const allAccounts = await keyringController.getAccounts();
      const expectedAllAccounts = previousAccounts.concat(
        expectedKeyringAccounts,
      );
      expect(allAccounts).toStrictEqual(expectedAllAccounts);
    });
  });

  describe('restoreKeyring', function () {
    it(`should pass a keyring's serialized data back to the correct type.`, async function () {
      const mockSerialized = {
        type: 'HD Key Tree',
        data: {
          mnemonic: seedWords,
          numberOfAccounts: 1,
        },
      };

      const keyring = await keyringController.restoreKeyring(mockSerialized);
      expect(keyring.wallets).toHaveLength(1);

      const accounts = await keyring.getAccounts();
      expect(accounts[0]).toBe(addresses[0]);
    });
  });

  describe('getAccounts', function () {
    it('returns the result of getAccounts for each keyring', async function () {
      keyringController.keyrings = [
        {
          getAccounts() {
            return Promise.resolve([1, 2, 3]);
          },
        },
        {
          getAccounts() {
            return Promise.resolve([4, 5, 6]);
          },
        },
      ];

      const result = await keyringController.getAccounts();
      expect(result).toStrictEqual([
        '0x01',
        '0x02',
        '0x03',
        '0x04',
        '0x05',
        '0x06',
      ]);
    });
  });

  describe('removeAccount', function () {
    it('removes an account from the corresponding keyring', async function () {
      const account = {
        privateKey:
          'c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3',
        publicKey: '0x627306090abab3a6e1400e9345bc60c78a8bef57',
      };

      const accountsBeforeAdding = await keyringController.getAccounts();

      // Add a new keyring with one account
      await keyringController.addNewKeyring('Simple Key Pair', [
        account.privateKey,
      ]);

      // remove that account that we just added
      await keyringController.removeAccount(account.publicKey);

      // fetch accounts after removal
      const result = await keyringController.getAccounts();
      expect(result).toStrictEqual(accountsBeforeAdding);
    });

    it('removes the keyring if there are no accounts after removal', async function () {
      const account = {
        privateKey:
          'c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3',
        publicKey: '0x627306090abab3a6e1400e9345bc60c78a8bef57',
      };

      // Add a new keyring with one account
      await keyringController.addNewKeyring('Simple Key Pair', [
        account.privateKey,
      ]);

      // We should have 2 keyrings
      expect(keyringController.keyrings).toHaveLength(2);

      // remove that account that we just added
      await keyringController.removeAccount(account.publicKey);

      // Check that the previous keyring with only one account
      // was also removed after removing the account
      expect(keyringController.keyrings).toHaveLength(1);
    });
  });

  describe('unlockKeyrings', function () {
    it('returns the list of keyrings', async function () {
      await keyringController.setLocked();
      const keyrings = await keyringController.unlockKeyrings(password);
      expect(keyrings).toHaveLength(1);
      keyrings.forEach((keyring) => {
        expect(keyring.wallets).toHaveLength(1);
      });
    });
  });

  describe('getAppKeyAddress', function () {
    it('returns the expected app key address', async function () {
      const address = '0x01560cd3bac62cc6d7e6380600d9317363400896';
      const privateKey =
        '0xb8a9c05beeedb25df85f8d641538cbffedf67216048de9c678ee26260eb91952';

      const keyring = await keyringController.addNewKeyring('Simple Key Pair', [
        privateKey,
      ]);
      keyring.getAppKeyAddress = sinon.spy();
      /* eslint-disable-next-line require-atomic-updates */
      keyringController.getKeyringForAccount = sinon
        .stub()
        .returns(Promise.resolve(keyring));

      await keyringController.getAppKeyAddress(address, 'someapp.origin.io');

      expect(keyringController.getKeyringForAccount.calledOnce).toBe(true);
      expect(keyringController.getKeyringForAccount.getCall(0).args[0]).toBe(
        normalizeAddress(address),
      );
      expect(keyring.getAppKeyAddress.calledOnce).toBe(true);
      expect(keyring.getAppKeyAddress.getCall(0).args).toStrictEqual([
        normalizeAddress(address),
        'someapp.origin.io',
      ]);
    });
  });

  describe('exportAppKeyForAddress', function () {
    it('returns a unique key', async function () {
      const address = '0x01560cd3bac62cc6d7e6380600d9317363400896';
      const privateKey =
        '0xb8a9c05beeedb25df85f8d641538cbffedf67216048de9c678ee26260eb91952';
      await keyringController.addNewKeyring('Simple Key Pair', [privateKey]);
      const appKeyAddress = await keyringController.getAppKeyAddress(
        address,
        'someapp.origin.io',
      );

      const privateAppKey = await keyringController.exportAppKeyForAddress(
        address,
        'someapp.origin.io',
      );

      const wallet = Wallet.fromPrivateKey(Buffer.from(privateAppKey, 'hex'));
      const recoveredAddress = `0x${wallet.getAddress().toString('hex')}`;

      expect(recoveredAddress).toBe(appKeyAddress);
      expect(privateAppKey).not.toBe(privateKey);
    });
  });
});
