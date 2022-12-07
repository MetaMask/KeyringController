const { strict: assert } = require('assert');
const sigUtil = require('eth-sig-util');

const normalizeAddress = sigUtil.normalize;
const sinon = require('sinon');
const Wallet = require('ethereumjs-wallet').default;

const { KeyringController, keyringBuilderFactory } = require('..');
const { KeyringMockWithInit } = require('./lib/mock-keyring');
const mockEncryptor = require('./lib/mock-encryptor');

const password = 'password123';

const MOCK_ENCRYPTION_KEY =
  '{"alg":"A256GCM","ext":true,"k":"wYmxkxOOFBDP6F6VuuYFcRt_Po-tSLFHCWVolsHs4VI","key_ops":["encrypt","decrypt"],"kty":"oct"}';
const MOCK_ENCRYPTION_SALT = 'HQ5sfhsb8XAQRJtD+UqcImT7Ve4n3YMagrh05YTOsjk=';
const MOCK_ENCRYPTION_DATA = `{"data":"2fOOPRKClNrisB+tmqIcETyZvDuL2iIR1Hr1nO7XZHyMqVY1cDBetw2gY5C+cIo1qkpyv3bPp+4buUjp38VBsjbijM0F/FLOqWbcuKM9h9X0uwxsgsZ96uwcIf5I46NiMgoFlhppTTMZT0Nkocz+SnvHM0IgLsFan7JqBU++vSJvx2M1PDljZSunOsqyyL+DKmbYmM4umbouKV42dipUwrCvrQJmpiUZrSkpMJrPJk9ufDQO4CyIVo0qry3aNRdYFJ6rgSyq/k6rXMwGExCMHn8UlhNnAMuMKWPWR/ymK1bzNcNs4VU14iVjEXOZGPvD9cvqVe/VtcnIba6axNEEB4HWDOCdrDh5YNWwMlQVL7vSB2yOhPZByGhnEOloYsj2E5KEb9jFGskt7EKDEYNofr6t83G0c+B72VGYZeCvgtzXzgPwzIbhTtKkP+gdBmt2JNSYrTjLypT0q+v4C9BN1xWTxPmX6TTt0NzkI9pJxgN1VQAfSU9CyWTVpd4CBkgom2cSBsxZ2MNbdKF+qSWz3fQcmJ55hxM0EGJSt9+8eQOTuoJlBapRk4wdZKHR2jdKzPjSF2MAmyVD2kU51IKa/cVsckRFEes+m7dKyHRvlNwgT78W9tBDdZb5PSlfbZXnv8z5q1KtAj2lM2ogJ7brHBdevl4FISdTkObpwcUMcvACOOO0dj6CSYjSKr0ZJ2RLChVruZyPDxEhKGb/8Kv8trLOR3mck/et6d050/NugezycNk4nnzu5iP90gPbSzaqdZI=","iv":"qTGO1afGv3waHN9KoW34Eg==","salt":"${MOCK_ENCRYPTION_SALT}"}`;

const walletOneSeedWords =
  'puzzle seed penalty soldier say clay field arctic metal hen cage runway';
const walletOneAddresses = ['0xef35ca8ebb9669a35c31b5f6f249a9941a812ac1'];

const walletTwoSeedWords =
  'urge letter protect palace city barely security section midnight wealth south deer';

const walletTwoAddresses = [
  '0xbbafcf3d00fb625b65bb1497c94bf42c1f4b3e78',
  '0x49dd2653f38f75d40fdbd51e83b9c9724c87f7eb',
];

describe('KeyringController', function () {
  let keyringController;

  beforeEach(async function () {
    keyringController = new KeyringController({
      encryptor: mockEncryptor,
      keyringBuilders: [keyringBuilderFactory(KeyringMockWithInit)],
    });

    await keyringController.createNewVaultAndKeychain(password);
    await keyringController.submitPassword(password);
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

      expect(keyringController.password).toBeUndefined();
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
    it('should not load keyrings when incorrect password', async function () {
      await keyringController.createNewVaultAndKeychain(password);
      await keyringController.persistAllKeyrings();
      expect(keyringController.keyrings).toHaveLength(1);

      await keyringController.setLocked();

      await expect(
        keyringController.submitPassword(`${password}a`),
      ).rejects.toThrow('Incorrect password.');
      expect(keyringController.password).toBeUndefined();
      expect(keyringController.keyrings).toHaveLength(0);
    });

    it('emits "unlock" event', async function () {
      await keyringController.setLocked();

      const spy = sinon.spy();
      keyringController.on('unlock', spy);

      await keyringController.submitPassword(password);
      expect(spy.calledOnce).toBe(true);
    });
  });

  describe('persistAllKeyrings', function () {
    it('should persist keyrings in _unsupportedKeyrings array', async function () {
      const unsupportedKeyring = 'DUMMY_KEYRING';
      keyringController._unsupportedKeyrings = [unsupportedKeyring];
      await keyringController.persistAllKeyrings();

      const { vault } = keyringController.store.getState();
      const keyrings = await mockEncryptor.decrypt(password, vault);
      expect(keyrings.indexOf(unsupportedKeyring) > -1).toBe(true);
      expect(keyrings).toHaveLength(2);
    });
  });

  describe('createNewVaultAndKeychain', function () {
    it('should create a new vault', async function () {
      keyringController.store.updateState({ vault: null });
      assert(!keyringController.store.getState().vault, 'no previous vault');

      const newVault = await keyringController.createNewVaultAndKeychain(
        password,
      );
      const { vault } = keyringController.store.getState();
      expect(vault).toStrictEqual(expect.stringMatching('.+'));
      expect(typeof newVault).toBe('object');
    });

    it('should unlock the vault', async function () {
      keyringController.store.updateState({ vault: null });
      assert(!keyringController.store.getState().vault, 'no previous vault');

      await keyringController.createNewVaultAndKeychain(password);
      const { isUnlocked } = keyringController.memStore.getState();
      expect(isUnlocked).toBe(true);
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

  describe('createNewVaultAndRestore', function () {
    it('clears old keyrings and creates a one', async function () {
      const initialAccounts = await keyringController.getAccounts();
      expect(initialAccounts).toHaveLength(1);

      await keyringController.addNewKeyring('HD Key Tree');
      const allAccounts = await keyringController.getAccounts();
      expect(allAccounts).toHaveLength(2);

      await keyringController.createNewVaultAndRestore(
        password,
        walletOneSeedWords,
      );

      const allAccountsAfter = await keyringController.getAccounts();
      expect(allAccountsAfter).toHaveLength(1);
      expect(allAccountsAfter[0]).toBe(walletOneAddresses[0]);
    });

    it('throws error if argument password is not a string', async function () {
      await expect(() =>
        keyringController.createNewVaultAndRestore(12, walletTwoSeedWords),
      ).rejects.toThrow('Password must be text.');
    });

    it('throws error if mnemonic passed is invalid', async function () {
      await expect(() =>
        keyringController.createNewVaultAndRestore(
          password,
          'test test test palace city barely security section midnight wealth south deer',
        ),
      ).rejects.toThrow('Seed phrase is invalid.');
    });

    it('accepts mnemonic passed as type array of numbers', async function () {
      const allAccountsBefore = await keyringController.getAccounts();
      expect(allAccountsBefore[0]).not.toBe(walletTwoAddresses[0]);
      const mnemonicAsArrayOfNumbers = Array.from(
        Buffer.from(walletTwoSeedWords).values(),
      );

      await keyringController.createNewVaultAndRestore(
        password,
        mnemonicAsArrayOfNumbers,
      );

      const allAccountsAfter = await keyringController.getAccounts();
      expect(allAccountsAfter).toHaveLength(1);
      expect(allAccountsAfter[0]).toBe(walletTwoAddresses[0]);
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

    it('should add HD Key Tree without mnemonic passed as an argument', async function () {
      const previousAllAccounts = await keyringController.getAccounts();
      expect(previousAllAccounts).toHaveLength(1);
      const keyring = await keyringController.addNewKeyring('HD Key Tree');
      const keyringAccounts = await keyring.getAccounts();
      expect(keyringAccounts).toHaveLength(1);
      const allAccounts = await keyringController.getAccounts();
      expect(allAccounts).toHaveLength(2);
    });

    it('should add HD Key Tree with mnemonic passed as an argument', async function () {
      const previousAllAccounts = await keyringController.getAccounts();
      expect(previousAllAccounts).toHaveLength(1);
      const keyring = await keyringController.addNewKeyring('HD Key Tree', {
        numberOfAccounts: 2,
        mnemonic: walletTwoSeedWords,
      });
      const keyringAccounts = await keyring.getAccounts();
      expect(keyringAccounts).toHaveLength(2);
      expect(keyringAccounts[0]).toStrictEqual(walletTwoAddresses[0]);
      expect(keyringAccounts[1]).toStrictEqual(walletTwoAddresses[1]);
      const allAccounts = await keyringController.getAccounts();
      expect(allAccounts).toHaveLength(3);
    });

    it('should call init method if available', async function () {
      const initSpy = sinon.spy(KeyringMockWithInit.prototype, 'init');

      const keyring = await keyringController.addNewKeyring(
        'Keyring Mock With Init',
      );

      expect(keyring).toBeInstanceOf(KeyringMockWithInit);

      sinon.assert.calledOnce(initSpy);
    });
  });

  describe('restoreKeyring', function () {
    it(`should pass a keyring's serialized data back to the correct type.`, async function () {
      const mockSerialized = {
        type: 'HD Key Tree',
        data: {
          mnemonic: walletOneSeedWords,
          numberOfAccounts: 1,
        },
      };

      const keyring = await keyringController.restoreKeyring(mockSerialized);
      expect(keyring.wallets).toHaveLength(1);

      const accounts = await keyring.getAccounts();
      expect(accounts[0]).toBe(walletOneAddresses[0]);
    });
    it('should return undefined if keyring type is not supported.', async function () {
      const unsupportedKeyring = { type: 'Ledger Keyring', data: 'DUMMY' };
      const keyring = await keyringController.restoreKeyring(
        unsupportedKeyring,
      );
      expect(keyring).toBeUndefined();
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
    it('add serialized keyring to _unsupportedKeyrings array if keyring type is not known', async function () {
      const _unsupportedKeyrings = [{ type: 'Ledger Keyring', data: 'DUMMY' }];
      mockEncryptor.encrypt(password, _unsupportedKeyrings);
      await keyringController.setLocked();
      const keyrings = await keyringController.unlockKeyrings(password);
      expect(keyrings).toHaveLength(0);
      expect(keyringController._unsupportedKeyrings).toStrictEqual(
        _unsupportedKeyrings,
      );
    });
  });

  describe('verifyPassword', function () {
    it('throws an error if no encrypted vault is in controller state', async function () {
      keyringController = new KeyringController({
        encryptor: mockEncryptor,
      });
      await expect(() =>
        keyringController.verifyPassword('test'),
      ).rejects.toThrow('Cannot unlock without a previous vault.');
    });
  });

  describe('addNewAccount', function () {
    it('adds a new account to the keyring it receives as an argument', async function () {
      const [HDKeyring] = await keyringController.getKeyringsByType(
        'HD Key Tree',
      );
      const initialAccounts = await HDKeyring.getAccounts();
      expect(initialAccounts).toHaveLength(1);

      await keyringController.addNewAccount(HDKeyring);
      const accountsAfterAdd = await HDKeyring.getAccounts();
      expect(accountsAfterAdd).toHaveLength(2);
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

  describe('forgetHardwareDevice', function () {
    it('throw when keyring is not hardware device', async function () {
      const privateKey =
        '0xb8a9c05beeedb25df85f8d641538cbffedf67216048de9c678ee26260eb91952';
      const keyring = await keyringController.addNewKeyring('Simple Key Pair', [
        privateKey,
      ]);
      expect(keyringController.keyrings).toHaveLength(2);
      expect(() => keyringController.forgetKeyring(keyring)).toThrow(
        new Error(
          'KeyringController - keyring does not have method "forgetDevice", keyring type: Simple Key Pair',
        ),
      );
    });

    it('forget hardware device', async function () {
      const hdKeyring = keyringController.getKeyringsByType('HD Key Tree');
      hdKeyring.forgetDevice = sinon.spy();
      keyringController.forgetKeyring(hdKeyring);
      expect(hdKeyring.forgetDevice.calledOnce).toBe(true);
    });
  });

  describe('getKeyringForAccount', function () {
    it('throws error when address is not provided', async function () {
      await expect(
        keyringController.getKeyringForAccount(undefined),
      ).rejects.toThrow(
        new Error(
          'No keyring found for the requested account. Error info: The address passed in is invalid/empty',
        ),
      );
    });

    it('throws error when there are no keyrings', async function () {
      keyringController.keyrings = [];
      await expect(
        keyringController.getKeyringForAccount('0x04'),
      ).rejects.toThrow(
        new Error(
          'No keyring found for the requested account. Error info: There are no keyrings',
        ),
      );
    });

    it('throws error when there are no matching keyrings', async function () {
      keyringController.keyrings = [
        {
          getAccounts() {
            return Promise.resolve([1, 2, 3]);
          },
        },
      ];
      await expect(
        keyringController.getKeyringForAccount('0x04'),
      ).rejects.toThrow(
        new Error(
          'No keyring found for the requested account. Error info: There are keyrings, but none match the address',
        ),
      );
    });
  });

  describe('cacheEncryptionKey', function () {
    it('sets encryption key data upon submitPassword', async function () {
      keyringController.cacheEncryptionKey = true;
      await keyringController.submitPassword(password);

      expect(keyringController.password).toBe(password);
      expect(keyringController.memStore.getState().encryptionSalt).toBe('SALT');
      expect(keyringController.memStore.getState().encryptionKey).toStrictEqual(
        expect.stringMatching('.+'),
      );
    });

    it('unlocks the keyrings with valid information', async function () {
      keyringController.cacheEncryptionKey = true;
      const returnValue = await keyringController.encryptor.decryptWithKey();
      const stub = sinon.stub(keyringController.encryptor, 'decryptWithKey');
      stub.resolves(Promise.resolve(returnValue));

      keyringController.store.updateState({ vault: MOCK_ENCRYPTION_DATA });

      await keyringController.setLocked();

      await keyringController.submitEncryptionKey(
        MOCK_ENCRYPTION_KEY,
        MOCK_ENCRYPTION_SALT,
      );

      expect(keyringController.encryptor.decryptWithKey.calledOnce).toBe(true);
      expect(keyringController.keyrings).toHaveLength(1);
    });

    it('should not load keyrings when invalid encryptionKey format', async function () {
      keyringController.cacheEncryptionKey = true;
      await keyringController.setLocked();
      keyringController.store.updateState({ vault: MOCK_ENCRYPTION_DATA });

      await expect(
        keyringController.submitEncryptionKey(`{}`, MOCK_ENCRYPTION_SALT),
      ).rejects.toThrow(
        `Failed to execute 'importKey' on 'SubtleCrypto': The provided value is not of type '(ArrayBuffer or ArrayBufferView or JsonWebKey)'.`,
      );
      expect(keyringController.password).toBeUndefined();
      expect(keyringController.keyrings).toHaveLength(0);
    });

    it('should not load keyrings when encryptionKey is expired', async function () {
      keyringController.cacheEncryptionKey = true;
      await keyringController.setLocked();
      keyringController.store.updateState({ vault: MOCK_ENCRYPTION_DATA });

      await expect(
        keyringController.submitEncryptionKey(
          MOCK_ENCRYPTION_KEY,
          'OUTDATED_SALT',
        ),
      ).rejects.toThrow('Encryption key and salt provided are expired');
      expect(keyringController.password).toBeUndefined();
      expect(keyringController.keyrings).toHaveLength(0);
    });

    it('persists keyrings when actions are performed', async function () {
      keyringController.cacheEncryptionKey = true;
      await keyringController.setLocked();
      keyringController.store.updateState({ vault: MOCK_ENCRYPTION_DATA });
      await keyringController.submitEncryptionKey(
        MOCK_ENCRYPTION_KEY,
        MOCK_ENCRYPTION_SALT,
      );

      const [firstKeyring] = keyringController.keyrings;

      await keyringController.addNewAccount(firstKeyring);
      expect(await keyringController.getAccounts()).toHaveLength(2);

      await keyringController.addNewAccount(firstKeyring);
      expect(await keyringController.getAccounts()).toHaveLength(3);

      const account = {
        privateKey:
          'c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3',
        publicKey: '0x627306090abab3a6e1400e9345bc60c78a8bef57',
      };

      // Add a new keyring with one account
      await keyringController.addNewKeyring('Simple Key Pair', [
        account.privateKey,
      ]);
      expect(await keyringController.getAccounts()).toHaveLength(4);

      // remove that account that we just added
      await keyringController.removeAccount(account.publicKey);
      expect(await keyringController.getAccounts()).toHaveLength(3);
    });

    it('triggers an error when trying to persist without password or encryption key', async function () {
      keyringController.password = undefined;
      await expect(keyringController.persistAllKeyrings()).rejects.toThrow(
        'Cannot persist vault without password and encryption key',
      );
    });

    it('cleans up login artifacts upon lock', async function () {
      keyringController.cacheEncryptionKey = true;
      await keyringController.submitPassword(password);
      expect(keyringController.password).toBe(password);
      expect(
        keyringController.memStore.getState().encryptionSalt,
      ).toStrictEqual(expect.stringMatching('.+'));
      expect(keyringController.memStore.getState().encryptionKey).toStrictEqual(
        expect.stringMatching('.+'),
      );

      await keyringController.setLocked();

      expect(keyringController.memStore.getState().encryptionSalt).toBeNull();
      expect(keyringController.password).toBeUndefined();
      expect(keyringController.memStore.getState().encryptionKey).toBeNull();
    });
  });
});
