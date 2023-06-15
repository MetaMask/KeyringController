import HdKeyring from '@metamask/eth-hd-keyring';
import { normalize as normalizeAddress } from '@metamask/eth-sig-util';
import type { Hex } from '@metamask/utils';
import { strict as assert } from 'assert';
import Wallet from 'ethereumjs-wallet';
import * as sinon from 'sinon';

import { KeyringController, keyringBuilderFactory } from '.';
import { KeyringType, KeyringControllerError } from './constants';
import {
  mockEncryptor,
  KeyringMockWithInit,
  PASSWORD,
  MOCK_HARDCODED_KEY,
  MOCK_HEX,
} from './test';

const MOCK_ENCRYPTION_KEY =
  '{"alg":"A256GCM","ext":true,"k":"wYmxkxOOFBDP6F6VuuYFcRt_Po-tSLFHCWVolsHs4VI","key_ops":["encrypt","decrypt"],"kty":"oct"}';
const MOCK_ENCRYPTION_SALT = 'HQ5sfhsb8XAQRJtD+UqcImT7Ve4n3YMagrh05YTOsjk=';
const MOCK_ENCRYPTION_DATA = `{"data":"2fOOPRKClNrisB+tmqIcETyZvDuL2iIR1Hr1nO7XZHyMqVY1cDBetw2gY5C+cIo1qkpyv3bPp+4buUjp38VBsjbijM0F/FLOqWbcuKM9h9X0uwxsgsZ96uwcIf5I46NiMgoFlhppTTMZT0Nkocz+SnvHM0IgLsFan7JqBU++vSJvx2M1PDljZSunOsqyyL+DKmbYmM4umbouKV42dipUwrCvrQJmpiUZrSkpMJrPJk9ufDQO4CyIVo0qry3aNRdYFJ6rgSyq/k6rXMwGExCMHn8UlhNnAMuMKWPWR/ymK1bzNcNs4VU14iVjEXOZGPvD9cvqVe/VtcnIba6axNEEB4HWDOCdrDh5YNWwMlQVL7vSB2yOhPZByGhnEOloYsj2E5KEb9jFGskt7EKDEYNofr6t83G0c+B72VGYZeCvgtzXzgPwzIbhTtKkP+gdBmt2JNSYrTjLypT0q+v4C9BN1xWTxPmX6TTt0NzkI9pJxgN1VQAfSU9CyWTVpd4CBkgom2cSBsxZ2MNbdKF+qSWz3fQcmJ55hxM0EGJSt9+8eQOTuoJlBapRk4wdZKHR2jdKzPjSF2MAmyVD2kU51IKa/cVsckRFEes+m7dKyHRvlNwgT78W9tBDdZb5PSlfbZXnv8z5q1KtAj2lM2ogJ7brHBdevl4FISdTkObpwcUMcvACOOO0dj6CSYjSKr0ZJ2RLChVruZyPDxEhKGb/8Kv8trLOR3mck/et6d050/NugezycNk4nnzu5iP90gPbSzaqdZI=","iv":"qTGO1afGv3waHN9KoW34Eg==","salt":"${MOCK_ENCRYPTION_SALT}"}`;

const walletOneSeedWords =
  'puzzle seed penalty soldier say clay field arctic metal hen cage runway';

const mockAddress = '0xef35ca8ebb9669a35c31b5f6f249a9941a812ac1';
const walletOneAddresses = ['0xef35ca8ebb9669a35c31b5f6f249a9941a812ac1'];
const walletOnePrivateKey = [
  'ace918800411c0b96b915f76efbbd4d50e6c997180fee58e01f60d3a412d2f7e',
];

const walletTwoSeedWords =
  'urge letter protect palace city barely security section midnight wealth south deer';

const walletTwoAddresses = [
  '0xbbafcf3d00fb625b65bb1497c94bf42c1f4b3e78',
  '0x49dd2653f38f75d40fdbd51e83b9c9724c87f7eb',
];

describe('KeyringController', () => {
  let keyringController: KeyringController;

  beforeEach(async () => {
    keyringController = new KeyringController({
      encryptor: mockEncryptor,
      cacheEncryptionKey: false,
      keyringBuilders: [keyringBuilderFactory(KeyringMockWithInit)],
    });

    await keyringController.createNewVaultAndKeychain(PASSWORD);
    await keyringController.submitPassword(PASSWORD);
  });

  afterEach(() => {
    sinon.restore();
  });

  describe('setLocked', () => {
    it('setLocked correctly sets lock state', async () => {
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

    it('emits "lock" event', async () => {
      const lockSpy = sinon.spy();
      keyringController.on('lock', lockSpy);

      await keyringController.setLocked();

      expect(lockSpy.calledOnce).toBe(true);
    });

    it('calls keyring optional destroy function', async () => {
      const destroy = sinon.spy(KeyringMockWithInit.prototype, 'destroy');
      await keyringController.addNewKeyring('Keyring Mock With Init');

      await keyringController.setLocked();

      expect(destroy.calledOnce).toBe(true);
    });
  });

  describe('submitPassword', () => {
    it('should not load keyrings when incorrect password', async () => {
      await keyringController.createNewVaultAndKeychain(PASSWORD);
      await keyringController.persistAllKeyrings();
      expect(keyringController.keyrings).toHaveLength(1);

      await keyringController.setLocked();

      await expect(
        keyringController.submitPassword('Wrong password'),
      ).rejects.toThrow('Incorrect password.');
      expect(keyringController.password).toBeUndefined();
      expect(keyringController.keyrings).toHaveLength(0);
    });

    it('emits "unlock" event', async () => {
      await keyringController.setLocked();

      const unlockSpy = sinon.spy();
      keyringController.on('unlock', unlockSpy);

      await keyringController.submitPassword(PASSWORD);
      expect(unlockSpy.calledOnce).toBe(true);
    });
  });

  describe('persistAllKeyrings', () => {
    it('should persist keyrings in _unsupportedKeyrings array', async () => {
      const unsupportedKeyring = { type: 'DUMMY_KEYRING', data: {} };
      keyringController.unsupportedKeyrings = [unsupportedKeyring];
      await keyringController.persistAllKeyrings();

      const { vault } = keyringController.store.getState();
      const keyrings = await mockEncryptor.decrypt(PASSWORD, vault);
      expect(keyrings).toContain(unsupportedKeyring);
      expect(keyrings).toHaveLength(2);
    });

    describe('when `cacheEncryptionKey` is enabled', () => {
      it('should save an up to date encryption salt to the `memStore` when `password` is unset and `encryptionKey` is set', async () => {
        delete keyringController.password;
        keyringController.cacheEncryptionKey = true;
        const vaultEncryptionKey = '🔑';
        const vaultEncryptionSalt = '🧂';
        const vault = JSON.stringify({ salt: vaultEncryptionSalt });
        keyringController.store.updateState({ vault });

        expect(keyringController.memStore.getState().encryptionKey).toBeNull();
        expect(
          keyringController.memStore.getState().encryptionSalt,
        ).toBeUndefined();

        await keyringController.unlockKeyrings(
          undefined,
          vaultEncryptionKey,
          vaultEncryptionSalt,
        );

        expect(keyringController.memStore.getState().encryptionKey).toBe(
          vaultEncryptionKey,
        );
        expect(keyringController.memStore.getState().encryptionSalt).toBe(
          vaultEncryptionSalt,
        );

        const response = await keyringController.persistAllKeyrings();

        expect(response).toBe(true);
        expect(keyringController.memStore.getState().encryptionKey).toBe(
          vaultEncryptionKey,
        );
        expect(keyringController.memStore.getState().encryptionSalt).toBe(
          vaultEncryptionSalt,
        );
      });

      it('should save an up to date encryption salt to the `memStore` when `password` is set through `createNewVaultAndKeychain`', async () => {
        keyringController.cacheEncryptionKey = true;

        await keyringController.createNewVaultAndKeychain(PASSWORD);

        const response = await keyringController.persistAllKeyrings();

        expect(response).toBe(true);
        expect(keyringController.memStore.getState().encryptionKey).toBe(
          MOCK_HARDCODED_KEY,
        );
        expect(keyringController.memStore.getState().encryptionSalt).toBe(
          MOCK_HEX,
        );
      });

      it('should save an up to date encryption salt to the `memStore` when `password` is set through `submitPassword`', async () => {
        keyringController.cacheEncryptionKey = true;

        await keyringController.submitPassword(PASSWORD);

        const response = await keyringController.persistAllKeyrings();

        expect(response).toBe(true);
        expect(keyringController.memStore.getState().encryptionKey).toBe(
          MOCK_HARDCODED_KEY,
        );
        expect(keyringController.memStore.getState().encryptionSalt).toBe(
          MOCK_HEX,
        );
      });
    });
  });

  describe('createNewVaultAndKeychain', () => {
    it('should create a new vault', async () => {
      keyringController.store.updateState({ vault: null });
      assert(!keyringController.store.getState().vault, 'no previous vault');

      const newVault = await keyringController.createNewVaultAndKeychain(
        PASSWORD,
      );
      const { vault } = keyringController.store.getState();
      expect(vault).toStrictEqual(expect.stringMatching('.+'));
      expect(typeof newVault).toBe('object');
    });

    it('should unlock the vault', async () => {
      keyringController.store.updateState({ vault: null });
      assert(!keyringController.store.getState().vault, 'no previous vault');

      await keyringController.createNewVaultAndKeychain(PASSWORD);
      const { isUnlocked } = keyringController.memStore.getState();
      expect(isUnlocked).toBe(true);
    });

    it('should encrypt keyrings with the correct password each time they are persisted', async () => {
      keyringController.store.updateState({ vault: null });
      assert(!keyringController.store.getState().vault, 'no previous vault');

      await keyringController.createNewVaultAndKeychain(PASSWORD);
      const { vault } = keyringController.store.getState();
      // eslint-disable-next-line jest/no-restricted-matchers
      expect(vault).toBeTruthy();
      keyringController.encryptor.encrypt.args.forEach(
        ([actualPassword]: string[]) => {
          expect(actualPassword).toBe(PASSWORD);
        },
      );
    });

    it('should throw error if accounts are not generated correctly', async () => {
      jest
        .spyOn(HdKeyring.prototype, 'getAccounts')
        .mockImplementation(async () => Promise.resolve([]));

      await expect(async () =>
        keyringController.createNewVaultAndKeychain(PASSWORD),
      ).rejects.toThrow(KeyringControllerError.NoAccountOnKeychain);
    });

    describe('when `cacheEncryptionKey` is enabled', () => {
      it('should add an `encryptionSalt` to the `memStore` when a new vault is created', async () => {
        keyringController.cacheEncryptionKey = true;

        const initialMemStore = keyringController.memStore.getState();
        await keyringController.createNewVaultAndKeychain(PASSWORD);
        const finalMemStore = keyringController.memStore.getState();

        expect(initialMemStore.encryptionKey).toBeNull();
        expect(initialMemStore.encryptionSalt).toBeUndefined();

        expect(finalMemStore.encryptionKey).toBe(MOCK_HARDCODED_KEY);
        expect(finalMemStore.encryptionSalt).toBe(MOCK_HEX);
      });
    });
  });

  describe('createNewVaultAndRestore', () => {
    it('clears old keyrings and creates a one', async () => {
      const initialAccounts = await keyringController.getAccounts();
      expect(initialAccounts).toHaveLength(1);

      await keyringController.addNewKeyring(KeyringType.HD);
      const allAccounts = await keyringController.getAccounts();
      expect(allAccounts).toHaveLength(2);

      await keyringController.createNewVaultAndRestore(
        PASSWORD,
        walletOneSeedWords,
      );

      const allAccountsAfter = await keyringController.getAccounts();
      expect(allAccountsAfter).toHaveLength(1);
      expect(allAccountsAfter[0]).toBe(walletOneAddresses[0]);
    });

    it('throws error if argument password is not a string', async () => {
      await expect(async () =>
        // @ts-expect-error Missing other required permission types.
        keyringController.createNewVaultAndRestore(12, walletTwoSeedWords),
      ).rejects.toThrow('KeyringController - Password must be of type string.');
    });

    it('throws error if mnemonic passed is invalid', async () => {
      await expect(async () =>
        keyringController.createNewVaultAndRestore(
          PASSWORD,
          'test test test palace city barely security section midnight wealth south deer',
        ),
      ).rejects.toThrow(
        'Eth-Hd-Keyring: Invalid secret recovery phrase provided',
      );

      await expect(async () =>
        keyringController.createNewVaultAndRestore(PASSWORD, '1234'),
      ).rejects.toThrow(
        'Eth-Hd-Keyring: Invalid secret recovery phrase provided',
      );
    });

    it('accepts mnemonic passed as type array of numbers', async () => {
      const allAccountsBefore = await keyringController.getAccounts();
      expect(allAccountsBefore[0]).not.toBe(walletTwoAddresses[0]);
      const mnemonicAsArrayOfNumbers = Array.from(
        Buffer.from(walletTwoSeedWords).values(),
      );

      await keyringController.createNewVaultAndRestore(
        PASSWORD,
        mnemonicAsArrayOfNumbers,
      );

      const allAccountsAfter = await keyringController.getAccounts();
      expect(allAccountsAfter).toHaveLength(1);
      expect(allAccountsAfter[0]).toBe(walletTwoAddresses[0]);
    });

    it('throws error if accounts are not created properly', async () => {
      jest
        .spyOn(HdKeyring.prototype, 'getAccounts')
        .mockImplementation(async () => Promise.resolve([]));

      await expect(async () =>
        keyringController.createNewVaultAndRestore(
          PASSWORD,
          walletTwoSeedWords,
        ),
      ).rejects.toThrow('KeyringController - First Account not found.');
    });

    describe('when `cacheEncryptionKey` is enabled', () => {
      it('should add an `encryptionSalt` to the `memStore` when a vault is restored', async () => {
        keyringController.cacheEncryptionKey = true;

        const initialMemStore = keyringController.memStore.getState();
        await keyringController.createNewVaultAndRestore(
          PASSWORD,
          walletOneSeedWords,
        );
        const finalMemStore = keyringController.memStore.getState();

        expect(initialMemStore.encryptionKey).toBeNull();
        expect(initialMemStore.encryptionSalt).toBeUndefined();

        expect(finalMemStore.encryptionKey).toBe(MOCK_HARDCODED_KEY);
        expect(finalMemStore.encryptionSalt).toBe(MOCK_HEX);
      });
    });
  });

  describe('addNewKeyring', () => {
    it('should add simple key pair', async () => {
      const privateKey =
        'c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3';
      const previousAccounts = await keyringController.getAccounts();
      const keyring = await keyringController.addNewKeyring(
        KeyringType.Simple,
        { privateKeys: [privateKey] },
      );

      const keyringAccounts = await keyring?.getAccounts();
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

    it('should add HD Key Tree without mnemonic passed as an argument', async () => {
      const previousAllAccounts = await keyringController.getAccounts();
      expect(previousAllAccounts).toHaveLength(1);
      const keyring = await keyringController.addNewKeyring(KeyringType.HD);
      const keyringAccounts = await keyring?.getAccounts();
      expect(keyringAccounts).toHaveLength(1);
      const allAccounts = await keyringController.getAccounts();
      expect(allAccounts).toHaveLength(2);
    });

    it('should add HD Key Tree with mnemonic passed as an argument', async () => {
      const previousAllAccounts = await keyringController.getAccounts();
      expect(previousAllAccounts).toHaveLength(1);
      const keyring = await keyringController.addNewKeyring(KeyringType.HD, {
        numberOfAccounts: 2,
        mnemonic: walletTwoSeedWords,
      });
      const keyringAccounts = await keyring?.getAccounts();
      expect(keyringAccounts).toHaveLength(2);
      expect(keyringAccounts?.[0]).toStrictEqual(walletTwoAddresses[0]);
      expect(keyringAccounts?.[1]).toStrictEqual(walletTwoAddresses[1]);
      const allAccounts = await keyringController.getAccounts();
      expect(allAccounts).toHaveLength(3);
    });

    it('should call init method if available', async () => {
      const initSpy = sinon.spy(KeyringMockWithInit.prototype, 'init');

      const keyring = await keyringController.addNewKeyring(
        'Keyring Mock With Init',
      );

      expect(keyring).toBeInstanceOf(KeyringMockWithInit);

      sinon.assert.calledOnce(initSpy);
    });

    it('should add HD Key Tree when addAccounts is asynchronous', async () => {
      const originalAccAccounts = HdKeyring.prototype.addAccounts;
      sinon.stub(HdKeyring.prototype, 'addAccounts').callsFake(async () => {
        return new Promise((resolve) => {
          setImmediate(() => {
            resolve(originalAccAccounts.bind(this)());
          });
        });
      });

      sinon.stub(HdKeyring.prototype, 'deserialize').callsFake(async () => {
        return new Promise<void>((resolve) => {
          setImmediate(() => {
            resolve();
          });
        });
      });

      sinon
        .stub(HdKeyring.prototype, 'getAccounts')
        .callsFake(() => ['mock account']);

      const keyring = await keyringController.addNewKeyring(KeyringType.HD, {
        mnemonic: 'mock mnemonic',
      });

      const keyringAccounts = await keyring?.getAccounts();
      expect(keyringAccounts).toHaveLength(1);
    });
  });

  describe('restoreKeyring', () => {
    it(`should pass a keyring's serialized data back to the correct type.`, async () => {
      const mockSerialized = {
        type: 'HD Key Tree',
        data: {
          mnemonic: walletOneSeedWords,
          numberOfAccounts: 1,
        },
      };

      const keyring = await keyringController.restoreKeyring(mockSerialized);
      // eslint-disable-next-line no-unsafe-optional-chaining
      // @ts-expect-error this value should never be undefined in this specific context.
      const { numberOfAccounts } = await keyring.serialize();
      expect(numberOfAccounts).toBe(1);

      const accounts = await keyring?.getAccounts();
      expect(accounts?.[0]).toBe(walletOneAddresses[0]);
    });

    it('should return undefined if keyring type is not supported.', async () => {
      const unsupportedKeyring = { type: 'Ledger Keyring', data: 'DUMMY' };
      const keyring = await keyringController.restoreKeyring(
        unsupportedKeyring,
      );
      expect(keyring).toBeUndefined();
    });
  });

  describe('getAccounts', () => {
    it('returns the result of getAccounts for each keyring', async () => {
      keyringController.keyrings = [
        {
          // @ts-expect-error there's only a need to mock the getAccounts method for this test.
          async getAccounts() {
            return Promise.resolve([1, 2, 3]);
          },
        },
        {
          // @ts-expect-error there's only a need to mock the getAccounts method for this test.
          async getAccounts() {
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

  describe('removeAccount', () => {
    it('removes an account from the corresponding keyring', async () => {
      const account: { privateKey: string; publicKey: Hex } = {
        privateKey:
          'c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3',
        publicKey: '0x627306090abab3a6e1400e9345bc60c78a8bef57',
      };

      const accountsBeforeAdding = await keyringController.getAccounts();

      // Add a new keyring with one account
      await keyringController.addNewKeyring(KeyringType.Simple, {
        privateKeys: [account.privateKey],
      });
      expect(keyringController.keyrings).toHaveLength(2);

      // remove that account that we just added
      await keyringController.removeAccount(account.publicKey);

      expect(keyringController.keyrings).toHaveLength(1);
      // fetch accounts after removal
      const result = await keyringController.getAccounts();
      expect(result).toStrictEqual(accountsBeforeAdding);
    });

    it('removes the keyring if there are no accounts after removal', async () => {
      const account: { privateKey: string; publicKey: Hex } = {
        privateKey:
          'c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3',
        publicKey: '0x627306090abab3a6e1400e9345bc60c78a8bef57',
      };

      // Add a new keyring with one account
      await keyringController.addNewKeyring(KeyringType.Simple, {
        privateKeys: [account.privateKey],
      });

      // We should have 2 keyrings
      expect(keyringController.keyrings).toHaveLength(2);

      // remove that account that we just added
      await keyringController.removeAccount(account.publicKey);

      // Check that the previous keyring with only one account
      // was also removed after removing the account
      expect(keyringController.keyrings).toHaveLength(1);
    });

    it('calls keyring optional destroy function', async () => {
      const destroy = sinon.spy(KeyringMockWithInit.prototype, 'destroy');
      const keyring = await keyringController.addNewKeyring(
        'Keyring Mock With Init',
      );
      sinon.stub(keyringController, 'getKeyringForAccount').resolves(keyring);

      await keyringController.removeAccount('0x0');

      expect(destroy.calledOnce).toBe(true);
    });

    it('does not remove the keyring if there are accounts remaining after removing one from the keyring', async () => {
      // Add a new keyring with two accounts
      await keyringController.addNewKeyring(KeyringType.HD, {
        mnemonic: walletTwoSeedWords,
        numberOfAccounts: 2,
      });

      // We should have 2 keyrings
      expect(keyringController.keyrings).toHaveLength(2);

      // remove one account from the keyring we just added
      // @ts-expect-error this value should never be undefied
      await keyringController.removeAccount(walletTwoAddresses[0]);

      // Check that the newly added keyring was not removed after
      // removing the account since it still has an account left
      expect(keyringController.keyrings).toHaveLength(2);
    });
  });

  describe('unlockKeyrings', () => {
    it('returns the list of keyrings', async () => {
      await keyringController.setLocked();
      const keyrings = await keyringController.unlockKeyrings(PASSWORD);
      expect(keyrings).toHaveLength(1);
      await Promise.all(
        keyrings.map(async (keyring) => {
          // @ts-expect-error numberOfAccounts mising in Json specification.
          const { numberOfAccounts } = await keyring.serialize();
          expect(numberOfAccounts).toBe(1);
        }),
      );
    });

    it('add serialized keyring to unsupportedKeyrings array if keyring type is not known', async () => {
      const unsupportedKeyrings = [{ type: 'Ledger Keyring', data: 'DUMMY' }];
      mockEncryptor.encrypt(PASSWORD, unsupportedKeyrings);
      await keyringController.setLocked();
      const keyrings = await keyringController.unlockKeyrings(PASSWORD);
      expect(keyrings).toHaveLength(0);
      expect(keyringController.unsupportedKeyrings).toStrictEqual(
        unsupportedKeyrings,
      );
    });
  });

  describe('verifyPassword', () => {
    beforeEach(() => {
      keyringController = new KeyringController({
        keyringBuilders: [keyringBuilderFactory(KeyringMockWithInit)],
        encryptor: mockEncryptor,
        cacheEncryptionKey: false,
      });
    });

    it('throws an error if no encrypted vault is in controller state', async () => {
      await expect(async () =>
        keyringController.verifyPassword('test'),
      ).rejects.toThrow('Cannot unlock without a previous vault.');
    });

    it('does not throw if a vault exists in state', async () => {
      await keyringController.createNewVaultAndRestore(
        PASSWORD,
        walletOneSeedWords,
      );

      expect(async () =>
        keyringController.verifyPassword(PASSWORD),
      ).not.toThrow();
    });
  });

  describe('addNewAccount', () => {
    it('adds a new account to the keyring it receives as an argument', async () => {
      const [HDKeyring] = keyringController.getKeyringsByType(KeyringType.HD);
      const initialAccounts = await HDKeyring?.getAccounts();
      expect(initialAccounts).toHaveLength(1);

      // @ts-expect-error this value should never be undefined in this specific context.
      await keyringController.addNewAccount(HDKeyring);
      const accountsAfterAdd = await HDKeyring?.getAccounts();
      expect(accountsAfterAdd).toHaveLength(2);
    });
  });

  describe('getAppKeyAddress', () => {
    it('returns the expected app key address', async () => {
      const address = '0x01560cd3bac62cc6d7e6380600d9317363400896';
      const privateKey =
        '0xb8a9c05beeedb25df85f8d641538cbffedf67216048de9c678ee26260eb91952';

      const keyring = await keyringController.addNewKeyring(
        KeyringType.Simple,
        { privateKeys: [privateKey] },
      );

      const getAppKeyAddressSpy = sinon.spy(
        keyringController,
        'getAppKeyAddress',
      );

      keyringController.getKeyringForAccount = sinon
        .stub()
        .returns(Promise.resolve(keyring));

      await keyringController.getAppKeyAddress(address, 'someapp.origin.io');

      expect(getAppKeyAddressSpy.calledOnce).toBe(true);
      expect(getAppKeyAddressSpy.getCall(0).args[0]).toBe(
        normalizeAddress(address),
      );
      expect(getAppKeyAddressSpy.calledOnce).toBe(true);
      expect(getAppKeyAddressSpy.getCall(0).args).toStrictEqual([
        normalizeAddress(address),
        'someapp.origin.io',
      ]);
    });
  });

  describe('exportAppKeyForAddress', () => {
    it('returns a unique key', async () => {
      const address = '0x01560cd3bac62cc6d7e6380600d9317363400896';
      const privateKey =
        '0xb8a9c05beeedb25df85f8d641538cbffedf67216048de9c678ee26260eb91952';
      await keyringController.addNewKeyring(KeyringType.Simple, {
        privateKeys: [privateKey],
      });
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

  describe('getKeyringForAccount', () => {
    it('throws error when address is not provided', async () => {
      await expect(
        // @ts-expect-error Missing other required permission types.
        keyringController.getKeyringForAccount(undefined),
      ).rejects.toThrow(
        new Error(
          `${KeyringControllerError.NoKeyring}. Error info: The address passed in is invalid/empty`,
        ),
      );
    });

    it('throws error when there are no keyrings', async () => {
      keyringController.keyrings = [];
      await expect(
        keyringController.getKeyringForAccount('0x04'),
      ).rejects.toThrow(
        new Error(
          `${KeyringControllerError.NoKeyring}. Error info: There are no keyrings`,
        ),
      );
    });

    it('throws error when there are no matching keyrings', async () => {
      keyringController.keyrings = [
        {
          // @ts-expect-error there's only a need to mock the getAccounts method for this test.
          async getAccounts() {
            return Promise.resolve([1, 2, 3]);
          },
        },
      ];

      await expect(
        keyringController.getKeyringForAccount('0x04'),
      ).rejects.toThrow(
        new Error(
          `${KeyringControllerError.NoKeyring}. Error info: There are keyrings, but none match the address`,
        ),
      );
    });
  });

  describe('cacheEncryptionKey', () => {
    it('sets encryption key data upon submitPassword', async () => {
      keyringController.cacheEncryptionKey = true;
      await keyringController.submitPassword(PASSWORD);

      expect(keyringController.password).toBe(PASSWORD);
      expect(keyringController.memStore.getState().encryptionSalt).toBe('SALT');
      expect(keyringController.memStore.getState().encryptionKey).toStrictEqual(
        expect.stringMatching('.+'),
      );
    });

    it('unlocks the keyrings with valid information', async () => {
      keyringController.cacheEncryptionKey = true;
      const returnValue = await keyringController.encryptor.decryptWithKey();
      const decryptWithKeyStub = sinon.stub(
        keyringController.encryptor,
        'decryptWithKey',
      );
      decryptWithKeyStub.resolves(Promise.resolve(returnValue));

      keyringController.store.updateState({ vault: MOCK_ENCRYPTION_DATA });

      await keyringController.setLocked();

      await keyringController.submitEncryptionKey(
        MOCK_ENCRYPTION_KEY,
        MOCK_ENCRYPTION_SALT,
      );

      expect(keyringController.encryptor.decryptWithKey.calledOnce).toBe(true);
      expect(keyringController.keyrings).toHaveLength(1);
    });

    it('should not load keyrings when invalid encryptionKey format', async () => {
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

    it('should not load keyrings when encryptionKey is expired', async () => {
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

    it('persists keyrings when actions are performed', async () => {
      keyringController.cacheEncryptionKey = true;
      await keyringController.setLocked();
      keyringController.store.updateState({ vault: MOCK_ENCRYPTION_DATA });
      await keyringController.submitEncryptionKey(
        MOCK_ENCRYPTION_KEY,
        MOCK_ENCRYPTION_SALT,
      );

      const [firstKeyring] = keyringController.keyrings;

      // @ts-expect-error this value should never be undefined in this specific context.
      await keyringController.addNewAccount(firstKeyring);
      expect(await keyringController.getAccounts()).toHaveLength(2);

      // @ts-expect-error this value should never be undefined in this specific context.
      await keyringController.addNewAccount(firstKeyring);
      expect(await keyringController.getAccounts()).toHaveLength(3);

      const account: { privateKey: string; publicKey: Hex } = {
        privateKey:
          'c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3',
        publicKey: '0x627306090abab3a6e1400e9345bc60c78a8bef57',
      };

      // Add a new keyring with one account
      await keyringController.addNewKeyring(KeyringType.Simple, {
        privateKeys: [account.privateKey],
      });
      expect(await keyringController.getAccounts()).toHaveLength(4);

      // remove that account that we just added
      await keyringController.removeAccount(account.publicKey);
      expect(await keyringController.getAccounts()).toHaveLength(3);
    });

    it('triggers an error when trying to persist without password or encryption key', async () => {
      delete keyringController.password;
      await expect(keyringController.persistAllKeyrings()).rejects.toThrow(
        'Cannot persist vault without password and encryption key',
      );
    });

    it('cleans up login artifacts upon lock', async () => {
      keyringController.cacheEncryptionKey = true;
      await keyringController.submitPassword(PASSWORD);
      expect(keyringController.password).toBe(PASSWORD);
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

  describe('exportAccount', () => {
    it('returns the private key for the public key it is passed', async () => {
      await keyringController.createNewVaultAndRestore(
        PASSWORD,
        walletOneSeedWords,
      );
      const privateKey = await keyringController.exportAccount(
        // @ts-expect-error this value should never be undefined in this specific context.
        walletOneAddresses[0],
      );
      expect(privateKey).toStrictEqual(walletOnePrivateKey[0]);
    });
  });

  describe('signing methods', () => {
    beforeEach(async () => {
      await keyringController.createNewVaultAndRestore(
        PASSWORD,
        walletOneSeedWords,
      );
    });

    it('signMessage', async () => {
      const inputParams = {
        from: walletOneAddresses[0],
        data: '0x879a053d4800c6354e76c7985a865d2922c82fb5b3f4577b2fe08b998954f2e0',
        origin: 'https://metamask.github.io',
      };
      // @ts-expect-error this value should never be undefined in this specific context.
      const result = await keyringController.signMessage(inputParams);
      expect(result).toMatchInlineSnapshot(
        `"0x93e0035090e8144debae03f45c5339a78d24c41e38e810a82dd3387e48353db645bd77716f3b7c4fb1f07f3b97bdbd33b0d7c55f7e7eedf3a678a2081948b67f1c"`,
      );
    });

    it('signPersonalMessage', async () => {
      const inputParams = {
        from: walletOneAddresses[0],
        data: '0x4578616d706c652060706572736f6e616c5f7369676e60206d657373616765',
        origin: 'https://metamask.github.io',
      };
      // @ts-expect-error this value should never be undefined in this specific context.
      const result = await keyringController.signPersonalMessage(inputParams);
      expect(result).toBe(
        '0xfa2e5989b483e1f40a41b306f275b0009bcc07bfe5322c87682145e7d4889a3247182b4bd8138a965a7e37dea9d9b492b6f9f6d01185412f2d80466237b2805e1b',
      );
    });

    it('getEncryptionPublicKey', async () => {
      const result = await keyringController.getEncryptionPublicKey(
        // @ts-expect-error this value should never be undefined in this specific context.
        walletOneAddresses[0],
      );
      expect(result).toBe('SR6bQ1m3OTHvI1FLwcGzm+Uk6hffoFPxsQ0DTOeKMEc=');
    });

    it('signTypedMessage', async () => {
      const inputParams = {
        from: mockAddress,
        data: [
          {
            type: 'string',
            name: 'Message',
            value: 'Hi, Alice!',
          },
          {
            type: 'uint32',
            name: 'A number',
            value: '1337',
          },
        ],
        origin: 'https://metamask.github.io',
      };
      const result = await keyringController.signTypedMessage(inputParams);
      expect(result).toBe(
        '0x089bb031f5bf2b2cbdf49eb2bb37d6071ab71f950b9dc49e398ca2ba984aca3c189b3b8de6c14c56461460dd9f59443340f1b144aeeff73275ace41ac184e54f1c',
      );
    });
  });
});
