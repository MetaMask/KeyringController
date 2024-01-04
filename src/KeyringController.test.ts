import { Wallet } from '@ethereumjs/wallet';
import HdKeyring from '@metamask/eth-hd-keyring';
import { normalize as normalizeAddress } from '@metamask/eth-sig-util';
import type { Hex } from '@metamask/utils';
import { bytesToHex } from '@metamask/utils';
import { strict as assert } from 'assert';
import * as sinon from 'sinon';

import { KeyringController, keyringBuilderFactory } from '.';
import { KeyringType, KeyringControllerError } from './constants';
import {
  MockEncryptor,
  KeyringMockWithInit,
  PASSWORD,
  MOCK_HARDCODED_KEY,
  MOCK_ENCRYPTION_SALT,
} from './test';
import type { KeyringControllerArgs } from './types';

const MOCK_ENCRYPTION_KEY =
  '{"alg":"A256GCM","ext":true,"k":"wYmxkxOOFBDP6F6VuuYFcRt_Po-tSLFHCWVolsHs4VI","key_ops":["encrypt","decrypt"],"kty":"oct"}';
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

/**
 * Create a keyring controller that has been initialized with the given options.
 *
 * @param options - Initialization options.
 * @param options.constructorOptions - Constructor options, merged with test defaults.
 * @param options.password - The vault password. If provided, creates a new vault (if necessary)
 * and unlocks the vault.
 * @param options.seedPhrase - A seed phrase. If provided, this is used to restore the vault.
 * @returns A keyring controller.
 */
async function initializeKeyringController({
  constructorOptions,
  password,
  seedPhrase,
}: {
  constructorOptions?: Partial<KeyringControllerArgs>;
  password?: string;
  seedPhrase?: string;
} = {}) {
  const keyringController = new KeyringController({
    encryptor: new MockEncryptor(),
    cacheEncryptionKey: false,
    keyringBuilders: [keyringBuilderFactory(KeyringMockWithInit)],
    ...constructorOptions,
  });

  if (seedPhrase && !password) {
    throw new Error('Password required to restore vault');
  } else if (seedPhrase && password) {
    await keyringController.createNewVaultWithKeyring(PASSWORD, {
      type: KeyringType.HD,
      opts: {
        mnemonic: walletOneSeedWords,
        numberOfAccounts: 1,
      },
    });
  } else if (password) {
    await keyringController.createNewVaultWithKeyring(PASSWORD, {
      type: KeyringType.HD,
    });
  }

  return keyringController;
}

/**
 * Delete the encryption key and salt from the `memStore` of the given keyring controller.
 *
 * @param keyringController - The keyring controller to delete the encryption key and salt from.
 */
function deleteEncryptionKeyAndSalt(keyringController: KeyringController) {
  const keyringControllerState = keyringController.memStore.getState();
  delete keyringControllerState.encryptionKey;
  delete keyringControllerState.encryptionSalt;
  keyringController.memStore.updateState(keyringControllerState);
}

describe('KeyringController', () => {
  afterEach(() => {
    sinon.restore();
  });

  describe('constructor', () => {
    describe('with cacheEncryptionKey = true', () => {
      it('should throw error if provided encryptor does not support key export', async () => {
        expect(
          () =>
            // @ts-expect-error we want to bypass typechecks here.
            new KeyringController({
              cacheEncryptionKey: true,
              encryptor: {
                decrypt: async (_pass: string, _text: string) =>
                  Promise.resolve('encrypted'),
                encrypt: async (_pass: string, _obj: any) => 'decrypted',
              },
            }),
        ).toThrow(KeyringControllerError.UnsupportedEncryptionKeyExport);
      });
    });
  });

  describe('setLocked', () => {
    it('setLocked correctly sets lock state', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
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
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      const lockSpy = sinon.spy();
      keyringController.on('lock', lockSpy);

      await keyringController.setLocked();

      expect(lockSpy.calledOnce).toBe(true);
    });

    it('calls keyring optional destroy function', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      const destroy = sinon.spy(KeyringMockWithInit.prototype, 'destroy');
      await keyringController.addNewKeyring('Keyring Mock With Init');

      await keyringController.setLocked();

      expect(destroy.calledOnce).toBe(true);
    });
  });

  describe('submitPassword', () => {
    it('should not load keyrings when incorrect password', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      await keyringController.createNewVaultWithKeyring(PASSWORD, {
        type: KeyringType.HD,
      });
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
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      await keyringController.setLocked();

      const unlockSpy = sinon.spy();
      keyringController.on('unlock', unlockSpy);

      await keyringController.submitPassword(PASSWORD);
      expect(unlockSpy.calledOnce).toBe(true);
    });
  });

  describe('persistAllKeyrings', () => {
    it('should persist keyrings in _unsupportedKeyrings array', async () => {
      const mockEncryptor = new MockEncryptor();
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
        constructorOptions: {
          encryptor: mockEncryptor,
        },
      });
      const encryptSpy = sinon.spy(mockEncryptor, 'encrypt');
      const unsupportedKeyring = { type: 'DUMMY_KEYRING', data: {} };
      keyringController.unsupportedKeyrings = [unsupportedKeyring];

      await keyringController.persistAllKeyrings();

      assert(keyringController.store.getState().vault, 'Vault is not set');
      expect(encryptSpy.calledOnce).toBe(true);
      expect(encryptSpy.getCalls()[0]?.args[1]).toHaveLength(2);
      expect(encryptSpy.getCalls()[0]?.args[1]).toContain(unsupportedKeyring);
    });

    describe('when `cacheEncryptionKey` is enabled', () => {
      describe('when `encryptionKey` is set', () => {
        it('should save an up to date encryption salt to the `memStore`', async () => {
          const keyringController = await initializeKeyringController({
            password: PASSWORD,
            constructorOptions: {
              cacheEncryptionKey: true,
            },
          });
          const vaultEncryptionKey = '🔑';
          const vaultEncryptionSalt = '🧂';
          const vault = JSON.stringify({ salt: vaultEncryptionSalt });
          keyringController.store.updateState({ vault });

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
      });

      describe('when `encryptionKey` is not set and `password` is set', () => {
        it('should save an up to date encryption salt to the `memStore` when `password` is set through `createNewVaultAndKeychain`', async () => {
          const keyringController = await initializeKeyringController({
            password: PASSWORD,
            constructorOptions: {
              cacheEncryptionKey: true,
            },
          });
          await keyringController.createNewVaultWithKeyring(PASSWORD, {
            type: KeyringType.HD,
          });
          deleteEncryptionKeyAndSalt(keyringController);

          const response = await keyringController.persistAllKeyrings();

          expect(response).toBe(true);
          expect(keyringController.memStore.getState().encryptionKey).toBe(
            MOCK_HARDCODED_KEY,
          );
          expect(keyringController.memStore.getState().encryptionSalt).toBe(
            MOCK_ENCRYPTION_SALT,
          );
        });

        it('should save an up to date encryption salt to the `memStore` when `password` is set through `submitPassword`', async () => {
          const keyringController = await initializeKeyringController({
            password: PASSWORD,
            constructorOptions: {
              cacheEncryptionKey: true,
            },
          });
          await keyringController.submitPassword(PASSWORD);
          deleteEncryptionKeyAndSalt(keyringController);

          const response = await keyringController.persistAllKeyrings();

          expect(response).toBe(true);
          expect(keyringController.memStore.getState().encryptionKey).toBe(
            MOCK_HARDCODED_KEY,
          );
          expect(keyringController.memStore.getState().encryptionSalt).toBe(
            MOCK_ENCRYPTION_SALT,
          );
        });
      });
    });

    it('should add an `encryptionSalt` to the `memStore` when a vault is restored', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
        constructorOptions: {
          cacheEncryptionKey: true,
        },
      });

      await keyringController.createNewVaultWithKeyring(PASSWORD, {
        type: KeyringType.HD,
        opts: {
          mnemonic: walletOneSeedWords,
          numberOfAccounts: 1,
        },
      });

      const finalMemStore = keyringController.memStore.getState();
      expect(finalMemStore.encryptionKey).toBe(MOCK_HARDCODED_KEY);
      expect(finalMemStore.encryptionSalt).toBe(MOCK_ENCRYPTION_SALT);
    });
  });

  describe('createNewVaultWithKeyring', () => {
    it('should create a new vault with a HD keyring', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      keyringController.store.putState({});
      assert(!keyringController.store.getState().vault, 'no previous vault');

      const newVault = await keyringController.createNewVaultWithKeyring(
        PASSWORD,
        {
          type: KeyringType.HD,
        },
      );
      const { vault } = keyringController.store.getState();
      expect(vault).toStrictEqual(expect.stringMatching('.+'));
      expect(typeof newVault).toBe('object');
    });

    it('should create a new vault with a simple keyring', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      keyringController.store.putState({});
      assert(!keyringController.store.getState().vault, 'no previous vault');

      const newVault = await keyringController.createNewVaultWithKeyring(
        PASSWORD,
        {
          type: KeyringType.Simple,
          opts: walletOnePrivateKey,
        },
      );
      const { vault } = keyringController.store.getState();
      expect(vault).toStrictEqual(expect.stringMatching('.+'));
      expect(typeof newVault).toBe('object');

      const accounts = await keyringController.getAccounts();
      expect(accounts).toHaveLength(1);
      expect(accounts[0]).toBe(walletOneAddresses[0]);
    });

    it('should unlock the vault', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      keyringController.store.putState({});
      assert(!keyringController.store.getState().vault, 'no previous vault');

      await keyringController.createNewVaultWithKeyring(PASSWORD, {
        type: KeyringType.HD,
      });
      const { isUnlocked } = keyringController.memStore.getState();
      expect(isUnlocked).toBe(true);
    });

    it('should encrypt keyrings with the correct password each time they are persisted', async () => {
      const mockEncryptor = new MockEncryptor();
      const encryptSpy = sinon.spy(mockEncryptor, 'encrypt');
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
        constructorOptions: {
          encryptor: mockEncryptor,
        },
      });
      keyringController.store.putState({});
      assert(!keyringController.store.getState().vault, 'no previous vault');

      await keyringController.createNewVaultWithKeyring(PASSWORD, {
        type: KeyringType.HD,
      });
      const { vault } = keyringController.store.getState();
      // eslint-disable-next-line jest/no-restricted-matchers
      expect(vault).toBeTruthy();
      encryptSpy.args.forEach(([actualPassword]) => {
        expect(actualPassword).toBe(PASSWORD);
      });
    });

    it('should throw error if accounts are not generated correctly', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      jest
        .spyOn(HdKeyring.prototype, 'getAccounts')
        .mockImplementation(async () => Promise.resolve([]));

      await expect(async () =>
        keyringController.createNewVaultWithKeyring(PASSWORD, {
          type: KeyringType.HD,
        }),
      ).rejects.toThrow(KeyringControllerError.NoFirstAccount);
    });

    describe('when `cacheEncryptionKey` is enabled', () => {
      it('should add an `encryptionSalt` to the `memStore` when a new vault is created', async () => {
        const keyringController = await initializeKeyringController({
          password: PASSWORD,
          constructorOptions: {
            cacheEncryptionKey: true,
          },
        });

        await keyringController.createNewVaultWithKeyring(PASSWORD, {
          type: KeyringType.HD,
        });

        const finalMemStore = keyringController.memStore.getState();
        expect(finalMemStore.encryptionKey).toBe(MOCK_HARDCODED_KEY);
        expect(finalMemStore.encryptionSalt).toBe(MOCK_ENCRYPTION_SALT);
      });
    });

    it('clears old keyrings and creates a one', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      const initialAccounts = await keyringController.getAccounts();
      expect(initialAccounts).toHaveLength(1);

      await keyringController.addNewKeyring(KeyringType.HD);
      const allAccounts = await keyringController.getAccounts();
      expect(allAccounts).toHaveLength(2);

      await keyringController.createNewVaultWithKeyring(PASSWORD, {
        type: KeyringType.HD,
        opts: {
          mnemonic: walletOneSeedWords,
          numberOfAccounts: 1,
        },
      });

      const allAccountsAfter = await keyringController.getAccounts();
      expect(allAccountsAfter).toHaveLength(1);
      expect(allAccountsAfter[0]).toBe(walletOneAddresses[0]);
    });

    it('throws error if argument password is not a string', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      await expect(async () =>
        // @ts-expect-error Missing other required permission types.
        keyringController.createNewVaultWithKeyring(12, {
          type: KeyringType.HD,
          opts: {
            mnemonic: walletTwoSeedWords,
            numberOfAccounts: 1,
          },
        }),
      ).rejects.toThrow('KeyringController - Password must be of type string.');
    });

    it('throws error if mnemonic passed is invalid', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      await expect(async () =>
        keyringController.createNewVaultWithKeyring(PASSWORD, {
          type: KeyringType.HD,
          opts: {
            mnemonic:
              'test test test palace city barely security section midnight wealth south deer',
            numberOfAccounts: 1,
          },
        }),
      ).rejects.toThrow(
        'Eth-Hd-Keyring: Invalid secret recovery phrase provided',
      );

      await expect(async () =>
        keyringController.createNewVaultWithKeyring(PASSWORD, {
          type: KeyringType.HD,
          opts: {
            mnemonic: '1234',
            numberOfAccounts: 1,
          },
        }),
      ).rejects.toThrow(
        'Eth-Hd-Keyring: Invalid secret recovery phrase provided',
      );
    });

    it('accepts mnemonic passed as type array of numbers', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      const allAccountsBefore = await keyringController.getAccounts();
      expect(allAccountsBefore[0]).not.toBe(walletTwoAddresses[0]);
      const mnemonicAsArrayOfNumbers = Array.from(
        Buffer.from(walletTwoSeedWords).values(),
      );

      await keyringController.createNewVaultWithKeyring(PASSWORD, {
        type: KeyringType.HD,
        opts: {
          mnemonic: mnemonicAsArrayOfNumbers,
          numberOfAccounts: 1,
        },
      });

      const allAccountsAfter = await keyringController.getAccounts();
      expect(allAccountsAfter).toHaveLength(1);
      expect(allAccountsAfter[0]).toBe(walletTwoAddresses[0]);
    });

    it('throws error if accounts are not created properly', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      jest
        .spyOn(HdKeyring.prototype, 'getAccounts')
        .mockImplementation(async () => Promise.resolve([]));

      await expect(async () =>
        keyringController.createNewVaultWithKeyring(PASSWORD, {
          type: KeyringType.HD,
          opts: {
            mnemonic: walletTwoSeedWords,
            numberOfAccounts: 1,
          },
        }),
      ).rejects.toThrow('KeyringController - First Account not found.');
    });
  });

  describe('addNewKeyring', () => {
    it('should add simple key pair', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      const privateKey =
        'c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3';
      const previousAccounts = await keyringController.getAccounts();
      const keyring = await keyringController.addNewKeyring(
        KeyringType.Simple,
        [privateKey],
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
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      const previousAllAccounts = await keyringController.getAccounts();
      expect(previousAllAccounts).toHaveLength(1);
      const keyring = await keyringController.addNewKeyring(KeyringType.HD);
      const keyringAccounts = await keyring?.getAccounts();
      expect(keyringAccounts).toHaveLength(1);
      const allAccounts = await keyringController.getAccounts();
      expect(allAccounts).toHaveLength(2);
    });

    it('should add HD Key Tree with mnemonic passed as an argument', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
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

    it('should add keyring that expects undefined serialized state', async () => {
      let deserializedSpy = sinon.spy();
      const mockKeyringBuilder = () => {
        const keyring = new KeyringMockWithInit();
        deserializedSpy = sinon.spy(keyring, 'deserialize');
        return keyring;
      };
      mockKeyringBuilder.type = 'Mock Keyring';
      const keyringController = await initializeKeyringController({
        constructorOptions: {
          keyringBuilders: [mockKeyringBuilder],
        },
        password: PASSWORD,
      });
      await keyringController.addNewKeyring('Mock Keyring');

      expect(deserializedSpy.callCount).toBe(1);
      expect(deserializedSpy.calledWith(undefined)).toBe(true);
    });

    it('should call init method if available', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      const initSpy = sinon.spy(KeyringMockWithInit.prototype, 'init');

      const keyring = await keyringController.addNewKeyring(
        'Keyring Mock With Init',
      );

      expect(keyring).toBeInstanceOf(KeyringMockWithInit);

      sinon.assert.calledOnce(initSpy);
    });

    it('should add HD Key Tree when addAccounts is asynchronous', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
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
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
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
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      const unsupportedKeyring = { type: 'Ledger Keyring', data: 'DUMMY' };
      const keyring = await keyringController.restoreKeyring(
        unsupportedKeyring,
      );
      expect(keyring).toBeUndefined();
    });
  });

  describe('getAccounts', () => {
    it('returns the result of getAccounts for each keyring', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
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
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      const account: { privateKey: string; publicKey: Hex } = {
        privateKey:
          'c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3',
        publicKey: '0x627306090abab3a6e1400e9345bc60c78a8bef57',
      };

      const accountsBeforeAdding = await keyringController.getAccounts();

      // Add a new keyring with one account
      await keyringController.addNewKeyring(KeyringType.Simple, [
        account.privateKey,
      ]);
      expect(keyringController.keyrings).toHaveLength(2);

      // remove that account that we just added
      await keyringController.removeAccount(account.publicKey);

      expect(keyringController.keyrings).toHaveLength(1);
      // fetch accounts after removal
      const result = await keyringController.getAccounts();
      expect(result).toStrictEqual(accountsBeforeAdding);
    });

    it('removes the keyring if there are no accounts after removal', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      const account: { privateKey: string; publicKey: Hex } = {
        privateKey:
          'c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3',
        publicKey: '0x627306090abab3a6e1400e9345bc60c78a8bef57',
      };

      // Add a new keyring with one account
      await keyringController.addNewKeyring(KeyringType.Simple, [
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

    it('calls keyring optional destroy function', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      const destroy = sinon.spy(KeyringMockWithInit.prototype, 'destroy');
      const keyring = await keyringController.addNewKeyring(
        'Keyring Mock With Init',
      );
      sinon.stub(keyringController, 'getKeyringForAccount').resolves(keyring);

      await keyringController.removeAccount('0x0');

      expect(destroy.calledOnce).toBe(true);
    });

    it('does not remove the keyring if there are accounts remaining after removing one from the keyring', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
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
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
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
      const mockEncryptor = new MockEncryptor();
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
        constructorOptions: {
          encryptor: mockEncryptor,
        },
      });
      const unsupportedKeyrings = [{ type: 'Ledger Keyring', data: 'DUMMY' }];
      await mockEncryptor.encrypt(PASSWORD, unsupportedKeyrings);
      await keyringController.setLocked();

      const keyrings = await keyringController.unlockKeyrings(PASSWORD);

      expect(keyrings).toHaveLength(0);
      expect(keyringController.unsupportedKeyrings).toStrictEqual(
        unsupportedKeyrings,
      );
    });

    it('should throw error if there is no vault', async () => {
      const keyringController = new KeyringController({
        cacheEncryptionKey: false,
      });

      await expect(async () =>
        keyringController.unlockKeyrings(PASSWORD),
      ).rejects.toThrow(KeyringControllerError.VaultError);
    });

    it('should throw error if decrypted vault is not an array of serialized keyrings', async () => {
      const mockEncryptor = new MockEncryptor();
      sinon
        .stub(mockEncryptor, 'decrypt')
        .resolves('[{"foo": "not a valid keyring}]');
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
        constructorOptions: {
          encryptor: mockEncryptor,
        },
      });

      await expect(async () =>
        keyringController.unlockKeyrings(PASSWORD),
      ).rejects.toThrow(KeyringControllerError.VaultDataError);
    });

    it('should throw error if decrypted vault includes an invalid keyring', async () => {
      const mockEncryptor = new MockEncryptor();
      sinon
        .stub(mockEncryptor, 'decrypt')
        .resolves([{ foo: 'not a valid keyring' }]);
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
        constructorOptions: {
          encryptor: mockEncryptor,
        },
      });

      await expect(async () =>
        keyringController.unlockKeyrings(PASSWORD),
      ).rejects.toThrow(KeyringControllerError.VaultDataError);
    });

    describe('with old vault format', () => {
      describe(`with cacheEncryptionKey = true and encryptionKey is unset`, () => {
        it('should update the vault', async () => {
          const mockEncryptor = new MockEncryptor();
          const keyringController = await initializeKeyringController({
            password: PASSWORD,
            constructorOptions: {
              cacheEncryptionKey: true,
              encryptor: mockEncryptor,
            },
          });
          deleteEncryptionKeyAndSalt(keyringController);
          const initialVault = keyringController.store.getState().vault;
          const mockEncryptionResult = {
            data: '0x1234',
            iv: 'an iv',
          };
          sinon.stub(mockEncryptor, 'isVaultUpdated').returns(false);
          sinon
            .stub(mockEncryptor, 'encryptWithKey')
            .resolves(mockEncryptionResult);

          await keyringController.unlockKeyrings(PASSWORD);
          const updatedVault = keyringController.store.getState().vault;

          expect(initialVault).not.toBe(updatedVault);
          expect(updatedVault).toBe(
            JSON.stringify({
              ...mockEncryptionResult,
              salt: MOCK_ENCRYPTION_SALT,
            }),
          );
        });
      });

      describe(`with cacheEncryptionKey = true and encryptionKey is set`, () => {
        it('should not update the vault', async () => {
          const mockEncryptor = new MockEncryptor();
          const keyringController = await initializeKeyringController({
            password: PASSWORD,
            constructorOptions: {
              cacheEncryptionKey: true,
              encryptor: mockEncryptor,
            },
          });
          const initialVault = keyringController.store.getState().vault;
          sinon.stub(mockEncryptor, 'isVaultUpdated').returns(false);

          await keyringController.unlockKeyrings(PASSWORD);
          const updatedVault = keyringController.store.getState().vault;

          expect(initialVault).toBe(updatedVault);
        });
      });

      describe(`with cacheEncryptionKey = false`, () => {
        it('should update the vault', async () => {
          const mockEncryptor = new MockEncryptor();
          const keyringController = await initializeKeyringController({
            password: PASSWORD,
            constructorOptions: {
              cacheEncryptionKey: false,
              encryptor: mockEncryptor,
            },
          });
          const initialVault = keyringController.store.getState().vault;
          const updatedVaultMock =
            '{"vault": "updated_vault_detail", "salt": "salt"}';
          sinon.stub(mockEncryptor, 'isVaultUpdated').returns(false);
          sinon.stub(mockEncryptor, 'encrypt').resolves(updatedVaultMock);

          await keyringController.unlockKeyrings(PASSWORD);
          const updatedVault = keyringController.store.getState().vault;

          expect(initialVault).not.toBe(updatedVault);
          expect(updatedVault).toBe(updatedVaultMock);
        });
      });
    });
  });

  describe('verifyPassword', () => {
    it('throws an error if no encrypted vault is in controller state', async () => {
      const keyringController = await initializeKeyringController();

      await expect(async () =>
        keyringController.verifyPassword('test'),
      ).rejects.toThrow('Cannot unlock without a previous vault.');
    });

    it('does not throw if a vault exists in state', async () => {
      const keyringController = await initializeKeyringController();

      await keyringController.createNewVaultWithKeyring(PASSWORD, {
        type: KeyringType.HD,
        opts: {
          mnemonic: walletOneSeedWords,
          numberOfAccounts: 1,
        },
      });

      expect(async () =>
        keyringController.verifyPassword(PASSWORD),
      ).not.toThrow();
    });
  });

  describe('addNewAccount', () => {
    it('adds a new account to the keyring it receives as an argument', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
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
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      const address = '0x01560cd3bac62cc6d7e6380600d9317363400896';
      const privateKey =
        '0xb8a9c05beeedb25df85f8d641538cbffedf67216048de9c678ee26260eb91952';

      const keyring = await keyringController.addNewKeyring(
        KeyringType.Simple,
        [privateKey],
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
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      const address = '0x01560cd3bac62cc6d7e6380600d9317363400896';
      const privateKey =
        '0xb8a9c05beeedb25df85f8d641538cbffedf67216048de9c678ee26260eb91952';
      await keyringController.addNewKeyring(KeyringType.Simple, [privateKey]);
      const appKeyAddress = await keyringController.getAppKeyAddress(
        address,
        'someapp.origin.io',
      );

      const privateAppKey = await keyringController.exportAppKeyForAddress(
        address,
        'someapp.origin.io',
      );

      const wallet = Wallet.fromPrivateKey(Buffer.from(privateAppKey, 'hex'));
      const recoveredAddress = bytesToHex(wallet.getAddress());

      expect(recoveredAddress).toBe(appKeyAddress);
      expect(privateAppKey).not.toBe(privateKey);
    });
  });

  describe('getKeyringForAccount', () => {
    it('throws error when address is not provided', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      await expect(
        // @ts-expect-error Missing other required permission types.
        keyringController.getKeyringForAccount(undefined),
      ).rejects.toThrow(
        new Error(
          `${KeyringControllerError.NoKeyring}. Error info: The address passed in is invalid/empty`,
        ),
      );
    });

    it('throws error when address is invalid', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      await expect(
        keyringController.getKeyringForAccount('0x04'),
      ).rejects.toThrow(
        new Error(
          `${KeyringControllerError.NoKeyring}. Error info: The address passed in is invalid/empty`,
        ),
      );
    });

    it('throws error when there are no keyrings', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      keyringController.keyrings = [];
      await expect(
        keyringController.getKeyringForAccount(
          '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
        ),
      ).rejects.toThrow(
        new Error(
          `${KeyringControllerError.NoKeyring}. Error info: There are no keyrings`,
        ),
      );
    });

    it('throws error when there are no matching keyrings', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      keyringController.keyrings = [
        {
          // @ts-expect-error there's only a need to mock the getAccounts method for this test.
          async getAccounts() {
            return Promise.resolve([1, 2, 3]);
          },
        },
      ];

      await expect(
        keyringController.getKeyringForAccount(
          '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
        ),
      ).rejects.toThrow(
        new Error(
          `${KeyringControllerError.NoKeyring}. Error info: There are keyrings, but none match the address`,
        ),
      );
    });
  });

  describe('cacheEncryptionKey', () => {
    it('sets encryption key data upon submitPassword', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
        constructorOptions: {
          cacheEncryptionKey: true,
        },
      });
      await keyringController.submitPassword(PASSWORD);

      expect(keyringController.password).toBe(PASSWORD);
      expect(keyringController.memStore.getState().encryptionSalt).toBe(
        MOCK_ENCRYPTION_SALT,
      );
      expect(keyringController.memStore.getState().encryptionKey).toStrictEqual(
        expect.stringMatching('.+'),
      );
    });

    it('unlocks the keyrings with valid information', async () => {
      const mockEncryptor = new MockEncryptor();
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
        constructorOptions: {
          cacheEncryptionKey: true,
          encryptor: mockEncryptor,
        },
      });
      const returnValue = await mockEncryptor.decryptWithKey('', '');
      const decryptWithKeyStub = sinon
        .stub(mockEncryptor, 'decryptWithKey')
        .resolves(returnValue);

      keyringController.store.updateState({ vault: MOCK_ENCRYPTION_DATA });

      await keyringController.setLocked();

      await keyringController.submitEncryptionKey(
        MOCK_ENCRYPTION_KEY,
        MOCK_ENCRYPTION_SALT,
      );

      expect(decryptWithKeyStub.calledOnce).toBe(true);
      expect(keyringController.keyrings).toHaveLength(1);
    });

    it('should not load keyrings when invalid encryptionKey format', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
        constructorOptions: {
          cacheEncryptionKey: true,
        },
      });
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
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
        constructorOptions: {
          cacheEncryptionKey: true,
        },
      });
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
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
        constructorOptions: {
          cacheEncryptionKey: true,
        },
      });
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
      await keyringController.addNewKeyring(KeyringType.Simple, [
        account.privateKey,
      ]);
      expect(await keyringController.getAccounts()).toHaveLength(4);

      // remove that account that we just added
      await keyringController.removeAccount(account.publicKey);
      expect(await keyringController.getAccounts()).toHaveLength(3);
    });

    it('triggers an error when trying to persist without password or encryption key', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      delete keyringController.password;
      await expect(keyringController.persistAllKeyrings()).rejects.toThrow(
        'Cannot persist vault without password and encryption key',
      );
    });

    it('cleans up login artifacts upon lock', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
        constructorOptions: {
          cacheEncryptionKey: true,
        },
      });
      await keyringController.submitPassword(PASSWORD);
      expect(keyringController.password).toBe(PASSWORD);
      expect(
        keyringController.memStore.getState().encryptionSalt,
      ).toStrictEqual(expect.stringMatching('.+'));

      expect(keyringController.memStore.getState().encryptionKey).toStrictEqual(
        expect.stringMatching('.+'),
      );

      await keyringController.setLocked();

      expect(
        keyringController.memStore.getState().encryptionSalt,
      ).toBeUndefined();
      expect(keyringController.password).toBeUndefined();
      expect(
        keyringController.memStore.getState().encryptionKey,
      ).toBeUndefined();
    });
  });

  describe('exportAccount', () => {
    it('returns the private key for the public key it is passed', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });
      await keyringController.createNewVaultWithKeyring(PASSWORD, {
        type: KeyringType.HD,
        opts: {
          mnemonic: walletOneSeedWords,
          numberOfAccounts: 1,
        },
      });
      const privateKey = await keyringController.exportAccount(
        // @ts-expect-error this value should never be undefined in this specific context.
        walletOneAddresses[0],
      );
      expect(privateKey).toStrictEqual(walletOnePrivateKey[0]);
    });
  });

  describe('signing methods', () => {
    it('signMessage', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
        seedPhrase: walletOneSeedWords,
      });
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

    it('prepares a base UserOperation', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });

      await keyringController.addNewKeyring('Keyring Mock With Init');
      const sender = '0x998B3FBB8159aF51a827DBf43A8054A5A3A28c95';
      const baseTxs = [
        {
          to: '0x8cBC0EA145491fe83104abA9ef916f8632367227',
          value: '0x0',
          data: '0x',
        },
      ];

      const baseUserOp = {
        callData: '0x7064',
        initCode: '0x22ff',
        nonce: '0x1',
        gasLimits: {
          callGasLimit: '0x58a83',
          verificationGasLimit: '0xe8c4',
          preVerificationGas: '0xc57c',
        },
        dummySignature: '0x0000',
        dummyPaymasterAndData: '0x',
        bundlerUrl: 'https://bundler.example.com/rpc',
      };

      jest
        .spyOn(KeyringMockWithInit.prototype, 'getAccounts')
        .mockResolvedValueOnce([sender]);

      jest
        .spyOn(KeyringMockWithInit.prototype, 'prepareUserOperation')
        .mockResolvedValueOnce(baseUserOp);

      const result = await keyringController.prepareUserOperation(
        sender,
        baseTxs,
      );

      expect(result).toStrictEqual(baseUserOp);
    });

    it('patches an UserOperation', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });

      await keyringController.addNewKeyring('Keyring Mock With Init');
      const sender = '0x998B3FBB8159aF51a827DBf43A8054A5A3A28c95';
      const userOp = {
        sender: '0x4584d2B4905087A100420AFfCe1b2d73fC69B8E4',
        nonce: '0x1',
        initCode: '0x',
        callData: '0x7064',
        callGasLimit: '0x58a83',
        verificationGasLimit: '0xe8c4',
        preVerificationGas: '0xc57c',
        maxFeePerGas: '0x87f0878c0',
        maxPriorityFeePerGas: '0x1dcd6500',
        paymasterAndData: '0x',
        signature: '0x',
      };

      const patch = {
        paymasterAndData: '0x1234',
      };

      jest
        .spyOn(KeyringMockWithInit.prototype, 'getAccounts')
        .mockResolvedValueOnce([sender]);

      jest
        .spyOn(KeyringMockWithInit.prototype, 'patchUserOperation')
        .mockResolvedValueOnce(patch);

      const result = await keyringController.patchUserOperation(sender, userOp);
      expect(result).toStrictEqual(patch);
    });

    it('signs an UserOperation', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
      });

      await keyringController.addNewKeyring('Keyring Mock With Init');
      const sender = '0x998B3FBB8159aF51a827DBf43A8054A5A3A28c95';
      const userOp = {
        sender: '0x4584d2B4905087A100420AFfCe1b2d73fC69B8E4',
        nonce: '0x1',
        initCode: '0x',
        callData: '0x7064',
        callGasLimit: '0x58a83',
        verificationGasLimit: '0xe8c4',
        preVerificationGas: '0xc57c',
        maxFeePerGas: '0x87f0878c0',
        maxPriorityFeePerGas: '0x1dcd6500',
        paymasterAndData: '0x',
        signature: '0x',
      };

      const signature = '0x1234';

      jest
        .spyOn(KeyringMockWithInit.prototype, 'getAccounts')
        .mockResolvedValueOnce([sender]);

      jest
        .spyOn(KeyringMockWithInit.prototype, 'signUserOperation')
        .mockResolvedValueOnce(signature);

      const result = await keyringController.signUserOperation(sender, userOp);
      expect(result).toStrictEqual(signature);
    });

    it("throws when the keyring doesn't implement prepareUserOperation", async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
        seedPhrase: walletOneSeedWords,
      });

      const txs = [
        {
          to: '0x8cBC0EA145491fe83104abA9ef916f8632367227',
          value: '0x0',
          data: '0x',
        },
      ];

      const result = keyringController.prepareUserOperation(
        walletOneAddresses[0] as string,
        txs,
      );

      await expect(result).rejects.toThrow(
        'KeyringController - The keyring for the current address does not support the method prepareUserOperation.',
      );
    });

    it("throws when the keyring doesn't implement patchUserOperation", async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
        seedPhrase: walletOneSeedWords,
      });

      const userOp = {
        sender: '0x4584d2B4905087A100420AFfCe1b2d73fC69B8E4',
        nonce: '0x1',
        initCode: '0x',
        callData: '0x7064',
        callGasLimit: '0x58a83',
        verificationGasLimit: '0xe8c4',
        preVerificationGas: '0xc57c',
        maxFeePerGas: '0x87f0878c0',
        maxPriorityFeePerGas: '0x1dcd6500',
        paymasterAndData: '0x',
        signature: '0x',
      };

      const result = keyringController.patchUserOperation(
        walletOneAddresses[0] as string,
        userOp,
      );

      await expect(result).rejects.toThrow(
        'KeyringController - The keyring for the current address does not support the method patchUserOperation.',
      );
    });

    it("throws when the keyring doesn't implement signUserOperation", async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
        seedPhrase: walletOneSeedWords,
      });

      const userOp = {
        sender: '0x4584d2B4905087A100420AFfCe1b2d73fC69B8E4',
        nonce: '0x1',
        initCode: '0x',
        callData: '0x7064',
        callGasLimit: '0x58a83',
        verificationGasLimit: '0xe8c4',
        preVerificationGas: '0xc57c',
        maxFeePerGas: '0x87f0878c0',
        maxPriorityFeePerGas: '0x1dcd6500',
        paymasterAndData: '0x',
        signature: '0x',
      };

      const result = keyringController.signUserOperation(
        walletOneAddresses[0] as string,
        userOp,
      );

      await expect(result).rejects.toThrow(
        'KeyringController - The keyring for the current address does not support the method signUserOperation.',
      );
    });

    it('signPersonalMessage', async () => {
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
        seedPhrase: walletOneSeedWords,
      });
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
      const keyringController = await initializeKeyringController({
        password: PASSWORD,
        seedPhrase: walletOneSeedWords,
      });
      const result = await keyringController.getEncryptionPublicKey(
        // @ts-expect-error this value should never be undefined in this specific context.
        walletOneAddresses[0],
      );
      expect(result).toBe('SR6bQ1m3OTHvI1FLwcGzm+Uk6hffoFPxsQ0DTOeKMEc=');
    });

    describe('signTypedMessage', () => {
      it('signs a v1 typed message if no version is provided', async () => {
        const keyringController = await initializeKeyringController({
          password: PASSWORD,
          seedPhrase: walletOneSeedWords,
        });
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
        expect(result).toMatchInlineSnapshot(
          `"0x089bb031f5bf2b2cbdf49eb2bb37d6071ab71f950b9dc49e398ca2ba984aca3c189b3b8de6c14c56461460dd9f59443340f1b144aeeff73275ace41ac184e54f1c"`,
        );
      });

      it('signs a v1 typed message', async () => {
        const keyringController = await initializeKeyringController({
          password: PASSWORD,
          seedPhrase: walletOneSeedWords,
        });
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
        const result = await keyringController.signTypedMessage(inputParams, {
          version: 'V1',
        });
        expect(result).toMatchInlineSnapshot(
          `"0x089bb031f5bf2b2cbdf49eb2bb37d6071ab71f950b9dc49e398ca2ba984aca3c189b3b8de6c14c56461460dd9f59443340f1b144aeeff73275ace41ac184e54f1c"`,
        );
      });

      it('signs a v3 typed message', async () => {
        const keyringController = await initializeKeyringController({
          password: PASSWORD,
          seedPhrase: walletOneSeedWords,
        });
        const typedData = {
          types: {
            EIP712Domain: [
              { name: 'name', type: 'string' },
              { name: 'version', type: 'string' },
              { name: 'chainId', type: 'uint256' },
              { name: 'verifyingContract', type: 'address' },
            ],
            Person: [
              { name: 'name', type: 'string' },
              { name: 'wallet', type: 'address' },
            ],
            Mail: [
              { name: 'from', type: 'Person' },
              { name: 'to', type: 'Person' },
              { name: 'contents', type: 'string' },
            ],
          },
          primaryType: 'Mail' as const,
          domain: {
            name: 'Ether Mail',
            version: '1',
            chainId: 1,
            verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
          },
          message: {
            from: {
              name: 'Cow',
              wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
            },
            to: {
              name: 'Bob',
              wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
            },
            contents: 'Hello, Bob!',
          },
        };
        const inputParams = {
          from: mockAddress,
          data: typedData,
          origin: 'https://metamask.github.io',
        };
        const result = await keyringController.signTypedMessage(inputParams, {
          version: 'V3',
        });
        expect(result).toMatchInlineSnapshot(
          `"0x1c496cc9f42fc8f8a30bef731b20a1b8722569473643c0cd92e3e494be9c62725043275475ca81d9691c6c31e188dfbd5884b4352ba21bd99f38e6d357c738b81b"`,
        );
      });

      it('signs a v4 typed message', async () => {
        const keyringController = await initializeKeyringController({
          password: PASSWORD,
          seedPhrase: walletOneSeedWords,
        });
        const typedData = {
          types: {
            EIP712Domain: [
              { name: 'name', type: 'string' },
              { name: 'version', type: 'string' },
              { name: 'chainId', type: 'uint256' },
              { name: 'verifyingContract', type: 'address' },
            ],
            Person: [
              { name: 'name', type: 'string' },
              { name: 'wallet', type: 'address[]' },
            ],
            Mail: [
              { name: 'from', type: 'Person' },
              { name: 'to', type: 'Person[]' },
              { name: 'contents', type: 'string' },
            ],
          },
          primaryType: 'Mail' as const,
          domain: {
            name: 'Ether Mail',
            version: '1',
            chainId: 1,
            verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
          },
          message: {
            from: {
              name: 'Cow',
              wallet: [
                '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
                '0xDD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
              ],
            },
            to: [
              {
                name: 'Bob',
                wallet: ['0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB'],
              },
            ],
            contents: 'Hello, Bob!',
          },
        };
        const inputParams = {
          from: mockAddress,
          data: typedData,
          origin: 'https://metamask.github.io',
        };
        const result = await keyringController.signTypedMessage(inputParams, {
          version: 'V4',
        });
        expect(result).toMatchInlineSnapshot(
          `"0xe8d6baed58a611bbe247aecf2a8cbe0e3877bf1828c6bd9402749ce9e16f557a5669102bd05f0c3e33c200ff965abf07dab9299cb4bcdc504c9a695205240b321c"`,
        );
      });
    });
  });
});
