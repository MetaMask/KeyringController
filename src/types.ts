import type {
  DetailedDecryptResult,
  DetailedEncryptionResult,
  EncryptionResult,
} from '@metamask/browser-passworder';
import type { Json, Keyring } from '@metamask/utils';

export type KeyringControllerArgs = {
  keyringBuilders?: { (): Keyring<Json>; type: string }[];
  cacheEncryptionKey: boolean;
  initState?: KeyringControllerPersistentState;
  encryptor?: GenericEncryptor | ExportableKeyEncryptor;
};

export type KeyringObject = {
  type: string;
  accounts: string[];
};

export type KeyringControllerPersistentState = {
  vault?: string;
};

export type KeyringControllerState = {
  keyrings: KeyringObject[];
  isUnlocked: boolean;
  encryptionKey?: string;
  encryptionSalt?: string;
};

export type SerializedKeyring = {
  type: string;
  data: Json;
};

/**
 * A generic encryptor interface that supports encrypting and decrypting
 * serializable data with a password.
 */
export type GenericEncryptor = {
  /**
   * Encrypts the given object with the given password.
   *
   * @param password - The password to encrypt with.
   * @param object - The object to encrypt.
   * @returns The encrypted string.
   */
  encrypt: <Obj>(password: string, object: Obj) => Promise<string>;
  /**
   * Decrypts the given encrypted string with the given password.
   *
   * @param password - The password to decrypt with.
   * @param encryptedString - The encrypted string to decrypt.
   * @returns The decrypted object.
   */
  decrypt: (password: string, encryptedString: string) => Promise<unknown>;
  /**
   * Optional vault migration helper. Updates the provided vault, re-encrypting
   * data with a safer algorithm if one is available.
   *
   * @param vault - The encrypted string to update.
   * @param password - The password to decrypt the vault with.
   * @returns The updated encrypted string.
   */
  updateVault?: (vault: string, password: string) => Promise<string>;
};

/**
 * An encryptor interface that supports encrypting and decrypting
 * serializable data with a password, and exporting and importing keys.
 */
export type ExportableKeyEncryptor = GenericEncryptor & {
  /**
   * Encrypts the given object with the given encryption key.
   *
   * @param key - The encryption key to encrypt with.
   * @param object - The object to encrypt.
   * @returns The encryption result.
   */
  encryptWithKey: <Obj>(key: unknown, object: Obj) => Promise<EncryptionResult>;
  /**
   * Encrypts the given object with the given password, and returns the
   * encryption result and the exported key string.
   *
   * @param password - The password to encrypt with.
   * @param object - The object to encrypt.
   * @param salt - The optional salt to use for encryption.
   * @returns The encrypted string and the exported key string.
   */
  encryptWithDetail: <Obj>(
    password: string,
    object: Obj,
    salt?: string,
  ) => Promise<DetailedEncryptionResult>;
  /**
   * Decrypts the given encrypted string with the given password.
   *
   * @param key - The encryption key to decrypt with.
   * @param encryptedString - The encrypted string to decrypt.
   * @returns The decrypted object.
   */
  decryptWithKey: (key: unknown, encryptedString: string) => Promise<unknown>;
  /**
   * Decrypts the given encrypted string with the given password, and returns
   * the decrypted object and the salt and exported key string used for
   * encryption.
   *
   * @param password - The password to decrypt with.
   * @param encryptedString - The encrypted string to decrypt.
   * @returns The decrypted object and the salt and exported key string used for
   * encryption.
   */
  decryptWithDetail: (
    password: string,
    encryptedString: string,
  ) => Promise<DetailedDecryptResult>;
  /**
   * Generates an encryption key from exported key string.
   *
   * @param key - The exported key string.
   * @returns The encryption key.
   */
  importKey: (key: string) => Promise<unknown>;
  /**
   * Vault migration helper. Updates the provided vault, re-encrypting
   * data with a safer algorithm if one is available and returning it along with
   * the updated exported key.
   *
   * @param encryptedData - The encrypted data to update.
   * @param password - The password to decrypt the vault with.
   * @returns The updated encrypted data and the updated exported key.
   */
  updateVaultWithDetail: (
    encryptedData: DetailedEncryptionResult,
    password: string,
  ) => Promise<DetailedEncryptionResult>;
};
