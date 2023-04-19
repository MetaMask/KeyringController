/* eslint-disable no-restricted-globals */
import { Json } from '@metamask/utils';
import { v4 as uuidv4 } from 'uuid';

// ----------------------------------------------------------------------------
// Types

type EncryptedData = {
  nonce: Uint8Array;
  data: Uint8Array;
};

type VaultEntry = {
  id: string;
  lastUpdatedAt: Date;
  createdAt: Date;
  value: EncryptedData;
};

// ----------------------------------------------------------------------------
// Private functions

/**
 * Convert a string to bytes.
 *
 * @param text - Text to convert.
 * @returns Bytes representing the text.
 */
function stringToBytes(text: string): Uint8Array {
  const encoder = new TextEncoder();
  return encoder.encode(text.normalize('NFC'));
}

/**
 * Decodes a byte array into a string.
 *
 * @param data - Bytes to decode.
 * @returns A string from the bytes.
 */
function bytesToString(data: Uint8Array): string {
  const decoder = new TextDecoder();
  return decoder.decode(data);
}

/**
 * Convert a JSON object to bytes.
 *
 * @param data - Object to convert.
 * @returns Bytes representing the JSON object.
 */
function jsonToBytes(data: Json): Uint8Array {
  return stringToBytes(JSON.stringify(data));
}

/**
 * Generate cryptographically secure random bytes.
 *
 * @param length - Number of bytes to generate.
 * @returns Cryptographically secure random bytes.
 */
function randomBytes(length: number): Uint8Array {
  const array = new Uint8Array(length);
  return crypto.getRandomValues(array);
}

/**
 * Ensure that a value is not null.
 *
 * @param value - Value to check.
 * @param message - Error message in case value is null.
 * @returns The value if it is not null.
 */
function ensureNotNull<T>(value: T | null, message: string): T {
  if (value === null) {
    throw new Error(message);
  }
  return value;
}

/**
 * Import a password as a raw key.
 *
 * @param password - Password to import.
 * @returns Password as a raw key.
 */
async function importPassword(password: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    stringToBytes(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
}

/**
 * Derive a wrapping key from a password and salt.
 *
 * The derived wrapping key actually have the encrypt and decrypt key usages
 * due to a limitation in Web Crypto API: the API doesn't allow KDF keys to be
 * generated, wrapped, nor unwrapped. So, as a workaround, we generate random
 * bits and import them as the master key.
 *
 * @param password - Password to derive the wrapping key from.
 * @param salt - Salt to be used in the key derivation.
 * @returns A wrapping key derived from the password and salt.
 */
async function deriveWrappingKey(
  password: string,
  salt: Uint8Array,
): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      hash: 'SHA-256',
      salt,
      iterations: 600_000,
    },
    await importPassword(password),
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Generate and wrap a random Master Key.
 *
 * @param wrappingKey - Wrapping key handler.
 * @param additionalData - Additional data.
 * @returns The wrapped Master Key and its handler.
 */
async function generateMasterKey(
  wrappingKey: CryptoKey,
  additionalData?: Uint8Array,
): Promise<{
  wrapped: EncryptedData;
  handler: CryptoKey;
}> {
  const rawKey = randomBytes(32);
  const wrappedKey = encryptData(wrappingKey, rawKey, additionalData);

  return {
    wrapped: await wrappedKey,
    handler: await crypto.subtle.importKey('raw', rawKey, 'HKDF', false, [
      'deriveKey',
    ]),
  };
}

/**
 * Unwrap and import the Master Key.
 *
 * @param unwrappingKey - Unwrapping key handler.
 * @param wrappedKey - Wrapped key data.
 * @param additionalData - Additional data.
 * @returns Handler to the Master Key.
 */
async function unwrapMasterKey(
  unwrappingKey: CryptoKey,
  wrappedKey: EncryptedData,
  additionalData?: Uint8Array,
): Promise<CryptoKey> {
  const rawKey = await decryptData(unwrappingKey, wrappedKey, additionalData);
  return crypto.subtle.importKey('raw', rawKey, 'HKDF', false, ['deriveKey']);
}

/**
 * Encrypt data with additional data.
 *
 * @param key - Encryption key handler.
 * @param data - Data to encrypt.
 * @param additionalData - Associated data.
 * @returns An object containing the nonce and the encrypted data.
 */
async function encryptData(
  key: CryptoKey,
  data: Uint8Array,
  additionalData?: Uint8Array,
): Promise<EncryptedData> {
  const iv = randomBytes(12);
  const ct = crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData,
      tagLength: 128,
    },
    key,
    data,
  );

  return { nonce: iv, data: new Uint8Array(await ct) };
}

/**
 * Decrypt data with additional data.
 *
 * @param key - Decryption key handler.
 * @param ciphertext - Ciphertext object with nonce and data.
 * @param additionalData - Additional data.
 * @returns The decrypted data.
 */
async function decryptData(
  key: CryptoKey,
  ciphertext: EncryptedData,
  additionalData?: Uint8Array,
): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ciphertext.nonce,
        additionalData,
        tagLength: 128,
      },
      key,
      ciphertext.data,
    ),
  );
}

// ----------------------------------------------------------------------------
// Public types

export class Vault {
  readonly id: string;

  #entries: Map<string, VaultEntry>;

  #passwordSalt: Uint8Array;

  #wrappedMasterKey: EncryptedData | null;

  #cachedMasterKey: CryptoKey | null;

  constructor() {
    this.id = uuidv4();
    this.#entries = new Map<string, VaultEntry>();
    this.#cachedMasterKey = null;
    this.#wrappedMasterKey = null;
    this.#passwordSalt = randomBytes(32);
  }

  /**
   * Initialize the vault after its creation.
   *
   * This method MUST to be called after the vault creation, otherwise the
   * master key will not be generated.
   *
   * @param password - Vault's password.
   */
  async init(password: string): Promise<void> {
    const wrappingKey = await deriveWrappingKey(password, this.#passwordSalt);
    const additionalData = jsonToBytes(['vaultId', this.id]);

    ({ wrapped: this.#wrappedMasterKey, handler: this.#cachedMasterKey } =
      await generateMasterKey(wrappingKey, additionalData));
  }

  // TODO: add a static method to create a vault from a serialized state.

  /**
   * Check if the vault is unlocked.
   *
   * @returns True if the vault is unlocked, false otherwise.
   */
  get isUnlocked(): boolean {
    return this.#cachedMasterKey !== null;
  }

  /**
   * Check if the vault was initialized.
   *
   * @returns True if the vault was initialized, false otherwise.
   */
  get isInitialized(): boolean {
    return this.#wrappedMasterKey !== null;
  }

  /**
   * Add a new value to the vault.
   *
   * @param key - Key to store the value under.
   * @param value - Value to be encrypted and added to the vault.
   */
  async set(key: string, value: Json): Promise<void> {
    const now = new Date();
    const current = this.#entries.get(key);
    const entryId = current?.id ?? uuidv4();
    const encryptionKey = await this.#deriveMasterKey(
      `metamask/vault/${this.id}/entry/${entryId}/key/${key}`,
    );

    this.#entries.set(key, {
      id: entryId,
      value: await encryptData(encryptionKey, jsonToBytes(value)),
      createdAt: current?.createdAt ?? now,
      lastUpdatedAt: now,
    });
  }

  /**
   * Get the value associated with a key.
   *
   * @param key - The key to get the value of.
   * @returns The value associated with the key or undefined if the key does
   * not exist.
   */
  async get(key: string): Promise<Json | undefined> {
    // Return undefined if the key does not exist.
    const entry = this.#entries.get(key);
    if (entry === undefined) {
      return undefined;
    }

    const decryptionKey = await this.#deriveMasterKey(
      `metamask/vault/${this.id}/entry/${entry.id}/key/${key}`,
    );

    // Decrypt and parse the value back to JSON.
    const data = await decryptData(decryptionKey, entry.value);
    return JSON.parse(bytesToString(data));
  }

  /**
   * Check if a key is present in the vault.
   *
   * @param key - Key to be checked.
   * @returns True if the key is present, false otherwise.
   */
  has(key: string): boolean {
    return this.#entries.has(key);
  }

  /**
   * Delete a vault entry.
   *
   * @param key - The key to delete.
   * @returns True if the entry existed, false otherwise.
   */
  delete(key: string): boolean {
    return this.#entries.delete(key);
  }

  /**
   * Lock the vault.
   */
  lock(): void {
    this.#cachedMasterKey = null;
  }

  /**
   * Unlock the vault.
   *
   * @param password - Password to unlock the vault.
   */
  async unlock(password: string): Promise<void> {
    const wrappingKey = await deriveWrappingKey(password, this.#passwordSalt);

    // Unwrap the master key and cache it.
    this.#cachedMasterKey = await unwrapMasterKey(
      wrappingKey,
      ensureNotNull(this.#wrappedMasterKey, 'Vault is not initialized'),
      jsonToBytes(['vaultId', this.id]),
    );
  }

  /**
   * Derive the Master Key given a derivation information.
   *
   * @param info - Derivation information.
   * @returns The handler to the derived key.
   */
  async #deriveMasterKey(info: string): Promise<CryptoKey> {
    // Make sure that info is provided.
    if (info === '') {
      throw new Error('Missing derivation information');
    }

    return crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        info: stringToBytes(info),
      },
      ensureNotNull(this.#cachedMasterKey, 'Vault is locked'),
      {
        name: 'AES-GCM',
        length: 256,
      },
      false,
      ['encrypt', 'decrypt'],
    );
  }
}

export const exportedForTesting = {
  stringToBytes,
  bytesToString,
  jsonToBytes,
  randomBytes,
  ensureNotNull,
  generateMasterKey,
  importPassword,
  deriveWrappingKey,
  unwrapMasterKey,
  encryptData,
  decryptData,
};
