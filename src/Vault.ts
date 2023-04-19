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
  lastAccessedAt: Date;
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
  additionalData: Uint8Array,
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

  /**
   * Check if the vault is unlocked.
   *
   * @returns True if the vault is unlocked, false otherwise.
   */
  get isLocked(): boolean {
    return this.#cachedMasterKey === null;
  }

  #assertUnlocked() {
    if (this.isLocked) {
      throw new Error('Vault is locked');
    }
  }

  /**
   * Store a new value in the vault.
   *
   * @param key - The key to store the value under.
   * @param value - The value to store.
   */
  async store(key: string, value: Json): Promise<void> {
    this.#assertUnlocked();

    const now = new Date();
    const encryptionKey = await this.#deriveMasterKey(['test']);
    const additionalData = jsonToBytes(['vaultId', this.id]);

    this.#entries.set(key, {
      id: uuidv4(),
      value: await encryptData(
        encryptionKey,
        jsonToBytes(value),
        additionalData,
      ),
      createdAt: now,
      lastAccessedAt: now,
      lastUpdatedAt: now,
    });
  }

  /**
   * Update an existing value in the vault.
   *
   * @param key - The key to update.
   * @param value - The new value.
   */
  async update(key: string, value: Json): Promise<void> {
    const current = this.#entries.get(key);
    if (current === undefined) {
      throw new Error('Key does not exist');
    }

    this.#entries.set(key, {
      ...current,
      value, // FIXME: encrypt value
      lastUpdatedAt: new Date(),
    });
  }

  /**
   * Get the value associated with a key.
   *
   * @param key - The key to get the value of.
   * @returns The value associated with the key.
   */
  async get(key: string): Promise<Json> {
    const entry = this.#entries.get(key);
    if (entry === undefined) {
      throw new Error('Key does not exist');
    }

    return entry.value; // FIXME: decrypt value
  }

  /**
   * Delete a vault entry.
   *
   * @param key - The key to delete.
   */
  async delete(key: string): Promise<void> {
    if (!this.#entries.has(key)) {
      throw new Error('Key does not exist');
    }

    this.#entries.delete(key);
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
    if (this.#wrappedMasterKey === null) {
      throw new Error('Vault is not initialized');
    }

    const wrappingKey = await deriveWrappingKey(password, this.#passwordSalt);
    this.#cachedMasterKey = await unwrapMasterKey(
      wrappingKey,
      this.#wrappedMasterKey,
      jsonToBytes(['vaultId', this.id]),
    );
  }

  /**
   * Derive the Master Key given a list of infos.
   *
   * @param infos - Derivation infos.
   * @returns The handler to the derived key.
   */
  async #deriveMasterKey(infos: string[]): Promise<CryptoKey> {
    // Make sure that at least one info is provided.
    if (infos.length === 0) {
      throw new Error('No infos provided');
    }

    // TypeScript isn't happy if we use `isLocked` here, it will say that
    // `#masterKey` can be null when we try to await on it.
    if (this.#cachedMasterKey === null) {
      throw new Error('Vault is locked');
    }

    let derivedKey = this.#cachedMasterKey;
    for (const [i, info] of infos.entries()) {
      let usages: KeyUsage[];
      let params: HmacKeyGenParams | AesKeyGenParams;

      // Only the last node in the derivation chain can be used to encrypt or
      // decrypt data, all intermediate nodes can only be used to derive keys.
      if (i === infos.length - 1) {
        usages = ['encrypt', 'decrypt'];
        params = {
          name: 'AES-GCM',
          length: 256,
        };
      } else {
        usages = ['deriveKey'];
        params = {
          name: 'HMAC',
          hash: 'SHA-256',
          length: 256,
        };
      }

      // Derive the next key from the previous one.
      derivedKey = await crypto.subtle.deriveKey(
        {
          name: 'HKDF',
          hash: 'SHA-256',
          info: Buffer.from(`metamask:vault:${i}:${info}`),
        },
        derivedKey,
        params,
        false,
        usages,
      );
    }

    return derivedKey;
  }

  /**
   * Derive the Wrapping Key given a password.
   *
   * @param password - The password to derive the wrapping key from.
   * @returns The handler to the Wrapping Key.
   */
  async #getWrappingKey(password: string): Promise<CryptoKey> {
    const rawKey = await crypto.subtle.importKey(
      'raw',
      stringToBytes(password),
      'PBKDF2',
      false,
      ['deriveKey'],
    );

    const wrappingKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        hash: 'SHA-256',
        salt: this.#passwordSalt,
        iterations: 600_000,
      },
      rawKey,
      {
        name: 'AES-GCM',
        length: 256,
      },
      true,
      ['deriveKey'],
    );

    return wrappingKey;
  }
}

export const exportedForTesting = {
  stringToBytes,
  jsonToBytes,
  randomBytes,
  generateMasterKey,
  importPassword,
  deriveWrappingKey,
  unwrapMasterKey,
  encryptData,
  decryptData,
};
