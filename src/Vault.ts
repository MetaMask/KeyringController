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
  modifiedAt: Date;
  createdAt: Date;
  value: EncryptedData;
};

export class VaultError extends Error {}

// ----------------------------------------------------------------------------
// Util functions

/**
 * Encode binary data in base64.
 *
 * @param data - Data to encode.
 * @returns The encoded data.
 */
function b64Encode(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data));
}

/**
 * Decode binary data from a base64 string.
 *
 * @param data - Encoded data.
 * @returns The decoded data.
 */
function b64Decode(data: string): Uint8Array {
  // eslint-disable-next-line id-length
  return new Uint8Array([...atob(data)].map((c) => c.charCodeAt(0)));
}

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
 * Ensure that a value is not null.
 *
 * @param value - Value to check.
 * @param cause - Error cause in case value is null.
 * @returns The value if it is not null.
 */
function ensureNotNull<T>(value: T | null, cause: string): T {
  if (value === null) {
    throw new VaultError(cause);
  }
  return value;
}

/**
 * Ensure that a Uint8Array has the expected length.
 *
 * @param data - Data array.
 * @param length - Expected length.
 * @returns The same data array.
 */
function ensureLength(data: Uint8Array, length: number): Uint8Array {
  if (data.length !== length) {
    throw new VaultError(
      `Invalid length: expected ${length}, got ${data.length}`,
    );
  }
  return data;
}

/**
 * Ensure that a value is a Uint8Array.
 *
 * @param value - Value to check or convert.
 * @returns A value whose type is Uint8Array.
 */
function ensureBytes(value: string | Uint8Array): Uint8Array {
  if (typeof value === 'string') {
    return stringToBytes(value);
  }
  return value;
}

// ----------------------------------------------------------------------------
// Crypto functions

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
 * Unwrap and re-wrap a key.
 *
 * @param unwrappingKey - Unwrapping key.
 * @param wrappingKey - Wrapping key.
 * @param wrappedKey - Key to re-wrap.
 * @param additionalData - Additional data.
 * @returns The re-wrapped key.
 */
async function reWrapMasterKey(
  unwrappingKey: CryptoKey,
  wrappingKey: CryptoKey,
  wrappedKey: EncryptedData,
  additionalData?: Uint8Array,
): Promise<EncryptedData> {
  const rawKey = await decryptData(unwrappingKey, wrappedKey, additionalData);
  return encryptData(wrappingKey, rawKey, additionalData);
}

/**
 * Derive an encryption key from the master key.
 *
 * @param masterKey - Master key to derived from.
 * @param info - Derivation information.
 * @param salt - Optional salt to be used in the derivation.
 * @returns The handler to the derived key.
 */
async function deriveEncryptionKey(
  masterKey: CryptoKey,
  info: string | Uint8Array,
  salt?: Uint8Array,
): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      info: ensureBytes(info),
      salt: salt ?? new Uint8Array(),
    },
    masterKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['encrypt', 'decrypt'],
  );
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

/**
 * Decrypt and re-encrypt data.
 *
 * @param decryptionKey - Decryption key.
 * @param encryptionKey - Encryption key.
 * @param ciphertext - Encrypted data.
 * @param additionalData - Additional data.
 * @returns The re-encrypted data.
 */
async function reEncryptData(
  decryptionKey: CryptoKey,
  encryptionKey: CryptoKey,
  ciphertext: EncryptedData,
  additionalData?: Uint8Array,
): Promise<EncryptedData> {
  const data = await decryptData(decryptionKey, ciphertext, additionalData);
  return encryptData(encryptionKey, data, additionalData);
}

// ----------------------------------------------------------------------------
// Main class

type EncryptedDataState = { nonce: string; data: string };

type VaultEntryState = {
  id: string;
  value: EncryptedDataState;
  createdAt: string;
  modifiedAt: string;
};

type VaultState = {
  id: string;
  salt: string;
  key: EncryptedDataState;
  entries: Record<string, VaultEntryState>;
};

export class Vault<Value extends Json> {
  public readonly id: string;

  #entries: Map<string, VaultEntry>;

  #passwordSalt: Uint8Array;

  #wrappedMasterKey: EncryptedData | null;

  #cachedMasterKey: CryptoKey | null;

  constructor(state?: VaultState) {
    this.#entries = new Map<string, VaultEntry>();

    if (state === undefined) {
      this.id = uuidv4();
      this.#passwordSalt = randomBytes(32);
      this.#wrappedMasterKey = null;
    } else {
      this.id = state.id;
      this.#passwordSalt = ensureLength(b64Decode(state.salt), 32);
      this.#wrappedMasterKey = {
        nonce: b64Decode(state.key.nonce),
        data: b64Decode(state.key.data),
      };
      for (const [key, entry] of Object.entries(state.entries)) {
        this.#entries.set(key, {
          ...entry,
          createdAt: new Date(entry.createdAt),
          modifiedAt: new Date(entry.modifiedAt),
          value: {
            nonce: ensureLength(b64Decode(entry.value.nonce), 12),
            data: b64Decode(entry.value.data),
          },
        });
      }
    }

    this.#cachedMasterKey = null;
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
   * Get the wrapped master key.
   *
   * This method will throw an error if the vault wasn't initialized.
   *
   * @returns The wrapped master key.
   */
  #getWrappedMasterKey(): EncryptedData {
    return ensureNotNull(this.#wrappedMasterKey, 'Vault is not initialized');
  }

  /**
   * Get the master key handler.
   *
   * This method will throw an error if the vault is locked.
   *
   * @returns The master key handler.
   */
  #getCachedMasterKey(): CryptoKey {
    return ensureNotNull(this.#cachedMasterKey, 'Vault is locked');
  }

  /**
   * Assert that the vault is initialized.
   */
  #assertIsInitialized(): void {
    this.#getWrappedMasterKey();
  }

  /**
   * Assert that the vault is unlocked.
   */
  #assertIsUnlocked(): void {
    this.#getCachedMasterKey();
  }

  /**
   * Assert that the vault is initialized and unlocked.
   */
  #assertIsOperational(): void {
    this.#assertIsInitialized();
    this.#assertIsUnlocked();
  }

  /**
   * Add a new value to the vault.
   *
   * @param key - Key to store the value under.
   * @param value - Value to be encrypted and added to the vault.
   */
  async set(key: string, value: Value): Promise<void> {
    this.#assertIsOperational();

    const now = new Date();
    const current = this.#entries.get(key);
    const entryId = current?.id ?? uuidv4();
    const encryptionKey = await this.#deriveEncryptionKey(entryId, key);

    this.#entries.set(key, {
      id: entryId,
      value: await encryptData(encryptionKey, jsonToBytes(value)),
      createdAt: current?.createdAt ?? now,
      modifiedAt: now,
    });
  }

  /**
   * Get the value associated with a key.
   *
   * @param key - The key to get the value of.
   * @returns The value associated with the key or undefined if the key does
   * not exist.
   */
  async get(key: string): Promise<Value | undefined> {
    this.#assertIsOperational();

    // Return undefined if the key does not exist.
    const entry = this.#entries.get(key);
    if (entry === undefined) {
      return undefined;
    }

    // Decrypt and parse the value back to an object.
    const decryptionKey = await this.#deriveEncryptionKey(entry.id, key);
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
    this.#assertIsOperational();
    return this.#entries.has(key);
  }

  /**
   * Delete a vault entry.
   *
   * @param key - The key to delete.
   * @returns True if the entry existed, false otherwise.
   */
  delete(key: string): boolean {
    this.#assertIsOperational();
    return this.#entries.delete(key);
  }

  /**
   * Change the vault master key.
   *
   * @param password - Vault password.
   */
  async rekey(password: string): Promise<void> {
    const wrappingKey = await deriveWrappingKey(password, this.#passwordSalt);
    const { wrapped: mkWrapped, handler: mkHandler } = await generateMasterKey(
      wrappingKey,
      jsonToBytes(['vaultId', this.id]),
    );

    const newEntries = new Map<string, VaultEntry>();
    for (const [key, entry] of this.#entries.entries()) {
      newEntries.set(key, {
        ...entry,
        value: await reEncryptData(
          await this.#deriveEncryptionKey(entry.id, key),
          await this.#deriveEncryptionKey(entry.id, key, mkHandler),
          entry.value,
        ),
      });
    }

    // Update all fields "at once".
    this.#cachedMasterKey = mkHandler;
    this.#wrappedMasterKey = mkWrapped;
    this.#entries = newEntries;
  }

  /**
   * Change the vault password and salt.
   *
   * @param oldPassword - Current password.
   * @param newPassword - New password.
   */
  async changePassword(
    oldPassword: string,
    newPassword: string,
  ): Promise<void> {
    const oldWrappingKey = await deriveWrappingKey(
      oldPassword,
      this.#passwordSalt,
    );

    const newPasswordSalt = randomBytes(32);
    const newWrappingKey = await deriveWrappingKey(
      newPassword,
      newPasswordSalt,
    );

    // Update the password salt _after_ setting the wrapped master key.
    this.#wrappedMasterKey = await reWrapMasterKey(
      oldWrappingKey,
      newWrappingKey,
      this.#getWrappedMasterKey(),
      jsonToBytes(['vaultId', this.id]),
    );
    this.#passwordSalt = newPasswordSalt;
  }

  /**
   * Lock the vault.
   *
   * Note from the Web Crypto API specification:
   *
   * > This specification places no normative requirements on how
   * > implementations handle key material once all references to it go away.
   * > That is, conforming user agents are not required to zeroize key
   * > material, and it may still be accessible on device storage or device
   * > memory, even after all references to the CryptoKey have gone away.
   */
  lock(): void {
    this.#cachedMasterKey = null;
  }

  /**
   * Unlock the vault and cache the Master Key.
   *
   * @param password - Password to unlock the vault.
   * @param testOnly - Try to unlock the vault but don't cache the master key.
   */
  async unlock(password: string, testOnly = false): Promise<void> {
    // We must get the wrapped master key _outside_ the try-catch block below
    // to distinguish an uninitialized vault from a wrong password.
    const wrappedMasterKey = this.#getWrappedMasterKey();
    const wrappingKey = await deriveWrappingKey(password, this.#passwordSalt);

    try {
      const masterKey = await unwrapMasterKey(
        wrappingKey,
        wrappedMasterKey,
        jsonToBytes(['vaultId', this.id]),
      );

      if (!testOnly) {
        this.#cachedMasterKey = masterKey;
      }
    } catch (error) {
      throw new VaultError('Invalid vault password');
    }
  }

  /**
   * Check if the provided password is correct.
   *
   * @param password - Password to verify.
   * @returns True if the password is correct, false otherwise.
   */
  async verifyPassword(password: string): Promise<boolean> {
    try {
      await this.unlock(password, true);
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Derive the Master Key given a derivation information.
   *
   * If a master key is provided, it will be used instead of the cached master
   * key.
   *
   * @param entryId - ID of the vault entry.
   * @param key - Key of the vault entry.
   * @param masterKey - Optional master key.
   * @returns The handler to the derived key.
   */
  async #deriveEncryptionKey(
    entryId: string,
    key: string,
    masterKey?: CryptoKey,
  ): Promise<CryptoKey> {
    return deriveEncryptionKey(
      masterKey ?? this.#getCachedMasterKey(),
      `metamask:vault:${this.id}:entry:${entryId}:key:${key}`,
    );
  }

  /**
   * Get the vault's serialized state.
   *
   * @returns The vault's serialized state.
   */
  getState(): VaultState {
    const encodeEncrypted = (encrypted: EncryptedData) => {
      return {
        nonce: b64Encode(encrypted.nonce),
        data: b64Encode(encrypted.data),
      };
    };

    const entries = new Map<string, VaultEntryState>();
    for (const [key, value] of this.#entries.entries()) {
      entries.set(key, {
        ...value,
        value: encodeEncrypted(value.value),
        modifiedAt: value.modifiedAt.toISOString(),
        createdAt: value.modifiedAt.toISOString(),
      });
    }

    return {
      id: this.id,
      salt: b64Encode(this.#passwordSalt),
      key: encodeEncrypted(this.#getWrappedMasterKey()),
      entries: Object.fromEntries(entries),
    };
  }
}

export const exportedForTesting = {
  b64Encode,
  b64Decode,
  stringToBytes,
  bytesToString,
  jsonToBytes,
  randomBytes,
  ensureLength,
  ensureNotNull,
  ensureBytes,
  generateMasterKey,
  importPassword,
  deriveWrappingKey,
  unwrapMasterKey,
  encryptData,
  decryptData,
  deriveEncryptionKey,
  reEncryptData,
  reWrapMasterKey,
};
