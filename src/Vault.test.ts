/* eslint-disable no-restricted-globals */
import { Json } from '@metamask/utils';
import { webcrypto as crypto } from 'crypto';

import { Vault, VaultState, exportedForTesting } from './Vault';

const {
  b64Encode,
  b64Decode,
  stringToBytes,
  bytesToString,
  jsonToBytes,
  randomBytes,
  ensureLength,
  ensureNotNull,
  ensureBytes,
  deriveWrappingKey,
  generateMasterKey,
  unwrapMasterKey,
  deriveEncryptionKey,
  encryptData,
  decryptData,
  reEncryptData,
} = exportedForTesting;

/**
 * Generate a random encryption key.
 *
 * @returns A Promise to a key handler.
 */
async function generateKey(): Promise<CryptoKey> {
  return await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );
}

describe('b64Encode', () => {
  it('should encode an empty Uint8Array', () => {
    const input = new Uint8Array([]);
    const result = b64Encode(input);
    expect(result).toBe('');
  });

  it('should encode a simple input', () => {
    const input = new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f]);
    const result = b64Encode(input);
    expect(result).toBe('aGVsbG8=');
  });

  it('should encode an input with special characters', () => {
    const input = new Uint8Array([0xe2, 0x9c, 0x93]);
    const result = b64Encode(input);
    expect(result).toBe('4pyT');
  });
});

describe('b64Decode', () => {
  it('should decode an empty string', () => {
    const input = '';
    const result = b64Decode(input);
    expect(result).toStrictEqual(new Uint8Array([]));
  });

  it('should decode a simple input', () => {
    const input = 'aGVsbG8=';
    const result = b64Decode(input);
    expect(result).toStrictEqual(
      new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f]),
    );
  });

  it('should decode an input with special characters', () => {
    const input = '4pyT';
    const result = b64Decode(input);
    expect(result).toStrictEqual(new Uint8Array([0xe2, 0x9c, 0x93]));
  });
});

describe('stringToBytes', () => {
  it('should return an empty Uint8Array for an empty string', () => {
    const result = stringToBytes('');
    expect(result).toStrictEqual(new Uint8Array());
  });

  it('should encode ASCII characters correctly', () => {
    const result = stringToBytes('hello world');
    const expected = new Uint8Array([
      104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100,
    ]);
    expect(result).toStrictEqual(expected);
  });

  it('should encode non-ASCII characters correctly', () => {
    const result = stringToBytes('øçñ');
    const expected = new Uint8Array([195, 184, 195, 167, 195, 177]);
    expect(result).toStrictEqual(expected);
  });

  it('should normalize text in NFC form', () => {
    const result = stringToBytes('é');
    const expected = new Uint8Array([195, 169]);
    expect(result).toStrictEqual(expected);
  });
});

describe('bytesToString', () => {
  it('should return an empty string for an empty Uint8Array', () => {
    const result = bytesToString(new Uint8Array());
    expect(result).toBe('');
  });

  it('should decode ASCII characters correctly', () => {
    const data = new Uint8Array([
      104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100,
    ]);
    const expected = 'hello world';
    const result = bytesToString(data);
    expect(result).toStrictEqual(expected);
  });

  it('should decode non-ASCII characters correctly', () => {
    const data = new Uint8Array([195, 184, 195, 167, 195, 177]);
    const expected = 'øçñ';
    const result = bytesToString(data);
    expect(result).toStrictEqual(expected);
  });

  it('should handle invalid byte sequences by replacing them with the replacement character', () => {
    const data = new Uint8Array([194, 194]);
    const expected = '��';
    const result = bytesToString(data);
    expect(result).toStrictEqual(expected);
  });
});

describe('jsonToBytes', () => {
  it('should encode JSON data to UTF-8 bytes', () => {
    const data = { name: 'John', age: 30 };
    const expected = new Uint8Array([
      123, 34, 110, 97, 109, 101, 34, 58, 34, 74, 111, 104, 110, 34, 44, 34, 97,
      103, 101, 34, 58, 51, 48, 125,
    ]);
    const result = jsonToBytes(data);
    expect(result).toStrictEqual(expected);
  });

  it('should handle empty JSON data', () => {
    const data = {};
    const expected = new Uint8Array([123, 125]);
    const result = jsonToBytes(data);
    expect(result).toStrictEqual(expected);
  });
});

describe('randomBytes', () => {
  it('should return a Uint8Array with the specified length', () => {
    const length = 16;
    const result = randomBytes(length);
    expect(result).toHaveLength(length);
  });

  it('should return different values for each invocation', () => {
    const length = 16;
    const result1 = randomBytes(length);
    const result2 = randomBytes(length);
    expect(result1).not.toStrictEqual(result2);
  });

  it('should throw an error if length is negative', () => {
    const length = -1;
    expect(() => {
      randomBytes(length);
    }).toThrow('Invalid typed array length');
  });
});

describe('ensureLength', () => {
  it('returns input when length matches', () => {
    const input = new Uint8Array([1, 2, 3]);
    const result = ensureLength(input, 3);
    expect(result).toStrictEqual(input);
  });

  it('throws an error when length does not match', () => {
    const input = new Uint8Array([1, 2, 3]);
    expect(() => {
      ensureLength(input, 4);
    }).toThrow('Invalid length: expected 4, got 3');
  });
});

describe('ensureNotNull', () => {
  it('should return the value if it is not null', () => {
    const value = 'hello';
    const result = ensureNotNull(value, 'Error message');
    expect(result).toBe(value);
  });

  it('should throw an error with the specified message if the value is null', () => {
    const value = null;
    const errorMessage = 'Error message';
    expect(() => ensureNotNull(value, errorMessage)).toThrow(errorMessage);
  });
});

describe('ensureBytes', () => {
  it('should return a Uint8Array for a string input', () => {
    const result = ensureBytes('hello');
    expect(result).toBeInstanceOf(Uint8Array);
  });

  it('should return the input value for a Uint8Array input', () => {
    const input = new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f]);
    const result = ensureBytes(input);
    expect(result).toStrictEqual(input);
  });

  it('should convert a string input to the correct bytes', () => {
    const input = '✓';
    const result = ensureBytes(input);
    const expected = new Uint8Array([0xe2, 0x9c, 0x93]);
    expect(result).toStrictEqual(expected);
  });
});

describe('deriveWrappingKey', () => {
  it('should derive a wrapping key and use it to encrypt a known text', async () => {
    const pt = new Uint8Array([
      0xb3, 0x4e, 0x75, 0x12, 0x9f, 0x2b, 0x15, 0x35, 0xa2, 0x95, 0x8c, 0xf3,
      0x83, 0xe2, 0xe2, 0x08,
    ]);

    const iv = new Uint8Array([
      0xd1, 0x37, 0x31, 0x96, 0x41, 0x9b, 0x0d, 0x80, 0x98, 0x7d, 0x57, 0x25,
      0x52, 0x31, 0x0e, 0xd2,
    ]);

    const additionalData = stringToBytes('additionalData');

    // key: 669cfe52482116fda1aa2cbe409b2f56c8e4563752b7a28f6eaab614ee005178
    // source: https://gchq.github.io/CyberChef/#recipe=Derive_PBKDF2_key(%7B'option':'UTF8','string':'password'%7D,256,600000,'SHA256',%7B'option':'UTF8','string':'salt'%7D)
    const wrappingKey = await deriveWrappingKey(
      'password',
      stringToBytes('salt'),
    );

    // source: https://gchq.github.io/CyberChef/#recipe=AES_Encrypt(%7B'option':'Hex','string':'669cfe52482116fda1aa2cbe409b2f56c8e4563752b7a28f6eaab614ee005178'%7D,%7B'option':'Hex','string':'d1373196419b0d80987d572552310ed2'%7D,'GCM','Hex','Hex',%7B'option':'UTF8','string':'additionalData'%7D)&input=YjM0ZTc1MTI5ZjJiMTUzNWEyOTU4Y2YzODNlMmUyMDg
    const expected = new Uint8Array([
      0x5e, 0x82, 0x04, 0x4f, 0xb7, 0x3e, 0xd3, 0xc7, 0xcb, 0x2a, 0xa7, 0xef,
      0xc2, 0xe2, 0x34, 0xa4, 0x9b, 0x75, 0x0e, 0xf2, 0x59, 0x25, 0x80, 0x43,
      0x47, 0x7f, 0xe2, 0x3f, 0x03, 0x37, 0xfe, 0xfd,
    ]);

    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv,
          additionalData,
        },
        wrappingKey,
        pt,
      ),
    );

    expect(ct).toStrictEqual(expected);
  });
});

describe('generateMasterKey', () => {
  it('should generate a new master key and wrap it', async () => {
    // key: 669cfe52482116fda1aa2cbe409b2f56c8e4563752b7a28f6eaab614ee005178
    // source: https://gchq.github.io/CyberChef/#recipe=Derive_PBKDF2_key(%7B'option':'UTF8','string':'password'%7D,256,600000,'SHA256',%7B'option':'UTF8','string':'salt'%7D)
    const wrappingKey = await deriveWrappingKey(
      'password',
      stringToBytes('salt'),
    );

    const additionalData = stringToBytes('vault');
    const { wrapped, handler } = await generateMasterKey(
      wrappingKey,
      additionalData,
    );
    expect(handler).toBeDefined();
    expect(wrapped).toBeDefined();
    expect(wrapped.nonce).toHaveLength(12);
    expect(wrapped.data).toHaveLength(32 + 16); // key + tag
  });
});

describe('unwrapMasterKey', () => {
  it('should generate and unwrap the same key', async () => {
    // key: 669cfe52482116fda1aa2cbe409b2f56c8e4563752b7a28f6eaab614ee005178
    // source: https://gchq.github.io/CyberChef/#recipe=Derive_PBKDF2_key(%7B'option':'UTF8','string':'password'%7D,256,600000,'SHA256',%7B'option':'UTF8','string':'salt'%7D)
    const wrappingKey = await deriveWrappingKey(
      'password',
      stringToBytes('salt'),
    );

    const additionalData = stringToBytes('vault');
    const { wrapped, handler } = await generateMasterKey(
      wrappingKey,
      additionalData,
    );

    const unwrappedKey = await unwrapMasterKey(
      wrappingKey,
      wrapped,
      additionalData,
    );
    expect(unwrappedKey).toBeDefined();

    // Derive keys from the unwrapped and from the generated master key, both
    // derived keys should have the same value.
    const salt = stringToBytes('salt');
    const encKey1 = await deriveEncryptionKey(handler, 'info', salt);
    const encKey2 = await deriveEncryptionKey(unwrappedKey, 'info', salt);

    // To check if encKey1 and encKey2 have the same value, we encrypt a text
    // using encKey1 and try to decrypt it using encKey2.
    const data = stringToBytes('hello world');
    const ct = await encryptData(encKey1, data, stringToBytes('additional'));
    const pt = await decryptData(encKey2, ct, stringToBytes('additional'));
    expect(ct.nonce).toHaveLength(12);
    expect(pt).toStrictEqual(data);
  });

  it('should fail if we try to unwrap the master key with the wrong password', async () => {
    const wrappingKey1 = await deriveWrappingKey('foo', stringToBytes('salt'));
    const wrappingKey2 = await deriveWrappingKey('bar', stringToBytes('salt'));
    const { wrapped } = await generateMasterKey(wrappingKey1);

    await expect(unwrapMasterKey(wrappingKey2, wrapped)).rejects.toThrow(
      'The operation failed for an operation-specific reason',
    );
  });

  it('should succeed to unwrap the master key with the correct password', async () => {
    const wrappingKey = await deriveWrappingKey('foo', stringToBytes('salt'));
    const { wrapped } = await generateMasterKey(wrappingKey);

    expect(async () => {
      await unwrapMasterKey(wrappingKey, wrapped);
    }).not.toThrow();
  });
});

describe('reEncryptData', () => {
  it('should re-encrypt data', async () => {
    const decryptionKey = await generateKey();
    const encryptionKey = await generateKey();
    const data = stringToBytes('test');
    const encrypted = await encryptData(decryptionKey, data);
    const reEncrypted = await reEncryptData(
      decryptionKey,
      encryptionKey,
      encrypted,
    );
    const decrypted = await decryptData(encryptionKey, reEncrypted);
    expect(decrypted).toStrictEqual(data);
  });

  it('should re-encrypt data with additional data', async () => {
    const decryptionKey = await generateKey();
    const encryptionKey = await generateKey();
    const data = stringToBytes('test');
    const additionalData = stringToBytes('metadata');
    const encrypted = await encryptData(decryptionKey, data, additionalData);
    const reEncrypted = await reEncryptData(
      decryptionKey,
      encryptionKey,
      encrypted,
      additionalData,
    );
    const decrypted = await decryptData(
      encryptionKey,
      reEncrypted,
      additionalData,
    );
    expect(decrypted).toStrictEqual(data);
  });
});

describe('Vault', () => {
  let vault: Vault<Json>;

  beforeEach(() => {
    vault = new Vault();
  });

  it('should check if the vault was created uninitialized', () => {
    expect(vault.isInitialized).toBe(false);
    expect(vault.isUnlocked).toBe(false);
  });

  it('should initialize the vault', async () => {
    await vault.unlock('password');
    expect(vault.isInitialized).toBe(true);
    expect(vault.isUnlocked).toBe(true);
  });

  it('should lock the vault', async () => {
    await vault.unlock('password');
    vault.lock();
    expect(vault.isInitialized).toBe(true);
    expect(vault.isUnlocked).toBe(false);
  });

  it('should fail if we try to store a value in an uninitialized vault', async () => {
    const value = { keyring: 'test' };
    await expect(vault.set('keyring', value)).rejects.toThrow(
      'Vault is not initialized',
    );
  });

  it('should fail if we try to store a value in a locked vault', async () => {
    await vault.unlock('password');
    vault.lock();

    const value = { keyring: 'test' };
    await expect(vault.set('keyring', value)).rejects.toThrow(
      'Vault is locked',
    );
  });

  it('should fail if we try to read a value from an uninitialized vault', async () => {
    await expect(vault.get('keyring')).rejects.toThrow(
      'Vault is not initialized',
    );
  });

  it('should fail if we try to read a value from a locked vault', async () => {
    await vault.unlock('password');
    vault.lock();
    await expect(vault.get('keyring')).rejects.toThrow('Vault is locked');
  });

  it('should be possible to set and get a value', async () => {
    await vault.unlock('password');
    const value = { keyring: 'test' };
    await vault.set('keyring', value);
    expect(await vault.get('keyring')).toStrictEqual(value);
  });

  it('should be possible to set, lock, unlock, and get a value', async () => {
    await vault.unlock('password');
    const value = { keyring: 'test' };
    await vault.set('keyring', value);
    vault.lock();
    await vault.unlock('password');
    expect(await vault.get('keyring')).toStrictEqual(value);
  });

  it('should return undefined if we try to get a key that does not exist', async () => {
    await vault.unlock('password');
    expect(await vault.get('foo')).toBeUndefined();
  });

  it('should have a key that was previouslly inserted', async () => {
    await vault.unlock('password');
    await vault.set('keyring', { keyring: 'test' });
    expect(vault.has('keyring')).toBe(true);
  });

  it('should not have a key that was not inserted', async () => {
    await vault.unlock('password');
    expect(vault.has('keyring')).toBe(false);
  });

  it('should not have a key after it is deleted', async () => {
    await vault.unlock('password');
    await vault.set('keyring', { keyring: 'test' });
    expect(vault.has('keyring')).toBe(true);
    vault.delete('keyring');
    expect(vault.has('keyring')).toBe(false);
  });

  it('should be possible to update an existing entry', async () => {
    await vault.unlock('password');
    await vault.set('keyring', { keyring: 'foo' });
    await vault.set('keyring', { keyring: 'bar' });
    expect(await vault.get('keyring')).toStrictEqual({ keyring: 'bar' });
  });

  it('should fail to unlock a vault using a wrong password', async () => {
    await vault.unlock('password');
    vault.lock();
    await expect(vault.unlock('foobar')).rejects.toThrow(
      'Invalid vault password',
    );
  });

  it('should fail to verify the password on an uninitialized vault', async () => {
    expect(await vault.verifyPassword('foo')).toBe(false);
  });

  it('should successful verify the password if it is correct', async () => {
    await vault.unlock('foo');
    expect(await vault.verifyPassword('foo')).toBe(true);
  });

  it('should fail to verify the password if it is incorrect', async () => {
    await vault.unlock('foo');
    expect(await vault.verifyPassword('bar')).toBe(false);
  });

  it('should unlock the vault after the correct password is presented', async () => {
    await vault.unlock('foo');
    vault.lock();
    expect(vault.isUnlocked).toBe(false);
    await vault.verifyPassword('foo');
    expect(vault.isUnlocked).toBe(false);
  });

  it('should unlock the vault after a incorrect password is presented', async () => {
    await vault.unlock('foo');
    vault.lock();
    expect(vault.isUnlocked).toBe(false);
    await vault.verifyPassword('bar');
    expect(vault.isUnlocked).toBe(false);
  });

  it('should change the vault password', async () => {
    await vault.unlock('foo');
    await vault.changePassword('foo', 'bar');
    expect(await vault.verifyPassword('foo')).toBe(false);
    expect(await vault.verifyPassword('bar')).toBe(true);
  });

  it('should change the password of a locked vault', async () => {
    await vault.unlock('foo');
    vault.lock();
    await vault.changePassword('foo', 'bar');
    expect(await vault.verifyPassword('foo')).toBe(false);
    expect(await vault.verifyPassword('bar')).toBe(true);
  });

  it('should be possible to get a value after a password change', async () => {
    await vault.unlock('foo');
    const value = { example: 123 };
    await vault.set('test', value);
    await vault.changePassword('foo', 'bar');
    expect(await vault.get('test')).toStrictEqual(value);
  });

  it('should be possible to get a value after rekeying the vault', async () => {
    await vault.unlock('foo');
    const value = { example: 123 };
    await vault.set('test', value);
    await vault.rekey('foo');
    expect(await vault.get('test')).toStrictEqual(value);
  });

  it('should serialize and deserialize a vault', async () => {
    await vault.unlock('foo');
    const value1 = { answer: 42 };
    const value2 = { answer: 42, verified: true };
    await vault.set('test-1', value1);
    await vault.set('test-2', value2);

    const serialized = vault.getState();
    const newVault = new Vault(serialized);
    await newVault.unlock('foo');
    expect(await newVault.get('test-1')).toStrictEqual(value1);
    expect(await newVault.get('test-2')).toStrictEqual(value2);
    expect(newVault.getState()).toStrictEqual(serialized);
  });

  it('should deserialize a vault from JSON', async () => {
    await vault.unlock('foo');
    await vault.set('test', { answer: 42 });

    const state = vault.getState();
    const newVault = new Vault(JSON.parse(JSON.stringify(state)));
    await newVault.unlock('foo');
    expect(await newVault.get('test')).toStrictEqual({ answer: 42 });
  });

  it('should fail to import an invalid state', async () => {
    await vault.unlock('foo');
    await vault.set('test', { answer: 42 });

    const state = { ...vault.getState(), version: 1 } as unknown as VaultState;
    expect(() => new Vault(state)).toThrow('Invalid vault state');
  });
});
