/* eslint-disable no-restricted-globals */
import { Vault, exportedForTesting } from './Vault';

const {
  stringToBytes,
  bytesToString,
  jsonToBytes,
  randomBytes,
  ensureNotNull,
  ensureBytes,
  deriveWrappingKey,
  generateMasterKey,
  unwrapMasterKey,
  deriveMasterKey,
  encryptData,
  decryptData,
} = exportedForTesting;

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

  it('should throw the given error if null', () => {
    expect(() => ensureNotNull(null, new Error('foo'))).toThrow('foo');
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
    const encKey1 = await deriveMasterKey(handler, 'info', salt);
    const encKey2 = await deriveMasterKey(unwrappedKey, 'info', salt);

    // To check if encKey1 and encKey2 have the same value, we encrypt a text
    // using encKey1 and try to decrypt it using encKey2.
    const data = stringToBytes('hello world');
    const ct = await encryptData(encKey1, data, stringToBytes('additional'));
    const pt = await decryptData(encKey2, ct, stringToBytes('additional'));
    expect(pt).toStrictEqual(data);
  });
});

describe('Vault', () => {
  let vault: Vault;

  beforeEach(() => {
    vault = new Vault();
  });

  it('should check if the vault was created uninitialized', () => {
    expect(vault).toBeDefined();
    expect(vault.isInitialized).toBe(false);
    expect(vault.isUnlocked).toBe(false);
  });

  it('should initialize the vault', async () => {
    await vault.init('password');
    expect(vault.isInitialized).toBe(true);
    expect(vault.isUnlocked).toBe(true);
  });

  it('should lock the vault', async () => {
    await vault.init('password');
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
    await vault.init('password');
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
    await vault.init('password');
    vault.lock();
    await expect(vault.get('keyring')).rejects.toThrow('Vault is locked');
  });

  it('should be possible to set and get a value', async () => {
    await vault.init('password');
    const value = { keyring: 'test' };
    await vault.set('keyring', value);
    expect(await vault.get('keyring')).toStrictEqual(value);
  });

  it('should be possible to set, lock, unlock, and get a value', async () => {
    await vault.init('password');
    const value = { keyring: 'test' };
    await vault.set('keyring', value);
    vault.lock();
    await vault.unlock('password');
    expect(await vault.get('keyring')).toStrictEqual(value);
  });

  it('should not be possible to unlock an uninitialized vault', async () => {
    await expect(vault.unlock('password')).rejects.toThrow(
      'Vault is not initialized',
    );
  });

  it('should return undefined if we try to get a key that does not exist', async () => {
    await vault.init('password');
    expect(await vault.get('foo')).toBeUndefined();
  });

  it('should have a key that was previouslly inserted', async () => {
    await vault.init('password');
    await vault.set('keyring', { keyring: 'test' });
    expect(vault.has('keyring')).toBe(true);
  });

  it('should not have a key that was not inserted', async () => {
    await vault.init('password');
    expect(vault.has('keyring')).toBe(false);
  });

  it('should not have a key after it is deleted', async () => {
    await vault.init('password');
    await vault.set('keyring', { keyring: 'test' });
    expect(vault.has('keyring')).toBe(true);
    vault.delete('keyring');
    expect(vault.has('keyring')).toBe(false);
  });

  it('should be possible to update an existing entry', async () => {
    await vault.init('password');
    await vault.set('keyring', { keyring: 'foo' });
    await vault.set('keyring', { keyring: 'bar' });
    expect(await vault.get('keyring')).toStrictEqual({ keyring: 'bar' });
  });

  it('should fail to unlock a vault using a wrong password', async () => {
    await vault.init('password');
    vault.lock();
    await expect(vault.unlock('foobar')).rejects.toThrow(
      'Invalid vault password',
    );
  });

  it('should fail to verify the password on an uninitialized vault', async () => {
    expect(await vault.verifyPassword('foo')).toBe(false);
  });

  it('should successful verify the password if it is correct', async () => {
    await vault.init('foo');
    expect(await vault.verifyPassword('foo')).toBe(true);
  });

  it('should fail to verify the password if it is incorrect', async () => {
    await vault.init('foo');
    expect(await vault.verifyPassword('bar')).toBe(false);
  });

  it('should unlock the vault after the correct password is presented', async () => {
    await vault.init('foo');
    vault.lock();
    expect(vault.isUnlocked).toBe(false);
    await vault.verifyPassword('foo');
    expect(vault.isUnlocked).toBe(false);
  });

  it('should unlock the vault after a incorrect password is presented', async () => {
    await vault.init('foo');
    vault.lock();
    expect(vault.isUnlocked).toBe(false);
    await vault.verifyPassword('bar');
    expect(vault.isUnlocked).toBe(false);
  });
});
