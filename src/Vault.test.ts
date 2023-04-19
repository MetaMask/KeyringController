/* eslint-disable no-restricted-globals */
import { exportedForTesting } from './Vault';

const {
  stringToBytes,
  bytesToString,
  jsonToBytes,
  randomBytes,
  ensureNotNull,
  deriveWrappingKey,
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
});

describe('deriveWrappingKey', () => {
  it('should derive a wrapping key and do an encryption and obtain the expected ciphertext', async () => {
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
