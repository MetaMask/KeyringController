// import { Vault } from '.';
import { exportedForTesting } from './Vault';

const {
  stringToBytes,
  bytesToString,
  jsonToBytes,
  randomBytes,
  ensureNotNull,
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
