const sinon = require('sinon');

const PASSWORD = 'password123';
const MOCK_ENCRYPTION_KEY =
  '{"alg":"A256GCM","ext":true,"k":"wYmxkxOOFBDP6F6VuuYFcRt_Po-tSLFHCWVolsHs4VI","key_ops":["encrypt","decrypt"],"kty":"oct"}';
const MOCK_ENCRYPTION_SALT = 'HQ5sfhsb8XAQRJtD+UqcImT7Ve4n3YMagrh05YTOsjk=';
const MOCK_ENCRYPTION_DATA = `{"data":"2fOOPRKClNrisB+tmqIcETyZvDuL2iIR1Hr1nO7XZHyMqVY1cDBetw2gY5C+cIo1qkpyv3bPp+4buUjp38VBsjbijM0F/FLOqWbcuKM9h9X0uwxsgsZ96uwcIf5I46NiMgoFlhppTTMZT0Nkocz+SnvHM0IgLsFan7JqBU++vSJvx2M1PDljZSunOsqyyL+DKmbYmM4umbouKV42dipUwrCvrQJmpiUZrSkpMJrPJk9ufDQO4CyIVo0qry3aNRdYFJ6rgSyq/k6rXMwGExCMHn8UlhNnAMuMKWPWR/ymK1bzNcNs4VU14iVjEXOZGPvD9cvqVe/VtcnIba6axNEEB4HWDOCdrDh5YNWwMlQVL7vSB2yOhPZByGhnEOloYsj2E5KEb9jFGskt7EKDEYNofr6t83G0c+B72VGYZeCvgtzXzgPwzIbhTtKkP+gdBmt2JNSYrTjLypT0q+v4C9BN1xWTxPmX6TTt0NzkI9pJxgN1VQAfSU9CyWTVpd4CBkgom2cSBsxZ2MNbdKF+qSWz3fQcmJ55hxM0EGJSt9+8eQOTuoJlBapRk4wdZKHR2jdKzPjSF2MAmyVD2kU51IKa/cVsckRFEes+m7dKyHRvlNwgT78W9tBDdZb5PSlfbZXnv8z5q1KtAj2lM2ogJ7brHBdevl4FISdTkObpwcUMcvACOOO0dj6CSYjSKr0ZJ2RLChVruZyPDxEhKGb/8Kv8trLOR3mck/et6d050/NugezycNk4nnzu5iP90gPbSzaqdZI=","iv":"qTGO1afGv3waHN9KoW34Eg==","salt":"${MOCK_ENCRYPTION_SALT}"}`;

const INVALID_PASSWORD_ERROR = 'Incorrect password.';

const MOCK_HEX = '0xabcdef0123456789';
const MOCK_KEY = Buffer.alloc(32);
let cacheVal;

module.exports = {
  encrypt: sinon.stub().callsFake(function (_password, dataObj) {
    cacheVal = dataObj;

    return Promise.resolve(MOCK_HEX);
  }),

  encryptWithDetail: sinon.stub().callsFake(function (_password, dataObj) {
    cacheVal = dataObj;

    return Promise.resolve({ vault: MOCK_HEX, exportedKeyString: '' });
  }),

  async decrypt(_password, _text) {
    if (_password && _password !== PASSWORD) {
      throw new Error(INVALID_PASSWORD_ERROR);
    }

    return Promise.resolve(cacheVal || {});
  },

  async decryptWithEncryptedKeyString(_keyStr) {
    const { vault } = await this.decryptWithDetail();
    return vault;
  },

  decryptWithDetail(_password, _text) {
    if (_password && _password !== PASSWORD) {
      throw new Error(INVALID_PASSWORD_ERROR);
    }

    const result = cacheVal
      ? {
          vault: cacheVal,
          exportedKeyString: MOCK_ENCRYPTION_KEY,
          salt: 'SALT',
        }
      : {};
    return Promise.resolve(result);
  },

  importKey(keyString) {
    if (keyString === '{}') {
      throw new TypeError(
        `Failed to execute 'importKey' on 'SubtleCrypto': The provided value is not of type '(ArrayBuffer or ArrayBufferView or JsonWebKey)'.`,
      );
    }
    return null;
  },

  encryptWithKey() {
    const data = JSON.parse(MOCK_ENCRYPTION_DATA);
    // Salt is not provided from this method
    delete data.salt;
    return data;
  },

  decryptWithKey(key, text) {
    return this.decrypt(key, text);
  },

  keyFromPassword(_password) {
    return Promise.resolve(MOCK_KEY);
  },

  generateSalt() {
    return 'WHADDASALT!';
  },
};
