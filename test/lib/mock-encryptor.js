const sinon = require('sinon');
const { MOCK_SALT } = require('./constants');

const mockHex = '0xabcdef0123456789';
const mockKey = Buffer.alloc(32);
let cacheVal;

module.exports = function generateMockEncryptor(changeSaltBetweenCalls) {
  return {
    encrypt: sinon.stub().callsFake(function (_password, dataObj) {
      cacheVal = dataObj;
      cacheVal.password = _password;
      return Promise.resolve(mockHex);
    }),

    decrypt(_password, _text) {
      if (_password !== cacheVal.password) {
        throw new Error(`Incorrect password: ${_password} != ${cacheVal.password}`);
      }
      return Promise.resolve(cacheVal || {});
    },

    encryptWithKey(key, dataObj) {
      return this.encrypt(key, dataObj);
    },

    decryptWithKey(key, text) {
      return this.decrypt(key, text);
    },

    keyFromPassword(_password) {
      return Promise.resolve(mockKey);
    },

    generateSalt() {
      if (changeSaltBetweenCalls) {
        return Date.now();
      }
      return MOCK_SALT;
    },
  };
};
