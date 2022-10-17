const sinon = require('sinon');

const PASSWORD = 'password123';
const MOCK_ENCRYPTION_KEY =
  '{"alg":"A256GCM","ext":true,"k":"wYmxkxOOFBDP6F6VuuYFcRt_Po-tSLFHCWVolsHs4VI","key_ops":["encrypt","decrypt"],"kty":"oct"}';

const MOCK_HEX = '0xabcdef0123456789';
const MOCK_KEY = Buffer.alloc(32);
let cacheVal;

module.exports = {
  encrypt: sinon.stub().callsFake(function (_password, dataObj) {
    cacheVal = dataObj;

    return Promise.resolve({ vault: MOCK_HEX, extractedKeyString: '' });
  }),

  async decryptWithEncryptedKeyString(_keyStr) {
    const { vault } = await this.decrypt();
    return vault;
  },

  decrypt(_password, _text) {
    if (_password && _password !== PASSWORD) {
      throw new Error('Incorrect password.');
    }

    const result = cacheVal
      ? {
          vault: cacheVal,
          extractedKeyString: MOCK_ENCRYPTION_KEY,
          salt: 'SALT',
        }
      : {};
    return Promise.resolve(result);
  },

  encryptWithKey(key, dataObj) {
    return this.encrypt(key, dataObj);
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
