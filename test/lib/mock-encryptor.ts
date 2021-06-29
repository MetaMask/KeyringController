import sinon from 'sinon';

const mockHex = '0xabcdef0123456789';
const mockKey = Buffer.alloc(32);
let cacheVal;

class MockEncryptor {
  encrypt = sinon.stub().callsFake(function (_password, dataObj) {
    cacheVal = dataObj;
    return Promise.resolve(mockHex);
  });

  decrypt(_password, _text) {
    return Promise.resolve(cacheVal || {});
  }

  encryptWithKey(key, dataObj) {
    return this.encrypt(key, dataObj);
  }

  decryptWithKey(key, text) {
    return this.decrypt(key, text);
  }

  keyFromPassword(_password) {
    return Promise.resolve(mockKey);
  }

  generateSalt() {
    return 'WHADDASALT!';
  }
}

export default new MockEncryptor();
