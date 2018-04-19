const sinon = require('sinon')
var mockHex = '0xabcdef0123456789'
var mockKey = new Buffer(32)
let cacheVal

module.exports = {
  encrypt: sinon.stub().callsFake(function (password, dataObj) {
    cacheVal = dataObj
    return Promise.resolve(mockHex)
  }),

  decrypt (password, text) {
    return Promise.resolve(cacheVal || {})
  },

  encryptWithKey (key, dataObj) {
    return this.encrypt(key, dataObj)
  },

  decryptWithKey (key, text) {
    return this.decrypt(key, text)
  },

  keyFromPassword (password) {
    return Promise.resolve(mockKey)
  },

  generateSalt () {
    return 'WHADDASALT!'
  },

}
