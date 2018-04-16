const assert = require('assert')
const KeyringController = require('../')
const configManagerGen = require('./lib/mock-config-manager')
const ethUtil = require('ethereumjs-util')
const BN = ethUtil.BN
const mockEncryptor = require('./lib/mock-encryptor')
const sinon = require('sinon')

describe('KeyringController', function () {
  let keyringController
  const password = 'password123'
  const seedWords = 'puzzle seed penalty soldier say clay field arctic metal hen cage runway'
  const addresses = ['0xeF35cA8EbB9669A35c31b5F6f249A9941a812AC1'.toLowerCase()]
  const accounts = []
  // let originalKeystore

  beforeEach(function (done) {
    this.sinon = sinon.sandbox.create()
    window.localStorage = {} // Hacking localStorage support into JSDom

    keyringController = new KeyringController({
      configManager: configManagerGen(),
      tcxManager: {
        getTxList: () => [],
        getUnapprovedTxList: () => [],
      },
      accountTracker: {
        addAccount (acct) { accounts.push(ethUtil.addHexPrefix(acct)) },
      },
      encryptor: mockEncryptor,
    })

    keyringController.createNewVaultAndKeychain(password)
    .then(function (newState) {
      newState
      done()
    })
    .catch((err) => {
      done(err)
    })
  })

  afterEach(function () {
    // Cleanup mocks
    this.sinon.restore()
  })

  describe('#createNewVaultAndKeychain', function () {
    this.timeout(10000)

    it('should set a vault on the configManager', function (done) {
      keyringController.store.updateState({ vault: null })
      assert(!keyringController.store.getState().vault, 'no previous vault')
      keyringController.createNewVaultAndKeychain(password)
      .then(() => {
        const vault = keyringController.store.getState().vault
        assert(vault, 'vault created')
        done()
      })
      .catch((reason) => {
        done(reason)
      })
    })
  })

  describe('#restoreKeyring', function () {
    it(`should pass a keyring's serialized data back to the correct type.`, function (done) {
      const mockSerialized = {
        type: 'HD Key Tree',
        data: {
          mnemonic: seedWords,
          numberOfAccounts: 1,
        },
      }

      keyringController.restoreKeyring(mockSerialized)
      .then((keyring) => {
        assert.equal(keyring.wallets.length, 1, 'one wallet restored')
        return keyring.getAccounts()
      })
      .then((accounts) => {
        assert.equal(accounts[0], addresses[0])
        done()
      })
      .catch((reason) => {
        done(reason)
      })
    })
  })

  describe('#getAccounts', function () {
    it('returns the result of getAccounts for each keyring', function (done) {
      keyringController.keyrings = [
        { getAccounts () { return Promise.resolve([1, 2, 3]) } },
        { getAccounts () { return Promise.resolve([4, 5, 6]) } },
      ]

      keyringController.getAccounts()
      .then((result) => {
        assert.deepEqual(result, [1, 2, 3, 4, 5, 6])
        done()
      })
    })
  })

  describe('#addGasBuffer', function () {
    it('adds 100k gas buffer to estimates', function () {
      const gas = '0x04ee59' // Actual estimated gas example
      const tooBigOutput = '0x80674f9' // Actual bad output
      const bnGas = new BN(ethUtil.stripHexPrefix(gas), 16)
      const correctBuffer = new BN('100000', 10)
      const correct = bnGas.add(correctBuffer)

      // const tooBig = new BN(tooBigOutput, 16)
      const result = keyringController.addGasBuffer(gas)
      const bnResult = new BN(ethUtil.stripHexPrefix(result), 16)

      assert.equal(result.indexOf('0x'), 0, 'included hex prefix')
      assert(bnResult.gt(bnGas), 'Estimate increased in value.')
      assert.equal(bnResult.sub(bnGas).toString(10), '100000', 'added 100k gas')
      assert.equal(result, '0x' + correct.toString(16), 'Added the right amount')
      assert.notEqual(result, tooBigOutput, 'not that bad estimate')
    })
  })
})
