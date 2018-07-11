const assert = require('assert')
const KeyringController = require('../')
const configManagerGen = require('./lib/mock-config-manager')
const ethUtil = require('ethereumjs-util')
const BN = ethUtil.BN
const mockEncryptor = require('./lib/mock-encryptor')
const sinon = require('sinon')

describe('KeyringController', () => {
  let keyringController
  const password = 'password123'
  const seedWords = 'puzzle seed penalty soldier say clay field arctic metal hen cage runway'
  const addresses = ['0xeF35cA8EbB9669A35c31b5F6f249A9941a812AC1'.toLowerCase()]
  const accounts = []
  // let originalKeystore

  beforeEach(async () => {
    this.sinon = sinon.sandbox.create()
    window.localStorage = {} // Hacking localStorage support into JSDom

    keyringController = new KeyringController({
      configManager: configManagerGen(),
      encryptor: mockEncryptor,
    })

    const newState = await keyringController.createNewVaultAndKeychain(password)
  })

  afterEach(() => {
    // Cleanup mocks
    this.sinon.restore()
  })


  describe('#submitPassword', function () {
    this.timeout(10000)

    it('should not create new keyrings when called in series', async () => {
      await keyringController.createNewVaultAndKeychain(password)
      await keyringController.persistAllKeyrings()

      assert.equal(keyringController.keyrings.length, 1, 'has one keyring')
      await keyringController.submitPassword(password + 'a')
      assert.equal(keyringController.keyrings.length, 1, 'has one keyring')
      await keyringController.submitPassword('')
      assert.equal(keyringController.keyrings.length, 1, 'has one keyring')
    })
  })


  describe('#createNewVaultAndKeychain', function () {
    this.timeout(10000)

    it('should set a vault on the configManager', async () => {
      keyringController.store.updateState({ vault: null })
      assert(!keyringController.store.getState().vault, 'no previous vault')
      await keyringController.createNewVaultAndKeychain(password)
      const vault = keyringController.store.getState().vault
      assert(vault, 'vault created')
    })

    it('should encrypt keyrings with the correct password each time they are persisted', async () => {
      keyringController.store.updateState({ vault: null })
      assert(!keyringController.store.getState().vault, 'no previous vault')
      await keyringController.createNewVaultAndKeychain(password)
      const vault = keyringController.store.getState().vault
      assert(vault, 'vault created')
      keyringController.encryptor.encrypt.args.forEach(([actualPassword]) => {
        assert.equal(actualPassword, password)
      })
    })
  })

  describe('#addNewKeyring', () => {
    it('Simple Key Pair', async () => {
      const privateKey = 'c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3'
      const previousAccounts = await keyringController.getAccounts()
      const keyring = await keyringController.addNewKeyring('Simple Key Pair', [ privateKey ])
      const keyringAccounts = await keyring.getAccounts()
      const expectedKeyringAccounts = ['0x627306090abab3a6e1400e9345bc60c78a8bef57']
      assert.deepEqual(keyringAccounts, expectedKeyringAccounts, 'keyringAccounts match expectation')
      const allAccounts = await keyringController.getAccounts()
      const expectedAllAccounts = previousAccounts.concat(expectedKeyringAccounts)
      assert.deepEqual(allAccounts, expectedAllAccounts, 'allAccounts match expectation')
    })
  })

  describe('#restoreKeyring', () => {
    it(`should pass a keyring's serialized data back to the correct type.`, async () => {
      const mockSerialized = {
        type: 'HD Key Tree',
        data: {
          mnemonic: seedWords,
          numberOfAccounts: 1,
        },
      }

      const keyring = await keyringController.restoreKeyring(mockSerialized)
      assert.equal(keyring.wallets.length, 1, 'one wallet restored')
      const accounts = await keyring.getAccounts()
      assert.equal(accounts[0], addresses[0])
    })
  })

  describe('#getAccounts', () => {
    it('returns the result of getAccounts for each keyring', async () => {
      keyringController.keyrings = [
        { async getAccounts () { return [1, 2, 3] } },
        { async getAccounts () { return [4, 5, 6] } },
      ]

      const result = await keyringController.getAccounts()
      assert.deepEqual(result, [1, 2, 3, 4, 5, 6])
    })
  })

  describe('#removeAccount', () => {
    it('removes an account from the corresponding keyring', async () => {
      const account = {
        privateKey: 'c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3',
        publicKey: '0x627306090abab3a6e1400e9345bc60c78a8bef57',
      }

      const accountsBeforeAdding = await keyringController.getAccounts()
      // Add a new keyring with one account
      await keyringController.addNewKeyring('Simple Key Pair', [ account.privateKey ])

      // remove that account that we just added
      await keyringController.removeAccount(account.publicKey)

      // fetch accounts after removal
      const result = await keyringController.getAccounts()
      assert.deepEqual(result, accountsBeforeAdding)
    })

    it('removes the keyring if there are no accounts after removal', async () => {
      const account = {
        privateKey: 'c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3',
        publicKey: '0x627306090abab3a6e1400e9345bc60c78a8bef57',
      }

      const accountsBeforeAdding = await keyringController.getAccounts()
      // Add a new keyring with one account
      await keyringController.addNewKeyring('Simple Key Pair', [ account.privateKey ])
      // We should have 2 keyrings
      assert.equal(keyringController.keyrings.length, 2)
      // remove that account that we just added
      await keyringController.removeAccount(account.publicKey)

      // Check that the previous keyring with only one account
      // was also removed after removing the account
      assert.equal(keyringController.keyrings.length, 1)
    })

  })

  describe('#addGasBuffer', () => {
    it('adds 100k gas buffer to estimates', () => {
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

  describe('#unlockKeyrings', () => {
    it('returns the list of keyrings', async () => {
      keyringController.setLocked()
      const keyrings = await keyringController.unlockKeyrings(password)
      assert.notStrictEqual(keyrings.length, 0)
      keyrings.forEach(keyring => {
        assert.strictEqual(keyring.wallets.length, 1)
      })
    })
  })
})
