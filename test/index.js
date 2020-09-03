const { strict: assert } = require('assert')
const ethUtil = require('ethereumjs-util')

const { BN } = ethUtil
const sigUtil = require('eth-sig-util')

const normalizeAddress = sigUtil.normalize
const sinon = require('sinon')
const Wallet = require('ethereumjs-wallet')

const configManagerGen = require('./lib/mock-config-manager')
const mockEncryptor = require('./lib/mock-encryptor')
const KeyringController = require('..')

const mockAddress = '0xeF35cA8EbB9669A35c31b5F6f249A9941a812AC1'.toLowerCase()

let sandbox

describe('KeyringController', function () {

  let keyringController
  const password = 'password123'
  const seedWords = 'puzzle seed penalty soldier say clay field arctic metal hen cage runway'
  const addresses = [mockAddress]

  beforeEach(async function () {
    sandbox = sinon.createSandbox()
    window.localStorage = {} // Hacking localStorage support into JSDom

    keyringController = new KeyringController({
      configManager: configManagerGen(),
      encryptor: mockEncryptor,
    })

    await keyringController.createNewVaultAndKeychain(password)
  })

  afterEach(function () {
    sandbox.restore()
  })

  describe('setLocked', function () {

    it('setLocked correctly sets lock state', async function () {

      assert.notDeepEqual(
        keyringController.keyrings, [],
        'keyrings should not be empty',
      )

      await keyringController.setLocked()

      assert.equal(
        keyringController.password, null,
        'password should be null',
      )
      assert.equal(
        keyringController.memStore.getState().isUnlocked, false,
        'isUnlocked should be false',
      )
      assert.deepEqual(
        keyringController.keyrings, [],
        'keyrings should be empty',
      )
    })

    it('emits "lock" event', async function () {

      const spy = sinon.spy()
      keyringController.on('lock', spy)

      await keyringController.setLocked()

      assert.ok(spy.calledOnce, 'lock event fired')
    })
  })

  describe('submitPassword', function () {

    it('should not create new keyrings when called in series', async function () {
      await keyringController.createNewVaultAndKeychain(password)
      await keyringController.persistAllKeyrings()
      assert.equal(keyringController.keyrings.length, 1, 'has one keyring')

      await keyringController.submitPassword(`${password}a`)
      assert.equal(keyringController.keyrings.length, 1, 'has one keyring')

      await keyringController.submitPassword('')
      assert.equal(keyringController.keyrings.length, 1, 'has one keyring')
    })

    it('emits "unlock" event', async function () {

      await keyringController.setLocked()

      const spy = sinon.spy()
      keyringController.on('unlock', spy)

      await keyringController.submitPassword(password)
      assert.ok(spy.calledOnce, 'unlock event fired')
    })
  })

  describe('createNewVaultAndKeychain', function () {

    it('should set a vault on the configManager', async function () {

      keyringController.store.updateState({ vault: null })
      assert(!keyringController.store.getState().vault, 'no previous vault')

      await keyringController.createNewVaultAndKeychain(password)
      const { vault } = keyringController.store.getState()
      assert(vault, 'vault created')
    })

    it('should encrypt keyrings with the correct password each time they are persisted', async function () {

      keyringController.store.updateState({ vault: null })
      assert(!keyringController.store.getState().vault, 'no previous vault')

      await keyringController.createNewVaultAndKeychain(password)
      const { vault } = keyringController.store.getState()
      assert(vault, 'vault created')
      keyringController.encryptor.encrypt.args.forEach(([actualPassword]) => {
        assert.equal(actualPassword, password)
      })
    })
  })

  describe('addNewKeyring', function () {

    it('Simple Key Pair', async function () {

      const privateKey = 'c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3'
      const previousAccounts = await keyringController.getAccounts()
      const keyring = await keyringController.addNewKeyring('Simple Key Pair', [privateKey])
      const keyringAccounts = await keyring.getAccounts()
      const expectedKeyringAccounts = ['0x627306090abab3a6e1400e9345bc60c78a8bef57']
      assert.deepEqual(keyringAccounts, expectedKeyringAccounts, 'keyringAccounts match expectation')

      const allAccounts = await keyringController.getAccounts()
      const expectedAllAccounts = previousAccounts.concat(expectedKeyringAccounts)
      assert.deepEqual(allAccounts, expectedAllAccounts, 'allAccounts match expectation')
    })
  })

  describe('restoreKeyring', function () {

    it(`should pass a keyring's serialized data back to the correct type.`, async function () {

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

  describe('getAccounts', function () {

    it('returns the result of getAccounts for each keyring', async function () {
      keyringController.keyrings = [
        {
          getAccounts () {
            return Promise.resolve([1, 2, 3])
          },
        },
        {
          getAccounts () {
            return Promise.resolve([4, 5, 6])
          },
        },
      ]

      const result = await keyringController.getAccounts()
      assert.deepEqual(result, ['0x01', '0x02', '0x03', '0x04', '0x05', '0x06'])
    })
  })

  describe('removeAccount', function () {

    it('removes an account from the corresponding keyring', async function () {

      const account = {
        privateKey: 'c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3',
        publicKey: '0x627306090abab3a6e1400e9345bc60c78a8bef57',
      }

      const accountsBeforeAdding = await keyringController.getAccounts()

      // Add a new keyring with one account
      await keyringController.addNewKeyring('Simple Key Pair', [account.privateKey])

      // remove that account that we just added
      await keyringController.removeAccount(account.publicKey)

      // fetch accounts after removal
      const result = await keyringController.getAccounts()
      assert.deepEqual(result, accountsBeforeAdding)
    })

    it('removes the keyring if there are no accounts after removal', async function () {

      const account = {
        privateKey: 'c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3',
        publicKey: '0x627306090abab3a6e1400e9345bc60c78a8bef57',
      }

      // Add a new keyring with one account
      await keyringController.addNewKeyring('Simple Key Pair', [account.privateKey])

      // We should have 2 keyrings
      assert.equal(keyringController.keyrings.length, 2)

      // remove that account that we just added
      await keyringController.removeAccount(account.publicKey)

      // Check that the previous keyring with only one account
      // was also removed after removing the account
      assert.equal(keyringController.keyrings.length, 1)
    })

  })

  describe('addGasBuffer', function () {

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
      assert.equal(result, `0x${correct.toString(16)}`, 'Added the right amount')
      assert.notEqual(result, tooBigOutput, 'not that bad estimate')
    })
  })

  describe('unlockKeyrings', function () {

    it('returns the list of keyrings', async function () {

      await keyringController.setLocked()
      const keyrings = await keyringController.unlockKeyrings(password)
      assert.notStrictEqual(keyrings.length, 0)
      keyrings.forEach((keyring) => {
        assert.strictEqual(keyring.wallets.length, 1)
      })
    })
  })

  describe('getAppKeyAddress', function () {

    it('returns the expected app key address', async function () {
      const address = '0x01560cd3bac62cc6d7e6380600d9317363400896'
      const privateKey = '0xb8a9c05beeedb25df85f8d641538cbffedf67216048de9c678ee26260eb91952'

      const keyring = await keyringController.addNewKeyring('Simple Key Pair', [privateKey])
      keyring.getAppKeyAddress = sinon.spy()
      /* eslint-disable-next-line require-atomic-updates */
      keyringController.getKeyringForAccount = sinon.stub().returns(Promise.resolve(keyring))

      await keyringController.getAppKeyAddress(address, 'someapp.origin.io')

      assert(keyringController.getKeyringForAccount.calledOnce)
      assert.equal(keyringController.getKeyringForAccount.getCall(0).args[0], normalizeAddress(address))
      assert(keyring.getAppKeyAddress.calledOnce)
      assert.deepEqual(keyring.getAppKeyAddress.getCall(0).args, [normalizeAddress(address), 'someapp.origin.io'])
    })
  })

  describe('exportAppKeyForAddress', function () {

    it('returns a unique key', async function () {
      const address = '0x01560cd3bac62cc6d7e6380600d9317363400896'
      const privateKey = '0xb8a9c05beeedb25df85f8d641538cbffedf67216048de9c678ee26260eb91952'
      await keyringController.addNewKeyring('Simple Key Pair', [privateKey])
      const appKeyAddress = await keyringController.getAppKeyAddress(address, 'someapp.origin.io')

      const privateAppKey = await keyringController.exportAppKeyForAddress(address, 'someapp.origin.io')

      const wallet = Wallet.fromPrivateKey(ethUtil.toBuffer(`0x${privateAppKey}`))
      const recoveredAddress = `0x${wallet.getAddress().toString('hex')}`

      assert.equal(recoveredAddress, appKeyAddress, 'Exported the appropriate private key')
      assert.notEqual(privateAppKey, privateKey)
    })
  })
})
