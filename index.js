/**
 * @file      WalletController Class
 * @copyright Copyright (c) 2018 MetaMask
 * @license   MIT
 */

const ethUtil = require('ethereumjs-util')
const BN = ethUtil.BN
const bip39 = require('bip39')
const EventEmitter = require('events').EventEmitter
const ObservableStore = require('obs-store')
const filter = require('promise-filter')
const encryptor = require('browser-passworder')
const sigUtil = require('eth-sig-util')
const normalizeAddress = sigUtil.normalize

// Wallets are wrappers around ethereumjs-wallet
// TODO: this should be renamed to "wallet"
//       https://github.com/MetaMask/metamask-extension/issues/3738

//!!! fetched from code
const SimpleWallet = require('./mm-wallet-simple')
const HdWallet = require('./mm-wallet-hd')
const walletTypes = [
  SimpleWallet,
  HdWallet,
]

const walletProviders = {}

/**
 * Controller a Collection of WalletProviders
 */
class WalletController extends EventEmitter {


  /**
   * Creates a new Wallet Controller Object
   * 
   * @constructor
   * @param {Object} opts
   * @param opts.initState
   * @param opts.encryptor
   * @param opts.getNetwork
   * 
   */
  constructor (opts) {
    super()
    const initState = opts.initState || {}
    this.walletTypes = walletTypes
    this.store = new ObservableStore(initState)
    this.memStore = new ObservableStore({
      isUnlocked: false,
      walletTypes: this.walletTypes.map(krt => krt.type),
      wallets: [],
      identities: {},
      walletProviders: {},
    })

    this.encryptor = opts.encryptor || encryptor
    this.wallets = []
    this.getNetwork = opts.getNetwork

    this.initwalletProviders()
  }

  /**
   * Fetch information from the walletProviders and set it up in memStore
   * 
   * TODO: automate this, after adding the information to the WalletProvider classes
   */
  initwalletProviders () {

    walletProviders[0] = {
      func: 'CREATE',
      text: 'createAccount',
      img:  'images/plus-btn-white.svg',
    }
    walletProviders[1] = {
      func: 'IMPORT',
      text: 'importAccount',
      img:  'images/import-account.svg'
    }
    this.memStore.updateState({ walletProviders })
    console.log('!!! HI @@@')
  }

  // Full Update
  // returns Promise( @object state )
  //
  // Emits the `update` event and
  // returns a Promise that resolves to the current state.
  //
  // Frequently used to end asynchronous chains in this class,
  // indicating consumers can often either listen for updates,
  // or accept a state-resolving promise to consume their results.
  //
  // Not all methods end with this, that might be a nice refactor.
  fullUpdate () {
    this.emit('update', this.memStore.getState())
    return Promise.resolve(this.memStore.getState())
  }

  // Create New Vault And Keychain
  // @string password - The password to encrypt the vault with
  //
  // returns Promise( @object state )
  //
  // Destroys any old encrypted storage,
  // creates a new encrypted store with the given password,
  // randomly creates a new HD wallet with 1 account,
  // faucets that account on the testnet.
  createNewVaultAndKeychain (password) {
    return this.persistAllWallets(password)
      .then(this.createFirstKeyTree.bind(this))
      .then(this.fullUpdate.bind(this))
  }

  // CreateNewVaultAndRestore
  // @string password - The password to encrypt the vault with
  // @string seed - The BIP44-compliant seed phrase.
  //
  // returns Promise( @object state )
  //
  // Destroys any old encrypted storage,
  // creates a new encrypted store with the given password,
  // creates a new HD wallet from the given seed with 1 account.
  createNewVaultAndRestore (password, seed) {
    if (typeof password !== 'string') {
      return Promise.reject('Password must be text.')
    }

    if (!bip39.validateMnemonic(seed)) {
      return Promise.reject(new Error('Seed phrase is invalid.'))
    }

    this.clearWallets()

    return this.persistAllWallets(password)
    .then(() => {
      return this.addNewWallet('HD Key Tree', {
        mnemonic: seed,
        numberOfAccounts: 1,
      })
    })
    .then((firstWallet) => {
      return firstWallet.getAccounts()
    })
    .then((accounts) => {
      const firstAccount = accounts[0]
      if (!firstAccount) throw new Error('WalletController - First Account not found.')
      return this.setupAccounts(accounts)
    })
    .then(this.persistAllWallets.bind(this, password))
    .then(this.fullUpdate.bind(this))
  }

  // Set Locked
  // returns Promise( @object state )
  //
  // This method deallocates all secrets, and effectively locks metamask.
  setLocked () {
    // set locked
    this.password = null
    this.memStore.updateState({ isUnlocked: false })
    // remove wallets
    this.wallets = []
    this._updateMemStoreWallets()
    return this.fullUpdate()
  }

  // Submit Password
  // @string password
  //
  // returns Promise( @object state )
  //
  // Attempts to decrypt the current vault and load its wallets
  // into memory.
  //
  // Temporarily also migrates any old-style vaults first, as well.
  // (Pre MetaMask 3.0.0)
  submitPassword (password) {
    return this.unlockWallets(password)
    .then((wallets) => {
      this.wallets = wallets
      return this.fullUpdate()
    })
  }

  // Add New Wallet
  // @string type
  // @object opts
  //
  // returns Promise( @Wallet wallet )
  //
  // Adds a new Wallet of the given `type` to the vault
  // and the current decrypted Wallets array.
  //
  // All Wallet classes implement a unique `type` string,
  // and this is used to retrieve them from the walletTypes array.
  addNewWallet (type, opts) {
    const Wallet = this.getWalletClassForType(type)
    const wallet = new Wallet(opts)
    return wallet.deserialize(opts)
    .then(() => {
      return wallet.getAccounts()
    })
    .then((accounts) => {
      return this.checkForDuplicate(type, accounts)
    })
    .then((checkedAccounts) => {
      this.wallets.push(wallet)
      return this.setupAccounts(checkedAccounts)
    })
    .then(() => this.persistAllWallets())
    .then(() => this._updateMemStoreWallets())
    .then(() => this.fullUpdate())
    .then(() => {
      return wallet
    })
  }

  // For now just checks for simple key pairs
  // but in the future
  // should possibly add HD and other types
  //
  checkForDuplicate (type, newAccount) {
    return this.getAccounts()
    .then((accounts) => {
      switch (type) {
        case 'Simple Key Pair':
          const isNotIncluded = !accounts.find((key) => key === newAccount[0] || key === ethUtil.stripHexPrefix(newAccount[0]))
          return (isNotIncluded) ? Promise.resolve(newAccount) : Promise.reject(new Error('The account you\'re are trying to import is a duplicate'))
        default:
          return Promise.resolve(newAccount)
      }
    })
  }


  // Add New Account
  // @number keyRingNum
  //
  // returns Promise( @object state )
  //
  // Calls the `addAccounts` method on the Wallet
  // in the kryings array at index `walletNum`,
  // and then saves those changes.
  addNewAccount (selectedWallet) {
    return selectedWallet.addAccounts(1)
    .then((accounts) => {
      accounts.forEach((hexAccount) => {
        this.emit('newAccount', hexAccount)
      })
      return accounts
    })
    .then(this.setupAccounts.bind(this))
    .then(this.persistAllWallets.bind(this))
    .then(this._updateMemStoreWallets.bind(this))
    .then(this.fullUpdate.bind(this))
  }

  // Save Account Label
  // @string account
  // @string label
  //
  // returns Promise( @string label )
  //
  // Persists a nickname equal to `label` for the specified account.
  saveAccountLabel (account, label) {
    try {
      const hexAddress = normalizeAddress(account)
      // update state on diskStore
      const state = this.store.getState()
      const walletNicknames = state.walletNicknames || {}
      walletNicknames[hexAddress] = label
      this.store.updateState({ walletNicknames })
      // update state on memStore
      const identities = this.memStore.getState().identities
      identities[hexAddress].name = label
      this.memStore.updateState({ identities })
      return Promise.resolve(label)
    } catch (err) {
      return Promise.reject(err)
    }
  }

  // Export Account
  // @string address
  //
  // returns Promise( @string privateKey )
  //
  // Requests the private key from the wallet controlling
  // the specified address.
  //
  // Returns a Promise that may resolve with the private key string.
  exportAccount (address) {
    try {
      return this.getWalletForAccount(address)
      .then((wallet) => {
        return wallet.exportAccount(normalizeAddress(address))
      })
    } catch (e) {
      return Promise.reject(e)
    }
  }


  // SIGNING METHODS
  //
  // This method signs tx and returns a promise for
  // TX Manager to update the state after signing

  signTransaction (ethTx, _fromAddress) {
    const fromAddress = normalizeAddress(_fromAddress)
    return this.getWalletForAccount(fromAddress)
    .then((wallet) => {
      return wallet.signTransaction(fromAddress, ethTx)
    })
  }

  // Sign Message
  // @object msgParams
  //
  // returns Promise(@buffer rawSig)
  //
  // Attempts to sign the provided @object msgParams.
  signMessage (msgParams) {
    const address = normalizeAddress(msgParams.from)
    return this.getWalletForAccount(address)
    .then((wallet) => {
      return wallet.signMessage(address, msgParams.data)
    })
  }

  // Sign Personal Message
  // @object msgParams
  //
  // returns Promise(@buffer rawSig)
  //
  // Attempts to sign the provided @object msgParams.
  // Prefixes the hash before signing as per the new geth behavior.
  signPersonalMessage (msgParams) {
    const address = normalizeAddress(msgParams.from)
    return this.getWalletForAccount(address)
    .then((wallet) => {
      return wallet.signPersonalMessage(address, msgParams.data)
    })
  }

  // Sign Typed Message (EIP712 https://github.com/ethereum/EIPs/pull/712#issuecomment-329988454)
  signTypedMessage (msgParams) {
    const address = normalizeAddress(msgParams.from)
    return this.getWalletForAccount(address)
      .then((wallet) => {
      return wallet.signTypedData(address, msgParams.data)
    })
  }

  // PRIVATE METHODS
  //
  // THESE METHODS ARE ONLY USED INTERNALLY TO THE KEYRING-CONTROLLER
  // AND SO MAY BE CHANGED MORE LIBERALLY THAN THE ABOVE METHODS.

  // Create First Key Tree
  // returns @Promise
  //
  // Clears the vault,
  // creates a new one,
  // creates a random new HD Wallet with 1 account,
  // makes that account the selected account,
  // faucets that account on testnet,
  // puts the current seed words into the state tree.
  createFirstKeyTree () {
    this.clearWallets()
    return this.addNewWallet('HD Key Tree', { numberOfAccounts: 1 })
    .then((wallet) => {
      return wallet.getAccounts()
    })
    .then((accounts) => {
      const firstAccount = accounts[0]
      if (!firstAccount) throw new Error('WalletController - No account found on keychain.')
      const hexAccount = normalizeAddress(firstAccount)
      this.emit('newVault', hexAccount)
      return this.setupAccounts(accounts)
    })
    .then(this.persistAllWallets.bind(this))
  }

  // Setup Accounts
  // @array accounts
  //
  // returns @Promise(@object account)
  //
  // Initializes the provided account array
  // Gives them numerically incremented nicknames,
  setupAccounts (accounts) {
    return this.getAccounts()
    .then((loadedAccounts) => {
      const arr = accounts || loadedAccounts
      return Promise.all(arr.map((account) => {
        return this.getBalanceAndNickname(account)
      }))
    })
  }

  // Get Balance And Nickname
  // @string account
  //
  // returns Promise( @string label )
  //
  // Takes an account address and an iterator representing
  // the current number of named accounts.
  getBalanceAndNickname (account) {
    if (!account) {
      throw new Error('Problem loading account.')
    }
    const address = normalizeAddress(account)
    return this.createNickname(address)
  }

  // Create Nickname
  // @string address
  //
  // returns Promise( @string label )
  //
  // Takes an address, and assigns it an incremented nickname, persisting it.
  createNickname (address) {
    const hexAddress = normalizeAddress(address)
    const identities = this.memStore.getState().identities
    const currentIdentityCount = Object.keys(identities).length + 1
    const nicknames = this.store.getState().walletNicknames || {}
    const existingNickname = nicknames[hexAddress]
    const name = existingNickname || `Account ${currentIdentityCount}`
    identities[hexAddress] = {
      address: hexAddress,
      name,
    }
    this.memStore.updateState({ identities })
    return this.saveAccountLabel(hexAddress, name)
  }

  // Persist All Wallets
  // @password string
  //
  // returns Promise
  //
  // Iterates the current `wallets` array,
  // serializes each one into a serialized array,
  // encrypts that array with the provided `password`,
  // and persists that encrypted string to storage.
  persistAllWallets (password = this.password) {
    if (typeof password === 'string') {
      this.password = password
      this.memStore.updateState({ isUnlocked: true })
    }
    return Promise.all(this.wallets.map((wallet) => {
      return Promise.all([wallet.type, wallet.serialize()])
      .then((serializedWalletArray) => {
        // Label the output values on each serialized Wallet:
        return {
          type: serializedWalletArray[0],
          data: serializedWalletArray[1],
        }
      })
    }))
    .then((serializedWallets) => {
      return this.encryptor.encrypt(this.password, serializedWallets)
    })
    .then((encryptedString) => {
      this.store.updateState({ vault: encryptedString })
      return true
    })
  }

  // Unlock Wallets
  // @string password
  //
  // returns Promise( @array wallets )
  //
  // Attempts to unlock the persisted encrypted storage,
  // initializing the persisted wallets to RAM.
  unlockWallets (password) {
    const encryptedVault = this.store.getState().vault
    if (!encryptedVault) {
      throw new Error('Cannot unlock without a previous vault.')
    }

    return this.encryptor.decrypt(password, encryptedVault)
    .then((vault) => {
      this.password = password
      this.memStore.updateState({ isUnlocked: true })
      vault.forEach(this.restoreWallet.bind(this))
      return this.wallets
    })
  }

  // Restore Wallet
  // @object serialized
  //
  // returns Promise( @Wallet deserialized )
  //
  // Attempts to initialize a new wallet from the provided
  // serialized payload.
  //
  // On success, returns the resulting @Wallet instance.
  restoreWallet (serialized) {
    const { type, data } = serialized

    const Wallet = this.getWalletClassForType(type)
    const wallet = new Wallet()
    return wallet.deserialize(data)
    .then(() => {
      return wallet.getAccounts()
    })
    .then((accounts) => {
      return this.setupAccounts(accounts)
    })
    .then(() => {
      this.wallets.push(wallet)
      this._updateMemStoreWallets()
      return wallet
    })
  }

  // Get Wallet Class For Type
  // @string type
  //
  // Returns @class Wallet
  //
  // Searches the current `walletTypes` array
  // for a Wallet class whose unique `type` property
  // matches the provided `type`,
  // returning it if it exists.
  getWalletClassForType (type) {
    return this.walletTypes.find(kr => kr.type === type)
  }

  getWalletsByType (type) {
    return this.wallets.filter((wallet) => wallet.type === type)
  }

  // Get Accounts
  // returns Promise( @Array[ @string accounts ] )
  //
  // Returns the public addresses of all current accounts
  // managed by all currently unlocked wallets.
  async getAccounts () {
    const wallets = this.wallets || []
    const addrs = await Promise.all(wallets.map(kr => kr.getAccounts()))
    .then((walletArrays) => {
      return walletArrays.reduce((res, arr) => {
        return res.concat(arr)
      }, [])
    })
    return addrs.map(normalizeAddress)
  }

  // Get Wallet For Account
  // @string address
  //
  // returns Promise(@Wallet wallet)
  //
  // Returns the currently initialized wallet that manages
  // the specified `address` if one exists.
  getWalletForAccount (address) {
    const hexed = normalizeAddress(address)
    log.debug(`WalletController - getWalletForAccount: ${hexed}`)

    return Promise.all(this.wallets.map((wallet) => {
      return Promise.all([
        wallet,
        wallet.getAccounts(),
      ])
    }))
    .then(filter((candidate) => {
      const accounts = candidate[1].map(normalizeAddress)
      return accounts.includes(hexed)
    }))
    .then((winners) => {
      if (winners && winners.length > 0) {
        return winners[0][0]
      } else {
        throw new Error('No wallet found for the requested account.')
      }
    })
  }

  // Display For Wallet
  // @Wallet wallet
  //
  // returns Promise( @Object { type:String, accounts:Array } )
  //
  // Is used for adding the current wallets to the state object.
  displayForWallet (wallet) {
    return wallet.getAccounts()
    .then((accounts) => {
      return {
        type: wallet.type,
        accounts: accounts.map(normalizeAddress),
      }
    })
  }

  // Add Gas Buffer
  // @string gas (as hexadecimal value)
  //
  // returns @string bufferedGas (as hexadecimal value)
  //
  // Adds a healthy buffer of gas to an initial gas estimate.
  addGasBuffer (gas) {
    const gasBuffer = new BN('100000', 10)
    const bnGas = new BN(ethUtil.stripHexPrefix(gas), 16)
    const correct = bnGas.add(gasBuffer)
    return ethUtil.addHexPrefix(correct.toString(16))
  }

  // Clear Wallets
  //
  // Deallocates all currently managed wallets and accounts.
  // Used before initializing a new vault.
  async clearWallets () {
    // clear wallets from memory
    this.wallets = []
    this.memStore.updateState({
      wallets: [],
      identities: {},
    })
  }

  _updateMemStoreWallets () {
    Promise.all(this.wallets.map(this.displayForWallet))
    .then((wallets) => {
      this.memStore.updateState({ wallets })
    })
  }

}

module.exports = WalletController
