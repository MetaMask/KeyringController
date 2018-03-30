/**
 * @file      A Simple Ethereum Wallet, with imported keys
 * @copyright Copyright (c) 2018 MetaMask
 * @license   MIT
 */

const EventEmitter = require('events').EventEmitter
const Wallet = require('ethereumjs-wallet')

const ethUtil = require('ethereumjs-util')
const sigUtil = require('eth-sig-util')

const MetaMaskWallet = require('./mm-wallet')
const type = 'Simple Key Pair'

// Options:
// none


class SimpleKeyring extends MetaMaskWallet {

  /* PUBLIC METHODS */

  constructor (opts) {
    super()
    this.type = type
    this.opts = opts || {}
    this.wallets = []
  }

  serialize () {
    return Promise.resolve(
      this.wallets.map(w => w.getPrivateKey().toString('hex'))
    )


  }

  deserialize (privateKeys = []) {
    return new Promise((resolve, reject) => {
      try {
        this.wallets = privateKeys.map((privateKey) => {
          const stripped = ethUtil.stripHexPrefix(privateKey)
          const buffer = new Buffer(stripped, 'hex')
          const wallet = Wallet.fromPrivateKey(buffer)
          return wallet
        })
      } catch (e) {
        reject(e)
      }
      resolve()
    })

    
  }

  addAccounts (n = 1) {
    var newWallets = []
    for (var i = 0; i < n; i++) {
      newWallets.push(Wallet.generate())
    }
    this.wallets = this.wallets.concat(newWallets)
    const hexWallets = newWallets.map(w => ethUtil.bufferToHex(w.getAddress()))
    return Promise.resolve(hexWallets)
  }

  getAccounts () {
    return Promise.resolve(this.wallets.map(w => ethUtil.bufferToHex(w.getAddress())))
  }

  /* PRIVATE METHODS */

  _getWalletForAccount (account) {
    const address = sigUtil.normalize(account)
    let wallet = this.wallets.find(w => ethUtil.bufferToHex(w.getAddress()) === address)
    if (!wallet) throw new Error('Simple Keyring - Unable to find matching address.')
    return wallet
  }

}

SimpleKeyring.type = type
module.exports = SimpleKeyring
