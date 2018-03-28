/**
 * @file      MetaMask Wallet Class, extends the EthereumWallet with further functionality
 * @copyright Copyright (c) 2018 MetaMask
 * @license   MIT
 */

const EventEmitter = require('events').EventEmitter

const ethUtil = require('ethereumjs-util')
const sigUtil = require('eth-sig-util')

const type = 'Abstract Wallet'


class MetaMaskWallet extends EventEmitter {

  //TODO: verify if this should become the simplest possible wallet (currently simple-keyring)

  /**
   * @constructor 
   */

  constructor() {
    super()
    if (this.constructor === MetaMaskWallet) {
      throw new TypeError('Abstract class "MetaMaskWallet" cannot be instantiated directly.');
    }
  }

  /**
   * Returns the Private Key for a given Address
   * 
   * @param  {string} address Address for which the private key should be retrieved
   * @return {string} A hex-encoded private key
   */
  exportAccount(address) {
    const wallet = this._getWalletForAccount(address)
    return Promise.resolve(wallet.getPrivateKey().toString('hex'))
  }


  // tx is an instance of the ethereumjs-transaction class.
  signTransaction (address, tx) {
    const wallet = this._getWalletForAccount(address)
    var privKey = wallet.getPrivateKey()
    tx.sign(privKey)
    return Promise.resolve(tx)
  }

  // For eth_sign, we need to sign arbitrary data:
  signMessage (withAccount, data) {
    const wallet = this._getWalletForAccount(withAccount)
    const message = ethUtil.stripHexPrefix(data)
    var privKey = wallet.getPrivateKey()
    var msgSig = ethUtil.ecsign(new Buffer(message, 'hex'), privKey)
    var rawMsgSig = ethUtil.bufferToHex(sigUtil.concatSig(msgSig.v, msgSig.r, msgSig.s))
    return Promise.resolve(rawMsgSig)
  }

  // For personal_sign, we need to prefix the message:
  signPersonalMessage (withAccount, msgHex) {
    const wallet = this._getWalletForAccount(withAccount)
    const privKey = ethUtil.stripHexPrefix(wallet.getPrivateKey())
    const privKeyBuffer = new Buffer(privKey, 'hex')
    const sig = sigUtil.personalSign(privKeyBuffer, { data: msgHex })
    return Promise.resolve(sig)
  }

  // personal_signTypedData, signs data along with the schema
  signTypedData (withAccount, typedData) {
    const wallet = this._getWalletForAccount(withAccount)
    const privKey = ethUtil.toBuffer(wallet.getPrivateKey())
    const sig = sigUtil.signTypedData(privKey, { data: typedData })
    return Promise.resolve(sig)
  }


}

MetaMaskWallet.type = type
module.exports = MetaMaskWallet
