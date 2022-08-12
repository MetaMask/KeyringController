const { EventEmitter } = require('events');
const { Buffer } = require('buffer');
const bip39 = require('@metamask/bip39');
const ObservableStore = require('obs-store');
const encryptor = require('browser-passworder');
const { normalize: normalizeAddress } = require('eth-sig-util');

const SimpleKeyring = require('eth-simple-keyring');
const HdKeyring = require('@metamask/eth-hd-keyring');

const keyringTypes = [SimpleKeyring, HdKeyring];

const VAULT_SEPARATOR = ':::';

const KEYRINGS_TYPE_MAP = {
  HD_KEYRING: 'HD Key Tree',
  SIMPLE_KEYRING: 'Simple Key Pair',
};
/**
 * Strip the hex prefix from an address, if present
 * @param {string} address - The address that might be hex prefixed.
 * @returns {string} The address without a hex prefix.
 */
function stripHexPrefix(address) {
  if (address.startsWith('0x')) {
    return address.slice(2);
  }
  return address;
}

class KeyringController extends EventEmitter {
  //
  // PUBLIC METHODS
  //

  constructor(opts) {
    super();
    const initState = opts.initState || {};
    this.keyringTypes = opts.keyringTypes
      ? keyringTypes.concat(opts.keyringTypes)
      : keyringTypes;
    this.store = new ObservableStore(initState);
    this.memStore = new ObservableStore({
      isUnlocked: false,
      keyringTypes: this.keyringTypes.map((krt) => krt.type),
      keyrings: [],
    });

    this.encryptor = opts.encryptor || encryptor;
    this.keyrings = [];
  }

  /**
   * Full Update
   *
   * Emits the `update` event and @returns a Promise that resolves to
   * the current state.
   *
   * Frequently used to end asynchronous chains in this class,
   * indicating consumers can often either listen for updates,
   * or accept a state-resolving promise to consume their results.
   *
   * @returns {Object} The controller state.
   */
  fullUpdate() {
    this.emit('update', this.memStore.getState());
    return this.memStore.getState();
  }

  /**
   * Create New Vault And Keychain
   *
   * Destroys any old encrypted storage,
   * creates a new encrypted store with the given password,
   * randomly creates a new HD wallet with 1 account,
   * faucets that account on the testnet.
   *
   * @emits KeyringController#unlock
   * @param {string} password - The password to encrypt the vault with.
   * @returns {Promise<Object>} A Promise that resolves to the state.
   */
  async createNewVaultAndKeychain(password) {
    await this.createFirstKeyTree(password);
    await this.persistAllKeyrings(password);
    this.setUnlocked.bind();
    this.fullUpdate();
  }

  /**
   * CreateNewVaultAndRestore
   *
   * Destroys any old encrypted storage,
   * creates a new encrypted store with the given password,
   * creates a new HD wallet from the given seed with 1 account.
   *
   * @emits KeyringController#unlock
   * @param {string} password - The password to encrypt the vault with
   * @param {string|Array<number>} seedPhrase - The BIP39-compliant seed phrase,
   * either as a string or an array of UTF-8 bytes that represent the string.
   * @returns {Promise<Object>} A Promise that resolves to the state.
   */
  async createNewVaultAndRestore(password, seedPhrase) {
    const seedPhraseAsBuffer =
      typeof seedPhrase === 'string'
        ? Buffer.from(seedPhrase, 'utf8')
        : Buffer.from(seedPhrase);

    if (typeof password !== 'string') {
      throw new Error('Password must be text.');
    }

    const wordlists = Object.values(bip39.wordlists);
    if (
      wordlists.every(
        (wordlist) => !bip39.validateMnemonic(seedPhraseAsBuffer, wordlist),
      )
    ) {
      throw new Error('Seed phrase is invalid.');
    }

    this.clearKeyrings();

    await this.persistAllKeyrings(password);
    const firstKeyring = await this.addNewKeyring(
      KEYRINGS_TYPE_MAP.HD_KEYRING,
      {
        mnemonic: seedPhraseAsBuffer,
        numberOfAccounts: 1,
      },
    );
    const [firstAccount] = await firstKeyring.getAccounts();
    if (!firstAccount) {
      throw new Error('KeyringController - First Account not found.');
    }

    await this.persistAllKeyrings(password);
    this.setUnlocked();
    return this.fullUpdate();
  }

  /**
   * Set Locked
   * This method deallocates all secrets, and effectively locks MetaMask.
   *
   * @emits KeyringController#lock
   * @returns {Promise<Object>} A Promise that resolves to the state.
   */
  async setLocked() {
    // set locked
    this.password = null;
    this.memStore.updateState({ isUnlocked: false });
    // remove keyrings
    this.keyrings = [];
    await this._updateMemStoreKeyrings();
    this.emit('lock');
    return this.fullUpdate();
  }

  /**
   * Submit Password
   *
   * Attempts to decrypt the current vault and load its keyrings
   * into memory.
   *
   * Temporarily also migrates any old-style vaults first, as well.
   * (Pre MetaMask 3.0.0)
   *
   * @emits KeyringController#unlock
   * @param {string} password - The keyring controller password.
   * @returns {Promise<Object>} A Promise that resolves to the state.
   */
  async submitPassword(password) {
    this.keyrings = await this.unlockKeyrings(password);
    this.setUnlocked();
    this.fullUpdate();

    return this.encryptedKey;
  }

  /* 
    MV3:  Unlock by encrypted key
  */
  async submitEncryptedKey(encryptedKey) {
    this.keyrings = await this.unlockKeyrings(undefined, encryptedKey);
    this.setUnlocked();
    this.fullUpdate();

    return this.encryptedKey;
  }

  /**
   * Verify Password
   *
   * Attempts to decrypt the current vault with a given password
   * to verify its validity.
   *
   * @param {string} password
   */
  async verifyPassword(password) {
    const encryptedVault = this.store.getState().vault;
    if (!encryptedVault) {
      throw new Error('Cannot unlock without a previous vault.');
    }
    await this.encryptor.decrypt(password, encryptedVault);
  }

  /**
   * Add New Keyring
   *
   * Adds a new Keyring of the given `type` to the vault
   * and the current decrypted Keyrings array.
   *
   * All Keyring classes implement a unique `type` string,
   * and this is used to retrieve them from the keyringTypes array.
   *
   * @param {string} type - The type of keyring to add.
   * @param {Object} opts - The constructor options for the keyring.
   * @returns {Promise<Keyring>} The new keyring.
   */
  async addNewKeyring(type, opts) {
    const Keyring = this.getKeyringClassForType(type);
    const keyring = new Keyring(opts);
    if ((!opts || !opts.mnemonic) && type === KEYRINGS_TYPE_MAP.HD_KEYRING) {
      keyring.generateRandomMnemonic();
      keyring.addAccounts();
    }

    const accounts = await keyring.getAccounts();
    await this.checkForDuplicate(type, accounts);

    this.keyrings.push(keyring);
    await this.persistAllKeyrings();

    await this._updateMemStoreKeyrings();
    this.fullUpdate();

    return keyring;
  }

  /**
   * Remove Empty Keyrings
   *
   * Loops through the keyrings and removes the ones with empty accounts
   * (usually after removing the last / only account) from a keyring
   */
  async removeEmptyKeyrings() {
    const validKeyrings = [];

    // Since getAccounts returns a Promise
    // We need to wait to hear back form each keyring
    // in order to decide which ones are now valid (accounts.length > 0)

    await Promise.all(
      this.keyrings.map(async (keyring) => {
        const accounts = await keyring.getAccounts();
        if (accounts.length > 0) {
          validKeyrings.push(keyring);
        }
      }),
    );
    this.keyrings = validKeyrings;
  }

  /**
   * Checks for duplicate keypairs, using the the first account in the given
   * array. Rejects if a duplicate is found.
   *
   * Only supports 'Simple Key Pair'.
   *
   * @param {string} type - The key pair type to check for.
   * @param {Array<string>} newAccountArray - Array of new accounts.
   * @returns {Promise<Array<string>>} The account, if no duplicate is found.
   */
  async checkForDuplicate(type, newAccountArray) {
    const accounts = await this.getAccounts();

    switch (type) {
      case KEYRINGS_TYPE_MAP.SIMPLE_KEYRING: {
        const isIncluded = Boolean(
          accounts.find(
            (key) =>
              key === newAccountArray[0] ||
              key === stripHexPrefix(newAccountArray[0]),
          ),
        );

        if (isIncluded) {
          throw new Error(
            "The account you're are trying to import is a duplicate",
          );
        }
        return newAccountArray;
      }
      default: {
        return newAccountArray;
      }
    }
  }

  /**
   * Add New Account
   *
   * Calls the `addAccounts` method on the given keyring,
   * and then saves those changes.
   *
   * @param {Keyring} selectedKeyring - The currently selected keyring.
   * @returns {Promise<Object>} A Promise that resolves to the state.
   */
  async addNewAccount(selectedKeyring) {
    const accounts = await selectedKeyring.addAccounts(1);
    accounts.forEach((hexAccount) => {
      this.emit('newAccount', hexAccount);
    });

    await this.persistAllKeyrings();
    await this._updateMemStoreKeyrings();
    this.fullUpdate();
  }

  /**
   * Export Account
   *
   * Requests the private key from the keyring controlling
   * the specified address.
   *
   * Returns a Promise that may resolve with the private key string.
   *
   * @param {string} address - The address of the account to export.
   * @returns {Promise<string>} The private key of the account.
   */
  async exportAccount(address) {
    const keyring = await this.getKeyringForAccount(address);
    return await keyring.exportAccount(normalizeAddress(address));
  }

  /**
   *
   * Remove Account
   *
   * Removes a specific account from a keyring
   * If the account is the last/only one then it also removes the keyring.
   *
   * @param {string} address - The address of the account to remove.
   * @returns {Promise<void>} A Promise that resolves if the operation was successful.
   */
  async removeAccount(address) {
    const keyring = await this.getKeyringForAccount(address);

    // Not all the keyrings support this, so we have to check
    if (typeof keyring.removeAccount === 'function') {
      keyring.removeAccount(address);
      this.emit('removedAccount', address);
    } else {
      throw new Error(
        `Keyring ${keyring.type} doesn't support account removal operations`,
      );
    }

    const accounts = await keyring.getAccounts();
    // Check if this was the last/only account
    if (accounts.length === 0) {
      await this.removeEmptyKeyrings();
    }

    await this.persistAllKeyrings();
    await this._updateMemStoreKeyrings();
    this.fullUpdate();
  }

  //
  // SIGNING METHODS
  //

  /**
   * Sign Ethereum Transaction
   *
   * Signs an Ethereum transaction object.
   *
   * @param {Object} ethTx - The transaction to sign.
   * @param {string} _fromAddress - The transaction 'from' address.
   * @param {Object} opts - Signing options.
   * @returns {Promise<Object>} The signed transaction object.
   */
  async signTransaction(ethTx, _fromAddress, opts = {}) {
    const fromAddress = normalizeAddress(_fromAddress);
    const keyring = await this.getKeyringForAccount(fromAddress);
    return await keyring.signTransaction(fromAddress, ethTx, opts);
  }

  /**
   * Sign Message
   *
   * Attempts to sign the provided message parameters.
   *
   * @param {Object} msgParams - The message parameters to sign.
   * @returns {Promise<Buffer>} The raw signature.
   */
  async signMessage(msgParams, opts = {}) {
    const address = normalizeAddress(msgParams.from);
    const keyring = await this.getKeyringForAccount(address);
    return await keyring.signMessage(address, msgParams.data, opts);
  }

  /**
   * Sign Personal Message
   *
   * Attempts to sign the provided message parameters.
   * Prefixes the hash before signing per the personal sign expectation.
   *
   * @param {Object} msgParams - The message parameters to sign.
   * @returns {Promise<Buffer>} The raw signature.
   */
  async signPersonalMessage(msgParams, opts = {}) {
    const address = normalizeAddress(msgParams.from);
    const keyring = await this.getKeyringForAccount(address);
    return await keyring.signPersonalMessage(address, msgParams.data, opts);
  }

  /**
   * Get encryption public key
   *
   * Get encryption public key for using in encrypt/decrypt process.
   *
   * @param {Object} address - The address to get the encryption public key for.
   * @returns {Promise<Buffer>} The public key.
   */
  async getEncryptionPublicKey(_address, opts = {}) {
    const address = normalizeAddress(_address);
    const keyring = await this.getKeyringForAccount(address);
    return await keyring.getEncryptionPublicKey(address, opts);
  }

  /**
   * Decrypt Message
   *
   * Attempts to decrypt the provided message parameters.
   *
   * @param {Object} msgParams - The decryption message parameters.
   * @returns {Promise<Buffer>} The raw decryption result.
   */
  async decryptMessage(msgParams, opts = {}) {
    const address = normalizeAddress(msgParams.from);
    const keyring = await this.getKeyringForAccount(address);
    return keyring.decryptMessage(address, msgParams.data, opts);
  }

  /**
   * Sign Typed Data
   * (EIP712 https://github.com/ethereum/EIPs/pull/712#issuecomment-329988454)
   *
   * @param {Object} msgParams - The message parameters to sign.
   * @returns {Promise<Buffer>} The raw signature.
   */
  async signTypedMessage(msgParams, opts = { version: 'V1' }) {
    const address = normalizeAddress(msgParams.from);
    const keyring = await this.getKeyringForAccount(address);
    return keyring.signTypedData(address, msgParams.data, opts);
  }

  /**
   * Gets the app key address for the given Ethereum address and origin.
   *
   * @param {string} _address - The Ethereum address for the app key.
   * @param {string} origin - The origin for the app key.
   * @returns {string} The app key address.
   */
  async getAppKeyAddress(_address, origin) {
    const address = normalizeAddress(_address);
    const keyring = await this.getKeyringForAccount(address);
    return keyring.getAppKeyAddress(address, origin);
  }

  /**
   * Exports an app key private key for the given Ethereum address and origin.
   *
   * @param {string} _address - The Ethereum address for the app key.
   * @param {string} origin - The origin for the app key.
   * @returns {string} The app key private key.
   */
  async exportAppKeyForAddress(_address, origin) {
    const address = normalizeAddress(_address);
    const keyring = await this.getKeyringForAccount(address);
    if (!('exportAccount' in keyring)) {
      throw new Error(
        `The keyring for address ${_address} does not support exporting.`,
      );
    }
    return keyring.exportAccount(address, { withAppKeyOrigin: origin });
  }

  //
  // PRIVATE METHODS
  //

  /**
   * Create First Key Tree
   *
   * - Clears the existing vault
   * - Creates a new vault
   * - Creates a random new HD Keyring with 1 account
   * - Makes that account the selected account
   * - Faucets that account on testnet
   * - Puts the current seed words into the state tree
   *
   * @param {string} password - The keyring controller password.
   * @returns {Promise<void>} - A promise that resolves if the operation was successful.
   */
  async createFirstKeyTree(password) {
    this.password = password;
    this.clearKeyrings();

    const keyring = await this.addNewKeyring(KEYRINGS_TYPE_MAP.HD_KEYRING);
    const [firstAccount] = await keyring.getAccounts();
    if (!firstAccount) {
      throw new Error('KeyringController - No account found on keychain.');
    }

    const hexAccount = normalizeAddress(firstAccount);
    this.emit('newVault', hexAccount);
    return null;
  }

  /**
   * Persist All Keyrings
   *
   * Iterates the current `keyrings` array,
   * serializes each one into a serialized array,
   * encrypts that array with the provided `password`,
   * and persists that encrypted string to storage.
   *
   * @param {string} password - The keyring controller password.
   * @returns {Promise<boolean>} Resolves to true once keyrings are persisted.
   */
  async persistAllKeyrings(password = this.password) {
    if (typeof password !== 'string') {
      throw new Error('KeyringController - password is not a string');
    }

    const salt = this._generateSalt();
    const encrypedKey = this._generateEncryptedKey(password, salt);
    this.encrypedKey = encrypedKey;

    this.password = password;
    const serializedKeyrings = await Promise.all(
      this.keyrings.map(async (keyring) => {
        const [type, data] = await Promise.all([
          keyring.type,
          keyring.serialize(),
        ]);
        return { type, data };
      }),
    );
    const encryptedString = await this.encryptor.encrypt(
      this.password,
      serializedKeyrings,
    );
    this.store.updateState({ vault: encryptedString });
    return true;
  }

  /**
   * Unlock Keyrings
   *
   * Attempts to unlock the persisted encrypted storage,
   * initializing the persisted keyrings to RAM.
   *
   * @param {string} password - The keyring controller password.
   * @returns {Promise<Array<Keyring>>} The keyrings.
   */
  async unlockKeyrings(password, encryptedKey) {
    const encryptedVault = this.store.getState().vault;
    if (!encryptedVault) {
      throw new Error('Cannot unlock without a previous vault.');
    }

    /* 
      MV3:  Store an encrypted key now that we have verified password
    */
    const loginByPassword =
      password !== undefined && encryptedKey === undefined;
    const [, salt] = encryptedVault.split(VAULT_SEPARATOR);
    this.encryptedKey =
      encryptedKey || this._generateEncryptedKey(password, salt);

    await this.clearKeyrings();

    const vault = loginByPassword
      ? await this.encryptor.decrypt(password, encryptedVault)
      : await this.encryptor.decrypt(this.encryptedKey, encryptedVault);

    this.password = password;

    await Promise.all(vault.map(this._restoreKeyring.bind(this)));

    await this._updateMemStoreKeyrings();
    return this.keyrings;
  }

  /* 
    MV3:  Generates the encrypted key
  */
  _generateEncryptedKey() {
    return '...';
  }

  /* 
    MV3:  Returns the encrypted key so it's accessible from the extension
  */
  getEncryptedKey() {
    return this.encryptedKey;
  }

  /* 
    MV3:  Creates a salt to be used in encrypted key unlocking
    https://github.com/MetaMask/browser-passworder/blob/d24b66934ab4d39d97ccff9ff0c3d25f86f1a141/src/index.ts#L180
  */
  _generateSalt(byteCount = 32) {
    const view = new Uint8Array(byteCount);
    global.crypto.getRandomValues(view);
    // Uint8Array is a fixed length array and thus does not have methods like pop, etc
    // so TypeScript complains about casting it to an array. Array.from() works here for
    // getting the proper type, but it results in a functional difference. In order to
    // cast, you have to first cast view to unknown then cast the unknown value to number[]
    // TypeScript ftw: double opt in to write potentially type-mismatched code.
    const b64encoded = window.btoa(String.fromCharCode.apply(null, view));
    return b64encoded;
  }

  /**
   * Restore Keyring
   *
   * Attempts to initialize a new keyring from the provided serialized payload.
   * On success, updates the memStore keyrings and returns the resulting
   * keyring instance.
   *
   * @param {Object} serialized - The serialized keyring.
   * @returns {Promise<Keyring>} The deserialized keyring.
   */
  async restoreKeyring(serialized) {
    const keyring = await this._restoreKeyring(serialized);
    await this._updateMemStoreKeyrings();
    return keyring;
  }

  /**
   * Restore Keyring Helper
   *
   * Attempts to initialize a new keyring from the provided serialized payload.
   * On success, returns the resulting keyring instance.
   *
   * @param {Object} serialized - The serialized keyring.
   * @returns {Promise<Keyring>} The deserialized keyring.
   */
  async _restoreKeyring(serialized) {
    const { type, data } = serialized;

    const Keyring = this.getKeyringClassForType(type);
    const keyring = new Keyring();
    await keyring.deserialize(data);
    // getAccounts also validates the accounts for some keyrings
    await keyring.getAccounts();
    this.keyrings.push(keyring);
    return keyring;
  }

  /**
   * Get Keyring Class For Type
   *
   * Searches the current `keyringTypes` array
   * for a Keyring class whose unique `type` property
   * matches the provided `type`,
   * returning it if it exists.
   *
   * @param {string} type - The type whose class to get.
   * @returns {Keyring|undefined} The class, if it exists.
   */
  getKeyringClassForType(type) {
    return this.keyringTypes.find((kr) => kr.type === type);
  }

  /**
   * Get Keyrings by Type
   *
   * Gets all keyrings of the given type.
   *
   * @param {string} type - The keyring types to retrieve.
   * @returns {Array<Keyring>} The keyrings.
   */
  getKeyringsByType(type) {
    return this.keyrings.filter((keyring) => keyring.type === type);
  }

  /**
   * Get Accounts
   *
   * Returns the public addresses of all current accounts
   * managed by all currently unlocked keyrings.
   *
   * @returns {Promise<Array<string>>} The array of accounts.
   */
  async getAccounts() {
    const keyrings = this.keyrings || [];

    const keyringArrays = await Promise.all(
      keyrings.map((keyring) => keyring.getAccounts()),
    );
    const addresses = keyringArrays.reduce((res, arr) => {
      return res.concat(arr);
    }, []);

    return addresses.map(normalizeAddress);
  }

  /**
   * Get Keyring For Account
   *
   * Returns the currently initialized keyring that manages
   * the specified `address` if one exists.
   *
   * @param {string} address - An account address.
   * @returns {Promise<Keyring>} The keyring of the account, if it exists.
   */
  async getKeyringForAccount(address) {
    const hexed = normalizeAddress(address);

    const candidates = await Promise.all(
      this.keyrings.map((keyring) => {
        return Promise.all([keyring, keyring.getAccounts()]);
      }),
    );

    const winners = candidates.filter((candidate) => {
      const accounts = candidate[1].map(normalizeAddress);
      return accounts.includes(hexed);
    });
    if (winners && winners.length > 0) {
      return winners[0][0];
    }

    // Adding more info to the error
    let errorInfo = '';
    if (!address) {
      errorInfo = 'The address passed in is invalid/empty';
    } else if (!candidates || !candidates.length) {
      errorInfo = 'There are no keyrings';
    } else if (!winners || !winners.length) {
      errorInfo = 'There are keyrings, but none match the address';
    }
    throw new Error(
      `No keyring found for the requested account. Error info: ${errorInfo}`,
    );
  }

  /**
   * Display For Keyring
   *
   * Is used for adding the current keyrings to the state object.
   * @param {Keyring} keyring
   * @returns {Promise<Object>} A keyring display object, with type and accounts properties.
   */
  async displayForKeyring(keyring) {
    const accounts = await keyring.getAccounts();

    return {
      type: keyring.type,
      accounts: accounts.map(normalizeAddress),
    };
  }

  /**
   * Clear Keyrings
   *
   * Deallocates all currently managed keyrings and accounts.
   * Used before initializing a new vault.
   */

  /* eslint-disable require-await */
  async clearKeyrings() {
    // clear keyrings from memory
    this.keyrings = [];
    this.memStore.updateState({
      keyrings: [],
    });
  }

  /**
   * Update memStore Keyrings
   *
   * Updates the in-memory keyrings, without persisting.
   */
  async _updateMemStoreKeyrings() {
    const keyrings = await Promise.all(
      this.keyrings.map(this.displayForKeyring),
    );
    return this.memStore.updateState({ keyrings });
  }

  /**
   * Unlock Keyrings
   *
   * Unlocks the keyrings.
   *
   * @emits KeyringController#unlock
   */
  setUnlocked() {
    this.memStore.updateState({ isUnlocked: true });
    this.emit('unlock');
  }

  /**
   * Forget hardware keyring
   *
   * Forget hardware and update memorized state.
   * @param {Keyring} keyring
   */
  forgetKeyring(keyring) {
    if (keyring.forgetDevice) {
      keyring.forgetDevice();
      this.persistAllKeyrings.bind(this)();
      this._updateMemStoreKeyrings.bind(this)();
    } else {
      throw new Error(
        `KeyringController - keyring does not have method "forgetDevice", keyring type: ${keyring.type}`,
      );
    }
  }
}

module.exports = KeyringController;
