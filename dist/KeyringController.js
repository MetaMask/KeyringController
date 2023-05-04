"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
var _KeyringController_instances, _KeyringController_createFirstKeyTree, _KeyringController_restoreKeyring, _KeyringController_clearKeyrings, _KeyringController_setUnlocked, _KeyringController_newKeyring;
Object.defineProperty(exports, "__esModule", { value: true });
exports.keyringBuilderFactory = exports.KeyringController = void 0;
const encryptorUtils = __importStar(require("@metamask/browser-passworder"));
const eth_hd_keyring_1 = __importDefault(require("@metamask/eth-hd-keyring"));
const eth_sig_util_1 = require("@metamask/eth-sig-util");
const eth_simple_keyring_1 = __importDefault(require("@metamask/eth-simple-keyring"));
const utils_1 = require("@metamask/utils");
// TODO: Stop using `events`, and remove the notice about this from the README
// eslint-disable-next-line import/no-nodejs-modules
const events_1 = require("events");
const obs_store_1 = __importDefault(require("obs-store"));
const constants_1 = require("./constants");
const defaultKeyringBuilders = [
    keyringBuilderFactory(eth_simple_keyring_1.default),
    keyringBuilderFactory(eth_hd_keyring_1.default),
];
class KeyringController extends events_1.EventEmitter {
    constructor({ keyringBuilders, cacheEncryptionKey, initState = {}, encryptor = encryptorUtils, }) {
        super();
        _KeyringController_instances.add(this);
        this.keyringBuilders = keyringBuilders
            ? defaultKeyringBuilders.concat(keyringBuilders)
            : defaultKeyringBuilders;
        this.store = new obs_store_1.default(initState);
        this.memStore = new obs_store_1.default({
            isUnlocked: false,
            keyringTypes: this.keyringBuilders.map((keyringBuilder) => keyringBuilder.type),
            keyrings: [],
            encryptionKey: null,
        });
        this.encryptor = encryptor;
        this.keyrings = [];
        this.unsupportedKeyrings = [];
        // This option allows the controller to cache an exported key
        // for use in decrypting and encrypting data without password
        this.cacheEncryptionKey = Boolean(cacheEncryptionKey);
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
     * @returns The controller state.
     */
    fullUpdate() {
        this.emit('update', this.memStore.getState());
        return this.memStore.getState();
    }
    /**
     * =======================================
     * === Public Vault Management Methods ===
     * =======================================
     */
    /**
     * Create New Vault And Keychain
     *
     * Destroys any old encrypted storage,
     * creates a new encrypted store with the given password,
     * randomly creates a new HD wallet with 1 account,
     * faucets that account on the testnet.
     *
     * @fires KeyringController#unlock
     * @param password - The password to encrypt the vault with.
     * @returns A promise that resolves to the state.
     */
    async createNewVaultAndKeychain(password) {
        this.password = password;
        await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_createFirstKeyTree).call(this);
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_setUnlocked).call(this);
        return this.fullUpdate();
    }
    /**
     * CreateNewVaultAndRestore
     *
     * Destroys any old encrypted storage,
     * creates a new encrypted store with the given password,
     * creates a new HD wallet from the given seed with 1 account.
     *
     * @fires KeyringController#unlock
     * @param password - The password to encrypt the vault with.
     * @param seedPhrase - The BIP39-compliant seed phrase,
     * either as a string or Uint8Array.
     * @returns A promise that resolves to the state.
     */
    async createNewVaultAndRestore(password, seedPhrase) {
        if (typeof password !== 'string') {
            throw new TypeError(constants_1.KeyringControllerError.WrongPasswordType);
        }
        this.password = password;
        await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_clearKeyrings).call(this);
        const keyring = await this.addNewKeyring(constants_1.KeyringType.HD, {
            mnemonic: seedPhrase,
            numberOfAccounts: 1,
        });
        const [firstAccount] = await keyring.getAccounts();
        if (!firstAccount) {
            throw new Error(constants_1.KeyringControllerError.NoFirstAccount);
        }
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_setUnlocked).call(this);
        return this.fullUpdate();
    }
    /**
     * Set Locked.
     * This method deallocates all secrets, and effectively locks MetaMask.
     *
     * @fires KeyringController#lock
     * @returns A promise that resolves to the state.
     */
    async setLocked() {
        delete this.password;
        // set locked
        this.memStore.updateState({
            isUnlocked: false,
            encryptionKey: null,
            encryptionSalt: null,
        });
        // remove keyrings
        this.keyrings = [];
        await this.updateMemStoreKeyrings();
        this.emit('lock');
        return this.fullUpdate();
    }
    /**
     * Submit password.
     *
     * Attempts to decrypt the current vault and load its keyrings
     * into memory.
     *
     * Temporarily also migrates any old-style vaults first, as well
     * (Pre MetaMask 3.0.0).
     *
     * @fires KeyringController#unlock
     * @param password - The keyring controller password.
     * @returns A promise that resolves to the state.
     */
    async submitPassword(password) {
        this.keyrings = await this.unlockKeyrings(password);
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_setUnlocked).call(this);
        return this.fullUpdate();
    }
    /**
     * Submit Encryption Key.
     *
     * Attempts to decrypt the current vault and load its keyrings
     * into memory based on the vault and CryptoKey information.
     *
     * @fires KeyringController#unlock
     * @param encryptionKey - The encrypted key information used to decrypt the vault.
     * @param encryptionSalt - The salt used to generate the last key.
     * @returns A promise that resolves to the state.
     */
    async submitEncryptionKey(encryptionKey, encryptionSalt) {
        this.keyrings = await this.unlockKeyrings(undefined, encryptionKey, encryptionSalt);
        __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_setUnlocked).call(this);
        return this.fullUpdate();
    }
    /**
     * Verify Password
     *
     * Attempts to decrypt the current vault with a given password
     * to verify its validity.
     *
     * @param password - The vault password.
     */
    async verifyPassword(password) {
        const encryptedVault = this.store.getState().vault;
        if (!encryptedVault) {
            throw new Error(constants_1.KeyringControllerError.VaultError);
        }
        await this.encryptor.decrypt(password, encryptedVault);
    }
    /**
     * =========================================
     * === Public Account Management Methods ===
     * =========================================
     */
    /**
     * Add New Account.
     *
     * Calls the `addAccounts` method on the given keyring,
     * and then saves those changes.
     *
     * @param selectedKeyring - The currently selected keyring.
     * @returns A Promise that resolves to the state.
     */
    async addNewAccount(selectedKeyring) {
        const accounts = await selectedKeyring.addAccounts(1);
        accounts.forEach((hexAccount) => {
            this.emit('newAccount', hexAccount);
        });
        await this.persistAllKeyrings();
        return this.fullUpdate();
    }
    /**
     * Export Account
     *
     * Requests the private key from the keyring controlling
     * the specified address.
     *
     * Returns a Promise that may resolve with the private key string.
     *
     * @param address - The address of the account to export.
     * @returns The private key of the account.
     */
    async exportAccount(address) {
        const keyring = await this.getKeyringForAccount(address);
        if (!keyring.exportAccount) {
            throw new Error(constants_1.KeyringControllerError.UnsupportedExportAccount);
        }
        return await keyring.exportAccount((0, eth_sig_util_1.normalize)(address));
    }
    /**
     * Remove Account.
     *
     * Removes a specific account from a keyring
     * If the account is the last/only one then it also removes the keyring.
     *
     * @param address - The address of the account to remove.
     * @returns A promise that resolves if the operation was successful.
     */
    async removeAccount(address) {
        const keyring = await this.getKeyringForAccount(address);
        // Not all the keyrings support this, so we have to check
        if (!keyring.removeAccount) {
            throw new Error(constants_1.KeyringControllerError.UnsupportedRemoveAccount);
        }
        keyring.removeAccount(address);
        this.emit('removedAccount', address);
        const accounts = await keyring.getAccounts();
        // Check if this was the last/only account
        if (accounts.length === 0) {
            await this.removeEmptyKeyrings();
        }
        await this.persistAllKeyrings();
        return this.fullUpdate();
    }
    /**
     * Get Accounts
     *
     * Returns the public addresses of all current accounts
     * managed by all currently unlocked keyrings.
     *
     * @returns The array of accounts.
     */
    async getAccounts() {
        const keyrings = this.keyrings || [];
        const keyringArrays = await Promise.all(keyrings.map(async (keyring) => keyring.getAccounts()));
        const addresses = keyringArrays.reduce((res, arr) => {
            return res.concat(arr);
        }, []);
        return addresses.map(eth_sig_util_1.normalize);
    }
    /**
     * Get Keyring Class For Type
     *
     * Searches the current `keyringBuilders` array
     * for a Keyring builder whose unique `type` property
     * matches the provided `type`,
     * returning it if it exists.
     *
     * @param type - The type whose class to get.
     * @returns The class, if it exists.
     */
    getKeyringBuilderForType(type) {
        return this.keyringBuilders.find((keyringBuilder) => keyringBuilder.type === type);
    }
    /**
     * Update memStore Keyrings
     *
     * Updates the in-memory keyrings, without persisting.
     */
    async updateMemStoreKeyrings() {
        const keyrings = await Promise.all(this.keyrings.map(displayForKeyring));
        return this.memStore.updateState({ keyrings });
    }
    /**
     * ===========================================
     * === Public RPC Requests Routing Methods ===
     * ===========================================
     */
    /**
     * Sign Ethereum Transaction
     *
     * Signs an Ethereum transaction object.
     *
     * @param ethTx - The transaction to sign.
     * @param rawAddress - The transaction 'from' address.
     * @param opts - Signing options.
     * @returns The signed transaction object.
     */
    async signTransaction(ethTx, rawAddress, opts = {}) {
        const address = (0, eth_sig_util_1.normalize)(rawAddress);
        const keyring = await this.getKeyringForAccount(address);
        if (!keyring.signTransaction) {
            throw new Error(constants_1.KeyringControllerError.UnsupportedSignTransaction);
        }
        return await keyring.signTransaction(address, ethTx, opts);
    }
    /**
     * Sign Message
     *
     * Attempts to sign the provided message parameters.
     *
     * @param msgParams - The message parameters to sign.
     * @param msgParams.from - From address.
     * @param msgParams.data - The message to sign.
     * @param opts - Additional signing options.
     * @returns The raw signature.
     */
    async signMessage(msgParams, opts = {}) {
        const address = (0, eth_sig_util_1.normalize)(msgParams.from);
        const keyring = await this.getKeyringForAccount(address);
        if (!keyring.signMessage) {
            throw new Error(constants_1.KeyringControllerError.UnsupportedSignMessage);
        }
        return await keyring.signMessage(address, msgParams.data, opts);
    }
    /**
     * Sign Personal Message
     *
     * Attempts to sign the provided message parameters.
     * Prefixes the hash before signing per the personal sign expectation.
     *
     * @param msgParams - The message parameters to sign.
     * @param msgParams.from - From address.
     * @param msgParams.data - The message to sign.
     * @param opts - Additional signing options.
     * @returns The raw signature.
     */
    async signPersonalMessage(msgParams, opts = {}) {
        const address = (0, eth_sig_util_1.normalize)(msgParams.from);
        const keyring = await this.getKeyringForAccount(address);
        if (!keyring.signPersonalMessage) {
            throw new Error(constants_1.KeyringControllerError.UnsupportedSignPersonalMessage);
        }
        const normalizedData = (0, eth_sig_util_1.normalize)(msgParams.data);
        return await keyring.signPersonalMessage(address, normalizedData, opts);
    }
    /**
     * Get encryption public key
     *
     * Get encryption public key for using in encrypt/decrypt process.
     *
     * @param address - The address to get the encryption public key for.
     * @param opts - Additional encryption options.
     * @returns The public key.
     */
    async getEncryptionPublicKey(address, opts = {}) {
        const normalizedAddress = (0, eth_sig_util_1.normalize)(address);
        const keyring = await this.getKeyringForAccount(address);
        if (!keyring.getEncryptionPublicKey) {
            throw new Error(constants_1.KeyringControllerError.UnsupportedGetEncryptionPublicKey);
        }
        return await keyring.getEncryptionPublicKey(normalizedAddress, opts);
    }
    /**
     * Decrypt Message
     *
     * Attempts to decrypt the provided message parameters.
     *
     * @param msgParams - The decryption message parameters.
     * @param msgParams.from - The address of the account you want to use to decrypt the message.
     * @param msgParams.data - The encrypted data that you want to decrypt.
     * @returns The raw decryption result.
     */
    async decryptMessage(msgParams) {
        const address = (0, eth_sig_util_1.normalize)(msgParams.from);
        const keyring = await this.getKeyringForAccount(address);
        if (!keyring.decryptMessage) {
            throw new Error(constants_1.KeyringControllerError.UnsupportedDecryptMessage);
        }
        return keyring.decryptMessage(address, msgParams.data);
    }
    /**
     * Sign Typed Data.
     *
     * @see {@link https://github.com/ethereum/EIPs/pull/712#issuecomment-329988454|EIP712}.
     * @param msgParams - The message parameters to sign.
     * @param msgParams.from - From address.
     * @param msgParams.data - The data to sign.
     * @param opts - Additional signing options.
     * @returns The raw signature.
     */
    async signTypedMessage(msgParams, opts = { version: 'V1' }) {
        const address = (0, eth_sig_util_1.normalize)(msgParams.from);
        const keyring = await this.getKeyringForAccount(address);
        if (!keyring.signTypedData) {
            throw new Error(constants_1.KeyringControllerError.UnsupportedSignTypedMessage);
        }
        // Looks like this is not well defined in the Keyring interface since
        // our tests show that we should be able to pass an array.
        // @ts-expect-error Missing other required permission types.
        return keyring.signTypedData(address, msgParams.data, opts);
    }
    /**
     * Gets the app key address for the given Ethereum address and origin.
     *
     * @param rawAddress - The Ethereum address for the app key.
     * @param origin - The origin for the app key.
     * @returns The app key address.
     */
    async getAppKeyAddress(rawAddress, origin) {
        const address = (0, eth_sig_util_1.normalize)(rawAddress);
        const keyring = await this.getKeyringForAccount(address);
        if (!keyring.getAppKeyAddress) {
            throw new Error(constants_1.KeyringControllerError.UnsupportedGetAppKeyAddress);
        }
        return keyring.getAppKeyAddress(address, origin);
    }
    /**
     * Exports an app key private key for the given Ethereum address and origin.
     *
     * @param rawAddress - The Ethereum address for the app key.
     * @param origin - The origin for the app key.
     * @returns The app key private key.
     */
    async exportAppKeyForAddress(rawAddress, origin) {
        const address = (0, eth_sig_util_1.normalize)(rawAddress);
        const keyring = await this.getKeyringForAccount(address);
        if (!keyring.exportAccount) {
            throw new Error(constants_1.KeyringControllerError.UnsupportedExportAppKeyForAddress);
        }
        return keyring.exportAccount(address, { withAppKeyOrigin: origin });
    }
    /**
     * =========================================
     * === Public Keyring Management Methods ===
     * =========================================
     */
    /**
     * Add New Keyring
     *
     * Adds a new Keyring of the given `type` to the vault
     * and the current decrypted Keyrings array.
     *
     * All Keyring classes implement a unique `type` string,
     * and this is used to retrieve them from the keyringBuilders array.
     *
     * @param type - The type of keyring to add.
     * @param opts - The constructor options for the keyring.
     * @returns The new keyring.
     */
    async addNewKeyring(type, opts = {}) {
        let keyring;
        switch (type) {
            case constants_1.KeyringType.Simple:
                keyring = await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_newKeyring).call(this, type, opts.privateKeys);
                break;
            default:
                keyring = await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_newKeyring).call(this, type, opts);
                break;
        }
        if (!keyring) {
            throw new Error(constants_1.KeyringControllerError.NoKeyring);
        }
        if (!opts.mnemonic && type === constants_1.KeyringType.HD) {
            if (!keyring.generateRandomMnemonic) {
                throw new Error(constants_1.KeyringControllerError.UnsupportedGenerateRandomMnemonic);
            }
            keyring.generateRandomMnemonic();
            await keyring.addAccounts(1);
        }
        const accounts = await keyring.getAccounts();
        await this.checkForDuplicate(type, accounts);
        this.keyrings.push(keyring);
        await this.persistAllKeyrings();
        this.fullUpdate();
        return keyring;
    }
    /**
     * Remove empty keyrings.
     *
     * Loops through the keyrings and removes the ones with empty accounts
     * (usually after removing the last / only account) from a keyring.
     */
    async removeEmptyKeyrings() {
        const validKeyrings = [];
        // Since getAccounts returns a Promise
        // We need to wait to hear back form each keyring
        // in order to decide which ones are now valid (accounts.length > 0)
        await Promise.all(this.keyrings.map(async (keyring) => {
            const accounts = await keyring.getAccounts();
            if (accounts.length > 0) {
                validKeyrings.push(keyring);
            }
        }));
        this.keyrings = validKeyrings;
    }
    /**
     * Checks for duplicate keypairs, using the the first account in the given
     * array. Rejects if a duplicate is found.
     *
     * Only supports 'Simple Key Pair'.
     *
     * @param type - The key pair type to check for.
     * @param newAccountArray - Array of new accounts.
     * @returns The account, if no duplicate is found.
     */
    async checkForDuplicate(type, newAccountArray) {
        const accounts = await this.getAccounts();
        switch (type) {
            case constants_1.KeyringType.Simple: {
                const isIncluded = Boolean(accounts.find((key) => newAccountArray[0] &&
                    (key === newAccountArray[0] ||
                        key === (0, utils_1.remove0x)(newAccountArray[0]))));
                if (isIncluded) {
                    throw new Error(constants_1.KeyringControllerError.DuplicatedAccount);
                }
                return newAccountArray;
            }
            default: {
                return newAccountArray;
            }
        }
    }
    /**
     * Get Keyring For Account
     *
     * Returns the currently initialized keyring that manages
     * the specified `address` if one exists.
     *
     * @param address - An account address.
     * @returns The keyring of the account, if it exists.
     */
    async getKeyringForAccount(address) {
        var _a;
        const hexed = (0, eth_sig_util_1.normalize)(address);
        const candidates = await Promise.all(this.keyrings.map(async (keyring) => {
            return Promise.all([keyring, keyring.getAccounts()]);
        }));
        const winners = candidates.filter((candidate) => {
            const accounts = candidate[1].map(eth_sig_util_1.normalize);
            return accounts.includes(hexed);
        });
        if (winners.length && ((_a = winners[0]) === null || _a === void 0 ? void 0 : _a.length)) {
            return winners[0][0];
        }
        // Adding more info to the error
        let errorInfo = '';
        if (!address) {
            errorInfo = 'The address passed in is invalid/empty';
        }
        else if (!candidates.length) {
            errorInfo = 'There are no keyrings';
        }
        else if (!winners.length) {
            errorInfo = 'There are keyrings, but none match the address';
        }
        throw new Error(`${constants_1.KeyringControllerError.NoKeyring}. Error info: ${errorInfo}`);
    }
    /**
     * Restore Keyring
     *
     * Attempts to initialize a new keyring from the provided serialized payload.
     * On success, updates the memStore keyrings and returns the resulting
     * keyring instance.
     *
     * @param serialized - The serialized keyring.
     * @returns The deserialized keyring.
     */
    async restoreKeyring(serialized) {
        const keyring = await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_restoreKeyring).call(this, serialized);
        if (keyring) {
            await this.updateMemStoreKeyrings();
        }
        return keyring;
    }
    /**
     * Get Keyrings by Type
     *
     * Gets all keyrings of the given type.
     *
     * @param type - The keyring types to retrieve.
     * @returns Keyrings matching the specified type.
     */
    getKeyringsByType(type) {
        const keyrings = this.keyrings.filter((keyring) => keyring.type === type);
        if (!keyrings.length) {
            throw new Error(constants_1.KeyringControllerError.NoKeyring);
        }
        return keyrings;
    }
    /**
     * Persist All Keyrings
     *
     * Iterates the current `keyrings` array,
     * serializes each one into a serialized array,
     * encrypts that array with the provided `password`,
     * and persists that encrypted string to storage.
     *
     * @returns Resolves to true once keyrings are persisted.
     */
    async persistAllKeyrings() {
        const { encryptionKey, encryptionSalt } = this.memStore.getState();
        if (!this.password && !encryptionKey) {
            throw new Error(constants_1.KeyringControllerError.MissingCredentials);
        }
        const serializedKeyrings = await Promise.all(this.keyrings.map(async (keyring) => {
            const [type, data] = await Promise.all([
                keyring.type,
                keyring.serialize(),
            ]);
            return { type, data };
        }));
        serializedKeyrings.push(...this.unsupportedKeyrings);
        let vault;
        let newEncryptionKey;
        if (this.cacheEncryptionKey) {
            if (this.password) {
                const { vault: newVault, exportedKeyString } = await this.encryptor.encryptWithDetail(this.password, serializedKeyrings);
                vault = newVault;
                newEncryptionKey = exportedKeyString;
            }
            else if (encryptionKey) {
                const key = await this.encryptor.importKey(encryptionKey);
                const vaultJSON = await this.encryptor.encryptWithKey(key, serializedKeyrings);
                vaultJSON.salt = encryptionSalt;
                vault = JSON.stringify(vaultJSON);
            }
        }
        else {
            if (typeof this.password !== 'string') {
                throw new TypeError(constants_1.KeyringControllerError.WrongPasswordType);
            }
            vault = await this.encryptor.encrypt(this.password, serializedKeyrings);
        }
        if (!vault) {
            throw new Error(constants_1.KeyringControllerError.MissingVaultData);
        }
        this.store.updateState({ vault });
        // The keyring updates need to be announced before updating the encryptionKey
        // so that the updated keyring gets propagated to the extension first.
        // Not calling {@link updateMemStoreKeyrings} results in the wrong account being selected
        // in the extension.
        await this.updateMemStoreKeyrings();
        if (newEncryptionKey) {
            this.memStore.updateState({
                encryptionKey: newEncryptionKey,
                encryptionSalt: JSON.parse(vault).salt,
            });
        }
        return true;
    }
    /**
     * Unlock Keyrings.
     *
     * Attempts to unlock the persisted encrypted storage,
     * initializing the persisted keyrings to RAM.
     *
     * @param password - The keyring controller password.
     * @param encryptionKey - An exported key string to unlock keyrings with.
     * @param encryptionSalt - The salt used to encrypt the vault.
     * @returns The keyrings array.
     */
    async unlockKeyrings(password, encryptionKey, encryptionSalt) {
        const encryptedVault = this.store.getState().vault;
        if (!encryptedVault) {
            throw new Error(constants_1.KeyringControllerError.VaultError);
        }
        await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_clearKeyrings).call(this);
        let vault;
        if (this.cacheEncryptionKey) {
            if (password) {
                const result = await this.encryptor.decryptWithDetail(password, encryptedVault);
                vault = result.vault;
                this.password = password;
                this.memStore.updateState({
                    encryptionKey: result.exportedKeyString,
                    encryptionSalt: result.salt,
                });
            }
            else {
                const parsedEncryptedVault = JSON.parse(encryptedVault);
                if (encryptionSalt !== parsedEncryptedVault.salt) {
                    throw new Error(constants_1.KeyringControllerError.ExpiredCredentials);
                }
                if (typeof encryptionKey !== 'string') {
                    throw new TypeError(constants_1.KeyringControllerError.WrongPasswordType);
                }
                const key = await this.encryptor.importKey(encryptionKey);
                vault = await this.encryptor.decryptWithKey(key, parsedEncryptedVault);
                // This call is required on the first call because encryptionKey
                // is not yet inside the memStore
                this.memStore.updateState({
                    encryptionKey,
                    encryptionSalt,
                });
            }
        }
        else {
            if (typeof password !== 'string') {
                throw new TypeError(constants_1.KeyringControllerError.WrongPasswordType);
            }
            vault = await this.encryptor.decrypt(password, encryptedVault);
            this.password = password;
        }
        await Promise.all(vault.map(__classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_restoreKeyring).bind(this)));
        await this.updateMemStoreKeyrings();
        return this.keyrings;
    }
}
exports.KeyringController = KeyringController;
_KeyringController_instances = new WeakSet(), _KeyringController_createFirstKeyTree = 
// =======================
// === Private Methods ===
// =======================
/**
 * Create First Key Tree.
 *
 * - Clears the existing vault.
 * - Creates a new vault.
 * - Creates a random new HD Keyring with 1 account.
 * - Makes that account the selected account.
 * - Faucets that account on testnet.
 * - Puts the current seed words into the state tree.
 *
 * @returns A promise that resolves if the operation was successful.
 */
async function _KeyringController_createFirstKeyTree() {
    await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_clearKeyrings).call(this);
    const keyring = await this.addNewKeyring(constants_1.KeyringType.HD);
    if (!keyring) {
        throw new Error(constants_1.KeyringControllerError.NoKeyring);
    }
    const [firstAccount] = await keyring.getAccounts();
    if (!firstAccount) {
        throw new Error(constants_1.KeyringControllerError.NoAccountOnKeychain);
    }
    const hexAccount = (0, eth_sig_util_1.normalize)(firstAccount);
    this.emit('newVault', hexAccount);
    return null;
}, _KeyringController_restoreKeyring = 
/**
 * Restore Keyring Helper
 *
 * Attempts to initialize a new keyring from the provided serialized payload.
 * On success, returns the resulting keyring instance.
 *
 * @param serialized - The serialized keyring.
 * @param serialized.type - Keyring type.
 * @param serialized.data - Keyring data.
 * @returns The deserialized keyring or undefined if the keyring type is unsupported.
 */
async function _KeyringController_restoreKeyring(serialized) {
    const { type, data } = serialized;
    let keyring;
    try {
        keyring = await __classPrivateFieldGet(this, _KeyringController_instances, "m", _KeyringController_newKeyring).call(this, type, data);
    }
    catch (error) {
        // Ignore error.
        console.error(error);
    }
    if (!keyring) {
        this.unsupportedKeyrings.push(serialized);
        return undefined;
    }
    // getAccounts also validates the accounts for some keyrings
    await keyring.getAccounts();
    this.keyrings.push(keyring);
    return keyring;
}, _KeyringController_clearKeyrings = 
/**
 * Clear Keyrings
 *
 * Deallocates all currently managed keyrings and accounts.
 * Used before initializing a new vault.
 */
async function _KeyringController_clearKeyrings() {
    // clear keyrings from memory
    this.keyrings = [];
    this.memStore.updateState({
        keyrings: [],
    });
}, _KeyringController_setUnlocked = function _KeyringController_setUnlocked() {
    this.memStore.updateState({ isUnlocked: true });
    this.emit('unlock');
}, _KeyringController_newKeyring = 
/**
 * Instantiate, initialize and return a new keyring
 *
 * The keyring instantiated is of the given `type`.
 *
 * @param type - The type of keyring to add.
 * @param data - The data to restore a previously serialized keyring.
 * @returns The new keyring.
 */
async function _KeyringController_newKeyring(type, data) {
    const keyringBuilder = this.getKeyringBuilderForType(type);
    if (!keyringBuilder) {
        throw new Error(`${constants_1.KeyringControllerError.NoKeyringBuilder}. Keyring type: ${type}`);
    }
    const keyring = keyringBuilder();
    if (!(0, utils_1.isValidJson)(data)) {
        throw new Error(constants_1.KeyringControllerError.DataType);
    }
    await keyring.deserialize(data);
    // @ts-expect-error The method 'init' is not part of the current Keyring type
    if (keyring.init) {
        // @ts-expect-error The method 'init' is not part of the current Keyring type
        await keyring.init();
    }
    return keyring;
};
/**
 * Get builder function for `Keyring`
 *
 * Returns a builder function for `Keyring` with a `type` property.
 *
 * @param KeyringConstructor - The Keyring class for the builder.
 * @returns A builder function for the given Keyring.
 */
function keyringBuilderFactory(KeyringConstructor) {
    const builder = () => new KeyringConstructor();
    builder.type = KeyringConstructor.type;
    return builder;
}
exports.keyringBuilderFactory = keyringBuilderFactory;
/**
 * Display For Keyring
 *
 * Is used for adding the current keyrings to the state object.
 *
 * @param keyring - The keyring to display.
 * @returns A keyring display object, with type and accounts properties.
 */
async function displayForKeyring(keyring) {
    const accounts = await keyring.getAccounts();
    return {
        type: keyring.type,
        accounts: accounts.map(eth_sig_util_1.normalize),
    };
}
//# sourceMappingURL=KeyringController.js.map