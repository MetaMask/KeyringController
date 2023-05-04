/// <reference types="node" />
import type { TypedTransaction, TxData } from '@ethereumjs/tx';
import type { Hex, Json, Bytes, Keyring, KeyringClass, Eip1024EncryptedData } from '@metamask/utils';
import { EventEmitter } from 'events';
import ObservableStore from 'obs-store';
import { SerializedKeyring, KeyringControllerArgs, KeyringControllerState } from './types';
declare class KeyringController extends EventEmitter {
    #private;
    keyringBuilders: {
        (): Keyring<Json>;
        type: string;
    }[];
    store: typeof ObservableStore;
    memStore: typeof ObservableStore;
    encryptor: any;
    keyrings: Keyring<Json>[];
    cacheEncryptionKey: boolean;
    unsupportedKeyrings: SerializedKeyring[];
    password?: string;
    constructor({ keyringBuilders, cacheEncryptionKey, initState, encryptor, }: KeyringControllerArgs);
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
    createNewVaultAndKeychain(password: string): Promise<KeyringControllerState>;
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
    createNewVaultAndRestore(password: string, seedPhrase: Uint8Array | string | number[]): Promise<KeyringControllerState>;
    /**
     * Set Locked.
     * This method deallocates all secrets, and effectively locks MetaMask.
     *
     * @fires KeyringController#lock
     * @returns A promise that resolves to the state.
     */
    setLocked(): Promise<KeyringControllerState>;
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
    submitPassword(password: string): Promise<KeyringControllerState>;
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
    submitEncryptionKey(encryptionKey: string, encryptionSalt: string): Promise<KeyringControllerState>;
    /**
     * Verify Password
     *
     * Attempts to decrypt the current vault with a given password
     * to verify its validity.
     *
     * @param password - The vault password.
     */
    verifyPassword(password: string): Promise<void>;
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
    addNewAccount(selectedKeyring: Keyring<Json>): Promise<KeyringControllerState>;
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
    exportAccount(address: string): Promise<string>;
    /**
     * Remove Account.
     *
     * Removes a specific account from a keyring
     * If the account is the last/only one then it also removes the keyring.
     *
     * @param address - The address of the account to remove.
     * @returns A promise that resolves if the operation was successful.
     */
    removeAccount(address: Hex): Promise<KeyringControllerState>;
    /**
     * Get Accounts
     *
     * Returns the public addresses of all current accounts
     * managed by all currently unlocked keyrings.
     *
     * @returns The array of accounts.
     */
    getAccounts(): Promise<string[]>;
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
    getKeyringBuilderForType(type: string): {
        (): Keyring<Json>;
        type: string;
    } | undefined;
    /**
     * Update memStore Keyrings
     *
     * Updates the in-memory keyrings, without persisting.
     */
    updateMemStoreKeyrings(): Promise<Json>;
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
    signTransaction(ethTx: TypedTransaction, rawAddress: string, opts?: Record<string, unknown>): Promise<TxData>;
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
    signMessage(msgParams: {
        from: string;
        data: string;
    }, opts?: Record<string, unknown>): Promise<string>;
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
    signPersonalMessage(msgParams: {
        from: string;
        data: string;
    }, opts?: Record<string, unknown>): Promise<string>;
    /**
     * Get encryption public key
     *
     * Get encryption public key for using in encrypt/decrypt process.
     *
     * @param address - The address to get the encryption public key for.
     * @param opts - Additional encryption options.
     * @returns The public key.
     */
    getEncryptionPublicKey(address: string, opts?: Record<string, unknown>): Promise<Bytes>;
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
    decryptMessage(msgParams: {
        from: string;
        data: Eip1024EncryptedData;
    }): Promise<Bytes>;
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
    signTypedMessage(msgParams: {
        from: string;
        data: Record<string, unknown>[];
    }, opts?: Record<string, unknown>): Promise<Bytes>;
    /**
     * Gets the app key address for the given Ethereum address and origin.
     *
     * @param rawAddress - The Ethereum address for the app key.
     * @param origin - The origin for the app key.
     * @returns The app key address.
     */
    getAppKeyAddress(rawAddress: string, origin: string): Promise<string>;
    /**
     * Exports an app key private key for the given Ethereum address and origin.
     *
     * @param rawAddress - The Ethereum address for the app key.
     * @param origin - The origin for the app key.
     * @returns The app key private key.
     */
    exportAppKeyForAddress(rawAddress: string, origin: string): Promise<string>;
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
    addNewKeyring(type: string, opts?: Record<string, unknown>): Promise<Keyring<Json>>;
    /**
     * Remove empty keyrings.
     *
     * Loops through the keyrings and removes the ones with empty accounts
     * (usually after removing the last / only account) from a keyring.
     */
    removeEmptyKeyrings(): Promise<void>;
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
    checkForDuplicate(type: string, newAccountArray: string[]): Promise<string[]>;
    /**
     * Get Keyring For Account
     *
     * Returns the currently initialized keyring that manages
     * the specified `address` if one exists.
     *
     * @param address - An account address.
     * @returns The keyring of the account, if it exists.
     */
    getKeyringForAccount(address: string): Promise<Keyring<Json>>;
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
    restoreKeyring(serialized: SerializedKeyring): Promise<Keyring<Json> | undefined>;
    /**
     * Get Keyrings by Type
     *
     * Gets all keyrings of the given type.
     *
     * @param type - The keyring types to retrieve.
     * @returns Keyrings matching the specified type.
     */
    getKeyringsByType(type: string): Keyring<Json>[];
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
    persistAllKeyrings(): Promise<boolean>;
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
    unlockKeyrings(password: string | undefined, encryptionKey?: string, encryptionSalt?: string): Promise<Keyring<Json>[]>;
}
/**
 * Get builder function for `Keyring`
 *
 * Returns a builder function for `Keyring` with a `type` property.
 *
 * @param KeyringConstructor - The Keyring class for the builder.
 * @returns A builder function for the given Keyring.
 */
declare function keyringBuilderFactory(KeyringConstructor: KeyringClass<Json>): {
    (): Keyring<Json>;
    type: string;
};
export { KeyringController, keyringBuilderFactory };
