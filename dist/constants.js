"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.KeyringControllerError = exports.KeyringType = void 0;
var KeyringType;
(function (KeyringType) {
    KeyringType["HD"] = "HD Key Tree";
    KeyringType["Simple"] = "Simple Key Pair";
})(KeyringType = exports.KeyringType || (exports.KeyringType = {}));
var KeyringControllerError;
(function (KeyringControllerError) {
    KeyringControllerError["NoKeyring"] = "KeyringController - No keyring found";
    KeyringControllerError["WrongPasswordType"] = "KeyringController - Password must be of type string.";
    KeyringControllerError["NoFirstAccount"] = "KeyringController - First Account not found.";
    KeyringControllerError["DuplicatedAccount"] = "KeyringController - The account you are trying to import is a duplicate";
    KeyringControllerError["VaultError"] = "KeyringController - Cannot unlock without a previous vault.";
    KeyringControllerError["UnsupportedGenerateRandomMnemonic"] = "KeyringController - The current keyring does not support the method generateRandomMnemonic.";
    KeyringControllerError["UnsupportedExportAccount"] = "`KeyringController - The keyring for the current address does not support the method exportAccount";
    KeyringControllerError["UnsupportedRemoveAccount"] = "`KeyringController - The keyring for the current address does not support the method removeAccount";
    KeyringControllerError["UnsupportedSignTransaction"] = "KeyringController - The keyring for the current address does not support the method signTransaction.";
    KeyringControllerError["UnsupportedSignMessage"] = "KeyringController - The keyring for the current address does not support the method signMessage.";
    KeyringControllerError["UnsupportedSignPersonalMessage"] = "KeyringController - The keyring for the current address does not support the method signPersonalMessage.";
    KeyringControllerError["UnsupportedGetEncryptionPublicKey"] = "KeyringController - The keyring for the current address does not support the method getEncryptionPublicKey.";
    KeyringControllerError["UnsupportedDecryptMessage"] = "KeyringController - The keyring for the current address does not support the method decryptMessage.";
    KeyringControllerError["UnsupportedSignTypedMessage"] = "KeyringController - The keyring for the current address does not support the method signTypedMessage.";
    KeyringControllerError["UnsupportedGetAppKeyAddress"] = "KeyringController - The keyring for the current address does not support the method getAppKeyAddress.";
    KeyringControllerError["UnsupportedExportAppKeyForAddress"] = "KeyringController - The keyring for the current address does not support the method exportAppKeyForAddress.";
    KeyringControllerError["NoAccountOnKeychain"] = "KeyringController - The keyring for the current address does not support the method decryptMessage.";
    KeyringControllerError["MissingCredentials"] = "KeyringController - Cannot persist vault without password and encryption key";
    KeyringControllerError["MissingVaultData"] = "KeyringController - Cannot persist vault without vault information";
    KeyringControllerError["ExpiredCredentials"] = "KeyringController - Encryption key and salt provided are expired";
    KeyringControllerError["NoKeyringBuilder"] = "KeyringController - No keyringBuilder found for keyring";
    KeyringControllerError["DataType"] = "KeyringController - Incorrect data type provided";
})(KeyringControllerError = exports.KeyringControllerError || (exports.KeyringControllerError = {}));
//# sourceMappingURL=constants.js.map