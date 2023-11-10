import type {
  DetailedDecryptResult,
  DetailedEncryptionResult,
  EncryptionResult,
} from '@metamask/browser-passworder';
import type { Json, Keyring } from '@metamask/utils';

export type KeyringControllerArgs = {
  keyringBuilders?: { (): Keyring<Json>; type: string }[];
  initState?: KeyringControllerPersistentState;
  encryptor?: GenericEncryptor | KeyEncryptor;
  cacheEncryptionKey: boolean;
};

export type KeyringObject = {
  type: string;
  accounts: string[];
};

export type KeyringControllerPersistentState = {
  vault?: string;
};

export type KeyringControllerState = {
  keyrings: KeyringObject[];
  isUnlocked: boolean;
  encryptionKey?: string;
  encryptionSalt?: string;
};

export type SerializedKeyring = {
  type: string;
  data: Json;
};

export type GenericEncryptor = {
  encrypt: <Obj>(password: string, object: Obj) => Promise<string>;
  decrypt: (password: string, encryptedString: string) => Promise<unknown>;
  updateVault?: (vault: string, password: string) => Promise<string>;
};

export type KeyEncryptor = GenericEncryptor & {
  encryptWithKey: <Obj>(key: unknown, object: Obj) => Promise<EncryptionResult>;
  encryptWithDetail: <Obj>(
    password: string,
    object: Obj,
    salt?: string,
  ) => Promise<DetailedEncryptionResult>;
  decryptWithKey: (key: unknown, encryptedString: string) => Promise<unknown>;
  decryptWithDetail: (
    password: string,
    encryptedString: string,
  ) => Promise<DetailedDecryptResult>;
  importKey: (key: string) => Promise<unknown>;
  updateVaultWithDetail: (
    encryptedData: DetailedEncryptionResult,
    password: string,
  ) => Promise<DetailedEncryptionResult>;
};
