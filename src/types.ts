import type { Json, Keyring } from '@metamask/utils';

export type KeyringControllerArgs = {
  keyringBuilders?: { (): Keyring<Json>; type: string }[];
  cacheEncryptionKey: boolean;
  initState?: KeyringControllerPersistentState;
  encryptor?: GenericEncryptor | KeyEncryptor;
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
};

export type KeyEncryptor = GenericEncryptor & {
  encryptWithKey: <Obj>(
    key: unknown,
    object: Obj,
  ) => Promise<{
    data: string;
    iv: string;
    salt?: string;
  }>;
  encryptWithDetail: <Obj>(
    password: string,
    object: Obj,
    salt?: string,
  ) => Promise<{
    vault: string;
    exportedKeyString: string;
  }>;
  decryptWithKey: (key: unknown, encryptedString: string) => Promise<unknown>;
  decryptWithDetail: (
    password: string,
    encryptedString: string,
  ) => Promise<{
    salt: string;
    vault: unknown;
    exportedKeyString: string;
  }>;
  importKey: (key: string) => Promise<unknown>;
};
