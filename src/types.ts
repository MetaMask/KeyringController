import type { Json, Keyring } from '@metamask/utils';

export type KeyringControllerArgs = {
  keyringBuilders:
    | { (): Keyring<Json>; type: string }
    | ConcatArray<{ (): Keyring<Json>; type: string }>;

  cacheEncryptionKey: boolean;
  initState?: KeyringControllerPersistentState;
  encryptor?: any;
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
