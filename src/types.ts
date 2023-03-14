import type { Hex, Json, Keyring, Eip1024EncryptedData } from '@metamask/utils';

export type MessageParams = {
  from: Hex | string;
  data: Hex | string | Eip1024EncryptedData | Record<string, unknown>[];
};

export type KeyringControllerArgs = {
  keyringBuilders:
    | { (): Keyring<Json>; type: string }
    | ConcatArray<{ (): Keyring<Json>; type: string }>;

  cacheEncryptionKey: boolean;
  initState?: KeyringControllerState;
  encryptor?: any;
};

export type KeyringControllerState = {
  keyrings?: Keyring<Json>[];

  vaultUnlock?: boolean;

  encryptionKey?: string;

  encryptionSalt?: string;

  password?: string;
};

export type SerializedKeyring = {
  type: string;
  data: Json;
};
