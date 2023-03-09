import type { Hex, Json, Keyring, Eip1024EncryptedData } from '@metamask/utils';

export type State = Json;

export type MessageParams = {
  from: Hex | string;
  data: Hex | string | Eip1024EncryptedData | Record<string, unknown>[];
};

export type KeyringControllerArgs = {
  keyringBuilders:
    | { (): Keyring<Json>; type: string }
    | ConcatArray<{ (): Keyring<Json>; type: string }>;

  cacheEncryptionKey: boolean;
  initState?: State;
  encryptor?: any;
};
