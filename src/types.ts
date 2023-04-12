import type { Json, Keyring } from '@metamask/utils';
import ObservableStore from 'obs-store';

export type KeyringControllerArgs = {
  keyringBuilders:
    | { (): Keyring<Json>; type: string }
    | ConcatArray<{ (): Keyring<Json>; type: string }>;

  cacheEncryptionKey: boolean;
  initState?: State;
  encryptor?: any;
};

export type State = {
  keyringBuilders?: { (): Keyring<Json>; type: string }[];

  store?: typeof ObservableStore;

  memStore?: typeof ObservableStore;

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

export type Account = {
  address: string;
  keyring: string;
};
