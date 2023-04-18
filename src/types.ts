import type { Json, Keyring } from '@metamask/utils';
import ObservableStore from 'obs-store';

export type KeyringControllerArgs = {
  keyringBuilders:
    | { (): Keyring<Json>; type: string }
    | ConcatArray<{ (): Keyring<Json>; type: string }>;

  cacheEncryptionKey: boolean;
  initState?: KeyringControllerState;
  encryptor?: any;
};

export type KeyringControllerState = {
  keyringBuilders?: { (): Keyring<Json>; type: string }[];

  store?: typeof ObservableStore;

  memStore?: typeof ObservableStore;

  keyrings?: Keyring<Json>[];

  isUnlocked?: boolean;

  encryptionKey?: string;

  encryptionSalt?: string;

  password?: string;
};

export type SerializedKeyring = {
  type: string;
  data: Json;
};
