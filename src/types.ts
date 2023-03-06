import type { Hex, Json, Keyring, Eip1024EncryptedData } from '@metamask/utils';

export type State = Json;

export type MessageParams = {
  from: Hex | string;
  data: Hex | string | Eip1024EncryptedData | Record<string, unknown>[];
};

export enum KeyringType {
  HD = 'HD Key Tree',
  Simple = 'Simple Key Pair',
}

export type ExtendedKeyring = Keyring<Json> & {
  generateRandomMnemonic: () => string;
};
