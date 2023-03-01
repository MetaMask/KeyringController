import type { Hex, Eip1024EncryptedData, Keyring } from '@metamask/utils';

export type IKeyringController = any;

export type MessageParams = {
  from: Hex | string;
  data: Hex | string | Eip1024EncryptedData | Record<string, unknown>[];
};

export enum KeyringType {
  HD = 'HD Key Tree',
  Simple = 'Simple Key Pair',
}

export type State = any;
export type ExtendedKeyring = Keyring<State> & {
  generateRandomMnemonic: () => string;
};