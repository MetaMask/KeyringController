import type { Hex, Json, Eip1024EncryptedData } from '@metamask/utils';

export type State = Json;

export type MessageParams = {
  from: Hex | string;
  data: Hex | string | Eip1024EncryptedData | Record<string, unknown>[];
};
