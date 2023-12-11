import type {
  EthBaseTransaction,
  EthBaseUserOperation,
  EthKeyring,
  EthUserOperation,
  EthUserOperationPatch,
} from '@metamask/keyring-api';
import type { Json, Hex } from '@metamask/utils';

const TYPE = 'Keyring Mock With Init';

class KeyringMockWithInit implements EthKeyring<Json> {
  static type = TYPE;

  public type = TYPE;

  #accounts: Hex[] = [];

  constructor(options: Record<string, unknown> | undefined = {}) {
    // eslint-disable-next-line @typescript-eslint/no-floating-promises, @typescript-eslint/promise-function-async
    this.deserialize(options);
  }

  async init() {
    return Promise.resolve();
  }

  async addAccounts(_: number): Promise<Hex[]> {
    return Promise.resolve(this.#accounts);
  }

  async getAccounts() {
    return Promise.resolve(this.#accounts);
  }

  async serialize() {
    return Promise.resolve({});
  }

  async deserialize(_: any) {
    return Promise.resolve();
  }

  async removeAccount(_: any) {
    return Promise.resolve();
  }

  async destroy() {
    return Promise.resolve();
  }

  async prepareUserOperation(
    _from: string,
    _txs: EthBaseTransaction[],
  ): Promise<EthBaseUserOperation> {
    return Promise.resolve() as any;
  }

  async patchUserOperation(
    _from: string,
    _userOp: EthUserOperation,
  ): Promise<EthUserOperationPatch> {
    return Promise.resolve() as any;
  }

  async signUserOperation(
    _from: string,
    _userOp: EthUserOperation,
  ): Promise<string> {
    return Promise.resolve() as any;
  }
}

export default KeyringMockWithInit;
