import type { TxData } from '@ethereumjs/tx';
import type {
  EthBaseTransaction,
  EthBaseUserOperation,
  EthKeyring,
  EthUserOperation,
  EthUserOperationPatch,
} from '@metamask/keyring-api';
import type { Json, Hex } from '@metamask/utils';

export class BaseKeyringMock implements EthKeyring<Json> {
  static type = 'Keyring Mock';

  public type = 'Keyring Mock';

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
}

export class KeyringMockWithInit extends BaseKeyringMock {
  static type = 'Keyring Mock With Init';

  public type = 'Keyring Mock With Init';

  constructor(options: Record<string, unknown> | undefined = {}) {
    super(options);
  }

  async init() {
    return Promise.resolve();
  }
}

export class KeyringMockWithRemoveAccount extends BaseKeyringMock {
  static type = 'Keyring Mock With Remove Account';

  public type = 'Keyring Mock With Remove Account';

  constructor(options: Record<string, unknown> | undefined = {}) {
    super(options);
  }

  async removeAccount(_: any) {
    return Promise.resolve();
  }
}

export class KeyringMockWithDestroy extends KeyringMockWithRemoveAccount {
  static type = 'Keyring Mock With Destroy';

  public type = 'Keyring Mock With Destroy';

  constructor(options: Record<string, unknown> | undefined = {}) {
    super(options);
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

export class KeyringMockWithSignTransaction extends BaseKeyringMock {
  static type = 'Keyring Mock With Sign Transaction';

  public type = 'Keyring Mock With Sign Transaction';

  constructor(options: Record<string, unknown> | undefined = {}) {
    super(options);
  }

  async signTransaction(_from: any, txData: any, _opts: any): Promise<TxData> {
    return Promise.resolve(txData);
  }
}

export class KeyringMockWithUserOp extends BaseKeyringMock {
  static type = 'Keyring Mock With User Operations';

  public type = 'Keyring Mock With User Operations';

  constructor(options: Record<string, unknown> | undefined = {}) {
    super(options);
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
