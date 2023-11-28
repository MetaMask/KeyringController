import type { TxData } from '@ethereumjs/tx';
import type { Keyring, Json, Hex } from '@metamask/utils';

const TYPE = 'Keyring Mock With Init';

export class BaseKeyringMock implements Keyring<Json> {
  static type = 'Keyring Mock';

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
}

export class KeyringMockWithSignTransaction extends BaseKeyringMock {
  static type = 'Keyring Mock With Sign Transaction';

  public type = 'Keyring Mock With Sign Transaction';

  constructor(options: Record<string, unknown> | undefined = {}) {
    super(options);
  }

  async signTransaction(_from: any, _txData: any, _opts: any): Promise<TxData> {
    return Promise.resolve(_txData);
  }
}
