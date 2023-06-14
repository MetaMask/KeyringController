import type { Keyring, Json, Hex } from '@metamask/utils';

const TYPE = 'Keyring Mock With Init';

class KeyringMockWithInit implements Keyring<Json> {
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
}

export default KeyringMockWithInit;
