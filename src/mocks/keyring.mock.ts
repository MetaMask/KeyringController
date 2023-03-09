class KeyringMockWithInit {
  static type: string;

  async init() {
    return Promise.resolve();
  }

  getAccounts() {
    return [];
  }

  async serialize() {
    return Promise.resolve({});
  }

  async deserialize(_: any) {
    return Promise.resolve();
  }
}

KeyringMockWithInit.type = 'Keyring Mock With Init';

export default KeyringMockWithInit;
