class KeyringMockWithInit {
  static type = 'Keyring Mock With Init';

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

export default KeyringMockWithInit;
