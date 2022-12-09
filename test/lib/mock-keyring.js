class KeyringMockWithInit {
  init() {
    return Promise.resolve();
  }

  getAccounts() {
    return [];
  }

  serialize() {
    return Promise.resolve({});
  }
}

KeyringMockWithInit.type = 'Keyring Mock With Init';

module.exports = {
  KeyringMockWithInit,
};
