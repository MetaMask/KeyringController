"use strict";
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var _KeyringMockWithInit_accounts;
Object.defineProperty(exports, "__esModule", { value: true });
const TYPE = 'Keyring Mock With Init';
class KeyringMockWithInit {
    constructor(options = {}) {
        this.type = TYPE;
        _KeyringMockWithInit_accounts.set(this, []);
        // eslint-disable-next-line @typescript-eslint/no-floating-promises, @typescript-eslint/promise-function-async
        this.deserialize(options);
    }
    async init() {
        return Promise.resolve();
    }
    async addAccounts(_) {
        return Promise.resolve(__classPrivateFieldGet(this, _KeyringMockWithInit_accounts, "f"));
    }
    async getAccounts() {
        return Promise.resolve(__classPrivateFieldGet(this, _KeyringMockWithInit_accounts, "f"));
    }
    async serialize() {
        return Promise.resolve({});
    }
    async deserialize(_) {
        return Promise.resolve();
    }
}
_KeyringMockWithInit_accounts = new WeakMap();
KeyringMockWithInit.type = TYPE;
exports.default = KeyringMockWithInit;
//# sourceMappingURL=keyring.mock.js.map