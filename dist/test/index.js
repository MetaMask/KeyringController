"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.MOCK_SALT = exports.MOCK_ENCRYPTION_KEY = exports.MOCK_HEX = exports.MOCK_HARDCODED_KEY = exports.PASSWORD = exports.KeyringMockWithInit = exports.mockEncryptor = void 0;
const encryptor_mock_1 = require("./encryptor.mock");
Object.defineProperty(exports, "mockEncryptor", { enumerable: true, get: function () { return encryptor_mock_1.mockEncryptor; } });
Object.defineProperty(exports, "PASSWORD", { enumerable: true, get: function () { return encryptor_mock_1.PASSWORD; } });
Object.defineProperty(exports, "MOCK_HARDCODED_KEY", { enumerable: true, get: function () { return encryptor_mock_1.MOCK_HARDCODED_KEY; } });
Object.defineProperty(exports, "MOCK_HEX", { enumerable: true, get: function () { return encryptor_mock_1.MOCK_HEX; } });
Object.defineProperty(exports, "MOCK_ENCRYPTION_KEY", { enumerable: true, get: function () { return encryptor_mock_1.MOCK_ENCRYPTION_KEY; } });
Object.defineProperty(exports, "MOCK_SALT", { enumerable: true, get: function () { return encryptor_mock_1.MOCK_SALT; } });
const keyring_mock_1 = __importDefault(require("./keyring.mock"));
exports.KeyringMockWithInit = keyring_mock_1.default;
//# sourceMappingURL=index.js.map