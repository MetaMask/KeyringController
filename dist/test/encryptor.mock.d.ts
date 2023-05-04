/// <reference types="sinon" />
/// <reference types="node" />
/// <reference types="node" />
import { Json } from '@metamask/utils';
declare const PASSWORD = "password123";
declare const MOCK_ENCRYPTION_KEY: string;
declare const MOCK_HARDCODED_KEY = "key";
declare const MOCK_HEX = "0xabcdef0123456789";
declare const MOCK_SALT = "SALT";
declare const mockEncryptor: {
    encrypt: import("sinon").SinonStub<any[], any>;
    encryptWithDetail: import("sinon").SinonStub<any[], any>;
    decrypt(_password: string, _text: string): Promise<string | number | boolean | Json[] | {
        [prop: string]: Json;
    }>;
    decryptWithEncryptedKeyString(_keyStr: string): Promise<string | number | true | Json[] | {
        [prop: string]: Json;
    } | undefined>;
    decryptWithDetail(_password: string, _text: string): Promise<{
        vault: string | number | true | Json[] | {
            [prop: string]: Json;
        };
        exportedKeyString: string;
        salt: string;
    } | {
        vault?: never;
        exportedKeyString?: never;
        salt?: never;
    }>;
    importKey(keyString: string): null;
    encryptWithKey(): any;
    decryptWithKey(key: string, text: string): Promise<string | number | boolean | Json[] | {
        [prop: string]: Json;
    }>;
    keyFromPassword(_password: string): Promise<Buffer>;
    generateSalt(): string;
};
export { mockEncryptor, PASSWORD, MOCK_HARDCODED_KEY, MOCK_HEX, MOCK_ENCRYPTION_KEY, MOCK_SALT, };
