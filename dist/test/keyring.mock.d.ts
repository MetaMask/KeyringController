import type { Keyring, Json, Hex } from '@metamask/utils';
declare class KeyringMockWithInit implements Keyring<Json> {
    #private;
    static type: string;
    type: string;
    constructor(options?: Record<string, unknown> | undefined);
    init(): Promise<void>;
    addAccounts(_: number): Promise<Hex[]>;
    getAccounts(): Promise<`0x${string}`[]>;
    serialize(): Promise<{}>;
    deserialize(_: any): Promise<void>;
}
export default KeyringMockWithInit;
