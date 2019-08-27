import { ITypedField, ITypedValue, ITypedData } from 'eth-sig-util';
import { Transaction } from 'ethereumjs-tx';

export interface IKeyring {
  signTypedData (withAccount: string, typedData: ITypedData, opts: Object): Promise<string>
}

type ITypedMessageParams = {
  from: string // The signing address
  data: ITypedData
}

type IKeyringControllerState = {
  isUnlocked: boolean
  keyringTypes: Array<string>
  keyrings: Array<any>
}

export interface IKeyringController {
  // State retrieval
  fullUpdate(): Promise<IKeyringControllerState>

  // Vault management and security
  createNewVaultAndKeychain (password:string): Promise<IKeyringControllerState>
  createNewVaultAndRestore (password:string, seed: string): Promise<IKeyringControllerState>
  setLocked(): Promise<IKeyringControllerState>
  submitPassword(password:string): Promise<IKeyringControllerState>
  addNewKeyring(type:string, opts: Object): Promise<IKeyring>
  removeEmptyKeyrings(): Promise<void>

  // Account management
  addNewAccount(toKeyring: IKeyring): Promise<IKeyringControllerState>
  exportAccount(address:string): Promise<string>
  removeAccount(address:string): Promise<IKeyringControllerState>
  checkForDuplicate(type: string, newAccount: string): Promise<string>
  getAccounts(): Promise<Array<string>>

  // Key usage
  signTransaction(tx: Transaction, from:string): Promise<Transaction>
  signMessage(msgParams: Object): Promise<string>
  signPersonalMessage(msgParams: Object): Promise<string>
  signTypedMessage (params: ITypedMessageParams): Promise<string>

  // Internal methods
  createFirstKeyTree(): Promise<Array<string> | null>
  persistAllKeyrings(password:string): Promise<boolean>
  unlockKeyrings(password:string): Array<IKeyring>
  restoreKeyrings (serialized: Object): Promise<IKeyring>
  getKeyringClassForType(type:string): IKeyring
  getKeyringsByType(type:string): Array<IKeyring>
  getKeyringForAccount(address:string): Promise<IKeyring>
  displayForKeyring(keyring: IKeyring): Promise<{ type: string, accounts: Array<string> }>
  addGasBuffer(gasHex:string): string
  clearKeyrings(): void
  _updateMemStoreKeyrings(): void
}