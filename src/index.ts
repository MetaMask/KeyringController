export {
  KeyringController,
  keyringBuilderFactory,
  controllerName,
} from './KeyringController';

export type {
  KeyringControllerState,
  KeyringControllerEvents,
  KeyringControllerActions,
  KeyringControllerMessenger,
  KeyringControllerArgs,
  // Events
  AccountRegistered,
  AccountRemoved,
  KeyringRegistered,
  KeyringRemoved,
  VaultLocked,
  VaultUnlocked,
  VaultCreated,
  StateUpdated,
  // Actions
  AddAccount,
  GetAccount,
  UpdateAccount,
  ListAccounts,
  RemoveAccount,
} from './KeyringController';

export { KeyringType, KeyringControllerError } from './constants';
