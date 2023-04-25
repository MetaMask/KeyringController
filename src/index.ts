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
  VaultLocked,
  VaultUnlocked,
  VaultCreated,
  StateUpdated,
  // Actions
  AddAccount,
  ListAccounts,
  RemoveAccount,
} from './KeyringController';

export { KeyringType, KeyringControllerError } from './constants';
