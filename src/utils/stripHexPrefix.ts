import { Hex } from '@metamask/utils';

/**
 * Strip the hex prefix from an address, if present.
 *
 * @param address - The address that might be hex prefixed.
 * @returns The address without a hex prefix.
 */
const stripHexPrefix = (address: Hex): string =>
  parseInt(address, 16).toString(16);

export default stripHexPrefix;
