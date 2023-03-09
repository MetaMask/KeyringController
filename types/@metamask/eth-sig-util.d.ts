// eslint-disable-next-line import/unambiguous
declare module '@metamask/eth-sig-util' {
  import { Hex } from '@metamask/utils';

  function normalize(address: string | Hex): Hex;
  export { normalize };
}
