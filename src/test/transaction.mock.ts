import { TransactionFactory, type TxData } from '@ethereumjs/tx';

export const baseTransactionMockFactory = (options: TxData = {}) =>
  TransactionFactory.fromTxData({
    to: options.to ?? '0xB1A13aBECeB71b2E758c7e0Da404DF0C72Ca3a12',
    value: options.value ?? '0x0',
    data: options.data ?? '0x',
    gasPrice: options.gasPrice ?? '0x0',
    nonce: options.nonce ?? '0x0',
  });
