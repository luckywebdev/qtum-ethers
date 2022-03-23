import { TransactionRequest } from "@ethersproject/abstract-provider";
import { Tx } from './helpers/utils';
export declare class QtumLedger {
    signTransaction(transaction: TransactionRequest): Promise<Tx>;
}
