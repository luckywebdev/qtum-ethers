import { Provider, TransactionRequest } from "@ethersproject/abstract-provider";
import { Tx } from './helpers/utils';
export declare class QtumLedger {
    readonly provider?: Provider;
    constructor(provider?: Provider);
    signTransaction(transaction: TransactionRequest): Promise<Tx>;
}
