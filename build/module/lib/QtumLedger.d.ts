import { Provider, TransactionRequest } from "@ethersproject/abstract-provider";
export declare class QtumLedger {
    readonly provider?: Provider;
    constructor(provider?: Provider);
    signTransaction(transaction: TransactionRequest): Promise<Array<any>>;
}
