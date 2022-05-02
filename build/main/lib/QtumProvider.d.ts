import { providers } from "ethers";
import { ConnectionInfo } from "ethers/lib/utils";
export declare class QtumProvider extends providers.JsonRpcProvider {
    constructor(url?: ConnectionInfo | string, network?: providers.Networkish);
    /**
     * Override for QTUM parsing of transaction
     * https://github.com/ethers-io/ethers.js/blob/master/packages/providers/src.ts/base-provider.ts
     */
    sendTransaction(signedTransaction: string | Promise<string>): Promise<providers.TransactionResponse>;
    /**
     * Function to handle grabbing UTXO's from janus
     * prepareRequest in https://github.com/ethers-io/ethers.js/blob/master/packages/providers/src.ts/json-rpc-provider.ts
     */
    getUtxos(from?: string, neededAmount?: number, type?: string): Promise<any>;
    /**
     * Override to handle grabbing UTXO's from janus
     * prepareRequest in https://github.com/ethers-io/ethers.js/blob/master/packages/providers/src.ts/json-rpc-provider.ts
     */
    prepareRequest(method: any, params: any): [string, Array<any>];
}
