import { providers } from "ethers";
import { ConnectionInfo } from "ethers/lib/utils";
export interface ClientVersion {
    name: string;
    version?: string;
    major?: number;
    minor?: number;
    patch?: number;
    system?: string;
}
export declare class QtumProvider extends providers.JsonRpcProvider {
    constructor(url?: ConnectionInfo | string, network?: providers.Networkish);
    /**
     * Override for QTUM parsing of transaction
     * https://github.com/ethers-io/ethers.js/blob/master/packages/providers/src.ts/base-provider.ts
     */
    sendTransaction(signedTransaction: string | Promise<string>): Promise<providers.TransactionResponse>;
    isClientVersionGreaterThanEqualTo(major: number, minor: number, patch: number): Promise<boolean>;
    getClientVersion(): Promise<ClientVersion>;
    private parseVersion;
    /**
     * Function to handle grabbing UTXO's from janus
     * prepareRequest in https://github.com/ethers-io/ethers.js/blob/master/packages/providers/src.ts/json-rpc-provider.ts
     */
    getUtxos(from: string, neededAmount?: number): Promise<any>;
    /**
     * Override to handle grabbing UTXO's from janus
     * prepareRequest in https://github.com/ethers-io/ethers.js/blob/master/packages/providers/src.ts/json-rpc-provider.ts
     */
    prepareRequest(method: any, params: any): [string, Array<any>];
}
export declare function compareVersion(version: ClientVersion, major: number, minor: number, patch: number): number;
