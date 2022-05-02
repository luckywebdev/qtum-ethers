import { providers } from "ethers";
import {
    ConnectionInfo
} from "ethers/lib/utils";
import { parseSignedTransaction } from "./helpers/utils";

export class QtumProvider extends providers.JsonRpcProvider {
  constructor(
    url?: ConnectionInfo | string,
    network?: providers.Networkish
  ) {
    super(url, network);
  }

  /**
   * Override for QTUM parsing of transaction
   * https://github.com/ethers-io/ethers.js/blob/master/packages/providers/src.ts/base-provider.ts
   */
  async sendTransaction(
    signedTransaction: string | Promise<string>
  ): Promise<providers.TransactionResponse> {
    await this.getNetwork();
    const signedTx = await Promise.resolve(signedTransaction);
    const hexTx = `0x${signedTx}`;
    // Parse the signed transaction here
    const tx = parseSignedTransaction(signedTx);
    try {
      const hash = await this.perform("sendTransaction", {
        signedTransaction: hexTx,
      });
      // Note: need to destructure return result here.
      return this._wrapTransaction(tx, hash);
    } catch (error) {
      error.transaction = tx;
      error.transactionHash = tx.hash;
      throw error;
    }
  }
  /**
   * Function to handle grabbing UTXO's from janus
   * prepareRequest in https://github.com/ethers-io/ethers.js/blob/master/packages/providers/src.ts/json-rpc-provider.ts
   */
  async getUtxos(from?: string, neededAmount?: number, type = "p2pkh") {
    await this.getNetwork();
    const params = [from, neededAmount, type];
    return await this.perform("qtum_qetUTXOs", params);
  }

  /**
   * Override to handle grabbing UTXO's from janus
   * prepareRequest in https://github.com/ethers-io/ethers.js/blob/master/packages/providers/src.ts/json-rpc-provider.ts
   */
  prepareRequest(method: any, params: any): [string, Array<any>] {
    if (method === "qtum_qetUTXOs") {
      return ["qtum_getUTXOs", params];
    }
    return super.prepareRequest(method, params);
  }
}
