import { providers } from "ethers";
import {
    ConnectionInfo
} from "ethers/lib/utils";
import { parseSignedTransaction } from "./helpers/utils";

export interface ClientVersion {
    name: string,
    version?: string,
    major?: number,
    minor?: number,
    patch?: number,
    system?: string,
}

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

  async isClientVersionGreaterThanEqualTo(major: number, minor: number, patch: number): Promise<boolean> {
      const ver = await this.getClientVersion();
    return compareVersion(ver, major, minor, patch) >= 0;
  }

  async getClientVersion(): Promise<ClientVersion> {
    await this.getNetwork();
    const version = await this.perform("web3_clientVersion", []);
    if (version === "QTUM ETHTestRPC/ethereum-js") {
        // 0.1.4, versions after this with a proper version string is 0.2.0
        // this version contains a bug we have to work around
        return {
            name: "Janus",
            version: "0.1.4",
            major: 0,
            minor: 1,
            patch: 4,
            system: "linux-amd64",
        };
    } else {
        const versionInfo = version.split("/");
        if (versionInfo.length >= 4) {
            const semver = this.parseVersion(versionInfo[1]);
            return {
                name: versionInfo[0],
                version: versionInfo[1],
                major: semver[0] || 0,
                minor: semver[1] || 0,
                patch: semver[2] || 0,
                system: versionInfo[2],
            };
        }
    }
    return {
        name: version,
    };
  }

  private parseVersion(version: string): Array<number> {
    const semver = version.split("-")[0];
    return semver.replace(/a-zA-Z\./g, "").split(".").map(i => parseInt(i) || 0);
  }

  /**
   * Function to handle grabbing UTXO's from janus
   * prepareRequest in https://github.com/ethers-io/ethers.js/blob/master/packages/providers/src.ts/json-rpc-provider.ts
   */
  async getUtxos(from: string, neededAmount?: number) {
    await this.getNetwork();
    const params = !!!neededAmount ? [from, neededAmount, "p2pkh"] : [from, "p2pkh"];
    return await this.perform("qtum_qetUTXOs", params);
  }

  /**
   * Override to handle grabbing UTXO's from janus
   * prepareRequest in https://github.com/ethers-io/ethers.js/blob/master/packages/providers/src.ts/json-rpc-provider.ts
   */
  prepareRequest(method: any, params: any): [string, Array<any>] {
    if (method === "qtum_qetUTXOs") {
      return ["qtum_getUTXOs", params];
    } else if (method === "web3_clientVersion") {
      return ["web3_clientVersion", params];
    }
    return super.prepareRequest(method, params);
  }
}

export function compareVersion(version: ClientVersion, major: number, minor: number, patch: number): number {
    return recursivelyCompareVersion(
        [
            version.major || 0,
            version.minor || 0,
            version.patch || 0
        ],
        [
            major,
            minor,
            patch
        ]
    );
}

function recursivelyCompareVersion(version: Array<number>, compareTo: Array<number>): number {
    if (version.length === 0) {
        return 0;
    }

    if (version[0] === compareTo[0]) {
        return recursivelyCompareVersion(version.slice(1), compareTo.slice(1));
    } else if (version[0] < compareTo[0]) {
        return -1;
    } else {
        return 1;
    }
}
