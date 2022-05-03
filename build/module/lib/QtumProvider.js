import { providers } from "ethers";
import { parseSignedTransaction } from "./helpers/utils";
export class QtumProvider extends providers.JsonRpcProvider {
    constructor(url, network) {
        super(url, network);
    }
    /**
     * Override for QTUM parsing of transaction
     * https://github.com/ethers-io/ethers.js/blob/master/packages/providers/src.ts/base-provider.ts
     */
    async sendTransaction(signedTransaction) {
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
        }
        catch (error) {
            error.transaction = tx;
            error.transactionHash = tx.hash;
            throw error;
        }
    }
    async isClientVersionGreaterThanEqualTo(major, minor, patch) {
        const ver = await this.getClientVersion();
        return compareVersion(ver, major, minor, patch) >= 0;
    }
    async getClientVersion() {
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
        }
        else {
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
    parseVersion(version) {
        const semver = version.split("-")[0];
        return semver.replace(/a-zA-Z\./g, "").split(".").map(i => parseInt(i) || 0);
    }
    /**
     * Function to handle grabbing UTXO's from janus
     * prepareRequest in https://github.com/ethers-io/ethers.js/blob/master/packages/providers/src.ts/json-rpc-provider.ts
     */
    async getUtxos(from, neededAmount, type = "p2pkh") {
        await this.getNetwork();
        const params = !!!neededAmount ? [from, neededAmount, type] : [from, type];
        return await this.perform("qtum_qetUTXOs", params);
    }
    /**
     * Override to handle grabbing UTXO's from janus
     * prepareRequest in https://github.com/ethers-io/ethers.js/blob/master/packages/providers/src.ts/json-rpc-provider.ts
     */
    prepareRequest(method, params) {
        if (method === "qtum_qetUTXOs") {
            return ["qtum_getUTXOs", params];
        }
        else if (method === "web3_clientVersion") {
            return ["web3_clientVersion", params];
        }
        return super.prepareRequest(method, params);
    }
}
export function compareVersion(version, major, minor, patch) {
    return recursivelyCompareVersion([
        version.major || 0,
        version.minor || 0,
        version.patch || 0
    ], [
        major,
        minor,
        patch
    ]);
}
function recursivelyCompareVersion(version, compareTo) {
    if (version.length === 0) {
        return 0;
    }
    if (version[0] === compareTo[0]) {
        return recursivelyCompareVersion(version.slice(1), compareTo.slice(1));
    }
    else if (version[0] < compareTo[0]) {
        return -1;
    }
    else {
        return 1;
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiUXR1bVByb3ZpZGVyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL2xpYi9RdHVtUHJvdmlkZXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsT0FBTyxFQUFFLFNBQVMsRUFBRSxNQUFNLFFBQVEsQ0FBQztBQUluQyxPQUFPLEVBQUUsc0JBQXNCLEVBQUUsTUFBTSxpQkFBaUIsQ0FBQztBQVd6RCxNQUFNLE9BQU8sWUFBYSxTQUFRLFNBQVMsQ0FBQyxlQUFlO0lBQ3pELFlBQ0UsR0FBNkIsRUFDN0IsT0FBOEI7UUFFOUIsS0FBSyxDQUFDLEdBQUcsRUFBRSxPQUFPLENBQUMsQ0FBQztJQUN0QixDQUFDO0lBRUQ7OztPQUdHO0lBQ0gsS0FBSyxDQUFDLGVBQWUsQ0FDbkIsaUJBQTJDO1FBRTNDLE1BQU0sSUFBSSxDQUFDLFVBQVUsRUFBRSxDQUFDO1FBQ3hCLE1BQU0sUUFBUSxHQUFHLE1BQU0sT0FBTyxDQUFDLE9BQU8sQ0FBQyxpQkFBaUIsQ0FBQyxDQUFDO1FBQzFELE1BQU0sS0FBSyxHQUFHLEtBQUssUUFBUSxFQUFFLENBQUM7UUFDOUIsb0NBQW9DO1FBQ3BDLE1BQU0sRUFBRSxHQUFHLHNCQUFzQixDQUFDLFFBQVEsQ0FBQyxDQUFDO1FBQzVDLElBQUk7WUFDRixNQUFNLElBQUksR0FBRyxNQUFNLElBQUksQ0FBQyxPQUFPLENBQUMsaUJBQWlCLEVBQUU7Z0JBQ2pELGlCQUFpQixFQUFFLEtBQUs7YUFDekIsQ0FBQyxDQUFDO1lBQ0gsZ0RBQWdEO1lBQ2hELE9BQU8sSUFBSSxDQUFDLGdCQUFnQixDQUFDLEVBQUUsRUFBRSxJQUFJLENBQUMsQ0FBQztTQUN4QztRQUFDLE9BQU8sS0FBVSxFQUFFO1lBQ25CLEtBQUssQ0FBQyxXQUFXLEdBQUcsRUFBRSxDQUFDO1lBQ3ZCLEtBQUssQ0FBQyxlQUFlLEdBQUcsRUFBRSxDQUFDLElBQUksQ0FBQztZQUNoQyxNQUFNLEtBQUssQ0FBQztTQUNiO0lBQ0gsQ0FBQztJ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