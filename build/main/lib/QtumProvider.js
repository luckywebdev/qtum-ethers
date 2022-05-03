"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.compareVersion = exports.QtumProvider = void 0;
const ethers_1 = require("ethers");
const utils_1 = require("./helpers/utils");
class QtumProvider extends ethers_1.providers.JsonRpcProvider {
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
        const tx = utils_1.parseSignedTransaction(signedTx);
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
exports.QtumProvider = QtumProvider;
function compareVersion(version, major, minor, patch) {
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
exports.compareVersion = compareVersion;
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiUXR1bVByb3ZpZGVyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL2xpYi9RdHVtUHJvdmlkZXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEsbUNBQW1DO0FBSW5DLDJDQUF5RDtBQVd6RCxNQUFhLFlBQWEsU0FBUSxrQkFBUyxDQUFDLGVBQWU7SUFDekQsWUFDRSxHQUE2QixFQUM3QixPQUE4QjtRQUU5QixLQUFLLENBQUMsR0FBRyxFQUFFLE9BQU8sQ0FBQyxDQUFDO0lBQ3RCLENBQUM7SUFFRDs7O09BR0c7SUFDSCxLQUFLLENBQUMsZUFBZSxDQUNuQixpQkFBMkM7UUFFM0MsTUFBTSxJQUFJLENBQUMsVUFBVSxFQUFFLENBQUM7UUFDeEIsTUFBTSxRQUFRLEdBQUcsTUFBTSxPQUFPLENBQUMsT0FBTyxDQUFDLGlCQUFpQixDQUFDLENBQUM7UUFDMUQsTUFBTSxLQUFLLEdBQUcsS0FBSyxRQUFRLEVBQUUsQ0FBQztRQUM5QixvQ0FBb0M7UUFDcEMsTUFBTSxFQUFFLEdBQUcsOEJBQXNCLENBQUMsUUFBUSxDQUFDLENBQUM7UUFDNUMsSUFBSTtZQUNGLE1BQU0sSUFBSSxHQUFHLE1BQU0sSUFBSSxDQUFDLE9BQU8sQ0FBQyxpQkFBaUIsRUFBRTtnQkFDakQsaUJBQWlCLEVBQUUsS0FBSzthQUN6QixDQUFDLENBQUM7WUFDSCxnREFBZ0Q7WUFDaEQsT0FBTyxJQUFJLENBQUMsZ0JBQWdCLENBQUMsRUFBRSxFQUFFLElBQUksQ0FBQyxDQUFDO1NBQ3hDO1FBQUMsT0FBTyxLQUFVLEVBQUU7WUFDbkIsS0FBSyxDQUFDLFdBQVcsR0FBRyxFQUFFLENBQUM7WUFDdkIsS0FBSyxDQUFDLGVBQWUsR0FBRyxFQUFFLENBQUMsSUFBSSxDQUFDO1lBQ2hDLE1BQU0sS0FBSyxDQUFDO1NBQ2I7SUFDSCxDQUFDO0lBRUQsS0FBSyxDQUFDLGlDQUFpQyxDQUFDLEtBQWEsRUFBRSxLQUFhLEVBQUUsS0FBYTtRQUMvRSxNQUFN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