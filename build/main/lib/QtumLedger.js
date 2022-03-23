"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.QtumLedger = void 0;
const utils_1 = require("ethers/lib/utils");
const bignumber_js_1 = require("bignumber.js");
const ethers_1 = require("ethers");
const utils_2 = require("./helpers/utils");
const global_vars_1 = require("./helpers/global-vars");
const properties_1 = require("@ethersproject/properties");
const logger = new utils_1.Logger("QtumLedger");
const forwardErrors = [
    utils_1.Logger.errors.INSUFFICIENT_FUNDS
];
class QtumLedger {
    constructor(provider) {
        properties_1.defineReadOnly(this, "provider", provider);
    }
    async signTransaction(transaction) {
        if (!transaction.gasPrice) {
            // 40 satoshi in WEI
            // 40 => 40000000000
            transaction.gasPrice = "0x9502f9000";
        }
        // convert gasPrice into satoshi
        let gasPrice = new bignumber_js_1.BigNumber(ethers_1.BigNumber.from(transaction.gasPrice).toString() + 'e-9');
        transaction.gasPrice = gasPrice.toNumber();
        const tx = await utils_1.resolveProperties(transaction);
        console.log('[qtum-qnekt 1 - tx]', tx);
        // Refactored to check TX type (call, create, p2pkh, deploy error) and calculate needed amount
        const { transactionType, neededAmount } = utils_2.checkTransactionType(tx);
        // Check if the transactionType matches the DEPLOY_ERROR, throw error else continue
        if (transactionType === global_vars_1.GLOBAL_VARS.DEPLOY_ERROR) {
            return logger.throwError("You cannot send QTUM while deploying a contract. Try deploying again without a value.", utils_1.Logger.errors.NOT_IMPLEMENTED, {
                error: "You cannot send QTUM while deploying a contract. Try deploying again without a value.",
            });
        }
        let utxos = [];
        try {
            // @ts-ignore
            utxos = await this.provider.getUtxos(tx.from, neededAmount);
            console.log('[qtum-qnekt 2 - utxos]', utxos);
            // Grab vins for transaction object.
        }
        catch (error) {
            if (forwardErrors.indexOf(error.code) >= 0) {
                throw error;
            }
            return logger.throwError("Needed amount of UTXO's exceed the total you own.", utils_1.Logger.errors.INSUFFICIENT_FUNDS, {
                error: error,
            });
        }
        console.log('[qtum-qnekt 3 - final params]', utxos, neededAmount.toString(), tx, transactionType);
        return await utils_2.getOutputScriptHexForLedger(utxos, neededAmount, tx, transactionType);
    }
}
exports.QtumLedger = QtumLedger;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiUXR1bUxlZGdlci5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9saWIvUXR1bUxlZGdlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFBQSw0Q0FHMEI7QUFFMUIsK0NBQXdDO0FBQ3hDLG1DQUFzRDtBQUN0RCwyQ0FBdUY7QUFDdkYsdURBQW1EO0FBQ25ELDBEQUEyRDtBQUUzRCxNQUFNLE1BQU0sR0FBRyxJQUFJLGNBQU0sQ0FBQyxZQUFZLENBQUMsQ0FBQztBQUN4QyxNQUFNLGFBQWEsR0FBRztJQUNsQixjQUFNLENBQUMsTUFBTSxDQUFDLGtCQUFrQjtDQUNuQyxDQUFDO0FBSUYsTUFBYSxVQUFVO0lBRW5CLFlBQVksUUFBbUI7UUFDM0IsMkJBQWMsQ0FBQyxJQUFJLEVBQUUsVUFBVSxFQUFFLFFBQVEsQ0FBQyxDQUFDO0lBQy9DLENBQUM7SUFFRCxLQUFLLENBQUMsZUFBZSxDQUFDLFdBQStCO1FBQ2pELElBQUksQ0FBQyxXQUFXLENBQUMsUUFBUSxFQUFFO1lBQ3ZCLG9CQUFvQjtZQUNwQixvQkFBb0I7WUFDcEIsV0FBVyxDQUFDLFFBQVEsR0FBRyxhQUFhLENBQUM7U0FDeEM7UUFFRCxnQ0FBZ0M7UUFDaEMsSUFBSSxRQUFRLEdBQUcsSUFBSSx3QkFBUyxDQUFDLGtCQUFlLENBQUMsSUFBSSxDQUFDLFdBQVcsQ0FBQyxRQUFRLENBQUMsQ0FBQyxRQUFRLEVBQUUsR0FBRyxLQUFLLENBQUMsQ0FBQztRQUM1RixXQUFXLENBQUMsUUFBUSxHQUFHLFFBQVEsQ0FBQyxRQUFRLEVBQUUsQ0FBQztRQUUzQyxNQUFNLEVBQUUsR0FBRyxNQUFNLHlCQUFpQixDQUFDLFdBQVcsQ0FBQyxDQUFDO1FBQ2hELE9BQU8sQ0FBQyxHQUFHLENBQUMscUJBQXFCLEVBQUUsRUFBRSxDQUFDLENBQUM7UUFFdkMsOEZBQThGO1FBQzlGLE1BQU0sRUFBRSxlQUFlLEVBQUUsWUFBWSxFQUFFLEdBQUcsNEJBQW9CLENBQUMsRUFBRSxDQUFDLENBQUM7UUFFbkUsbUZBQW1GO1FBQ25GLElBQUksZUFBZSxLQUFLLHlCQUFXLENBQUMsWUFBWSxFQUFFO1lBQzlDLE9BQU8sTUFBTSxDQUFDLFVBQVUsQ0FDcEIsdUZBQXVGLEVBQ3ZGLGNBQU0sQ0FBQyxNQUFNLENBQUMsZUFBZSxFQUM3QjtnQkFDSSxLQUFLLEVBQUUsdUZBQXVGO2FBQ2pHLENBQ0osQ0FBQztTQUNMO1FBRUQsSUFBSSxLQUFLLEdBQUcsRUFBRSxDQUFDO1FBQ2YsSUFBSTtZQUNBLGFBQWE7WUFDYixLQUFLLEdBQUcsTUFBTSxJQUFJLENBQUMsUUFBUSxDQUFDLFFBQVEsQ0FBQyxFQUFFLENBQUMsSUFBSSxFQUFFLFlBQVksQ0FBQyxDQUFDO1lBQzVELE9BQU8sQ0FBQyxHQUFHLENBQUMsd0JBQXdCLEVBQUUsS0FBSyxDQUFDLENBQUE7WUFDNUMsb0NBQW9DO1NBQ3ZDO1FBQUMsT0FBTyxLQUFVLEVBQUU7WUFDakIsSUFBSSxhQUFhLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLEVBQUU7Z0JBQ3hDLE1BQU0sS0FBSyxDQUFDO2FBQ2Y7WUFDRCxPQUFPLE1BQU0sQ0FBQyxVQUFVLENBQ3BCLG1EQUFtRCxFQUNuRCxjQUFNLENBQUMsTUFBTSxDQUFDLGtCQUFrQixFQUNoQztnQkFDSSxLQUFLLEVBQUUsS0FBSzthQUNmLENBQ0osQ0FBQztTQUNMO1FBRUQsT0FBTyxDQUFDLEdBQUcsQ0FBQywrQkFBK0IsRUFBRSxLQUFLLEVBQUUsWUFBWSxDQUFDLFFBQVEsRUFBRSxFQUFFLEVBQUUsRUFBRSxlQUFlLENBQUMsQ0FBQTtRQUVqRyxPQUFPLE1BQU0sbUNBQTJCLENBQUMsS0FBSyxFQUFFLFlBQVksRUFBRSxFQUFFLEVBQUUsZUFBZSxDQUFDLENBQUM7SUFDdkYsQ0FBQztDQUNKO0FBekRELGdDQXlEQyJ9