"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.signTransaction = exports.defaultPath = exports.SLIP_BIP44_PATH = exports.QTUM_BIP44_PATH = void 0;
const utils_1 = require("ethers/lib/utils");
const bignumber_js_1 = require("bignumber.js");
const ethers_1 = require("ethers");
const utils_2 = require("./helpers/utils");
const global_vars_1 = require("./helpers/global-vars");
const logger = new utils_1.Logger("QtumLedger");
const forwardErrors = [
    utils_1.Logger.errors.INSUFFICIENT_FUNDS
];
// Qtum core wallet and electrum use coin 88
exports.QTUM_BIP44_PATH = "m/44'/88'/0'/0/0";
// Other wallets use coin 2301
// for more details, see: https://github.com/satoshilabs/slips/pull/196
exports.SLIP_BIP44_PATH = "m/44'/2301'/0'/0/0";
exports.defaultPath = exports.SLIP_BIP44_PATH;
async function signTransaction(transaction) {
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
exports.signTransaction = signTransaction;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiUXR1bUxlZ2VyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL2xpYi9RdHVtTGVnZXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEsNENBRzBCO0FBRTFCLCtDQUF3QztBQUN4QyxtQ0FBc0Q7QUFDdEQsMkNBQXVGO0FBQ3ZGLHVEQUFtRDtBQUVuRCxNQUFNLE1BQU0sR0FBRyxJQUFJLGNBQU0sQ0FBQyxZQUFZLENBQUMsQ0FBQztBQUN4QyxNQUFNLGFBQWEsR0FBRztJQUNsQixjQUFNLENBQUMsTUFBTSxDQUFDLGtCQUFrQjtDQUNuQyxDQUFDO0FBRUYsNENBQTRDO0FBQy9CLFFBQUEsZUFBZSxHQUFHLGtCQUFrQixDQUFDO0FBQ2xELDhCQUE4QjtBQUM5Qix1RUFBdUU7QUFDMUQsUUFBQSxlQUFlLEdBQUcsb0JBQW9CLENBQUM7QUFDdkMsUUFBQSxXQUFXLEdBQUcsdUJBQWUsQ0FBQztBQUVwQyxLQUFLLFVBQVUsZUFBZSxDQUFDLFdBQStCO0lBQ2pFLElBQUksQ0FBQyxXQUFXLENBQUMsUUFBUSxFQUFFO1FBQ3ZCLG9CQUFvQjtRQUNwQixvQkFBb0I7UUFDcEIsV0FBVyxDQUFDLFFBQVEsR0FBRyxhQUFhLENBQUM7S0FDeEM7SUFFRCxnQ0FBZ0M7SUFDaEMsSUFBSSxRQUFRLEdBQUcsSUFBSSx3QkFBUyxDQUFDLGtCQUFlLENBQUMsSUFBSSxDQUFDLFdBQVcsQ0FBQyxRQUFRLENBQUMsQ0FBQyxRQUFRLEVBQUUsR0FBRyxLQUFLLENBQUMsQ0FBQztJQUM1RixXQUFXLENBQUMsUUFBUSxHQUFHLFFBQVEsQ0FBQyxRQUFRLEVBQUUsQ0FBQztJQUUzQyxNQUFNLEVBQUUsR0FBRyxNQUFNLHlCQUFpQixDQUFDLFdBQVcsQ0FBQyxDQUFDO0lBQ2hELE9BQU8sQ0FBQyxHQUFHLENBQUMscUJBQXFCLEVBQUUsRUFBRSxDQUFDLENBQUM7SUFFdkMsOEZBQThGO0lBQzlGLE1BQU0sRUFBRSxlQUFlLEVBQUUsWUFBWSxFQUFFLEdBQUcsNEJBQW9CLENBQUMsRUFBRSxDQUFDLENBQUM7SUFFbkUsbUZBQW1GO0lBQ25GLElBQUksZUFBZSxLQUFLLHlCQUFXLENBQUMsWUFBWSxFQUFFO1FBQzlDLE9BQU8sTUFBTSxDQUFDLFVBQVUsQ0FDcEIsdUZBQXVGLEVBQ3ZGLGNBQU0sQ0FBQyxNQUFNLENBQUMsZUFBZSxFQUM3QjtZQUNJLEtBQUssRUFBRSx1RkFBdUY7U0FDakcsQ0FDSixDQUFDO0tBQ0w7SUFFRCxJQUFJLEtBQUssR0FBRyxFQUFFLENBQUM7SUFDZixJQUFJO1FBQ0EsYUFBYTtRQUNiLEtBQUssR0FBRyxNQUFNLElBQUksQ0FBQyxRQUFRLENBQUMsUUFBUSxDQUFDLEVBQUUsQ0FBQyxJQUFJLEVBQUUsWUFBWSxDQUFDLENBQUM7UUFDNUQsT0FBTyxDQUFDLEdBQUcsQ0FBQyx3QkFBd0IsRUFBRSxLQUFLLENBQUMsQ0FBQTtRQUM1QyxvQ0FBb0M7S0FDdkM7SUFBQyxPQUFPLEtBQVUsRUFBRTtRQUNqQixJQUFJLGFBQWEsQ0FBQyxPQUFPLENBQUMsS0FBSyxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsRUFBRTtZQUN4QyxNQUFNLEtBQUssQ0FBQztTQUNmO1FBQ0QsT0FBTyxNQUFNLENBQUMsVUFBVSxDQUNwQixtREFBbUQsRUFDbkQsY0FBTSxDQUFDLE1BQU0sQ0FBQyxrQkFBa0IsRUFDaEM7WUFDSSxLQUFLLEVBQUUsS0FBSztTQUNmLENBQ0osQ0FBQztLQUNMO0lBRUQsT0FBTyxDQUFDLEdBQUcsQ0FBQywrQkFBK0IsRUFBRSxLQUFLLEVBQUUsWUFBWSxDQUFDLFFBQVEsRUFBRSxFQUFFLEVBQUUsRUFBRSxlQUFlLENBQUMsQ0FBQTtJQUVqRyxPQUFPLE1BQU0sbUNBQTJCLENBQUMsS0FBSyxFQUFFLFlBQVksRUFBRSxFQUFFLEVBQUUsZUFBZSxDQUFDLENBQUM7QUFDdkYsQ0FBQztBQWxERCwwQ0FrREMifQ==