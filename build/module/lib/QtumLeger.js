import { resolveProperties, Logger, } from "ethers/lib/utils";
import { BigNumber } from "bignumber.js";
import { BigNumber as BigNumberEthers } from "ethers";
import { checkTransactionType, getOutputScriptHexForLedger } from './helpers/utils';
import { GLOBAL_VARS } from './helpers/global-vars';
const logger = new Logger("QtumLedger");
const forwardErrors = [
    Logger.errors.INSUFFICIENT_FUNDS
];
// Qtum core wallet and electrum use coin 88
export const QTUM_BIP44_PATH = "m/44'/88'/0'/0/0";
// Other wallets use coin 2301
// for more details, see: https://github.com/satoshilabs/slips/pull/196
export const SLIP_BIP44_PATH = "m/44'/2301'/0'/0/0";
export const defaultPath = SLIP_BIP44_PATH;
export async function signTransaction(transaction) {
    if (!transaction.gasPrice) {
        // 40 satoshi in WEI
        // 40 => 40000000000
        transaction.gasPrice = "0x9502f9000";
    }
    // convert gasPrice into satoshi
    let gasPrice = new BigNumber(BigNumberEthers.from(transaction.gasPrice).toString() + 'e-9');
    transaction.gasPrice = gasPrice.toNumber();
    const tx = await resolveProperties(transaction);
    console.log('[qtum-qnekt 1 - tx]', tx);
    // Refactored to check TX type (call, create, p2pkh, deploy error) and calculate needed amount
    const { transactionType, neededAmount } = checkTransactionType(tx);
    // Check if the transactionType matches the DEPLOY_ERROR, throw error else continue
    if (transactionType === GLOBAL_VARS.DEPLOY_ERROR) {
        return logger.throwError("You cannot send QTUM while deploying a contract. Try deploying again without a value.", Logger.errors.NOT_IMPLEMENTED, {
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
        return logger.throwError("Needed amount of UTXO's exceed the total you own.", Logger.errors.INSUFFICIENT_FUNDS, {
            error: error,
        });
    }
    console.log('[qtum-qnekt 3 - final params]', utxos, neededAmount.toString(), tx, transactionType);
    return await getOutputScriptHexForLedger(utxos, neededAmount, tx, transactionType);
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiUXR1bUxlZ2VyLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL2xpYi9RdHVtTGVnZXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsT0FBTyxFQUNILGlCQUFpQixFQUNqQixNQUFNLEdBQ1QsTUFBTSxrQkFBa0IsQ0FBQztBQUUxQixPQUFPLEVBQUUsU0FBUyxFQUFFLE1BQU0sY0FBYyxDQUFBO0FBQ3hDLE9BQU8sRUFBRSxTQUFTLElBQUksZUFBZSxFQUFFLE1BQU0sUUFBUSxDQUFDO0FBQ3RELE9BQU8sRUFBRSxvQkFBb0IsRUFBRSwyQkFBMkIsRUFBTSxNQUFNLGlCQUFpQixDQUFBO0FBQ3ZGLE9BQU8sRUFBRSxXQUFXLEVBQUUsTUFBTSx1QkFBdUIsQ0FBQTtBQUVuRCxNQUFNLE1BQU0sR0FBRyxJQUFJLE1BQU0sQ0FBQyxZQUFZLENBQUMsQ0FBQztBQUN4QyxNQUFNLGFBQWEsR0FBRztJQUNsQixNQUFNLENBQUMsTUFBTSxDQUFDLGtCQUFrQjtDQUNuQyxDQUFDO0FBRUYsNENBQTRDO0FBQzVDLE1BQU0sQ0FBQyxNQUFNLGVBQWUsR0FBRyxrQkFBa0IsQ0FBQztBQUNsRCw4QkFBOEI7QUFDOUIsdUVBQXVFO0FBQ3ZFLE1BQU0sQ0FBQyxNQUFNLGVBQWUsR0FBRyxvQkFBb0IsQ0FBQztBQUNwRCxNQUFNLENBQUMsTUFBTSxXQUFXLEdBQUcsZUFBZSxDQUFDO0FBRTNDLE1BQU0sQ0FBQyxLQUFLLFVBQVUsZUFBZSxDQUFDLFdBQStCO0lBQ2pFLElBQUksQ0FBQyxXQUFXLENBQUMsUUFBUSxFQUFFO1FBQ3ZCLG9CQUFvQjtRQUNwQixvQkFBb0I7UUFDcEIsV0FBVyxDQUFDLFFBQVEsR0FBRyxhQUFhLENBQUM7S0FDeEM7SUFFRCxnQ0FBZ0M7SUFDaEMsSUFBSSxRQUFRLEdBQUcsSUFBSSxTQUFTLENBQUMsZUFBZSxDQUFDLElBQUksQ0FBQyxXQUFXLENBQUMsUUFBUSxDQUFDLENBQUMsUUFBUSxFQUFFLEdBQUcsS0FBSyxDQUFDLENBQUM7SUFDNUYsV0FBVyxDQUFDLFFBQVEsR0FBRyxRQUFRLENBQUMsUUFBUSxFQUFFLENBQUM7SUFFM0MsTUFBTSxFQUFFLEdBQUcsTUFBTSxpQkFBaUIsQ0FBQyxXQUFXLENBQUMsQ0FBQztJQUNoRCxPQUFPLENBQUMsR0FBRyxDQUFDLHFCQUFxQixFQUFFLEVBQUUsQ0FBQyxDQUFDO0lBRXZDLDhGQUE4RjtJQUM5RixNQUFNLEVBQUUsZUFBZSxFQUFFLFlBQVksRUFBRSxHQUFHLG9CQUFvQixDQUFDLEVBQUUsQ0FBQyxDQUFDO0lBRW5FLG1GQUFtRjtJQUNuRixJQUFJLGVBQWUsS0FBSyxXQUFXLENBQUMsWUFBWSxFQUFFO1FBQzlDLE9BQU8sTUFBTSxDQUFDLFVBQVUsQ0FDcEIsdUZBQXVGLEVBQ3ZGLE1BQU0sQ0FBQyxNQUFNLENBQUMsZUFBZSxFQUM3QjtZQUNJLEtBQUssRUFBRSx1RkFBdUY7U0FDakcsQ0FDSixDQUFDO0tBQ0w7SUFFRCxJQUFJLEtBQUssR0FBRyxFQUFFLENBQUM7SUFDZixJQUFJO1FBQ0EsYUFBYTtRQUNiLEtBQUssR0FBRyxNQUFNLElBQUksQ0FBQyxRQUFRLENBQUMsUUFBUSxDQUFDLEVBQUUsQ0FBQyxJQUFJLEVBQUUsWUFBWSxDQUFDLENBQUM7UUFDNUQsT0FBTyxDQUFDLEdBQUcsQ0FBQyx3QkFBd0IsRUFBRSxLQUFLLENBQUMsQ0FBQTtRQUM1QyxvQ0FBb0M7S0FDdkM7SUFBQyxPQUFPLEtBQVUsRUFBRTtRQUNqQixJQUFJLGFBQWEsQ0FBQyxPQUFPLENBQUMsS0FBSyxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsRUFBRTtZQUN4QyxNQUFNLEtBQUssQ0FBQztTQUNmO1FBQ0QsT0FBTyxNQUFNLENBQUMsVUFBVSxDQUNwQixtREFBbUQsRUFDbkQsTUFBTSxDQUFDLE1BQU0sQ0FBQyxrQkFBa0IsRUFDaEM7WUFDSSxLQUFLLEVBQUUsS0FBSztTQUNmLENBQ0osQ0FBQztLQUNMO0lBRUQsT0FBTyxDQUFDLEdBQUcsQ0FBQywrQkFBK0IsRUFBRSxLQUFLLEVBQUUsWUFBWSxDQUFDLFFBQVEsRUFBRSxFQUFFLEVBQUUsRUFBRSxlQUFlLENBQUMsQ0FBQTtJQUVqRyxPQUFPLE1BQU0sMkJBQTJCLENBQUMsS0FBSyxFQUFFLFlBQVksRUFBRSxFQUFFLEVBQUUsZUFBZSxDQUFDLENBQUM7QUFDdkYsQ0FBQyJ9