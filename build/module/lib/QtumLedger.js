import { resolveProperties, Logger, } from "ethers/lib/utils";
import { BigNumber } from "bignumber.js";
import { BigNumber as BigNumberEthers } from "ethers";
import { checkTransactionType, getOutputScriptHexForLedger } from './helpers/utils';
import { GLOBAL_VARS } from './helpers/global-vars';
import { defineReadOnly } from "@ethersproject/properties";
const logger = new Logger("QtumLedger");
const forwardErrors = [
    Logger.errors.INSUFFICIENT_FUNDS
];
export class QtumLedger {
    constructor(provider) {
        defineReadOnly(this, "provider", provider);
    }
    async signTransaction(transaction) {
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
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiUXR1bUxlZGdlci5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9saWIvUXR1bUxlZGdlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxPQUFPLEVBQ0gsaUJBQWlCLEVBQ2pCLE1BQU0sR0FDVCxNQUFNLGtCQUFrQixDQUFDO0FBRTFCLE9BQU8sRUFBRSxTQUFTLEVBQUUsTUFBTSxjQUFjLENBQUE7QUFDeEMsT0FBTyxFQUFFLFNBQVMsSUFBSSxlQUFlLEVBQUUsTUFBTSxRQUFRLENBQUM7QUFDdEQsT0FBTyxFQUFFLG9CQUFvQixFQUFFLDJCQUEyQixFQUFNLE1BQU0saUJBQWlCLENBQUE7QUFDdkYsT0FBTyxFQUFFLFdBQVcsRUFBRSxNQUFNLHVCQUF1QixDQUFBO0FBQ25ELE9BQU8sRUFBRSxjQUFjLEVBQUUsTUFBTSwyQkFBMkIsQ0FBQztBQUUzRCxNQUFNLE1BQU0sR0FBRyxJQUFJLE1BQU0sQ0FBQyxZQUFZLENBQUMsQ0FBQztBQUN4QyxNQUFNLGFBQWEsR0FBRztJQUNsQixNQUFNLENBQUMsTUFBTSxDQUFDLGtCQUFrQjtDQUNuQyxDQUFDO0FBSUYsTUFBTSxPQUFPLFVBQVU7SUFFbkIsWUFBWSxRQUFtQjtRQUMzQixjQUFjLENBQUMsSUFBSSxFQUFFLFVBQVUsRUFBRSxRQUFRLENBQUMsQ0FBQztJQUMvQyxDQUFDO0lBRUQsS0FBSyxDQUFDLGVBQWUsQ0FBQyxXQUErQjtRQUNqRCxJQUFJLENBQUMsV0FBVyxDQUFDLFFBQVEsRUFBRTtZQUN2QixvQkFBb0I7WUFDcEIsb0JBQW9CO1lBQ3BCLFdBQVcsQ0FBQyxRQUFRLEdBQUcsYUFBYSxDQUFDO1NBQ3hDO1FBRUQsZ0NBQWdDO1FBQ2hDLElBQUksUUFBUSxHQUFHLElBQUksU0FBUyxDQUFDLGVBQWUsQ0FBQyxJQUFJLENBQUMsV0FBVyxDQUFDLFFBQVEsQ0FBQyxDQUFDLFFBQVEsRUFBRSxHQUFHLEtBQUssQ0FBQyxDQUFDO1FBQzVGLFdBQVcsQ0FBQyxRQUFRLEdBQUcsUUFBUSxDQUFDLFFBQVEsRUFBRSxDQUFDO1FBRTNDLE1BQU0sRUFBRSxHQUFHLE1BQU0saUJBQWlCLENBQUMsV0FBVyxDQUFDLENBQUM7UUFDaEQsT0FBTyxDQUFDLEdBQUcsQ0FBQyxxQkFBcUIsRUFBRSxFQUFFLENBQUMsQ0FBQztRQUV2Qyw4RkFBOEY7UUFDOUYsTUFBTSxFQUFFLGVBQWUsRUFBRSxZQUFZLEVBQUUsR0FBRyxvQkFBb0IsQ0FBQyxFQUFFLENBQUMsQ0FBQztRQUVuRSxtRkFBbUY7UUFDbkYsSUFBSSxlQUFlLEtBQUssV0FBVyxDQUFDLFlBQVksRUFBRTtZQUM5QyxPQUFPLE1BQU0sQ0FBQyxVQUFVLENBQ3BCLHVGQUF1RixFQUN2RixNQUFNLENBQUMsTUFBTSxDQUFDLGVBQWUsRUFDN0I7Z0JBQ0ksS0FBSyxFQUFFLHVGQUF1RjthQUNqRyxDQUNKLENBQUM7U0FDTDtRQUVELElBQUksS0FBSyxHQUFHLEVBQUUsQ0FBQztRQUNmLElBQUk7WUFDQSxhQUFhO1lBQ2IsS0FBSyxHQUFHLE1BQU0sSUFBSSxDQUFDLFFBQVEsQ0FBQyxRQUFRLENBQUMsRUFBRSxDQUFDLElBQUksRUFBRSxZQUFZLENBQUMsQ0FBQztZQUM1RCxPQUFPLENBQUMsR0FBRyxDQUFDLHdCQUF3QixFQUFFLEtBQUssQ0FBQyxDQUFBO1lBQzVDLG9DQUFvQztTQUN2QztRQUFDLE9BQU8sS0FBVSxFQUFFO1lBQ2pCLElBQUksYUFBYSxDQUFDLE9BQU8sQ0FBQyxLQUFLLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxFQUFFO2dCQUN4QyxNQUFNLEtBQUssQ0FBQzthQUNmO1lBQ0QsT0FBTyxNQUFNLENBQUMsVUFBVSxDQUNwQixtREFBbUQsRUFDbkQsTUFBTSxDQUFDLE1BQU0sQ0FBQyxrQkFBa0IsRUFDaEM7Z0JBQ0ksS0FBSyxFQUFFLEtBQUs7YUFDZixDQUNKLENBQUM7U0FDTDtRQUVELE9BQU8sQ0FBQyxHQUFHLENBQUMsK0JBQStCLEVBQUUsS0FBSyxFQUFFLFlBQVksQ0FBQyxRQUFRLEVBQUUsRUFBRSxFQUFFLEVBQUUsZUFBZSxDQUFDLENBQUE7UUFFakcsT0FBTyxNQUFNLDJCQUEyQixDQUFDLEtBQUssRUFBRSxZQUFZLEVBQUUsRUFBRSxFQUFFLGVBQWUsQ0FBQyxDQUFDO0lBQ3ZGLENBQUM7Q0FDSiJ9