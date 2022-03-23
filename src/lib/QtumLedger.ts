import {
    resolveProperties,
    Logger,
} from "ethers/lib/utils";
import { TransactionRequest } from "@ethersproject/abstract-provider";
import { BigNumber } from "bignumber.js"
import { BigNumber as BigNumberEthers } from "ethers";
import { checkTransactionType, getOutputScriptHexForLedger, Tx } from './helpers/utils'
import { GLOBAL_VARS } from './helpers/global-vars'

const logger = new Logger("QtumLedger");
const forwardErrors = [
    Logger.errors.INSUFFICIENT_FUNDS
];

export class QtumLedger {
    async signTransaction(transaction: TransactionRequest): Promise<Tx> {
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
            return logger.throwError(
                "You cannot send QTUM while deploying a contract. Try deploying again without a value.",
                Logger.errors.NOT_IMPLEMENTED,
                {
                    error: "You cannot send QTUM while deploying a contract. Try deploying again without a value.",
                }
            );
        }

        let utxos = [];
        try {
            // @ts-ignore
            utxos = await this.provider.getUtxos(tx.from, neededAmount);
            console.log('[qtum-qnekt 2 - utxos]', utxos)
            // Grab vins for transaction object.
        } catch (error: any) {
            if (forwardErrors.indexOf(error.code) >= 0) {
                throw error;
            }
            return logger.throwError(
                "Needed amount of UTXO's exceed the total you own.",
                Logger.errors.INSUFFICIENT_FUNDS,
                {
                    error: error,
                }
            );
        }

        console.log('[qtum-qnekt 3 - final params]', utxos, neededAmount.toString(), tx, transactionType)

        return await getOutputScriptHexForLedger(utxos, neededAmount, tx, transactionType);
    }
}
