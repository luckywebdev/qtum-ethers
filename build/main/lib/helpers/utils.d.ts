/// <reference types="node" />
import { BytesLike } from "ethers/lib/utils";
import { Transaction } from "@ethersproject/transactions";
import { BigNumberish } from "ethers";
import { TransactionRequest } from "@ethersproject/abstract-provider";
export interface ListUTXOs {
    address: string;
    txid: string;
    vout: number;
    amount: string;
    safe: boolean;
    spendable: boolean;
    solvable: boolean;
    label: string;
    type: string;
    confirmations: number;
    scriptPubKey: string;
    redeemScript: string;
}
export interface TxVinWithNullScriptSig {
    txid: Buffer;
    hash: Buffer;
    vout: number;
    sequence: number;
    script: Buffer;
    scriptSig: null;
}
export interface TxVinWithoutNullScriptSig {
    txid: Buffer;
    hash: Buffer;
    vout: number;
    sequence: number;
    script: Buffer;
    scriptSig: Buffer;
}
export interface TxVinForLedger {
    prevout: Buffer;
    script: Buffer;
    sequence: Buffer;
    tree?: Buffer;
}
export interface CloneTxVin {
    txid: Buffer;
    hash: Buffer;
    vout: number;
    sequence: number;
    script: Buffer;
    scriptSig: null;
}
export interface TxVout {
    script: Buffer;
    value: number;
}
export interface TxVoutForLedger {
    script: Buffer;
    amount: Buffer;
}
export interface CloneTx {
    version: number;
    locktime: number;
    vins: Array<TxVinWithNullScriptSig | TxVinWithoutNullScriptSig>;
    vouts: Array<TxVout>;
}
export interface Tx {
    version: number;
    locktime: number;
    vins: Array<TxVinWithNullScriptSig | TxVinWithoutNullScriptSig>;
    vouts: Array<TxVout>;
}
export interface TxForLedger {
    version: Buffer;
    locktime: Buffer;
    inputs: Array<TxVinForLedger>;
    outputs: Array<TxVoutForLedger>;
    witness?: Buffer;
    timestamp?: Buffer;
    nVersionGroupId?: Buffer;
    nExpiryHeight?: Buffer;
    extraData?: Buffer;
}
export interface CheckTransactionType {
    transactionType: number;
    neededAmount: any;
}
export declare function calcTxBytes(vins: Array<TxVinWithoutNullScriptSig | TxVinWithNullScriptSig>, vouts: Array<TxVout>): number;
export declare function txToBuffer(tx: any): Buffer;
export declare function signp2pkh(tx: any, vindex: number, privKey: string): Promise<Buffer>;
export declare function signp2pkhWith(tx: any, vindex: number, signer: Function): Promise<Buffer>;
export declare function p2pkhScriptSig(sig: any, pubkey: any): Buffer;
export declare function p2pkhScript(hash160PubKey: Buffer): Buffer;
export declare function contractTxScript(contractAddress: string, gasLimit: number, gasPrice: number, encodedData: string): Buffer;
export declare function generateContractAddress(txid: string): string;
export declare function addVins(outputs: Array<any>, utxos: Array<ListUTXOs>, neededAmount: string, total: string, gasPriceString: string, hash160PubKey: string): Promise<Array<any>>;
export declare function getMinNonDustValue(input: ListUTXOs, feePerByte: BigNumberish): number;
export declare function parseSignedTransaction(transaction: string): Transaction;
export declare function computeAddress(key: BytesLike | string, compressed?: boolean): string;
export declare function computeAddressFromPublicKey(publicKey: string): string;
export declare function checkTransactionType(tx: TransactionRequest): CheckTransactionType;
export declare function serializeTransaction(utxos: Array<any>, neededAmount: string, tx: TransactionRequest, transactionType: number, privateKey: string, publicKey: string): Promise<string>;
export declare function serializeTransactionWith(utxos: Array<any>, neededAmount: string, tx: TransactionRequest, transactionType: number, signer: Function, publicKey: string): Promise<string>;
export declare function addVinsForLedger(outputs: Array<any>, utxos: Array<ListUTXOs>, neededAmount: string, total: string, gasPriceString: string, hash160PubKey: string): Promise<Array<any>>;
export declare function getOutputScriptHexForLedger(utxos: Array<any>, neededAmount: string, tx: TransactionRequest, transactionType: number): Promise<Array<any>>;
