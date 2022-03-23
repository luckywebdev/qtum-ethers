import { TransactionRequest } from "@ethersproject/abstract-provider";
import { Tx } from './helpers/utils';
export declare const QTUM_BIP44_PATH = "m/44'/88'/0'/0/0";
export declare const SLIP_BIP44_PATH = "m/44'/2301'/0'/0/0";
export declare const defaultPath = "m/44'/2301'/0'/0/0";
export declare function signTransaction(transaction: TransactionRequest): Promise<Tx>;
