import { Provider, TransactionRequest } from "@ethersproject/abstract-provider";
import { ExternallyOwnedAccount, Signer, TypedDataDomain, TypedDataField, TypedDataSigner } from "@ethersproject/abstract-signer";
import { Bytes, BytesLike, SignatureLike } from "@ethersproject/bytes";
import { Mnemonic } from "@ethersproject/hdnode";
import { SigningKey } from "@ethersproject/signing-key";
import { ProgressCallback } from "@ethersproject/json-wallets";
import { Wordlist } from "@ethersproject/wordlists";
export declare const version = "wallet/5.1.0";
export declare const messagePrefix = "\u0015Qtum Signed Message:\n";
export declare function hashMessage(message: Bytes | string): string;
export declare class IntermediateWallet extends Signer implements ExternallyOwnedAccount, TypedDataSigner {
    readonly address: string;
    readonly provider: Provider;
    readonly _signingKey: () => SigningKey;
    readonly _mnemonic: () => Mnemonic;
    constructor(privateKey: BytesLike | ExternallyOwnedAccount | SigningKey, provider?: Provider);
    get mnemonic(): Mnemonic;
    get privateKey(): string;
    get publicKey(): string;
    get compressedPublicKey(): string;
    getAddress(): Promise<string>;
    connect(provider: Provider): IntermediateWallet;
    signTransaction(transaction: TransactionRequest): Promise<string>;
    signMessage(message: Bytes | string): Promise<string>;
    signHash(message: Bytes | string): Promise<string>;
    _signTypedData(domain: TypedDataDomain, types: Record<string, Array<TypedDataField>>, value: Record<string, any>): Promise<string>;
    encrypt(password: Bytes | string, options?: any, progressCallback?: ProgressCallback): Promise<string>;
    /**
     *  Static methods to create Wallet instances.
     */
    static createRandom(options?: any): IntermediateWallet;
    static fromEncryptedJson(json: string, password: Bytes | string, progressCallback?: ProgressCallback): Promise<IntermediateWallet>;
    static fromEncryptedJsonSync(json: string, password: Bytes | string): IntermediateWallet;
    static fromMnemonic(mnemonic: string, path?: string, wordlist?: Wordlist): IntermediateWallet;
}
export declare function verifyMessage(message: Bytes | string, signature: SignatureLike): string;
export declare function verifyHash(message: Bytes | string, signature: SignatureLike): string;
export declare function recoverAddress(digest: BytesLike, signature: SignatureLike): string;
export declare function verifyTypedData(domain: TypedDataDomain, types: Record<string, Array<TypedDataField>>, value: Record<string, any>, signature: SignatureLike): string;
