// @ts-nocheck
import { getAddress } from "@ethersproject/address";
import { Provider, TransactionRequest } from "@ethersproject/abstract-provider";
import { ExternallyOwnedAccount, Signer, TypedDataDomain, TypedDataField, TypedDataSigner } from "@ethersproject/abstract-signer";
import { arrayify, Bytes, BytesLike, concat, hexDataSlice, isHexString, joinSignature, SignatureLike } from "@ethersproject/bytes";
import { _TypedDataEncoder } from "@ethersproject/hash";
import { toUtf8Bytes } from "@ethersproject/strings";
import { defaultPath, HDNode, entropyToMnemonic, Mnemonic } from "@ethersproject/hdnode";
import { keccak256 } from "@ethersproject/keccak256";
import { defineReadOnly, resolveProperties } from "@ethersproject/properties";
import { randomBytes } from "@ethersproject/random";
import { SigningKey } from "@ethersproject/signing-key";
import { decryptJsonWallet, decryptJsonWalletSync, encryptKeystore, ProgressCallback } from "@ethersproject/json-wallets";
import { serialize, UnsignedTransaction } from "@ethersproject/transactions";
import { Wordlist } from "@ethersproject/wordlists";
import { computeAddress, computeAddressFromPublicKey} from "./utils"
import { computeAddress as computeEthereumAddress } from "@ethersproject/transactions";
import { Logger } from "@ethersproject/logger";
import secp256k1 from "secp256k1";
import wif from 'wif';
export const version = "wallet/5.1.0";
const logger = new Logger(version);

export const messagePrefix = "\x15Qtum Signed Message:\n";

export function hashMessage(message: Bytes | string): string {
    if (typeof(message) === "string") { message = toUtf8Bytes(message); }
    return keccak256(concat([
        toUtf8Bytes(messagePrefix),
        toUtf8Bytes(String(message.length)),
        message
    ]));
}

function encodeSignatureRSV(signature, recovery, compressed, segwitType) {
    /*
    if (segwitType !== undefined) {
      recovery += 8
      if (segwitType === SEGWIT_TYPES.P2WPKH) recovery += 4
    } else {
        */
      if (compressed) recovery += 4
    // }
    // return Buffer.concat([Buffer.alloc(1, recovery + 27), signature])
    return Buffer.concat([signature, Buffer.alloc(1, recovery + 27)])
}

function isAccount(value: any): value is ExternallyOwnedAccount {
    return (value != null && isHexString(value.privateKey, 32) && value.address != null);
}

function hasMnemonic(value: any): value is { mnemonic: Mnemonic } {
    const mnemonic = value.mnemonic;
    return (mnemonic && mnemonic.phrase);
}
// Created this class due to address being read only and unwriteable from derived classes.
export class IntermediateWallet extends Signer implements ExternallyOwnedAccount, TypedDataSigner {

    readonly address: string;
    readonly provider: Provider;

    // Wrapping the _signingKey and _mnemonic in a getter function prevents
    // leaking the private key in console.log; still, be careful! :)
    readonly _signingKey: () => SigningKey;
    readonly _mnemonic: () => Mnemonic;

    constructor(privateKey: BytesLike | ExternallyOwnedAccount | SigningKey, provider?: Provider) {
        super();

        if (isAccount(privateKey)) {
            const signingKey = new SigningKey(privateKey.privateKey);
            defineReadOnly(this, "_signingKey", () => signingKey);
            defineReadOnly(this, "address", computeAddress(this.publicKey, true));

            if (getAddress(this.address) !== getAddress(privateKey.qtumAddress || privateKey.address)) {
                if (getAddress(computeEthereumAddress(this.publicKey)) === getAddress(privateKey.qtumAddress || privateKey.address)) {
                    logger.throwArgumentError("privateKey/address mismatch: Your address is being generated the ethereum way, please use QTUM address generation scheme", "privateKey", "[REDACTED]");
                } else {
                    logger.throwArgumentError("privateKey/address mismatch", "privateKey", "[REDACTED]");
                }
            }

            if (hasMnemonic(privateKey)) {
                const srcMnemonic = privateKey.mnemonic;
                defineReadOnly(this, "_mnemonic", () => (
                    {
                        phrase: srcMnemonic.phrase,
                        path: srcMnemonic.path || defaultPath,
                        locale: srcMnemonic.locale || "en"
                    }
                ));
                const mnemonic = this.mnemonic;
                const node = HDNode.fromMnemonic(mnemonic.phrase, null, mnemonic.locale).derivePath(mnemonic.path);
                if (computeAddress(node.privateKey, true) !== this.address) {
                    logger.throwArgumentError("mnemonic/address mismatch", "privateKey", "[REDACTED]");
                }
            } else {
                defineReadOnly(this, "_mnemonic", (): Mnemonic => null);
            }


        } else {
            if (SigningKey.isSigningKey(privateKey)) {
                /* istanbul ignore if */
                if (privateKey.curve !== "secp256k1") {
                    logger.throwArgumentError("unsupported curve; must be secp256k1", "privateKey", "[REDACTED]");
                }
                defineReadOnly(this, "_signingKey", () => (<SigningKey>privateKey));

            } else {
                // A lot of common tools do not prefix private keys with a 0x (see: #1166)
                if (typeof(privateKey) === "string") {
                    if (privateKey.match(/^[0-9a-f]*$/i) && privateKey.length === 64) {
                        privateKey = "0x" + privateKey;
                    }
                }

                try {
                    if (!privateKey.startsWith("0x")) {
                        let decodedKey = wif.decode(privateKey);
                        privateKey = '0x' + decodedKey.privateKey.toString("hex");
                    }
                } catch (e) {
                    // not WIF format
                }

                const signingKey = new SigningKey(privateKey);
                defineReadOnly(this, "_signingKey", () => signingKey);
            }

            defineReadOnly(this, "_mnemonic", (): Mnemonic => null);
            defineReadOnly(this, "address", computeAddressFromPublicKey(this.compressedPublicKey));
        }

        /* istanbul ignore if */
        if (provider && !Provider.isProvider(provider)) {
            logger.throwArgumentError("invalid provider", "provider", provider);
        }

        defineReadOnly(this, "provider", provider || null);
    }

    get mnemonic(): Mnemonic { return this._mnemonic(); }
    get privateKey(): string { return this._signingKey().privateKey; }
    get publicKey(): string { return this._signingKey().publicKey; }
    get compressedPublicKey(): string { return this._signingKey().compressedPublicKey; }

    getAddress(): Promise<string> {
        return Promise.resolve(this.address);
    }

    connect(provider: Provider): IntermediateWallet {
        return new IntermediateWallet(this, provider);
    }

    signTransaction(transaction: TransactionRequest): Promise<string> {
        return resolveProperties(transaction).then((tx) => {
            if (tx.from != null) {
                if (getAddress(tx.from) !== this.address) {
                    logger.throwArgumentError("transaction from address mismatch", "transaction.from", transaction.from);
                }
                delete tx.from;
            }

            const signature = this._signingKey().signDigest(keccak256(serialize(<UnsignedTransaction>tx)));
            return serialize(<UnsignedTransaction>tx, signature);
        });
    }

    async signMessage(message: Bytes | string): Promise<string> {
        const digest = hashMessage(message);
        return await this.signHash(arrayify(digest));
    }

    async signHash(message: Bytes | string): Promise<string> {
        if (typeof(message) === "string") { message = toUtf8Bytes(message); }
        const sigObj = secp256k1.ecdsaSign(message, Buffer.from(this.privateKey.slice(2), "hex"));
        return encodeSignatureRSV(
            sigObj.signature,
            sigObj.recid,
            true,
        );
    }

    async _signTypedData(domain: TypedDataDomain, types: Record<string, Array<TypedDataField>>, value: Record<string, any>): Promise<string> {
        // Populate any ENS names
        const populated = await _TypedDataEncoder.resolveNames(domain, types, value, (name: string) => {
            if (this.provider == null) {
                logger.throwError("cannot resolve ENS names without a provider", Logger.errors.UNSUPPORTED_OPERATION, {
                    operation: "resolveName",
                    value: name
                });
            }
            return this.provider.resolveName(name);
        });

        return await this.signHash(_TypedDataEncoder.hash(populated.domain, types, populated.value));
    }

    encrypt(password: Bytes | string, options?: any, progressCallback?: ProgressCallback): Promise<string> {
        if (typeof(options) === "function" && !progressCallback) {
            progressCallback = options;
            options = {};
        }

        if (progressCallback && typeof(progressCallback) !== "function") {
            throw new Error("invalid callback");
        }

        if (!options) { options = {}; }

        return encryptKeystore(this, password, options, progressCallback);
    }


    /**
     *  Static methods to create Wallet instances.
     */
    static createRandom(options?: any): IntermediateWallet {
        let entropy: Uint8Array = randomBytes(16);

        if (!options) { options = { }; }

        if (options.extraEntropy) {
            entropy = arrayify(hexDataSlice(keccak256(concat([ entropy, options.extraEntropy ])), 0, 16));
        }

        const mnemonic = entropyToMnemonic(entropy, options.locale);
        return IntermediateWallet.fromMnemonic(mnemonic, options.path, options.locale);
    }

    static fromEncryptedJson(json: string, password: Bytes | string, progressCallback?: ProgressCallback): Promise<IntermediateWallet> {
        return decryptJsonWallet(json, password, progressCallback).then((account) => {
            return new IntermediateWallet(account);
        });
    }

    static fromEncryptedJsonSync(json: string, password: Bytes | string): IntermediateWallet {
        return new IntermediateWallet(decryptJsonWalletSync(json, password));
    }

    static fromMnemonic(mnemonic: string, path?: string, wordlist?: Wordlist): IntermediateWallet {
        if (!path) { path = defaultPath; }
        return new IntermediateWallet(HDNode.fromMnemonic(mnemonic, null, wordlist).derivePath(path));
    }
}

export function verifyMessage(message: Bytes | string, signature: SignatureLike): string {
    return recoverAddress(hashMessage(message), signature);
}

export function verifyHash(message: Bytes | string, signature: SignatureLike): string {
    return recoverAddress(message, signature);
}

export function recoverAddress(digest: BytesLike, signature: SignatureLike): string {
    return computeAddress(recoverPublicKey(arrayify(digest), signature));
}

export function verifyTypedData(domain: TypedDataDomain, types: Record<string, Array<TypedDataField>>, value: Record<string, any>, signature: SignatureLike): string {
    return recoverAddress(_TypedDataEncoder.hash(domain, types, value), signature);
}
