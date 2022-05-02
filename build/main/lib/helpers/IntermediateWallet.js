"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyTypedData = exports.recoverAddress = exports.verifyHash = exports.verifyMessage = exports.IntermediateWallet = exports.hashMessage = exports.messagePrefix = exports.version = void 0;
// @ts-nocheck
const address_1 = require("@ethersproject/address");
const abstract_provider_1 = require("@ethersproject/abstract-provider");
const abstract_signer_1 = require("@ethersproject/abstract-signer");
const bytes_1 = require("@ethersproject/bytes");
const hash_1 = require("@ethersproject/hash");
const strings_1 = require("@ethersproject/strings");
const hdnode_1 = require("@ethersproject/hdnode");
const keccak256_1 = require("@ethersproject/keccak256");
const properties_1 = require("@ethersproject/properties");
const random_1 = require("@ethersproject/random");
const signing_key_1 = require("@ethersproject/signing-key");
const json_wallets_1 = require("@ethersproject/json-wallets");
const transactions_1 = require("@ethersproject/transactions");
const utils_1 = require("./utils");
const transactions_2 = require("@ethersproject/transactions");
const logger_1 = require("@ethersproject/logger");
const secp256k1_1 = __importDefault(require("secp256k1"));
const wif_1 = __importDefault(require("wif"));
exports.version = "wallet/5.1.0";
const logger = new logger_1.Logger(exports.version);
exports.messagePrefix = "\x15Qtum Signed Message:\n";
function hashMessage(message) {
    if (typeof (message) === "string") {
        message = strings_1.toUtf8Bytes(message);
    }
    return keccak256_1.keccak256(bytes_1.concat([
        strings_1.toUtf8Bytes(exports.messagePrefix),
        strings_1.toUtf8Bytes(String(message.length)),
        message
    ]));
}
exports.hashMessage = hashMessage;
function encodeSignatureRSV(signature, recovery, compressed, segwitType) {
    /*
    if (segwitType !== undefined) {
      recovery += 8
      if (segwitType === SEGWIT_TYPES.P2WPKH) recovery += 4
    } else {
        */
    if (compressed)
        recovery += 4;
    // }
    // return Buffer.concat([Buffer.alloc(1, recovery + 27), signature])
    return Buffer.concat([signature, Buffer.alloc(1, recovery + 27)]);
}
function isAccount(value) {
    return (value != null && bytes_1.isHexString(value.privateKey, 32) && value.address != null);
}
function hasMnemonic(value) {
    const mnemonic = value.mnemonic;
    return (mnemonic && mnemonic.phrase);
}
// Created this class due to address being read only and unwriteable from derived classes.
class IntermediateWallet extends abstract_signer_1.Signer {
    constructor(privateKey, provider) {
        super();
        if (isAccount(privateKey)) {
            const signingKey = new signing_key_1.SigningKey(privateKey.privateKey);
            properties_1.defineReadOnly(this, "_signingKey", () => signingKey);
            properties_1.defineReadOnly(this, "address", utils_1.computeAddress(this.publicKey, true));
            if (address_1.getAddress(this.address) !== address_1.getAddress(privateKey.qtumAddress || privateKey.address)) {
                if (address_1.getAddress(transactions_2.computeAddress(this.publicKey)) === address_1.getAddress(privateKey.qtumAddress || privateKey.address)) {
                    logger.throwArgumentError("privateKey/address mismatch: Your address is being generated the ethereum way, please use QTUM address generation scheme", "privateKey", "[REDACTED]");
                }
                else {
                    logger.throwArgumentError("privateKey/address mismatch", "privateKey", "[REDACTED]");
                }
            }
            if (hasMnemonic(privateKey)) {
                const srcMnemonic = privateKey.mnemonic;
                properties_1.defineReadOnly(this, "_mnemonic", () => ({
                    phrase: srcMnemonic.phrase,
                    path: srcMnemonic.path || hdnode_1.defaultPath,
                    locale: srcMnemonic.locale || "en"
                }));
                const mnemonic = this.mnemonic;
                const node = hdnode_1.HDNode.fromMnemonic(mnemonic.phrase, null, mnemonic.locale).derivePath(mnemonic.path);
                if (utils_1.computeAddress(node.privateKey, true) !== this.address) {
                    logger.throwArgumentError("mnemonic/address mismatch", "privateKey", "[REDACTED]");
                }
            }
            else {
                properties_1.defineReadOnly(this, "_mnemonic", () => null);
            }
        }
        else {
            if (signing_key_1.SigningKey.isSigningKey(privateKey)) {
                /* istanbul ignore if */
                if (privateKey.curve !== "secp256k1") {
                    logger.throwArgumentError("unsupported curve; must be secp256k1", "privateKey", "[REDACTED]");
                }
                properties_1.defineReadOnly(this, "_signingKey", () => privateKey);
            }
            else {
                // A lot of common tools do not prefix private keys with a 0x (see: #1166)
                if (typeof (privateKey) === "string") {
                    if (privateKey.match(/^[0-9a-f]*$/i) && privateKey.length === 64) {
                        privateKey = "0x" + privateKey;
                    }
                }
                try {
                    if (!privateKey.startsWith("0x")) {
                        let decodedKey = wif_1.default.decode(privateKey);
                        privateKey = '0x' + decodedKey.privateKey.toString("hex");
                    }
                }
                catch (e) {
                    // not WIF format
                }
                const signingKey = new signing_key_1.SigningKey(privateKey);
                properties_1.defineReadOnly(this, "_signingKey", () => signingKey);
            }
            properties_1.defineReadOnly(this, "_mnemonic", () => null);
            properties_1.defineReadOnly(this, "address", utils_1.computeAddressFromPublicKey(this.compressedPublicKey));
        }
        /* istanbul ignore if */
        if (provider && !abstract_provider_1.Provider.isProvider(provider)) {
            logger.throwArgumentError("invalid provider", "provider", provider);
        }
        properties_1.defineReadOnly(this, "provider", provider || null);
    }
    get mnemonic() { return this._mnemonic(); }
    get privateKey() { return this._signingKey().privateKey; }
    get publicKey() { return this._signingKey().publicKey; }
    get compressedPublicKey() { return this._signingKey().compressedPublicKey; }
    getAddress() {
        return Promise.resolve(this.address);
    }
    connect(provider) {
        return new IntermediateWallet(this, provider);
    }
    signTransaction(transaction) {
        return properties_1.resolveProperties(transaction).then((tx) => {
            if (tx.from != null) {
                if (address_1.getAddress(tx.from) !== this.address) {
                    logger.throwArgumentError("transaction from address mismatch", "transaction.from", transaction.from);
                }
                delete tx.from;
            }
            const signature = this._signingKey().signDigest(keccak256_1.keccak256(transactions_1.serialize(tx)));
            return transactions_1.serialize(tx, signature);
        });
    }
    async signMessage(message) {
        const digest = hashMessage(message);
        return await this.signHash(bytes_1.arrayify(digest));
    }
    async signHash(message) {
        if (typeof (message) === "string") {
            message = strings_1.toUtf8Bytes(message);
        }
        const sigObj = secp256k1_1.default.ecdsaSign(message, Buffer.from(this.privateKey.slice(2), "hex"));
        return encodeSignatureRSV(sigObj.signature, sigObj.recid, true);
    }
    async _signTypedData(domain, types, value) {
        // Populate any ENS names
        const populated = await hash_1._TypedDataEncoder.resolveNames(domain, types, value, (name) => {
            if (this.provider == null) {
                logger.throwError("cannot resolve ENS names without a provider", logger_1.Logger.errors.UNSUPPORTED_OPERATION, {
                    operation: "resolveName",
                    value: name
                });
            }
            return this.provider.resolveName(name);
        });
        return await this.signHash(hash_1._TypedDataEncoder.hash(populated.domain, types, populated.value));
    }
    encrypt(password, options, progressCallback) {
        if (typeof (options) === "function" && !progressCallback) {
            progressCallback = options;
            options = {};
        }
        if (progressCallback && typeof (progressCallback) !== "function") {
            throw new Error("invalid callback");
        }
        if (!options) {
            options = {};
        }
        return json_wallets_1.encryptKeystore(this, password, options, progressCallback);
    }
    /**
     *  Static methods to create Wallet instances.
     */
    static createRandom(options) {
        let entropy = random_1.randomBytes(16);
        if (!options) {
            options = {};
        }
        if (options.extraEntropy) {
            entropy = bytes_1.arrayify(bytes_1.hexDataSlice(keccak256_1.keccak256(bytes_1.concat([entropy, options.extraEntropy])), 0, 16));
        }
        const mnemonic = hdnode_1.entropyToMnemonic(entropy, options.locale);
        return IntermediateWallet.fromMnemonic(mnemonic, options.path, options.locale);
    }
    static fromEncryptedJson(json, password, progressCallback) {
        return json_wallets_1.decryptJsonWallet(json, password, progressCallback).then((account) => {
            return new IntermediateWallet(account);
        });
    }
    static fromEncryptedJsonSync(json, password) {
        return new IntermediateWallet(json_wallets_1.decryptJsonWalletSync(json, password));
    }
    static fromMnemonic(mnemonic, path, wordlist) {
        if (!path) {
            path = hdnode_1.defaultPath;
        }
        return new IntermediateWallet(hdnode_1.HDNode.fromMnemonic(mnemonic, null, wordlist).derivePath(path));
    }
}
exports.IntermediateWallet = IntermediateWallet;
function verifyMessage(message, signature) {
    return recoverAddress(hashMessage(message), signature);
}
exports.verifyMessage = verifyMessage;
function verifyHash(message, signature) {
    return recoverAddress(message, signature);
}
exports.verifyHash = verifyHash;
function recoverAddress(digest, signature) {
    return utils_1.computeAddress(recoverPublicKey(bytes_1.arrayify(digest), signature));
}
exports.recoverAddress = recoverAddress;
function verifyTypedData(domain, types, value, signature) {
    return recoverAddress(hash_1._TypedDataEncoder.hash(domain, types, value), signature);
}
exports.verifyTypedData = verifyTypedData;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiSW50ZXJtZWRpYXRlV2FsbGV0LmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vc3JjL2xpYi9oZWxwZXJzL0ludGVybWVkaWF0ZVdhbGxldC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7QUFBQSxjQUFjO0FBQ2Qsb0RBQW9EO0FBQ3BELHdFQUFnRjtBQUNoRixvRUFBa0k7QUFDbEksZ0RBQW1JO0FBQ25JLDhDQUF3RDtBQUN4RCxvREFBcUQ7QUFDckQsa0RBQXlGO0FBQ3pGLHdEQUFxRDtBQUNyRCwwREFBOEU7QUFDOUUsa0RBQW9EO0FBQ3BELDREQUF3RDtBQUN4RCw4REFBMEg7QUFDMUgsOERBQTZFO0FBRTdFLG1DQUFvRTtBQUNwRSw4REFBdUY7QUFDdkYsa0RBQStDO0FBQy9DLDBEQUFrQztBQUNsQyw4Q0FBc0I7QUFDVCxRQUFBLE9BQU8sR0FBRyxjQUFjLENBQUM7QUFDdEMsTUFBTSxNQUFNLEdBQUcsSUFBSSxlQUFNLENBQUMsZUFBTyxDQUFDLENBQUM7QUFFdEIsUUFBQSxhQUFhLEdBQUcsNEJBQTRCLENBQUM7QUFFMUQsU0FBZ0IsV0FBVyxDQUFDLE9BQXVCO0lBQy9DLElBQUksT0FBTSxDQUFDLE9BQU8sQ0FBQyxLQUFLLFFBQVEsRUFBRTtRQUFFLE9BQU8sR0FBRyxxQkFBVyxDQUFDLE9BQU8sQ0FBQyxDQUFDO0tBQUU7SUFDckUsT0FBTyxxQkFBUyxDQUFDLGNBQU0sQ0FBQztRQUNwQixxQkFBVyxDQUFDLHFCQUFhLENBQUM7UUFDMUIscUJBQVcsQ0FBQyxNQUFNLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FBQyxDQUFDO1FBQ25DLE9BQU87S0FDVixDQUFDLENBQUMsQ0FBQztBQUNSLENBQUM7QUFQRCxrQ0FPQztBQUVELFNBQVMsa0JBQWtCLENBQUMsU0FBUyxFQUFFLFFBQVEsRUFBRSxVQUFVLEVBQUUsVUFBVTtJQUNuRTs7Ozs7VUFLTTtJQUNKLElBQUksVUFBVTtRQUFFLFFBQVEsSUFBSSxDQUFD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