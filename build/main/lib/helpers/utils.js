"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getOutputScriptHexForLedger = exports.addVinsForLedger = exports.serializeTransactionWith = exports.serializeTransaction = exports.checkTransactionType = exports.computeAddressFromPublicKey = exports.computeAddress = exports.parseSignedTransaction = exports.getMinNonDustValue = exports.addVins = exports.generateContractAddress = exports.contractTxScript = exports.p2pkhScript = exports.p2pkhScriptSig = exports.signp2pkhWith = exports.signp2pkh = exports.txToBuffer = exports.calcTxBytes = void 0;
const bip66_1 = require("bip66");
const varuint_bitcoin_1 = require("varuint-bitcoin");
const opcodes_1 = require("./opcodes");
const global_vars_1 = require("./global-vars");
const buffer_cursor_1 = require("./buffer-cursor");
const address_1 = require("@ethersproject/address");
//@ts-ignore
const secp256k1_1 = require("secp256k1");
let secp256k1Sign = secp256k1_1.ecdsaSign;
if (!secp256k1_1.ecdsaSign && secp256k1_1.sign) {
    // support version 3 secp256k1 library (used by metamask)
    //@ts-ignore
    secp256k1Sign = function (buffer, privateKey) {
        // v3 uses different version of Buffer, fake that these are compatabile
        //@ts-ignore
        buffer._isBuffer = true;
        //@ts-ignore
        privateKey._isBuffer = true;
        return secp256k1_1.sign(buffer, privateKey);
    };
}
const script_number_1 = require("bitcoinjs-lib/src/script_number");
const hash_js_1 = require("hash.js");
const bignumber_js_1 = require("bignumber.js");
// 1 satoshi is e-8 so we need bignumber to not set an exponent for numbers greater than that
// since we use exponents to do multiplication
// BigNumber.config({ EXPONENTIAL_AT: 10 })
const utils_1 = require("ethers/lib/utils");
const ethers_1 = require("ethers");
const hex_decoder_1 = require("./hex-decoder");
const signing_key_1 = require("@ethersproject/signing-key");
// const toBuffer = require('typedarray-to-buffer')
const bitcoinjs = require("bitcoinjs-lib");
// metamask BigNumber uses a different version so the API doesn't match up
[
    "lessThanOrEqualTo",
    "greaterThan",
    "lessThan",
].forEach((methodName) => {
    // adds is ____ to prototype to reference existing method for api compat
    const is = "is" + methodName.charAt(0).toUpperCase() + methodName.slice(1);
    // @ts-ignore
    if (!bignumber_js_1.BigNumber.prototype[is] && bignumber_js_1.BigNumber.prototype[methodName]) {
        // @ts-ignore
        bignumber_js_1.BigNumber.prototype[is] = bignumber_js_1.BigNumber.prototype[methodName];
    }
});
function cloneBuffer(buffer) {
    let result = Buffer.alloc(buffer.length);
    buffer.copy(result);
    return result;
}
function cloneTx(tx) {
    let result = { version: tx.version, locktime: tx.locktime, vins: [], vouts: [] };
    for (let vin of tx.vins) {
        result.vins.push({
            txid: cloneBuffer(vin.txid),
            vout: vin.vout,
            hash: cloneBuffer(vin.hash),
            sequence: vin.sequence,
            script: cloneBuffer(vin.script),
            scriptSig: null
        });
    }
    for (let vout of tx.vouts) {
        result.vouts.push({
            script: cloneBuffer(vout.script),
            value: vout.value,
        });
    }
    return result;
}
// refer to https://en.bitcoin.it/wiki/Transaction#General_format_of_a_Bitcoin_transaction_.28inside_a_block.29
function calcTxBytes(vins, vouts) {
    return global_vars_1.GLOBAL_VARS.TX_OVERHEAD_NVERSION +
        varuint_bitcoin_1.encodingLength(vins.length) +
        vins
            .map(vin => (vin.scriptSig ? vin.scriptSig.byteLength : vin.script.byteLength))
            .reduce((sum, len) => sum + global_vars_1.GLOBAL_VARS.TX_INPUT_OUTPOINT + varuint_bitcoin_1.encodingLength(len) + len + global_vars_1.GLOBAL_VARS.TX_INPUT_NSEQUENCE, 0) +
        varuint_bitcoin_1.encodingLength(vouts.length) +
        vouts
            .map(vout => vout.script.byteLength)
            .reduce((sum, len) => sum + global_vars_1.GLOBAL_VARS.TX_OUTPUT_NVALUE + varuint_bitcoin_1.encodingLength(len) + len, 0) +
        global_vars_1.GLOBAL_VARS.TX_OVERHEAD_NLOCKTIME;
}
exports.calcTxBytes = calcTxBytes;
function txToBuffer(tx) {
    let neededBytes = calcTxBytes(tx.vins, tx.vouts);
    let buffer = Buffer.alloc(neededBytes);
    let cursor = new buffer_cursor_1.BufferCursor(buffer);
    // version
    cursor.writeUInt32LE(tx.version);
    // vin length
    cursor.writeBytes(varuint_bitcoin_1.encode(tx.vins.length));
    // vin
    for (let vin of tx.vins) {
        cursor.writeBytes(vin.hash);
        cursor.writeUInt32LE(vin.vout);
        if (vin.scriptSig !== null) {
            cursor.writeBytes(varuint_bitcoin_1.encode(vin.scriptSig.length));
            cursor.writeBytes(vin.scriptSig);
        }
        else {
            cursor.writeBytes(varuint_bitcoin_1.encode(vin.script.length));
            cursor.writeBytes(vin.script);
        }
        cursor.writeUInt32LE(vin.sequence);
    }
    // vout length
    cursor.writeBytes(varuint_bitcoin_1.encode(tx.vouts.length));
    // vouts
    for (let vout of tx.vouts) {
        cursor.writeUInt64LE(vout.value);
        cursor.writeBytes(varuint_bitcoin_1.encode(vout.script.length));
        cursor.writeBytes(vout.script);
    }
    // locktime
    cursor.writeUInt32LE(tx.locktime);
    return buffer;
}
exports.txToBuffer = txToBuffer;
// refer to: https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/script_signature.js
function toDER(x) {
    let i = 0;
    while (x[i] === 0)
        ++i;
    if (i === x.length)
        return Buffer.alloc(1);
    x = x.slice(i);
    if (x[0] & 0x80)
        return Buffer.concat([Buffer.alloc(1), x], 1 + x.length);
    return x;
}
// refer to: https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/script_signature.js
function encodeSig(signature, hashType) {
    const hashTypeMod = hashType & ~0x80;
    if (hashTypeMod <= 0 || hashTypeMod >= 4)
        throw new Error('Invalid hashType ' + hashType);
    const hashTypeBuffer = Buffer.from([hashType]);
    const bufferSignature = Buffer.from(signature);
    const r = toDER(bufferSignature.slice(0, 32));
    const s = toDER(bufferSignature.slice(32, 64));
    return Buffer.concat([bip66_1.encode(r, s), hashTypeBuffer]);
}
/////////////////////////////////////////
async function signp2pkh(tx, vindex, privKey) {
    return await signp2pkhWith(tx, vindex, (hash) => {
        return secp256k1Sign(hash, utils_1.arrayify(privKey));
    });
}
exports.signp2pkh = signp2pkh;
async function signp2pkhWith(tx, vindex, signer) {
    let clone = cloneTx(tx);
    // clean up relevant script
    // TODO: Implement proper handling of OP_CODESEPARATOR, this was filtering 'ab' from the script entirely preventing pubkeyhash with ab addresses from generating proper tx
    // Since all scripts are generated locally in this library, temporarily not having this implemented is OK as no scripts will have this opcode
    // let filteredPrevOutScript = clone.vins[vindex].script.filter((op: any) => op !== OPS.OP_CODESEPARATOR);
    // Uint8Array issue here
    // clone.vins[vindex].script = toBuffer(filteredPrevOutScript);
    // zero out scripts of other inputs
    for (let i = 0; i < clone.vins.length; i++) {
        if (i === vindex)
            continue;
        clone.vins[i].script = Buffer.alloc(0);
    }
    // write to the buffer
    let buffer = txToBuffer(clone);
    // extend and append hash type
    buffer = Buffer.alloc(buffer.byteLength + 4, buffer);
    // append the hash type
    buffer.writeUInt32LE(global_vars_1.GLOBAL_VARS.HASH_TYPE, buffer.byteLength - 4);
    // double-sha256
    let firstHash = hash_js_1.sha256().update(buffer).digest();
    let secondHash = hash_js_1.sha256().update(firstHash).digest();
    // sign on next tick so we don't block UI
    await new Promise((resolve) => setImmediate(resolve));
    // sign hash
    let sig = await signer(new Uint8Array(secondHash));
    // encode sig
    return encodeSig(sig.signature, global_vars_1.GLOBAL_VARS.HASH_TYPE);
}
exports.signp2pkhWith = signp2pkhWith;
function p2pkhScriptSig(sig, pubkey) {
    return bitcoinjs.script.compile([sig, Buffer.from(pubkey, 'hex')]);
}
exports.p2pkhScriptSig = p2pkhScriptSig;
// Refer to:
// https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/payments/p2pkh.js#L58
function p2pkhScript(hash160PubKey) {
    return bitcoinjs.script.compile([
        opcodes_1.OPS.OP_DUP,
        opcodes_1.OPS.OP_HASH160,
        hash160PubKey,
        opcodes_1.OPS.OP_EQUALVERIFY,
        opcodes_1.OPS.OP_CHECKSIG
    ]);
}
exports.p2pkhScript = p2pkhScript;
const scriptMap = {
    p2pkh: p2pkhScript,
};
function contractTxScript(contractAddress, gasLimit, gasPrice, encodedData) {
    // If contractAddress is missing, assume it's a create script, else assume its a call contract interaction
    if (contractAddress === "") {
        return bitcoinjs.script.compile([
            opcodes_1.OPS.OP_4,
            script_number_1.encode(gasLimit),
            script_number_1.encode(gasPrice),
            Buffer.from(encodedData, "hex"),
            opcodes_1.OPS.OP_CREATE,
        ]);
    }
    else {
        return bitcoinjs.script.compile([
            opcodes_1.OPS.OP_4,
            script_number_1.encode(gasLimit),
            script_number_1.encode(gasPrice),
            Buffer.from(encodedData, "hex"),
            Buffer.from(contractAddress, "hex"),
            opcodes_1.OPS.OP_CALL,
        ]);
    }
}
exports.contractTxScript = contractTxScript;
function reverse(src) {
    let buffer = Buffer.alloc(src.length);
    for (var i = 0, j = src.length - 1; i <= j; ++i, --j) {
        buffer[i] = src[j];
        buffer[j] = src[i];
    }
    return buffer;
}
function generateContractAddress(txid) {
    let buffer = Buffer.alloc(32 + 4);
    let cursor = new buffer_cursor_1.BufferCursor(buffer);
    cursor.writeBytes(reverse(Buffer.from(txid, "hex")));
    // Assuming vout index is 0 as the transaction is serialized with that assumption.
    cursor.writeUInt32LE(0);
    let firstHash = hash_js_1.sha256().update(buffer.toString("hex"), "hex").digest("hex");
    let secondHash = hash_js_1.ripemd160().update(firstHash, "hex").digest("hex");
    return address_1.getAddress(secondHash).substring(2);
}
exports.generateContractAddress = generateContractAddress;
async function addVins(outputs, spendableUtxos, neededAmount, needChange, gasPriceString, hash160PubKey) {
    // minimum gas price is 40 satoshi
    // minimum sat/kb is 4000
    const gasPrice = ethers_1.BigNumber.from(gasPriceString);
    const minimumSatoshiPerByte = 400;
    if (gasPrice.lt(ethers_1.BigNumber.from(minimumSatoshiPerByte))) {
        throw new Error("Gas price lower than minimum relay fee: " + gasPriceString + " => " + gasPrice.toString() + " < " + minimumSatoshiPerByte);
    }
    let inputs = [];
    let amounts = [];
    let change;
    let inputsAmount = ethers_1.BigNumber.from(0);
    const neededAmountBN = ethers_1.BigNumber.from(new bignumber_js_1.BigNumber(qtumToSatoshi(neededAmount)).toString());
    let vbytes = ethers_1.BigNumber.from(global_vars_1.GLOBAL_VARS.TX_OVERHEAD_BASE);
    const spendVSizeLookupMap = {
        p2pkh: ethers_1.BigNumber.from(global_vars_1.GLOBAL_VARS.TX_INPUT_BASE + global_vars_1.GLOBAL_VARS.TX_INPUT_SCRIPTSIG_P2PKH).toNumber(),
    };
    const changeType = 'p2pkh';
    const outputVSizeLookupMap = {
        p2pkh: ethers_1.BigNumber.from(global_vars_1.GLOBAL_VARS.TX_OUTPUT_BASE + global_vars_1.GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2PKH).toNumber(),
        p2wpkh: ethers_1.BigNumber.from(global_vars_1.GLOBAL_VARS.TX_OUTPUT_BASE + global_vars_1.GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2WPKH).toNumber(),
        p2sh2of3: ethers_1.BigNumber.from(global_vars_1.GLOBAL_VARS.TX_OUTPUT_BASE + global_vars_1.GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2SH2OF3).toNumber(),
        p2wsh2of3: ethers_1.BigNumber.from(global_vars_1.GLOBAL_VARS.TX_OUTPUT_BASE + global_vars_1.GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2WSH2OF3).toNumber(),
        p2tr: ethers_1.BigNumber.from(global_vars_1.GLOBAL_VARS.TX_OUTPUT_BASE + global_vars_1.GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2TR).toNumber(),
    };
    for (let i = 0; i < outputs.length; i++) {
        const output = outputs[i];
        let outputVSize = output;
        if (typeof output === "string") {
            if (!outputVSizeLookupMap.hasOwnProperty(output.toLowerCase())) {
                throw new Error("Unsupported output script type: " + output.toLowerCase());
            }
            else {
                // @ts-ignore
                outputVSize = outputVSizeLookupMap[output.toLowerCase()];
            }
        }
        else if (output.hasOwnProperty('script') && output.hasOwnProperty('value')) {
            // longer script sizes require up to 3 vbytes to encode
            const scriptEncodingLength = varuint_bitcoin_1.encodingLength(output.script.byteLength) - 1;
            outputVSize = ethers_1.BigNumber.from(global_vars_1.GLOBAL_VARS.TX_OUTPUT_BASE + scriptEncodingLength + output.script.byteLength).toNumber();
        }
        else {
            outputVSize = ethers_1.BigNumber.from(outputVSize).toNumber();
        }
        vbytes = vbytes.add(outputVSize);
    }
    let needMoreInputs = true;
    let i = 0;
    for (i = 0; i < spendableUtxos.length; i++) {
        const spendableUtxo = spendableUtxos[i];
        // investigate issue where amount has no decimal point as calculation panics
        // @ts-ignore
        const amount = spendableUtxo.amountNumber;
        const utxoValue = parseFloat(shiftBy(amount, 8));
        // balance += utxoValue;
        let script = Buffer.from(spendableUtxo.scriptPubKey);
        // all scripts will be p2pkh for now
        const typ = spendableUtxo.type || '';
        if (typ.toLowerCase() === "p2pkh") {
            script = p2pkhScript(Buffer.from(hash160PubKey, "hex"));
        }
        if (!spendVSizeLookupMap.hasOwnProperty(typ.toLowerCase())) {
            throw new Error("Unsupported spendable script type: " + typ.toLowerCase());
        }
        inputs.push({
            txid: Buffer.from(spendableUtxo.txid, 'hex'),
            vout: spendableUtxo.vout,
            hash: reverse(Buffer.from(spendableUtxo.txid, 'hex')),
            sequence: 0xffffffff,
            script: script,
            scriptSig: null
        });
        // @ts-ignore
        const outputVSize = spendVSizeLookupMap[typ.toLowerCase()];
        vbytes = vbytes.add(outputVSize);
        const fee = ethers_1.BigNumber.from(vbytes).mul(gasPrice);
        inputsAmount = inputsAmount.add(utxoValue);
        amounts.push(utxoValue);
        if (neededAmountBN.eq(inputsAmount)) {
            if (i === spendableUtxos.length - 1) {
                // reached end
                // have exactly the needed amount
                // spending all utxo values
                // when caller computes change, it won't generate a change address
                needMoreInputs = false;
            }
            else {
                // not sending all
                // confirm that there is enough in inputs to cover network fees
                const neededAmountPlusFees = neededAmountBN.add(fee);
                const changeVBytes = outputVSizeLookupMap[changeType];
                const changeFee = ethers_1.BigNumber.from(changeVBytes).mul(gasPrice).toNumber();
                const neededAmountPlusFeesAndChange = needChange ? neededAmountPlusFees.add(changeFee) : neededAmountPlusFees;
                if (inputsAmount.eq(neededAmountPlusFees)) {
                    // no change output required, matches exactly
                    needMoreInputs = false;
                }
                else if (inputsAmount.lt(neededAmountPlusFees)) {
                    // not enough to cover total to send + fees, we need another input
                }
                else if (inputsAmount.gte(neededAmountPlusFeesAndChange)) {
                    // has enough to cover with a change output
                    needMoreInputs = false;
                    vbytes = vbytes.add(changeVBytes);
                    change = inputsAmount.sub(neededAmountPlusFeesAndChange);
                }
                else {
                    // not enough to cover with a change output, we need another input
                }
            }
        }
        else if (neededAmountBN.lt(inputsAmount)) {
            // have enough, check that there is enough change to cover fees
            const totalNeededPlusFees = neededAmountBN.add(fee);
            const changeVBytes = outputVSizeLookupMap[changeType];
            const changeFee = ethers_1.BigNumber.from(changeVBytes).mul(gasPrice).toNumber();
            const totalNeededPlusFeesAndChange = needChange ? totalNeededPlusFees.add(changeFee) : totalNeededPlusFees;
            if (inputsAmount.eq(totalNeededPlusFees)) {
                // no change output required, matches exactly
                needMoreInputs = false;
            }
            else if (inputsAmount.lt(totalNeededPlusFees)) {
                // not enough to cover total to send + fees, we need another input
            }
            else if (inputsAmount.gte(totalNeededPlusFeesAndChange)) {
                if (needChange) {
                    // has enough to cover with a change output
                    needMoreInputs = false;
                    vbytes = vbytes.add(changeVBytes);
                    change = inputsAmount.sub(totalNeededPlusFeesAndChange);
                    // throw new Error("Change output...2");
                }
                else {
                    // no change output requested
                    // bump the output by the change
                }
            }
            else {
                // not enough to cover with a change output, we need another input
            }
        }
        else {
            // neededAmountBN.gt(inputsAmount)
        }
        if (!needMoreInputs) {
            break;
        }
        if (i % 100 === 0) {
            // lots of UTXOs, don't block UI
            await new Promise((resolve) => setImmediate(resolve));
        }
    }
    if (needMoreInputs) {
        const missing = neededAmountBN.sub(inputsAmount).toNumber();
        throw new Error("Need " + missing + " more satoshi, we have " + inputsAmount.toString());
    }
    const fee = ethers_1.BigNumber.from(vbytes).mul(gasPrice);
    const availableAmount = inputsAmount.sub(fee).toNumber();
    return [inputs, amounts, availableAmount, fee, change, changeType];
}
exports.addVins = addVins;
function getMinNonDustValue(input, feePerByte) {
    // "Dust" is defined in terms of dustRelayFee,
    // which has units satoshis-per-kilobyte.
    // If you'd pay more in fees than the value of the output
    // to spend something, then we consider it dust.
    // A typical spendable non-segwit txout is 34 bytes big, and will
    // need a CTxIn of at least 148 bytes to spend:
    // so dust is a spendable txout less than
    // 182*dustRelayFee/1000 (in satoshis).
    // 546 satoshis at the default rate of 3000 sat/kB.
    // A typical spendable segwit txout is 31 bytes big, and will
    // need a CTxIn of at least 67 bytes to spend:
    // so dust is a spendable txout less than
    // 98*dustRelayFee/1000 (in satoshis).
    // 294 satoshis at the default rate of 3000 sat/kB.
    let size = 0;
    switch (input.type) {
        case "P2PKH":
            // size = 8 + encodingLength(input.scriptPubKey.length) + input.scriptPubKey.length
            size = global_vars_1.GLOBAL_VARS.TX_OUTPUT_SCRIPTPUBKEY_P2PKH;
            size += 32 + 4 + 1 + 107 + 4; // 148
            break;
        // @ts-ignore
        case "P2PK":
            // TODO: Implement support
            // size = 8 + encodingLength(input.scriptPubKey.length) + input.scriptPubKey.length
            size += 32 + 4 + 1 + 107 + 4; // 148
        // fallthrough, unsupported script type
        // @ts-ignore
        case "P2SH":
            // TODO: Implement support
            // size = 8 + encodingLength(input.scriptPubKey.length) + input.scriptPubKey.length
            size += 32 + 4 + 1 + 107 + 4; // 148
        // fallthrough, unsupported script type
        // @ts-ignore
        case "P2WH":
            // TODO: Implement support
            // size = 8 + encodingLength(input.scriptPubKey.length) + input.scriptPubKey.length
            size += 32 + 4 + 1 + (107 / global_vars_1.GLOBAL_VARS.WITNESS_SCALE_FACTOR) + 4; // 68
        // fallthrough, unsupported script type
        default:
            throw new Error("Unsupported output script type: " + input.type);
    }
    return ethers_1.BigNumber.from(feePerByte).mul(size).toNumber();
}
exports.getMinNonDustValue = getMinNonDustValue;
function shiftBy(amount, byPowerOfTen) {
    let amountString;
    if (typeof amount === "number") {
        amountString = `${amount}`;
    }
    else if (typeof amount === 'string') {
        amountString = amount;
    }
    else {
        amountString = ethers_1.BigNumber.from(amount).toString();
    }
    const indexOfExponent = amountString.indexOf('e');
    if (indexOfExponent !== -1) {
        // very small or large number with lots of decimals with an exponent
        // we want to adjust the exponent
        const exponentString = amountString.substring(indexOfExponent + 1, amountString.length);
        // exponentString = '-10', '+10' etc
        const exponent = parseInt(exponentString);
        const shiftedExponent = exponent + byPowerOfTen;
        amountString = amountString.substring(0, indexOfExponent);
        byPowerOfTen = shiftedExponent;
    }
    return byPowerOfTen === 0 ? amountString : `${amountString}e${byPowerOfTen < 0 ? '' : '+'}${byPowerOfTen}`;
}
function satoshiToQtum(inSatoshi) {
    return shiftBy(inSatoshi || 0, -8);
}
function qtumToSatoshi(inQtum) {
    return shiftBy(inQtum || 0, 8);
}
function checkLostPrecisionInGasPrice(gasPrice) {
    const roundedGasPrice = new bignumber_js_1.BigNumber(new bignumber_js_1.BigNumber(satoshiToQtum(gasPrice)).toFixed(8)).toNumber();
    const originalGasPrice = new bignumber_js_1.BigNumber(new bignumber_js_1.BigNumber(satoshiToQtum(gasPrice)).toFixed()).toNumber();
    if (roundedGasPrice != originalGasPrice) {
        throw new Error("Precision lost in gasPrice: " + (originalGasPrice - roundedGasPrice));
    }
}
function getContractVout(gasPrice, gasLimit, data, address, value) {
    return {
        script: contractTxScript(address === "" ? "" : address.split("0x")[1], gasLimit, gasPrice, data.split("0x")[1]),
        value: new bignumber_js_1.BigNumber(value).times(1e8).toNumber(),
    };
}
function getContractVoutForLedger(gasPrice, gasLimit, data, address, value) {
    return {
        script: contractTxScript(address === "" ? "" : address.split("0x")[1], gasLimit, gasPrice, data.split("0x")[1]),
        amount: Buffer.from(new bignumber_js_1.BigNumber(value).times(1e8).toString(), 'hex'),
    };
}
function parseSignedTransaction(transaction) {
    if (transaction.startsWith("0x")) {
        transaction = transaction.substring(2);
    }
    let tx = {
        hash: "",
        to: "",
        from: "",
        nonce: 1,
        gasLimit: ethers_1.BigNumber.from("0x3d090"),
        gasPrice: ethers_1.BigNumber.from("0x28"),
        data: "",
        value: ethers_1.BigNumber.from("0x0"),
        chainId: 81,
    };
    // Set hash (double sha256 of raw TX string)
    const sha256HashFirst = hash_js_1.sha256().update(transaction, "hex").digest("hex");
    const sha256HashSecond = reverse(Buffer.from(hash_js_1.sha256().update(sha256HashFirst, "hex").digest("hex"), "hex")).toString("hex");
    tx['hash'] = `0x${sha256HashSecond}`;
    const btcDecodedRawTx = hex_decoder_1.decode(transaction);
    // Check if first OP code is OP_DUP -> assume p2pkh script
    if (bitcoinjs.script.decompile(btcDecodedRawTx.outs[global_vars_1.GLOBAL_VARS.UTXO_VINDEX].script)[0] === opcodes_1.OPS.OP_DUP) {
        tx['to'] = `0x${bitcoinjs.script.decompile(btcDecodedRawTx.outs[global_vars_1.GLOBAL_VARS.UTXO_VINDEX].script)[2].toString("hex")}`;
        // If there is no change output, which is currently being used to identify the sender, how else can we find out the from address?
        tx['from'] = btcDecodedRawTx.outs.length > 1 ? `0x${bitcoinjs.script.decompile(btcDecodedRawTx.outs[1].script)[2].toString("hex")}` : "";
        tx['value'] = ethers_1.BigNumber.from(utils_1.hexlify(btcDecodedRawTx.outs[global_vars_1.GLOBAL_VARS.UTXO_VINDEX].value));
    }
    // Check if first OP code is OP_4 and length is > 5 -> assume contract call
    else if (bitcoinjs.script.decompile(btcDecodedRawTx.outs[global_vars_1.GLOBAL_VARS.UTXO_VINDEX].script)[0] === opcodes_1.OPS.OP_4 && bitcoinjs.script.decompile(btcDecodedRawTx.outs[global_vars_1.GLOBAL_VARS.UTXO_VINDEX].script).length > 5) {
        tx['to'] = `0x${bitcoinjs.script.decompile(btcDecodedRawTx.outs[global_vars_1.GLOBAL_VARS.UTXO_VINDEX].script)[4].toString("hex")}`;
        // If there is no change output, which is currently being used to identify the sender, how else can we find out the from address?
        tx['from'] = btcDecodedRawTx.outs.length > 1 ? `0x${bitcoinjs.script.decompile(btcDecodedRawTx.outs[1].script)[2].toString("hex")}` : "";
        tx['value'] = btcDecodedRawTx.outs[global_vars_1.GLOBAL_VARS.UTXO_VINDEX].value > 0 ? ethers_1.BigNumber.from(utils_1.hexlify(btcDecodedRawTx.outs[global_vars_1.GLOBAL_VARS.UTXO_VINDEX].value)) : ethers_1.BigNumber.from("0x0");
        tx['data'] = bitcoinjs.script.decompile(btcDecodedRawTx.outs[global_vars_1.GLOBAL_VARS.UTXO_VINDEX].script)[3].toString("hex");
        tx['value'] = ethers_1.BigNumber.from(utils_1.hexlify(btcDecodedRawTx.outs[global_vars_1.GLOBAL_VARS.UTXO_VINDEX].value)).toNumber() === 0 ? ethers_1.BigNumber.from("0x0") : ethers_1.BigNumber.from(utils_1.hexlify(btcDecodedRawTx.outs[global_vars_1.GLOBAL_VARS.UTXO_VINDEX].value));
    }
    // assume contract creation
    else {
        tx['to'] = "";
        // If there is no change output, which is currently being used to identify the sender, how else can we find out the from address?
        tx['from'] = btcDecodedRawTx.outs.length > 1 ? `0x${bitcoinjs.script.decompile(btcDecodedRawTx.outs[1].script)[2].toString("hex")}` : "";
        tx['gasLimit'] = ethers_1.BigNumber.from(utils_1.hexlify(script_number_1.decode(bitcoinjs.script.decompile(btcDecodedRawTx.outs[0].script)[1])));
        tx['gasPrice'] = ethers_1.BigNumber.from(utils_1.hexlify(script_number_1.decode(bitcoinjs.script.decompile(btcDecodedRawTx.outs[0].script)[2])));
        tx['data'] = bitcoinjs.script.decompile(btcDecodedRawTx.outs[0].script)[3].toString("hex");
    }
    return tx;
}
exports.parseSignedTransaction = parseSignedTransaction;
function computeAddress(key, compressed) {
    const publicKey = signing_key_1.computePublicKey(key, compressed);
    return computeAddressFromPublicKey(publicKey);
}
exports.computeAddress = computeAddress;
function computeAddressFromPublicKey(publicKey) {
    if (!publicKey.startsWith("0x")) {
        publicKey = "0x" + publicKey;
    }
    const sha256Hash = hash_js_1.sha256().update(publicKey.split("0x")[1], "hex").digest("hex");
    const prefixlessAddress = hash_js_1.ripemd160().update(sha256Hash, "hex").digest("hex");
    return address_1.getAddress(`0x${prefixlessAddress}`);
}
exports.computeAddressFromPublicKey = computeAddressFromPublicKey;
function checkTransactionType(tx) {
    if (!!tx.to === false && (!!tx.value === false || ethers_1.BigNumber.from(tx.value).toNumber() === 0) && !!tx.data === true) {
        const needed = new bignumber_js_1.BigNumber(satoshiToQtum(tx.gasPrice)).times(ethers_1.BigNumber.from(tx.gasLimit).toNumber()).toFixed(8).toString();
        return { transactionType: global_vars_1.GLOBAL_VARS.CONTRACT_CREATION, neededAmount: needed };
    }
    else if (!!tx.to === false && ethers_1.BigNumber.from(tx.value).toNumber() > 0 && !!tx.data === true) {
        return { transactionType: global_vars_1.GLOBAL_VARS.DEPLOY_ERROR, neededAmount: "0" };
    }
    else if (!!tx.to === true && !!tx.data === true) {
        const needed = !!tx.value === true ?
            new bignumber_js_1.BigNumber(new bignumber_js_1.BigNumber(satoshiToQtum(tx.gasPrice)).toFixed(8))
                .times(ethers_1.BigNumber.from(tx.gasLimit).toNumber())
                .plus(satoshiToQtum(tx.value)).toFixed(8) :
            new bignumber_js_1.BigNumber(new bignumber_js_1.BigNumber(satoshiToQtum(tx.gasPrice)).toFixed(8))
                .times(ethers_1.BigNumber.from(tx.gasLimit).toNumber()).toFixed(8);
        return { transactionType: global_vars_1.GLOBAL_VARS.CONTRACT_CALL, neededAmount: needed };
    }
    else {
        const gas = new bignumber_js_1.BigNumber(satoshiToQtum(tx.gasPrice)).times(ethers_1.BigNumber.from(tx.gasLimit).toNumber());
        const needed = new bignumber_js_1.BigNumber(satoshiToQtum(tx.value)).plus(gas).toFixed(8);
        return { transactionType: global_vars_1.GLOBAL_VARS.P2PKH, neededAmount: needed };
    }
}
exports.checkTransactionType = checkTransactionType;
async function serializeTransaction(utxos, fetchUtxos, neededAmount, tx, transactionType, privateKey, publicKey, filterDust) {
    const signer = (hash) => {
        return secp256k1Sign(hash, utils_1.arrayify(privateKey));
    };
    return await serializeTransactionWith(utxos, fetchUtxos, neededAmount, tx, transactionType, signer, publicKey, filterDust);
}
exports.serializeTransaction = serializeTransaction;
async function serializeTransactionWith(utxos, fetchUtxos, neededAmount, tx, transactionType, signer, publicKey, filterDust) {
    // Building the QTUM tx that will eventually be serialized.
    let qtumTx = { version: 2, locktime: 0, vins: [], vouts: [] };
    // reduce precision in gasPrice to 1 satoshi
    tx.gasPrice = tx.gasPrice;
    // tx.gasPrice = dropPrecisionLessThanOneSatoshi(BigNumberEthers.from(tx.gasPrice).toString());
    // in ethereum, the way to send your entire balance is to solve a simple equation:
    // amount to send in wei = entire balance in wei - (gas limit * gas price)
    // in order to properly be able to spend all UTXOs we need compute
    // we need to filter outputs that are dust
    // something is considered dust
    checkLostPrecisionInGasPrice(ethers_1.BigNumber.from(tx.gasPrice).toNumber());
    // 40 satoshi gasPrice => 400 satoshi/byte which is the minimum relay fee
    const satoshiPerByte = ethers_1.BigNumber.from(tx.gasPrice).mul(10);
    const gas = ethers_1.BigNumber.from(ethers_1.BigNumber.from(tx.gasPrice).mul(ethers_1.BigNumber.from(tx.gasLimit).toNumber()).toString());
    const nonContractTx = transactionType === global_vars_1.GLOBAL_VARS.P2PKH;
    let neededAmountBN = ethers_1.BigNumber.from(parseFloat(neededAmount + `e+8`));
    const neededAmountMinusGasBN = nonContractTx ? neededAmountBN.sub(gas) : neededAmountBN;
    const spendableUtxos = filterUtxos(utxos, satoshiPerByte, filterDust);
    const vouts = [];
    let needChange = true;
    if (transactionType === global_vars_1.GLOBAL_VARS.CONTRACT_CREATION) {
        const contractCreateVout = getContractVout(ethers_1.BigNumber.from(tx.gasPrice).toNumber(), ethers_1.BigNumber.from(tx.gasLimit).toNumber(), 
        // @ts-ignore
        tx.data, "", 
        // OP_CREATE cannot send QTUM when deploying contract
        new bignumber_js_1.BigNumber(ethers_1.BigNumber.from("0x0").toNumber() + `e-8`).toFixed(8));
        vouts.push(contractCreateVout);
        qtumTx.vouts.push(contractCreateVout);
    }
    else if (transactionType === global_vars_1.GLOBAL_VARS.CONTRACT_CALL) {
        const contractVoutValue = !!tx.value === true ?
            new bignumber_js_1.BigNumber(satoshiToQtum(tx.value)).toNumber() :
            new bignumber_js_1.BigNumber(ethers_1.BigNumber.from("0x0").toNumber() + `e-8`).toFixed(8);
        const contractCallVout = getContractVout(ethers_1.BigNumber.from(tx.gasPrice).toNumber(), ethers_1.BigNumber.from(tx.gasLimit).toNumber(), 
        // @ts-ignore
        tx.data, tx.to, contractVoutValue);
        vouts.push(contractCallVout);
        qtumTx.vouts.push(contractCallVout);
    }
    else if (transactionType === global_vars_1.GLOBAL_VARS.P2PKH) {
        // need to correct neededAmount
        // check if sending all
        let inputsAmount = ethers_1.BigNumber.from(0);
        let i = 0;
        for (i = 0; i < spendableUtxos.length; i++) {
            const spendableUtxo = spendableUtxos[i];
            // investigate issue where amount has no decimal point as calculation panics
            // @ts-ignore
            const amount = spendableUtxo.amountNumber;
            const utxoValue = parseFloat(shiftBy(amount, 8));
            inputsAmount = inputsAmount.add(utxoValue);
        }
        needChange = !inputsAmount.eq(neededAmountBN);
        if (needChange) {
            neededAmountBN = neededAmountMinusGasBN;
            neededAmount = satoshiToQtum(neededAmountBN);
        }
        if (!neededAmountBN.eq(ethers_1.BigNumber.from(0))) {
            // no need to generate an empty UTXO and clog the blockchain
            vouts.push('p2pkh');
        }
    }
    else if (transactionType === global_vars_1.GLOBAL_VARS.DEPLOY_ERROR) {
        // user requested sending QTUM with OP_CREATE which will result in the QTUM being lost
        throw new Error("Cannot send QTUM to contract when deploying a contract");
    }
    else {
        throw new Error("Internal error: unknown transaction type: " + transactionType);
    }
    // @ts-ignore
    const hash160PubKey = tx.from.split("0x")[1];
    // @ts-ignore
    let vins, amounts, availableAmount, fee, changeAmount, changeType;
    try {
        // @ts-ignore
        [vins, amounts, availableAmount, fee, changeAmount, changeType] = await addVins(vouts, spendableUtxos, neededAmount, needChange, satoshiPerByte.toString(), hash160PubKey);
    }
    catch (e) {
        if (!neededAmountBN.eq(neededAmountMinusGasBN) || ((typeof e.message) === 'string' && e.message.indexOf('more satoshi') === -1)) {
            throw e;
        }
        // needs more satoshi, provide more inputs
        // we probably need to filter dust here since the above non-filtered dust failed, there should be more inputs here
        const allSpendableUtxos = filterUtxos(await fetchUtxos(), satoshiPerByte, filterDust);
        const neededAmountMinusGas = satoshiToQtum(neededAmountMinusGasBN);
        // @ts-ignore
        [vins, amounts, availableAmount, fee, changeAmount, changeType] = await addVins(vouts, allSpendableUtxos, neededAmountMinusGas, needChange, satoshiPerByte.toString(), hash160PubKey);
    }
    if (vins.length === 0) {
        throw new Error("Couldn't find any vins");
    }
    qtumTx.vins = vins;
    if (transactionType === global_vars_1.GLOBAL_VARS.P2PKH) {
        // @ts-ignore
        const hash160Address = tx.to.split("0x")[1];
        let value;
        if (changeAmount) {
            // not using all
            value = new bignumber_js_1.BigNumber(ethers_1.BigNumber.from(tx.value).toNumber()).toNumber();
        }
        else {
            value = new bignumber_js_1.BigNumber(availableAmount).toNumber();
        }
        if (value != 0) {
            const p2pkhVout = {
                script: p2pkhScript(Buffer.from(hash160Address, "hex")),
                value: value
            };
            qtumTx.vouts.push(p2pkhVout);
        }
    }
    // add change if needed
    if (changeAmount) {
        qtumTx.vouts.push({
            // @ts-ignore
            script: scriptMap[changeType](Buffer.from(hash160PubKey, "hex")),
            value: changeAmount.toNumber()
        });
    }
    // Sign necessary vins
    const updatedVins = [];
    for (let i = 0; i < qtumTx.vins.length; i++) {
        updatedVins.push(Object.assign(Object.assign({}, qtumTx.vins[i]), { ['scriptSig']: p2pkhScriptSig(await signp2pkhWith(qtumTx, i, signer), publicKey.split("0x")[1]) }));
    }
    qtumTx.vins = updatedVins;
    // Build the serialized transaction string.
    const serialized = txToBuffer(qtumTx).toString('hex');
    return serialized;
}
exports.serializeTransactionWith = serializeTransactionWith;
function filterUtxos(utxos, satoshiPerByte, filterDust) {
    for (let i = 0; i < utxos.length; i++) {
        // @ts-ignore
        utxos[i].amountNumber = parseFloat(parseFloat(utxos[i].amount).toFixed(8));
    }
    return utxos.filter((utxo) => {
        if (utxo.safe === undefined || !utxo.safe) {
            // unsafe to spend utxo
            return false;
        }
        if (filterDust) {
            // @ts-ignore
            const utxoValue = parseFloat(utxo.amountNumber + `e+8`);
            const minimumValueToNotBeDust = getMinNonDustValue(utxo, satoshiPerByte);
            return utxoValue >= minimumValueToNotBeDust;
        }
        return true;
    });
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidXRpbHMuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9zcmMvbGliL2hlbHBlcnMvdXRpbHMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEscURBQTBFO0FBQzFFLGlDQUErQjtBQUMvQix1Q0FBZ0M7QUFDaEMsK0NBQTRDO0FBQzVDLG1EQUErQztBQUMvQyxvREFBb0Q7QUFFcEQsWUFBWTtBQUNaLHlDQUE0QztBQUM1QyxJQUFJLGFBQWEsR0FBRyxxQkFBUyxDQUFBO0FBQzdCLElBQUksQ0FBQyxxQkFBUyxJQUFJLGdCQUFJLEVBQUU7SUFDcEIseURBQXlEO0lBQ3pELFlBQVk7SUFDWixhQUFhLEdBQUcsVUFBUyxNQUFNLEVBQUUsVUFBVTtRQUN2Qyx1RUFBdUU7UUFDdkUsWUFBWTtRQUNaLE1BQU0sQ0FBQyxTQUFTLEdBQUcsSUFBSSxDQUFDO1FBQ3hCLFlBQVk7UUFDWixVQUFVLENBQUMsU0FBUyxHQUFHLElBQUksQ0FBQztRQUM1QixPQUFPLGdCQUFJLENBQUMsTUFBTSxFQUFFLFVBQVUsQ0FBQyxDQUFDO0lBQ3BDLENBQUMsQ0FBQTtDQUNKO0FBQ0QsbUVBQTRGO0FBQzVGLHFDQUEyQztBQUMzQywrQ0FBd0M7QUFDeEMsNkZBQTZGO0FBQzdGLDhDQUE4QztBQUM5QywyQ0FBMkM7QUFDM0MsNENBSTBCO0FBRTFCLG1DQUFvRTtBQUNwRSwrQ0FBdUM7QUFDdkMsNERBQThEO0FBRzlELG1EQUFtRDtBQUNuRCxNQUFNLFNBQVMsR0FBRyxPQUFPLENBQUMsZUFBZSxDQUFDLENBQUM7QUFFM0MsMEVBQTBFO0FBQzFFO0lBQ0ksbUJBQW1CO0lBQ25CLGFBQWE7SUFDYixVQUFVO0NBQ2IsQ0FBQyxPQUFPLENBQUMsQ0FBQyxVQUFVLEVBQUUsRUFBRTtJQUNyQix3RUFBd0U7SUFDeEUsTUFBTSxFQUFFLEdBQUcsSUFBSSxHQUFHLFVBQVUsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUMsV0FBVyxFQUFFLEdBQUcs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
