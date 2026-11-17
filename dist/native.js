"use strict";
// Copyright (c) 2026, The Kryptokrona Developers
//
// Please see the included LICENSE file for more information.
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.nativeExports = exports.createReactNativeCrypto = void 0;
/**
 * @ignore
 */
function pair(keys) {
    return { private_key: keys[0], public_key: keys[1] };
}
/**
 * @ignore
 * The object the Crypto class runs on with CryptoType.REACTNATIVE. Functions the Turbo
 * Native Module does not have are absent, so the Crypto methods that need them reject
 * (or use a function the host registered in Crypto.userCryptoFunctions).
 */
function createReactNativeCrypto(module) {
    return {
        checkKey: (publicKey) => module.checkKey(publicKey),
        checkSignature: (prefixHash, publicKey, signature) => module.checkSignature(prefixHash, publicKey, signature),
        checkRingSignature: (prefixHash, keyImage, publicKeys, signatures) => module.checkRingSignature(prefixHash, keyImage, publicKeys, signatures),
        cn_fast_hash: (data) => module.cn_fast_hash(data),
        secretKeyToPublicKey: (privateKey) => module.secretKeyToPublicKey(privateKey),
        scReduce32: (scalar) => module.scReduce32(scalar),
        hashToEllipticCurve: (hash) => module.hashToEllipticCurve(hash),
        hashToScalar: (data) => module.hashToScalar(data),
        generateKeys: () => pair(module.generateKeys()),
        generateKeyDerivation: (publicKey, privateKey) => module.generateKeyDerivation(publicKey, privateKey),
        derivePublicKey: (derivation, outputIndex, publicKey) => module.derivePublicKey(derivation, outputIndex, publicKey),
        deriveSecretKey: (derivation, outputIndex, privateKey) => module.deriveSecretKey(derivation, outputIndex, privateKey),
        underivePublicKey: (derivation, outputIndex, derivedKey) => module.underivePublicKey(derivation, outputIndex, derivedKey),
        generateKeyImage: (publicKey, privateKey) => module.generateKeyImage(publicKey, privateKey),
        generateSignature: (prefixHash, publicKey, privateKey) => module.generateSignature(prefixHash, publicKey, privateKey),
        deriveViewTag: (derivation, outputIndex) => module.deriveViewTag(derivation, outputIndex),
        clsagVerify: (prefixHash, ring, keyImage, c1, s) => module.clsagVerify(prefixHash, ring, keyImage, c1, s),
        cn_turtle_lite_slow_hash_v2: (data) => module.cn_turtle_lite_slow_hash_v2(data),
        generateDeterministicSubwalletKeys: (basePrivateKey, walletIndex) => __awaiter(this, void 0, void 0, function* () { return pair(yield module.generateDeterministicSubwalletKeys(basePrivateKey, walletIndex)); }),
        generateRingSignatures: (prefixHash, keyImage, publicKeys, privateKey, realIndex) => module.generateRingSignatures(prefixHash, keyImage, publicKeys, privateKey, realIndex),
        clsagSign: (prefixHash, ring, privateEphemeral, realOutputIndex, alpha, decoyResponses) => __awaiter(this, void 0, void 0, function* () {
            const [c1, ...s] = yield module.clsagSign(prefixHash, ring, privateEphemeral, realOutputIndex, alpha, decoyResponses);
            return { c1, s };
        }),
        processBlockOutputs: (blockJson, privateViewKey, spendKeysJson, isViewWallet, processCoinbaseTransactions) => module.processBlockOutputs(blockJson, privateViewKey, spendKeysJson, isViewWallet, processCoinbaseTransactions),
        findPowShare: (blobHex, targetHex, startNonce, maxAttempts, nonceTagBits, nonceTagValue) => module.findPowShare(blobHex, targetHex, startNonce, maxAttempts, nonceTagBits, nonceTagValue)
    };
}
exports.createReactNativeCrypto = createReactNativeCrypto;
/**
 * @ignore
 * processBlockOutputs and findPowShare of a native module (the Node-API addon or the
 * adapter above) with JavaScript objects in and out
 */
function nativeExports(module) {
    return {
        processBlockOutputs: (block, privateViewKey, spendKeys, isViewWallet, processCoinbaseTransactions) => __awaiter(this, void 0, void 0, function* () {
            return JSON.parse(yield module.processBlockOutputs(JSON.stringify(block), privateViewKey, JSON.stringify(spendKeys), isViewWallet, processCoinbaseTransactions));
        }),
        findPowShare: (blobHex, targetHex, startNonce, maxAttempts, nonceTagBits, nonceTagValue) => __awaiter(this, void 0, void 0, function* () {
            return JSON.parse(yield module.findPowShare(blobHex, targetHex, startNonce, maxAttempts, nonceTagBits || 0, nonceTagValue || 0));
        })
    };
}
exports.nativeExports = nativeExports;
