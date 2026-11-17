// Copyright (c) 2026, The Kryptokrona Developers
//
// Please see the included LICENSE file for more information.

/*
 * Shape adapters between the native modules of this package and the Crypto class:
 *
 *   createReactNativeCrypto  wraps the KryptokronaCrypto Turbo Native Module (only strings,
 *                            numbers, booleans and string arrays cross its boundary) into the
 *                            object the Crypto class calls (the names tryRunFunc uses, key
 *                            pairs as { private_key, public_key }, CLSAG as { c1, s })
 *   nativeExports            processBlockOutputs / findPowShare of either native module with
 *                            objects in and out (JSON text crosses the boundary)
 *
 * No require() of its own: react-native.ts and index.ts hand the module in.
 */

import { IClsagSignature, IKeyPair } from './Interfaces';

/**
 * A subwallet spend key pair as processBlockOutputs takes it
 */
export interface ISpendKey {
    publicKey: string;
    privateKey: string;
}

/**
 * One owned output found by processBlockOutputs
 */
export interface IFoundInput {
    publicSpendKey: string;
    input: {
        keyImage: string;
        amount: number;
        transactionIndex: number;
        /** -1 when the block did not carry it */
        globalOutputIndex: number;
        key: string;
        parentTransactionHash: string;
    };
}

/**
 * The result of findPowShare: nonce and result are set when a share was found
 */
export interface IFindPowShareResult {
    job_id?: string;
    nonce?: string;
    result?: string;
    hashes_performed: number;
    threads: number;
}

/**
 * @ignore
 */
function pair (keys: string[]): IKeyPair {
    return { private_key: keys[0], public_key: keys[1] };
}

/**
 * @ignore
 * The object the Crypto class runs on with CryptoType.REACTNATIVE. Functions the Turbo
 * Native Module does not have are absent, so the Crypto methods that need them reject
 * (or use a function the host registered in Crypto.userCryptoFunctions).
 */
export function createReactNativeCrypto (module: any): any {
    return {
        checkKey: (publicKey: string) => module.checkKey(publicKey),
        checkSignature: (prefixHash: string, publicKey: string, signature: string) =>
            module.checkSignature(prefixHash, publicKey, signature),
        checkRingSignature: (prefixHash: string, keyImage: string, publicKeys: string[], signatures: string[]) =>
            module.checkRingSignature(prefixHash, keyImage, publicKeys, signatures),
        cn_fast_hash: (data: string) => module.cn_fast_hash(data),
        secretKeyToPublicKey: (privateKey: string) => module.secretKeyToPublicKey(privateKey),
        scReduce32: (scalar: string) => module.scReduce32(scalar),
        hashToEllipticCurve: (hash: string) => module.hashToEllipticCurve(hash),
        hashToScalar: (data: string) => module.hashToScalar(data),
        generateKeys: () => pair(module.generateKeys()),
        generateKeyDerivation: (publicKey: string, privateKey: string) =>
            module.generateKeyDerivation(publicKey, privateKey),
        derivePublicKey: (derivation: string, outputIndex: number, publicKey: string) =>
            module.derivePublicKey(derivation, outputIndex, publicKey),
        deriveSecretKey: (derivation: string, outputIndex: number, privateKey: string) =>
            module.deriveSecretKey(derivation, outputIndex, privateKey),
        underivePublicKey: (derivation: string, outputIndex: number, derivedKey: string) =>
            module.underivePublicKey(derivation, outputIndex, derivedKey),
        generateKeyImage: (publicKey: string, privateKey: string) =>
            module.generateKeyImage(publicKey, privateKey),
        generateSignature: (prefixHash: string, publicKey: string, privateKey: string) =>
            module.generateSignature(prefixHash, publicKey, privateKey),
        deriveViewTag: (derivation: string, outputIndex: number) => module.deriveViewTag(derivation, outputIndex),
        clsagVerify: (prefixHash: string, ring: string[], keyImage: string, c1: string, s: string[]) =>
            module.clsagVerify(prefixHash, ring, keyImage, c1, s),
        cn_turtle_lite_slow_hash_v2: (data: string) => module.cn_turtle_lite_slow_hash_v2(data),
        generateDeterministicSubwalletKeys: async (basePrivateKey: string, walletIndex: number) =>
            pair(await module.generateDeterministicSubwalletKeys(basePrivateKey, walletIndex)),
        generateRingSignatures: (prefixHash: string, keyImage: string, publicKeys: string[], privateKey: string,
            realIndex: number) =>
            module.generateRingSignatures(prefixHash, keyImage, publicKeys, privateKey, realIndex),
        clsagSign: async (prefixHash: string, ring: string[], privateEphemeral: string, realOutputIndex: number,
            alpha: string, decoyResponses: string[]): Promise<IClsagSignature> => {
            const [c1, ...s] = await module.clsagSign(
                prefixHash, ring, privateEphemeral, realOutputIndex, alpha, decoyResponses);

            return { c1, s };
        },
        processBlockOutputs: (blockJson: string, privateViewKey: string, spendKeysJson: string,
            isViewWallet: boolean, processCoinbaseTransactions: boolean) =>
            module.processBlockOutputs(
                blockJson, privateViewKey, spendKeysJson, isViewWallet, processCoinbaseTransactions),
        findPowShare: (blobHex: string, targetHex: string, startNonce: number, maxAttempts: number,
            nonceTagBits: number, nonceTagValue: number) =>
            module.findPowShare(blobHex, targetHex, startNonce, maxAttempts, nonceTagBits, nonceTagValue)
    };
}

/**
 * @ignore
 */
export interface INativeExports {
    processBlockOutputs (
        block: any, privateViewKey: string, spendKeys: ISpendKey[], isViewWallet: boolean,
        processCoinbaseTransactions: boolean): Promise<IFoundInput[]>;
    findPowShare (
        blobHex: string, targetHex: string, startNonce: number, maxAttempts: number,
        nonceTagBits: number, nonceTagValue: number): Promise<IFindPowShareResult | null>;
}

/**
 * @ignore
 * processBlockOutputs and findPowShare of a native module (the Node-API addon or the
 * adapter above) with JavaScript objects in and out
 */
export function nativeExports (module: any): INativeExports {
    return {
        processBlockOutputs: async (block, privateViewKey, spendKeys, isViewWallet, processCoinbaseTransactions) =>
            JSON.parse(await module.processBlockOutputs(
                JSON.stringify(block), privateViewKey, JSON.stringify(spendKeys),
                isViewWallet, processCoinbaseTransactions)),
        findPowShare: async (blobHex, targetHex, startNonce, maxAttempts, nonceTagBits, nonceTagValue) =>
            JSON.parse(await module.findPowShare(
                blobHex, targetHex, startNonce, maxAttempts, nonceTagBits || 0, nonceTagValue || 0))
    };
}
