// Copyright (c) 2026, The Kryptokrona Developers
//
// Please see the included LICENSE file for more information.

/*
 * Codegen spec of the C++ Turbo Native Module KryptokronaCrypto (cpp/KryptokronaCryptoModule.h).
 * React Native's codegen reads this file (package.json "codegenConfig"); it is not part of the
 * TypeScript build. Only strings, numbers, booleans, string arrays and promises of those, so
 * the C++ side needs no custom bridging types; typescript/native.ts adapts the shapes.
 */

import type { TurboModule } from 'react-native';
import { TurboModuleRegistry } from 'react-native';

export interface Spec extends TurboModule {
    checkKey(publicKey: string): boolean;
    checkSignature(prefixHash: string, publicKey: string, signature: string): boolean;
    checkRingSignature(prefixHash: string, keyImage: string, publicKeys: string[], signatures: string[]): boolean;
    cn_fast_hash(data: string): string;
    secretKeyToPublicKey(privateKey: string): string;
    scReduce32(scalar: string): string;
    hashToEllipticCurve(hash: string): string;
    hashToScalar(data: string): string;
    /** [private_key, public_key] */
    generateKeys(): string[];
    generateKeyDerivation(publicKey: string, privateKey: string): string;
    derivePublicKey(derivation: string, outputIndex: number, publicKey: string): string;
    deriveSecretKey(derivation: string, outputIndex: number, privateKey: string): string;
    underivePublicKey(derivation: string, outputIndex: number, derivedKey: string): string;
    generateKeyImage(publicKey: string, privateKey: string): string;
    generateSignature(prefixHash: string, publicKey: string, privateKey: string): string;
    deriveViewTag(derivation: string, outputIndex: number): string;
    clsagVerify(prefixHash: string, ring: string[], keyImage: string, c1: string, s: string[]): boolean;

    cn_turtle_lite_slow_hash_v2(data: string): Promise<string>;
    /** [private_key, public_key] */
    generateDeterministicSubwalletKeys(basePrivateKey: string, walletIndex: number): Promise<string[]>;
    generateRingSignatures(
        prefixHash: string, keyImage: string, publicKeys: string[], privateKey: string,
        realIndex: number): Promise<string[]>;
    /** [c1, ...s] */
    clsagSign(
        prefixHash: string, ring: string[], privateEphemeral: string, realOutputIndex: number,
        alpha: string, decoyResponses: string[]): Promise<string[]>;
    /** JSON text in and out */
    processBlockOutputs(
        blockJson: string, privateViewKey: string, spendKeysJson: string,
        isViewWallet: boolean, processCoinbaseTransactions: boolean): Promise<string>;
    /** JSON text, "null" for unusable input */
    findPowShare(
        blobHex: string, targetHex: string, startNonce: number, maxAttempts: number,
        nonceTagBits: number, nonceTagValue: number): Promise<string>;
}

export default TurboModuleRegistry.get<Spec>('KryptokronaCrypto');
