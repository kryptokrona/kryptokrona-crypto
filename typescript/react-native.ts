// Copyright (c) 2020, The TurtleCoin Developers
// Copyright (c) 2026, The Kryptokrona Developers
//
// Please see the included LICENSE file for more information.

/*
 * The React Native entry point (the "react-native" field of package.json, which Metro
 * reads before "main").
 *
 * When the app has the KryptokronaCrypto Turbo Native Module of this package (New
 * Architecture, autolinked from cpp/, ios/ and android/), the wrapper runs on it
 * (CryptoType.REACTNATIVE) without any registration by the app. Otherwise it starts in
 * CryptoType.EXTERNAL and every primitive comes from the functions the host registers,
 * either
 *
 *     Crypto.userCryptoFunctions = { cn_fast_hash, generateKeyDerivation, ... };
 *
 * or `new Crypto({ ... })` (kryptokrona-utils' CryptoNote and kryptokrona-wallet-backend-js
 * pass their crypto config this way). Registered functions take precedence over the module in
 * both cases. A primitive that is neither registered nor in the module rejects with an error
 * naming it. deriveViewTag falls back to a JS computation (js-sha3).
 *
 * It never requires the Node.js addon or any Node.js module: the module graph of this file is
 * Crypto.ts, Interfaces.ts, native.ts, js-sha3 and react-native.
 */

import { setCryptoLoader, setCryptoModule, useExternalCrypto } from './Crypto';
import { CryptoType } from './Interfaces';
import { createReactNativeCrypto, nativeExports, IFindPowShareResult, IFoundInput, ISpendKey } from './native';

export {
    Crypto,
    CryptoType,
    IKeyPair,
    ICryptoConfig,
    IPreparedRingSignatures,
    IClsagSignature
} from './Crypto';

export { IFindPowShareResult, IFoundInput, ISpendKey } from './native';

/**
 * @ignore
 * The Turbo Native Module, or null outside React Native or when the app does not have it
 */
function loadTurboModule (): any {
    try {
        const ReactNative = require('react-native');

        const registry = ReactNative && ReactNative.TurboModuleRegistry;

        if (registry && typeof registry.get === 'function') {
            return registry.get('KryptokronaCrypto') || null;
        }
    } catch (e) {
        /* not running in React Native */
    }

    return null;
}

/**
 * @ignore
 */
const turboModule = loadTurboModule();

/**
 * The KryptokronaCrypto module adapted to the Crypto method names and shapes, or null when the
 * app does not have the module. For direct calls; the Crypto class already uses it.
 */
export const nativeCrypto: any = turboModule ? createReactNativeCrypto(turboModule) : null;

setCryptoLoader({
    initialize: () => (nativeCrypto ? setCryptoModule(nativeCrypto, CryptoType.REACTNATIVE) : useExternalCrypto()),
    forceJS: () => false
});

/**
 * @ignore
 */
function requireModule (): any {
    if (!nativeCrypto) {
        throw new Error('kryptokrona-crypto: the KryptokronaCrypto native module is not available');
    }

    return nativeCrypto;
}

/**
 * Scans the outputs of a block for a wallet's subwallets (the hook that
 * wallet-backend-js installs with setBlockOutputProcessFunc), off the JS thread. Coinbase
 * first (when processed), then the transactions in order; a missing globalIndex gives
 * globalOutputIndex -1; a view wallet gets the all-zero key image. Rejects when the module is
 * not available.
 */
export async function processBlockOutputs (
    block: any,
    privateViewKey: string,
    spendKeys: ISpendKey[],
    isViewWallet: boolean,
    processCoinbaseTransactions: boolean
): Promise<IFoundInput[]> {
    return nativeExports(requireModule()).processBlockOutputs(
        block, privateViewKey, spendKeys, isViewWallet, processCoinbaseTransactions);
}

/**
 * Searches for a Hugin message proof-of-work share off the JS thread:
 * { job_id: '', nonce, result, hashes_performed, threads } when found,
 * { hashes_performed, threads } when not, null for unusable input. Rejects when the module is
 * not available.
 */
export async function findPowShare (
    blobHex: string,
    targetHex: string,
    startNonce: number,
    maxAttempts: number,
    nonceTagBits = 0,
    nonceTagValue = 0
): Promise<IFindPowShareResult | null> {
    return nativeExports(requireModule()).findPowShare(
        blobHex, targetHex, startNonce, maxAttempts, nonceTagBits, nonceTagValue);
}
