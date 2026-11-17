// Copyright (c) 2020, The TurtleCoin Developers
// Copyright (c) 2026, The Kryptokrona Developers
//
// Please see the included LICENSE file for more information.

/*
 * The Node.js / Electron entry point ("main"): the Node-API addon of this package
 * (prebuilt/napi/kryptokrona-crypto.<platform>.node, Rust; see rust/napi).
 *
 * React Native (Metro) resolves the "react-native" field of package.json to
 * react-native.ts instead, which never loads it. Without an addon for the platform the
 * wrapper runs on the functions the host registers (CryptoType.EXTERNAL), as on React Native.
 */

import * as path from 'path';
import { CryptoType } from './Interfaces';
import { setCryptoLoader, setCryptoModule, useExternalCrypto } from './Crypto';
import { nativeExports, IFindPowShareResult } from './native';

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
 * require() with a computed specifier: bundlers (Metro, webpack, esbuild, ...) do not
 * follow it, so the addon is not pulled into a bundle that only references this file.
 * Node.js resolves it as usual.
 */
function loadOptionalModule (id: string): any {
    return require(id);
}

/**
 * @ignore
 * The platform part of the addon file name, as napi-rs names its builds
 */
export function napiPlatform (): string {
    const { platform, arch } = process;

    switch (platform) {
        case 'linux':
            return 'linux-' + arch + '-gnu';
        case 'win32':
            return 'win32-' + arch + '-msvc';
        default:
            return platform + '-' + arch;
    }
}

/**
 * @ignore
 * Where the addon is looked for: KRYPTOKRONA_CRYPTO_NAPI (a path to a .node file) first,
 * then the prebuilt file of this platform shipped in the package
 */
export function napiCandidates (): string[] {
    const candidates: string[] = [];

    if (process.env.KRYPTOKRONA_CRYPTO_NAPI) {
        candidates.push(path.resolve(process.env.KRYPTOKRONA_CRYPTO_NAPI));
    }

    candidates.push(path.join(__dirname, '..', 'prebuilt', 'napi', 'kryptokrona-crypto.' + napiPlatform() + '.node'));

    return candidates;
}

/**
 * @ignore
 */
let addon: any = null;

/**
 * @ignore
 */
function loadNapi (): boolean {
    for (const candidate of napiCandidates()) {
        try {
            const Self = loadOptionalModule(candidate);

            if (Self && typeof Self.cn_fast_hash === 'function') {
                addon = Self;

                return setCryptoModule(Self, CryptoType.NAPI);
            }
        } catch (e) {
            /* try the next one */
        }
    }

    return false;
}

setCryptoLoader({
    initialize: () => loadNapi() || useExternalCrypto(),
    forceJS: () => false
});

/**
 * Scans the outputs of a block for a wallet's subwallets (the hook that
 * wallet-backend-js installs with setBlockOutputProcessFunc), on the addon's thread pool.
 * Rejects when the addon is not loaded.
 */
export async function processBlockOutputs (
    block: any,
    privateViewKey: string,
    spendKeys: Array<{ publicKey: string, privateKey: string }>,
    isViewWallet: boolean,
    processCoinbaseTransactions: boolean
): Promise<any[]> {
    return nativeExports(requireAddon()).processBlockOutputs(
        block, privateViewKey, spendKeys, isViewWallet, processCoinbaseTransactions);
}

/**
 * Searches for a Hugin message proof-of-work share, on the addon's thread pool; null for
 * unusable input. Rejects when the addon is not loaded.
 */
export async function findPowShare (
    blobHex: string,
    targetHex: string,
    startNonce: number,
    maxAttempts: number,
    nonceTagBits = 0,
    nonceTagValue = 0
): Promise<IFindPowShareResult | null> {
    return nativeExports(requireAddon()).findPowShare(
        blobHex, targetHex, startNonce, maxAttempts, nonceTagBits, nonceTagValue);
}

/**
 * @ignore
 */
function requireAddon (): any {
    if (addon === null) {
        loadNapi();
    }

    if (addon === null) {
        throw new Error('kryptokrona-crypto: no native addon for ' + napiPlatform());
    }

    return addon;
}
