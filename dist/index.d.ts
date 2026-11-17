import { IFindPowShareResult } from './native';
export { Crypto, CryptoType, IKeyPair, ICryptoConfig, IPreparedRingSignatures, IClsagSignature } from './Crypto';
export { IFindPowShareResult, IFoundInput, ISpendKey } from './native';
/**
 * @ignore
 * The platform part of the addon file name, as napi-rs names its builds
 */
export declare function napiPlatform(): string;
/**
 * @ignore
 * Where the addon is looked for: KRYPTOKRONA_CRYPTO_NAPI (a path to a .node file) first,
 * then the prebuilt file of this platform shipped in the package
 */
export declare function napiCandidates(): string[];
/**
 * Scans the outputs of a block for a wallet's subwallets (the hook that
 * wallet-backend-js installs with setBlockOutputProcessFunc), on the addon's thread pool.
 * Rejects when the addon is not loaded.
 */
export declare function processBlockOutputs(block: any, privateViewKey: string, spendKeys: Array<{
    publicKey: string;
    privateKey: string;
}>, isViewWallet: boolean, processCoinbaseTransactions: boolean): Promise<any[]>;
/**
 * Searches for a Hugin message proof-of-work share, on the addon's thread pool; null for
 * unusable input. Rejects when the addon is not loaded.
 */
export declare function findPowShare(blobHex: string, targetHex: string, startNonce: number, maxAttempts: number, nonceTagBits?: number, nonceTagValue?: number): Promise<IFindPowShareResult | null>;
