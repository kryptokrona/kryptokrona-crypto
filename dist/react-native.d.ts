import { IFindPowShareResult, IFoundInput, ISpendKey } from './native';
export { Crypto, CryptoType, IKeyPair, ICryptoConfig, IPreparedRingSignatures, IClsagSignature } from './Crypto';
export { IFindPowShareResult, IFoundInput, ISpendKey } from './native';
/**
 * The KryptokronaCrypto module adapted to the Crypto method names and shapes, or null when the
 * app does not have the module. For direct calls; the Crypto class already uses it.
 */
export declare const nativeCrypto: any;
/**
 * Scans the outputs of a block for a wallet's subwallets (the hook that
 * wallet-backend-js installs with setBlockOutputProcessFunc), off the JS thread. Coinbase
 * first (when processed), then the transactions in order; a missing globalIndex gives
 * globalOutputIndex -1; a view wallet gets the all-zero key image. Rejects when the module is
 * not available.
 */
export declare function processBlockOutputs(block: any, privateViewKey: string, spendKeys: ISpendKey[], isViewWallet: boolean, processCoinbaseTransactions: boolean): Promise<IFoundInput[]>;
/**
 * Searches for a Hugin message proof-of-work share off the JS thread:
 * { job_id: '', nonce, result, hashes_performed, threads } when found,
 * { hashes_performed, threads } when not, null for unusable input. Rejects when the module is
 * not available.
 */
export declare function findPowShare(blobHex: string, targetHex: string, startNonce: number, maxAttempts: number, nonceTagBits?: number, nonceTagValue?: number): Promise<IFindPowShareResult | null>;
