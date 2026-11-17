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
 * The object the Crypto class runs on with CryptoType.REACTNATIVE. Functions the Turbo
 * Native Module does not have are absent, so the Crypto methods that need them reject
 * (or use a function the host registered in Crypto.userCryptoFunctions).
 */
export declare function createReactNativeCrypto(module: any): any;
/**
 * @ignore
 */
export interface INativeExports {
    processBlockOutputs(block: any, privateViewKey: string, spendKeys: ISpendKey[], isViewWallet: boolean, processCoinbaseTransactions: boolean): Promise<IFoundInput[]>;
    findPowShare(blobHex: string, targetHex: string, startNonce: number, maxAttempts: number, nonceTagBits: number, nonceTagValue: number): Promise<IFindPowShareResult | null>;
}
/**
 * @ignore
 * processBlockOutputs and findPowShare of a native module (the Node-API addon or the
 * adapter above) with JavaScript objects in and out
 */
export declare function nativeExports(module: any): INativeExports;
