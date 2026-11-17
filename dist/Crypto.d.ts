import { IKeyPair, ICryptoConfig, IPreparedRingSignatures, IClsagSignature, CryptoType } from './Interfaces';
export { IKeyPair, ICryptoConfig, IPreparedRingSignatures, IClsagSignature, CryptoType };
/**
 * @ignore
 * How an entry point of the package loads the underlying cryptographic primitives.
 * `index` (Node.js) loads the Node-API addon (CryptoType.NAPI); `react-native` uses the
 * KryptokronaCrypto Turbo Native Module when the app has it (CryptoType.REACTNATIVE) and
 * otherwise runs on the functions the host registers (CryptoType.EXTERNAL).
 */
export interface ICryptoLoader {
    /**
     * Loads the default primitives (through setCryptoModule); false when none could be loaded
     */
    initialize: () => boolean;
    /**
     * Loads the JS (slow) primitives; false when the entry point has none (every entry point
     * since 2.0.0)
     */
    forceJS: () => boolean;
}
/**
 * @ignore
 * Called once by the entry point (index.ts or react-native.ts) when it is loaded
 */
export declare function setCryptoLoader(loader: ICryptoLoader): void;
/**
 * @ignore
 * Installs a loaded module of primitives
 */
export declare function setCryptoModule(crypto: any, type: CryptoType): boolean;
/**
 * @ignore
 * No module of our own: every primitive comes from Crypto.userCryptoFunctions
 * (the deriveViewTag and CLSAG parameter checks and the JS view tag still run here)
 */
export declare function useExternalCrypto(): boolean;
/**
 * A class containing the TurtleCoin cryptographic primitive methods that wraps
 * the Node.js addon (CryptoType.NAPI), the React Native module (CryptoType.REACTNATIVE)
 * or the functions supplied by the host (CryptoType.EXTERNAL) into a common interface
 */
export declare class Crypto {
    /**
     * Returns the type of the cryptographic primitives used by the wrapper
     */
    static get type(): CryptoType;
    /**
     * Returns if a native library of this package is being used (Node.js addon or React
     * Native module)
     */
    static get isNative(): boolean;
    /**
     * Returns if the wrapper is loaded and ready
     */
    static get isReady(): boolean;
    /**
     * Retrieves the array of user-defined cryptographic primitive functions
     * that replace our primitives at runtime
     */
    static get userCryptoFunctions(): ICryptoConfig;
    /**
     * Allows for updating the user-defined cryptographic primitive functions
     * that will replace our primitives at runtime.
     * @param config
     */
    static set userCryptoFunctions(config: ICryptoConfig);
    /**
     * Forces the wrapper to use the JS (slow) cryptographic primitives. There is no JS
     * build since 2.0.0: always returns false and leaves the primitives as they are
     */
    static forceJSCrypto(): boolean;
    /**
     * Creates a new wrapper object
     * @param [config] may contain user-defined cryptographic primitive functions
     * that will replace our primitives at runtime.
     */
    constructor(config?: ICryptoConfig);
    /**
     * Returns the type of the cryptographic primitives used by the wrapper
     */
    get type(): CryptoType;
    /**
     * Returns if a native library of this package is being used
     */
    get isNative(): boolean;
    /**
     * Returns if the wrapper is loaded and ready
     */
    get isReady(): boolean;
    /**
     * Retrieves the array of user-defined cryptographic primitive functions
     * that replace our primitives at runtime
     */
    get userCryptoFunctions(): ICryptoConfig;
    /**
     * Allows for updating the user-defined cryptographic primitive functions
     * that will replace our primitives at runtime.
     * @param config
     */
    set userCryptoFunctions(config: ICryptoConfig);
    /**
     * Forces the wrapper to use the JS (slow) cryptographic primitives (none since 2.0.0:
     * returns false)
     */
    forceJSCrypto(): boolean;
    /**
     * Calculates the multisignature (m) private keys using our private spend key
     * and the public spend keys of other participants in a M:N scheme
     * @param private_spend_key our private spend key
     * @param public_keys an array of the other participants public spend keys
     */
    calculateMultisigPrivateKeys(private_spend_key: string, public_keys: string[]): Promise<string[]>;
    /**
     * Calculates a shared private key from the private keys supplied
     * @param private_keys the array of private keys
     */
    calculateSharedPrivateKey(private_keys: string[]): Promise<string>;
    /**
     * Calculates a shared public key from the public keys supplied
     * @param public_keys the array of public keys
     */
    calculateSharedPublicKey(public_keys: string[]): Promise<string>;
    /**
     * Checks whether a given key is a public key
     * @param public_key the public key to check
     */
    checkKey(public_key: string): Promise<boolean>;
    /**
     * Checks a set of ring signatures to verify that they are valid
     * @param prefix_hash the hash (often the transaction prefix hash)
     * @param key_image real key_image used to generate the signatures
     * @param input_keys the output keys used during signing (mixins + real)
     * @param signatures the signatures
     */
    checkRingSignatures(prefix_hash: string, key_image: string, input_keys: string[], signatures: string[]): Promise<boolean>;
    /**
     * Checks whether the given key is a private key
     * @param private_key
     */
    checkScalar(private_key: string): Promise<boolean>;
    /**
     * Checks that the given signature is valid for the hash and public key supplied
     * @param message_digest the hash (message digest) used
     * @param public_key the public key of the private key used to sign
     * @param signature the signature
     */
    checkSignature(message_digest: string, public_key: string, signature: string): Promise<boolean>;
    /**
     * Generates a single-key CLSAG signature (transaction version 2, fork 14) over
     * the ring. The key image that goes into the input is the ordinary one
     * (generateKeyImage of the real output key and private_ephemeral).
     *
     * Without alpha and decoy_responses the randomness is drawn by the underlying
     * library. With them the signature is deterministic (test vectors, split signing):
     * alpha is the nonce, decoy_responses the ring.length - 1 responses of the other
     * members in consumption order s_{l+1}, .., s_{n-1}, s_0, .., s_{l-1}
     * (l = real_output_index), every one a reduced scalar.
     * @param prefix_hash the message digest (the transaction prefix hash)
     * @param ring the output keys of the ring in transaction order (mixins + real)
     * @param private_ephemeral the private ephemeral of the output being spent
     * @param real_output_index the index of the real output in ring
     * @param [alpha] the nonce (deterministic signing only)
     * @param [decoy_responses] the decoy responses (deterministic signing only)
     */
    clsagSign(prefix_hash: string, ring: string[], private_ephemeral: string, real_output_index: number, alpha?: string, decoy_responses?: string[]): Promise<IClsagSignature>;
    /**
     * Verifies a single-key CLSAG signature (transaction version 2, fork 14).
     * Malformed input gives false, as an invalid signature does.
     * @param prefix_hash the message digest (the transaction prefix hash)
     * @param ring the output keys of the ring in transaction order
     * @param key_image the key image of the input
     * @param c1 the challenge of the signature
     * @param s the responses of the signature, one per ring member
     */
    clsagVerify(prefix_hash: string, ring: string[], key_image: string, c1: string, s: string[]): Promise<boolean>;
    /**
     * Calculates the hash of the data supplied using the cn_fast_hash method
     * @param data
     */
    cn_fast_hash(data: string): Promise<string>;
    /**
     * Completes a given set of prepared ring signatures using the single
     * private_ephemeral
     * @param private_ephemeral private ephemeral of the output being spent
     * @param real_output_index the position of the signature in the array that belongs
     * to the real output being spent
     * @param k the random scalar provided with the prepared ring signatures
     * @param signatures the prepared ring signatures
     */
    completeRingSignatures(private_ephemeral: string, real_output_index: number, k: string, signatures: string[]): Promise<string[]>;
    /**
     * Converts a key derivation to its resulting scalar
     * @param derivation the key derivation
     * @param output_index the index of the output in the transaction
     */
    derivationToScalar(derivation: string, output_index: number): Promise<string>;
    /**
     * Derives the public ephemeral from the key derivation, output index, and
     * our public spend key
     * @param derivation the key derivation
     * @param output_index the index of the output in the transaction
     * @param public_key our public spend key
     */
    derivePublicKey(derivation: string, output_index: number, public_key: string): Promise<string>;
    /**
     * Derives the private ephemeral from the key derivation, output index, and
     * our private spend key
     * @param derivation the key derivation
     * @param output_index the index of the output in the transaction
     * @param private_key our private spend key
     */
    deriveSecretKey(derivation: string, output_index: number, private_key: string): Promise<string>;
    /**
     * Calculates the view tag of an output (transaction version 2, fork 14):
     * the first byte of cn_fast_hash("view_tag" || derivation || varint(output_index))
     * as two lowercase hex characters, the form the daemon's JSON uses
     * @param derivation the key derivation
     * @param output_index the index of the output in the transaction
     */
    deriveViewTag(derivation: string, output_index: number): Promise<string>;
    /**
     * Generates a set of deterministic spend keys for a sub wallet given
     * our root private spend key and the index of the subwallet
     * @param private_key our root private spend key (seed)
     * @param walletIndex the index of the subwallet
     */
    generateDeterministicSubwalletKeys(private_key: string, walletIndex: number): Promise<IKeyPair>;
    /**
     * Generates a key derivation (aB) given the public key and private key
     * @param public_key
     * @param private_key
     */
    generateKeyDerivation(public_key: string, private_key: string): Promise<string>;
    /**
     * Generates a key derivation scalar H_s(aB) given the public key and private key
     * @param public_key the public key
     * @param private_key the private key
     * @param output_index the output index
     */
    generateKeyDerivationScalar(public_key: string, private_key: string, output_index: number): Promise<string>;
    /**
     * Generates a key image given the public ephemeral and the private ephemeral
     * @param publicEphemeral the public ephemeral of the output
     * @param private_ephemeral the private ephemeral of the output
     */
    generateKeyImage(publicEphemeral: string, private_ephemeral: string): Promise<string>;
    /**
     * Generates a new random key pair
     */
    generateKeys(): Promise<IKeyPair>;
    /**
     * Generates a partial signing key for a multisig ring signature set
     * @param signature the prepared real input signature
     * @param private_key our private spend key (or multisig private key)
     */
    generatePartialSigningKey(signature: string, private_key: string): Promise<string>;
    /**
     * Generates a private view key from the private spend key
     * @param private_key the private spend key
     */
    generatePrivateViewKeyFromPrivateSpendKey(private_key: string): Promise<string>;
    /**
     * Generates ring signatures for the supplied values
     * @param hash the message digest hash (often the transaction prefix hash)
     * @param key_image the key image of the output being spent
     * @param public_keys an array of the output keys used for signing (mixins + our output)
     * @param private_ephemeral the private ephemeral of the output being spent
     * @param real_output_index the array index of the real output being spent in the public_keys array
     */
    generateRingSignatures(hash: string, key_image: string, public_keys: string[], private_ephemeral: string, real_output_index: number): Promise<string[]>;
    /**
     * Generates a signature for the given message digest (hash)
     * @param hash the hash
     * @param public_key the public key used in signing
     * @param private_key the private key used to sign
     */
    generateSignature(hash: string, public_key: string, private_key: string): Promise<string>;
    /**
     * Generates a vew key pair from the private spend key
     * @param private_key the private spend key
     */
    generateViewKeysFromPrivateSpendKey(private_key: string): Promise<IKeyPair>;
    /**
     * Converts a hash to an elliptic curve point
     * @param hash the hash
     */
    hashToEllipticCurve(hash: string): Promise<string>;
    /**
     * Converts a hash to a scalar
     * @param hash the hash
     */
    hashToScalar(hash: string): Promise<string>;
    /**
     * Prepares ring signatures for completion or restoration later
     * @param hash the message digest hash (often the transaction prefix hash)
     * @param key_image the key image of the output being spent
     * @param public_keys an array of the output keys used for signing (mixins + our output)
     * @param real_output_index the array index of the real output being spent in the public_keys array
     * @param k a random scalar (private key)
     */
    prepareRingSignatures(hash: string, key_image: string, public_keys: string[], real_output_index: number, k?: string): Promise<IPreparedRingSignatures>;
    /**
     * Re-initializes the underlying cryptographic primitives
     */
    reloadCrypto(): Promise<boolean>;
    /**
     * Restores a key image from a set of partial key images generated by the other
     * participants in a multisig wallet
     * @param publicEphemeral the transaction public ephemeral
     * @param derivation the key derivation of the our output
     * @param output_index the index of our output in the transaction
     * @param partialKeyImages the array of partial key images from the needed
     * number of participants in the multisig scheme
     */
    restoreKeyImage(publicEphemeral: string, derivation: string, output_index: number, partialKeyImages: string[]): Promise<string>;
    /**
     * Restores the ring signatures using the previously prepared ring signatures
     * and the necessary number of partial signing keys generated by other
     * participants in the multisig wallet
     * @param derivation the key derivation for the output being spent
     * @param output_index the index of the output being spent in the transaction
     * @param partialSigningKeys the array of partial signing keys from the necessary number
     * of participants
     * @param real_output_index the index of the real input in the ring signatures
     * @param k the random scalar generated py preparing the ring signatures
     * @param signatures the prepared ring signatures
     */
    restoreRingSignatures(derivation: string, output_index: number, partialSigningKeys: string[], real_output_index: number, k: string, signatures: string[]): Promise<string[]>;
    /**
     * Derives the public key using the derivation scalar
     * @param derivationScalar the derivation scalar
     * @param public_key the public key
     */
    scalarDerivePublicKey(derivationScalar: string, public_key: string): Promise<string>;
    /**
     * Derives the private key using the derivation scalar
     * @param derivationScalar the derivation scalar
     * @param private_key the private key
     */
    scalarDeriveSecretKey(derivationScalar: string, private_key: string): Promise<string>;
    /**
     * Multiplies two key images together
     * @param key_imageA
     * @param key_imageB
     */
    scalarmultKey(key_imageA: string, key_imageB: string): Promise<string>;
    /**
     * Reduces a value to a scalar (mod q)
     * @param data
     */
    scReduce32(data: string): Promise<string>;
    /**
     * Calculates the public key of a private key
     * @param private_key
     */
    secretKeyToPublicKey(private_key: string): Promise<string>;
    /**
     * Calculates the merkle tree branch of the given hashes
     * @param hashes the array of hashes
     */
    tree_branch(hashes: string[]): Promise<string[]>;
    /**
     * Calculates the depth of the merkle tree
     * @param count the number of hashes in the tree
     */
    tree_depth(count: number): Promise<number>;
    /**
     * Calculates the merkle tree hash of the given hashes
     * @param hashes the array of hashes
     */
    tree_hash(hashes: string[]): Promise<string>;
    /**
     * Calculates the merkle tree hash from the given branch information
     * @param branches the merkle tree branches
     * @param leaf the leaf on the merkle tree
     * @param path the path on the merkle tree
     */
    tree_hash_from_branch(branches: string[], leaf: string, path: number): Promise<string>;
    /**
     * Underives a public key instead of deriving it
     * @param derivation the key derivation
     * @param output_index the index of the output in the transaction
     * @param outputKey the output key in the transaction
     */
    underivePublicKey(derivation: string, output_index: number, outputKey: string): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the cn_slow_hash_v0 method
     * @param data
     */
    cn_slow_hash_v0(data: string): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the cn_slow_hash_v1 method
     * @param data
     */
    cn_slow_hash_v1(data: string): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the cn_slow_hash_v2 method
     * @param data
     */
    cn_slow_hash_v2(data: string): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the cn_lite_slow_hash_v0 method
     * @param data
     */
    cn_lite_slow_hash_v0(data: string): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the cn_lite_slow_hash_v1 method
     * @param data
     */
    cn_lite_slow_hash_v1(data: string): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the cn_lite_slow_hash_v2 method
     * @param data
     */
    cn_lite_slow_hash_v2(data: string): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the cn_dark_slow_hash_v0 method
     * @param data
     */
    cn_dark_slow_hash_v0(data: string): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the cn_dark_slow_hash_v1 method
     * @param data
     */
    cn_dark_slow_hash_v1(data: string): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the cn_dark_slow_hash_v2 method
     * @param data
     */
    cn_dark_slow_hash_v2(data: string): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the cn_dark_lite_slow_hash_v0 method
     * @param data
     */
    cn_dark_lite_slow_hash_v0(data: string): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the cn_dark_lite_slow_hash_v1 method
     * @param data
     */
    cn_dark_lite_slow_hash_v1(data: string): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the cn_dark_lite_slow_hash_v2 method
     * @param data
     */
    cn_dark_lite_slow_hash_v2(data: string): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the cn_turtle_slow_hash_v0 method
     * @param data
     */
    cn_turtle_slow_hash_v0(data: string): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the cn_turtle_slow_hash_v1 method
     * @param data
     */
    cn_turtle_slow_hash_v1(data: string): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the cn_turtle_slow_hash_v2 method
     * @param data
     */
    cn_turtle_slow_hash_v2(data: string): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the cn_turtle_lite_slow_hash_v0 method
     * @param data
     */
    cn_turtle_lite_slow_hash_v0(data: string): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the cn_turtle_lite_slow_hash_v1 method
     * @param data
     */
    cn_turtle_lite_slow_hash_v1(data: string): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the cn_turtle_lite_slow_hash_v2 method
     * @param data
     */
    cn_turtle_lite_slow_hash_v2(data: string): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the cn_soft_shell_slow_hash_v0 method
     * @param data
     * @param height the height of the blockchain
     */
    cn_soft_shell_slow_hash_v0(data: string, height: number): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the cn_soft_shell_slow_hash_v1 method
     * @param data
     * @param height the height of the blockchain
     */
    cn_soft_shell_slow_hash_v1(data: string, height: number): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the cn_soft_shell_slow_hash_v2 method
     * @param data
     * @param height the height of the blockchain
     */
    cn_soft_shell_slow_hash_v2(data: string, height: number): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the chukwa_slow_hash method
     * @param data
     * @param version
     */
    chukwa_slow_hash(data: string, version?: number): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the chukwa_slow_hash_base method
     * @param data
     * @param iterations
     * @param memory
     * @param threads
     */
    chukwa_slow_hash_base(data: string, iterations: number, memory: number, threads: number): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the chukwa_slow_hash_v1 method
     * @param data
     */
    chukwa_slow_hash_v1(data: string): Promise<string>;
    /**
     * Calculates the hash of the data supplied using the chukwa_slow_hash_v2 method
     * @param data
     */
    chukwa_slow_hash_v2(data: string): Promise<string>;
}
