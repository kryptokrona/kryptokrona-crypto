// Copyright (c) 2020, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

import { keccak256 } from 'js-sha3';
import {
    IKeyPair,
    ICryptoConfig,
    IModuleSettings,
    IPreparedRingSignatures,
    IClsagSignature,
    CryptoType
} from './Interfaces';

export { IKeyPair, ICryptoConfig, IPreparedRingSignatures, IClsagSignature, CryptoType };

/**
 * @ignore
 */
const userCryptoFunctions: ICryptoConfig = {};

/**
 * @ignore
 */
const moduleVars: IModuleSettings = {
    crypto: null,
    type: CryptoType.UNKNOWN
};

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
 */
let cryptoLoader: ICryptoLoader = {
    initialize: useExternalCrypto,
    forceJS: () => false
};

/**
 * @ignore
 * Called once by the entry point (index.ts or react-native.ts) when it is loaded
 */
export function setCryptoLoader (loader: ICryptoLoader): void {
    cryptoLoader = loader;
}

/**
 * @ignore
 * Installs a loaded module of primitives
 */
export function setCryptoModule (crypto: any, type: CryptoType): boolean {
    moduleVars.crypto = crypto;
    moduleVars.type = type;

    return true;
}

/**
 * @ignore
 * No module of our own: every primitive comes from Crypto.userCryptoFunctions
 * (the deriveViewTag and CLSAG parameter checks and the JS view tag still run here)
 */
export function useExternalCrypto (): boolean {
    return setCryptoModule({}, CryptoType.EXTERNAL);
}

/**
 * A class containing the TurtleCoin cryptographic primitive methods that wraps
 * the Node.js addon (CryptoType.NAPI), the React Native module (CryptoType.REACTNATIVE)
 * or the functions supplied by the host (CryptoType.EXTERNAL) into a common interface
 */
export class Crypto {
    /**
     * Returns the type of the cryptographic primitives used by the wrapper
     */
    public static get type (): CryptoType {
        return moduleVars.type;
    }

    /**
     * Returns if a native library of this package is being used (Node.js addon or React
     * Native module)
     */
    public static get isNative (): boolean {
        switch (moduleVars.type) {
            case CryptoType.NAPI:
            case CryptoType.REACTNATIVE:
                return true;
            default:
                return false;
        }
    }

    /**
     * Returns if the wrapper is loaded and ready
     */
    public static get isReady (): boolean {
        if (moduleVars.type === CryptoType.EXTERNAL) {
            return typeof userCryptoFunctions.cn_fast_hash === 'function';
        }

        return (moduleVars.crypto !== null &&
            typeof moduleVars.crypto.cn_fast_hash === 'function');
    }

    /**
     * Retrieves the array of user-defined cryptographic primitive functions
     * that replace our primitives at runtime
     */
    public static get userCryptoFunctions (): ICryptoConfig {
        return userCryptoFunctions;
    }

    /**
     * Allows for updating the user-defined cryptographic primitive functions
     * that will replace our primitives at runtime.
     * @param config
     */
    public static set userCryptoFunctions (config: ICryptoConfig) {
        Object.keys(config)
            .forEach(key => {
                userCryptoFunctions[key] = config[key];
            });
    }

    /**
     * Forces the wrapper to use the JS (slow) cryptographic primitives. There is no JS
     * build since 2.0.0: always returns false and leaves the primitives as they are
     */
    public static forceJSCrypto (): boolean {
        return cryptoLoader.forceJS();
    }

    /**
     * Creates a new wrapper object
     * @param [config] may contain user-defined cryptographic primitive functions
     * that will replace our primitives at runtime.
     */
    public constructor (config?: ICryptoConfig) {
        if (!initialize()) {
            throw new Error('Could not initialize underlying cryptographic library');
        }

        if (config) {
            Crypto.userCryptoFunctions = config;
        }
    }

    /**
     * Returns the type of the cryptographic primitives used by the wrapper
     */
    public get type (): CryptoType {
        return Crypto.type;
    }

    /**
     * Returns if a native library of this package is being used
     */
    public get isNative (): boolean {
        return Crypto.isNative;
    }

    /**
     * Returns if the wrapper is loaded and ready
     */
    public get isReady (): boolean {
        return Crypto.isReady;
    }

    /**
     * Retrieves the array of user-defined cryptographic primitive functions
     * that replace our primitives at runtime
     */
    public get userCryptoFunctions (): ICryptoConfig {
        return Crypto.userCryptoFunctions;
    }

    /**
     * Allows for updating the user-defined cryptographic primitive functions
     * that will replace our primitives at runtime.
     * @param config
     */
    public set userCryptoFunctions (config: ICryptoConfig) {
        Crypto.userCryptoFunctions = config;
    }

    /**
     * Forces the wrapper to use the JS (slow) cryptographic primitives (none since 2.0.0:
     * returns false)
     */
    public forceJSCrypto (): boolean {
        return Crypto.forceJSCrypto();
    }

    /**
     * Calculates the multisignature (m) private keys using our private spend key
     * and the public spend keys of other participants in a M:N scheme
     * @param private_spend_key our private spend key
     * @param public_keys an array of the other participants public spend keys
     */
    public async calculateMultisigPrivateKeys (
        private_spend_key: string,
        public_keys: string[]
    ): Promise<string[]> {
        if (!await this.checkScalar(private_spend_key)) {
            throw new Error('privateSpendKey is not a scalar');
        }
        if (!Array.isArray(public_keys)) {
            throw new Error('public_keys must be an array');
        }

        public_keys = public_keys.map(elem => elem.toLowerCase());

        for (const key of public_keys) {
            if (!await this.checkKey(key)) {
                throw new Error('Invalid public key found');
            }
        }

        return tryRunFunc('calculateMultisigPrivateKeys',
            private_spend_key.toLowerCase(), public_keys);
    }

    /**
     * Calculates a shared private key from the private keys supplied
     * @param private_keys the array of private keys
     */
    public async calculateSharedPrivateKey (private_keys: string[]): Promise<string> {
        if (!Array.isArray(private_keys)) {
            throw new Error('private_keys must be an array');
        }

        private_keys = private_keys.map(elem => elem.toLowerCase());

        for (const key of private_keys) {
            if (!await this.checkScalar(key)) {
                throw new Error('Invalid private key found');
            }
        }

        return tryRunFunc('calculateSharedPrivateKey', private_keys);
    }

    /**
     * Calculates a shared public key from the public keys supplied
     * @param public_keys the array of public keys
     */
    public async calculateSharedPublicKey (public_keys: string[]): Promise<string> {
        if (!Array.isArray(public_keys)) {
            throw new Error('public_keys must be an array');
        }

        public_keys = public_keys.map(elem => elem.toLowerCase());

        for (const key of public_keys) {
            if (!await this.checkKey(key)) {
                throw new Error('Invalid public key found');
            }
        }

        return tryRunFunc('calculateSharedPublicKey', public_keys);
    }

    /**
     * Checks whether a given key is a public key
     * @param public_key the public key to check
     */
    public async checkKey (public_key: string): Promise<boolean> {
        if (!isHex64(public_key)) {
            return false;
        }

        return tryRunFunc('checkKey', public_key.toLowerCase());
    }

    /**
     * Checks a set of ring signatures to verify that they are valid
     * @param prefix_hash the hash (often the transaction prefix hash)
     * @param key_image real key_image used to generate the signatures
     * @param input_keys the output keys used during signing (mixins + real)
     * @param signatures the signatures
     */
    public async checkRingSignatures (
        prefix_hash: string,
        key_image: string,
        input_keys: string[],
        signatures: string[]
    ): Promise<boolean> {
        if (!isHex64(prefix_hash)) {
            return false;
        }
        if (!isHex64(key_image)) {
            return false;
        }
        if (!Array.isArray(input_keys)) {
            return false;
        }
        if (!Array.isArray(signatures)) {
            return false;
        }

        let err = false;

        input_keys = input_keys.map(elem => elem.toLowerCase());

        signatures = signatures.map(elem => elem.toLowerCase());

        for (const key of input_keys) {
            if (!await this.checkKey(key)) {
                err = true;
            }
        }

        for (const sig of signatures) {
            if (!isHex128(sig)) {
                err = true;
            }
        }

        if (err) {
            return false;
        }

        return tryRunFunc('checkRingSignature',
            prefix_hash.toLowerCase(), key_image.toLowerCase(), input_keys, signatures);
    }

    /**
     * Checks whether the given key is a private key
     * @param private_key
     */
    public async checkScalar (private_key: string): Promise<boolean> {
        if (!isHex64(private_key)) {
            return false;
        }

        private_key = private_key.toLowerCase();

        return (private_key === await this.scReduce32(private_key));
    }

    /**
     * Checks that the given signature is valid for the hash and public key supplied
     * @param message_digest the hash (message digest) used
     * @param public_key the public key of the private key used to sign
     * @param signature the signature
     */
    public async checkSignature (
        message_digest: string,
        public_key: string,
        signature: string
    ): Promise<boolean> {
        if (!isHex64(message_digest)) {
            return false;
        }
        if (!await this.checkKey(public_key)) {
            return false;
        }
        if (!isHex128(signature)) {
            return false;
        }

        return tryRunFunc('checkSignature',
            message_digest.toLowerCase(), public_key.toLowerCase(), signature.toLowerCase());
    }

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
    public async clsagSign (
        prefix_hash: string,
        ring: string[],
        private_ephemeral: string,
        real_output_index: number,
        alpha?: string,
        decoy_responses?: string[]
    ): Promise<IClsagSignature> {
        if (!isHex64(prefix_hash)) {
            throw new Error('Invalid hash found');
        }
        if (!Array.isArray(ring) || ring.length === 0) {
            throw new Error('ring must be a non-empty array');
        }
        if (!isIndex(real_output_index) || real_output_index > ring.length - 1) {
            throw new Error('Invalid real index found');
        }
        if (!await this.checkScalar(private_ephemeral)) {
            throw new Error('Invalid private key found');
        }

        ring = ring.map(elem => elem.toLowerCase());

        for (const key of ring) {
            if (!await this.checkKey(key)) {
                throw new Error('Invalid public key found');
            }
        }

        let randomness: string[] = [];

        if (alpha !== undefined || decoy_responses !== undefined) {
            if (alpha === undefined || !await this.checkScalar(alpha)) {
                throw new Error('Invalid alpha found');
            }
            if (!Array.isArray(decoy_responses) || decoy_responses.length !== ring.length - 1) {
                throw new Error('decoy_responses must be an array of ring.length - 1 scalars');
            }

            randomness = decoy_responses.map(elem => elem.toLowerCase());

            for (const response of randomness) {
                if (!await this.checkScalar(response)) {
                    throw new Error('Invalid decoy response found');
                }
            }

            alpha = alpha.toLowerCase();
        }

        const result = await tryRunFunc('clsagSign',
            prefix_hash.toLowerCase(), ring, private_ephemeral.toLowerCase(), real_output_index,
            alpha || '', randomness);

        if (!result || !isHex64(result.c1) || !Array.isArray(result.s) || result.s.length !== ring.length) {
            throw new Error('Could not generate CLSAG signature');
        }

        return {
            c1: result.c1,
            s: result.s
        };
    }

    /**
     * Verifies a single-key CLSAG signature (transaction version 2, fork 14).
     * Malformed input gives false, as an invalid signature does.
     * @param prefix_hash the message digest (the transaction prefix hash)
     * @param ring the output keys of the ring in transaction order
     * @param key_image the key image of the input
     * @param c1 the challenge of the signature
     * @param s the responses of the signature, one per ring member
     */
    public async clsagVerify (
        prefix_hash: string,
        ring: string[],
        key_image: string,
        c1: string,
        s: string[]
    ): Promise<boolean> {
        if (!isHex64(prefix_hash) || !isHex64(key_image) || !isHex64(c1)) {
            return false;
        }
        if (!Array.isArray(ring) || !Array.isArray(s)) {
            return false;
        }
        if (ring.length === 0 || s.length !== ring.length) {
            return false;
        }

        for (const elem of ring.concat(s)) {
            if (typeof elem !== 'string' || !isHex64(elem)) {
                return false;
            }
        }

        return tryRunFunc('clsagVerify',
            prefix_hash.toLowerCase(),
            ring.map(elem => elem.toLowerCase()),
            key_image.toLowerCase(),
            c1.toLowerCase(),
            s.map(elem => elem.toLowerCase()));
    }

    /**
     * Calculates the hash of the data supplied using the cn_fast_hash method
     * @param data
     */
    public async cn_fast_hash (data: string): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Supplied data must be in hexadecimal form');
        }

        data = data.toLowerCase();

        return tryRunFunc('cn_fast_hash', data)
            .catch(() => { return keccak256(hexToBytes(data)); });
    }

    /**
     * Completes a given set of prepared ring signatures using the single
     * private_ephemeral
     * @param private_ephemeral private ephemeral of the output being spent
     * @param real_output_index the position of the signature in the array that belongs
     * to the real output being spent
     * @param k the random scalar provided with the prepared ring signatures
     * @param signatures the prepared ring signatures
     */
    public async completeRingSignatures (
        private_ephemeral: string,
        real_output_index: number,
        k: string,
        signatures: string[]
    ): Promise<string[]> {
        if (!await this.checkScalar(private_ephemeral)) {
            throw new Error('Invalid private key found');
        }
        if (!Array.isArray(signatures)) {
            throw new Error('signatures must be an array');
        }
        if (!isUInt(real_output_index) || real_output_index > signatures.length - 1) {
            throw new Error('Invalid real_output_index format');
        }
        if (!await this.checkScalar(k)) {
            throw new Error('Invalid k found');
        }

        for (const sig of signatures) {
            if (!isHex128(sig)) {
                throw new Error('Invalid signature found');
            }
        }

        return tryRunFunc('completeRingSignatures',
            private_ephemeral.toLowerCase(), real_output_index, k.toLowerCase(), signatures);
    }

    /**
     * Converts a key derivation to its resulting scalar
     * @param derivation the key derivation
     * @param output_index the index of the output in the transaction
     */
    public async derivationToScalar (
        derivation: string,
        output_index: number
    ): Promise<string> {
        if (!isHex64(derivation)) {
            throw new Error('Invalid derivation found');
        }

        if (!isUInt(output_index)) {
            throw new Error('Invalid output index found');
        }

        return tryRunFunc('derivationToScalar', derivation.toLowerCase(), output_index);
    }

    /**
     * Derives the public ephemeral from the key derivation, output index, and
     * our public spend key
     * @param derivation the key derivation
     * @param output_index the index of the output in the transaction
     * @param public_key our public spend key
     */
    public async derivePublicKey (
        derivation: string,
        output_index: number,
        public_key: string
    ): Promise<string> {
        if (!isHex64(derivation)) {
            throw new Error('Invalid derivation found');
        }
        if (!isUInt(output_index)) {
            throw new Error('Invalid output index found');
        }
        if (!await this.checkKey(public_key)) {
            throw new Error('Invalid public key found');
        }

        return tryRunFunc('derivePublicKey',
            derivation.toLowerCase(), output_index, public_key.toLowerCase());
    }

    /**
     * Derives the private ephemeral from the key derivation, output index, and
     * our private spend key
     * @param derivation the key derivation
     * @param output_index the index of the output in the transaction
     * @param private_key our private spend key
     */
    public async deriveSecretKey (
        derivation: string,
        output_index: number,
        private_key: string
    ): Promise<string> {
        if (!isHex64(derivation)) {
            throw new Error('Invalid derivation found');
        }
        if (!isUInt(output_index)) {
            throw new Error('Invalid output index found');
        }
        if (!await this.checkScalar(private_key)) {
            throw new Error('Invalid private key found');
        }

        return tryRunFunc('deriveSecretKey',
            derivation.toLowerCase(), output_index, private_key.toLowerCase());
    }

    /**
     * Calculates the view tag of an output (transaction version 2, fork 14):
     * the first byte of cn_fast_hash("view_tag" || derivation || varint(output_index))
     * as two lowercase hex characters, the form the daemon's JSON uses
     * @param derivation the key derivation
     * @param output_index the index of the output in the transaction
     */
    public async deriveViewTag (
        derivation: string,
        output_index: number
    ): Promise<string> {
        if (!isHex64(derivation)) {
            throw new Error('Invalid derivation found');
        }
        if (!isIndex(output_index)) {
            throw new Error('Invalid output index found');
        }

        derivation = derivation.toLowerCase();

        /* The underlying modules take a 32-bit index; beyond that, and when a module
           predates the function, compute it here (one Keccak, as cn_fast_hash does) */
        if (output_index > 0x7fffffff) {
            return deriveViewTagJS(derivation, output_index);
        }

        return tryRunFunc('deriveViewTag', derivation, output_index)
            .then((tag: any) => {
                if (typeof tag === 'number' && isIndex(tag) && tag < 256) {
                    return tag.toString(16).padStart(2, '0');
                }
                if (typeof tag === 'string' && /^[0-9a-fA-F]{2}$/.test(tag)) {
                    return tag.toLowerCase();
                }

                return deriveViewTagJS(derivation, output_index);
            })
            .catch(() => { return deriveViewTagJS(derivation, output_index); });
    }

    /**
     * Generates a set of deterministic spend keys for a sub wallet given
     * our root private spend key and the index of the subwallet
     * @param private_key our root private spend key (seed)
     * @param walletIndex the index of the subwallet
     */
    public async generateDeterministicSubwalletKeys (
        private_key: string,
        walletIndex: number
    ): Promise<IKeyPair> {
        if (!await this.checkScalar(private_key)) {
            throw new Error('Invalid private key found');
        }
        if (!isUInt(walletIndex)) {
            throw new Error('Invalid wallet index found');
        }

        const keys = await tryRunFunc('generateDeterministicSubwalletKeys',
            private_key.toLowerCase(), walletIndex);

        if (keys) {
            return keyPair(keys);
        } else {
            throw new Error('Could not generate deterministic subwallet keys');
        }
    }

    /**
     * Generates a key derivation (aB) given the public key and private key
     * @param public_key
     * @param private_key
     */
    public async generateKeyDerivation (public_key: string, private_key: string): Promise<string> {
        if (!await this.checkKey(public_key)) {
            if (!isHex64(public_key)) {
                throw new Error('Invalid public key found');
            }
            /** If someone sends an invalid public key, ignore it and just hash it
            * and make sure it's an ec point
            **/
            public_key = await this.hashToEllipticCurve(await this.cn_fast_hash(public_key));
        }
        if (!await this.checkScalar(private_key)) {
            throw new Error('Invalid private key found');
        }

        return tryRunFunc('generateKeyDerivation',
            public_key.toLowerCase(), private_key.toLowerCase());
    }

    /**
     * Generates a key derivation scalar H_s(aB) given the public key and private key
     * @param public_key the public key
     * @param private_key the private key
     * @param output_index the output index
     */
    public async generateKeyDerivationScalar (
        public_key: string,
        private_key: string,
        output_index: number
    ): Promise<string> {
        if (!await this.checkKey(public_key)) {
            throw new Error('Invalid public key found');
        }

        if (!await this.checkScalar(private_key)) {
            throw new Error('Invalid private key found');
        }

        if (!isUInt(output_index)) {
            throw new Error('Invalid output index found');
        }

        return tryRunFunc('generateKeyDerivationScalar',
            public_key.toLowerCase(), private_key.toLowerCase(), output_index);
    }

    /**
     * Generates a key image given the public ephemeral and the private ephemeral
     * @param publicEphemeral the public ephemeral of the output
     * @param private_ephemeral the private ephemeral of the output
     */
    public async generateKeyImage (publicEphemeral: string, private_ephemeral: string): Promise<string> {
        if (!await this.checkKey(publicEphemeral)) {
            throw new Error('Invalid public ephemeral found');
        }
        if (!await this.checkScalar(private_ephemeral)) {
            throw new Error('Invalid private ephemeral found');
        }

        return tryRunFunc('generateKeyImage',
            publicEphemeral.toLowerCase(), private_ephemeral.toLowerCase());
    }

    /**
     * Generates a new random key pair
     */
    public async generateKeys (): Promise<IKeyPair> {
        const keys = await tryRunFunc('generateKeys');

        if (keys) {
            return keyPair(keys);
        } else {
            throw new Error('Could not generate keys');
        }
    }

    /**
     * Generates a partial signing key for a multisig ring signature set
     * @param signature the prepared real input signature
     * @param private_key our private spend key (or multisig private key)
     */
    public async generatePartialSigningKey (signature: string, private_key: string): Promise<string> {
        if (!isHex128(signature)) {
            throw new Error('Invalid signature found');
        }
        if (!await this.checkScalar(private_key)) {
            throw new Error('Invalid private key found');
        }

        return tryRunFunc('generatePartialSigningKey',
            signature.toLowerCase(), private_key.toLowerCase());
    }

    /**
     * Generates a private view key from the private spend key
     * @param private_key the private spend key
     */
    public async generatePrivateViewKeyFromPrivateSpendKey (private_key: string): Promise<string> {
        if (!await this.checkScalar(private_key)) {
            throw new Error('Invalid private key found');
        }

        return tryRunFunc('generatePrivateViewKeyFromPrivateSpendKey', private_key.toLowerCase());
    }

    /**
     * Generates ring signatures for the supplied values
     * @param hash the message digest hash (often the transaction prefix hash)
     * @param key_image the key image of the output being spent
     * @param public_keys an array of the output keys used for signing (mixins + our output)
     * @param private_ephemeral the private ephemeral of the output being spent
     * @param real_output_index the array index of the real output being spent in the public_keys array
     */
    public async generateRingSignatures (
        hash: string,
        key_image: string,
        public_keys: string[],
        private_ephemeral: string,
        real_output_index: number
    ): Promise<string[]> {
        if (!isHex64(hash)) {
            throw new Error('Invalid hash found');
        }
        if (!isHex64(key_image)) {
            throw new Error('Invalid key image found');
        }
        if (!await this.checkScalar(private_ephemeral)) {
            throw new Error('Invalid private key found');
        }
        if (!Array.isArray(public_keys)) {
            throw new Error('public keys must be an array');
        }
        if (!isUInt(real_output_index) || real_output_index > public_keys.length - 1) {
            throw new Error('Invalid real index found');
        }

        public_keys = public_keys.map(elem => elem.toLowerCase());

        for (const key of public_keys) {
            if (!await this.checkKey(key)) {
                throw new Error('Invalid public key found');
            }
        }

        return tryRunFunc('generateRingSignatures',
            hash.toLowerCase(), key_image.toLowerCase(), public_keys,
            private_ephemeral.toLowerCase(), real_output_index);
    }

    /**
     * Generates a signature for the given message digest (hash)
     * @param hash the hash
     * @param public_key the public key used in signing
     * @param private_key the private key used to sign
     */
    public async generateSignature (
        hash: string,
        public_key: string,
        private_key: string
    ): Promise<string> {
        if (!isHex64(hash)) {
            throw new Error('Invalid hash found');
        }
        if (!await this.checkKey(public_key)) {
            throw new Error('Invalid public key found');
        }
        if (!await this.checkScalar(private_key)) {
            throw new Error('Invalid private key found');
        }

        return tryRunFunc('generateSignature',
            hash.toLowerCase(), public_key.toLowerCase(), private_key.toLowerCase());
    }

    /**
     * Generates a vew key pair from the private spend key
     * @param private_key the private spend key
     */
    public async generateViewKeysFromPrivateSpendKey (private_key: string): Promise<IKeyPair> {
        if (!await this.checkScalar(private_key)) {
            throw new Error('Invalid private key found');
        }

        const keys = await tryRunFunc('generateViewKeysFromPrivateSpendKey',
            private_key.toLowerCase());

        if (keys) {
            return keyPair(keys);
        } else {
            throw new Error('Could not generate view keys from private spend key');
        }
    }

    /**
     * Converts a hash to an elliptic curve point
     * @param hash the hash
     */
    public async hashToEllipticCurve (hash: string): Promise<string> {
        if (!isHex64(hash)) {
            throw new Error('Invalid hash found');
        }

        return tryRunFunc('hashToEllipticCurve', hash.toLowerCase());
    }

    /**
     * Converts a hash to a scalar
     * @param hash the hash
     */
    public async hashToScalar (hash: string): Promise<string> {
        if (!isHex64(hash)) {
            throw new Error('Invalid hash found');
        }

        return tryRunFunc('hashToScalar', hash.toLowerCase());
    }

    /**
     * Prepares ring signatures for completion or restoration later
     * @param hash the message digest hash (often the transaction prefix hash)
     * @param key_image the key image of the output being spent
     * @param public_keys an array of the output keys used for signing (mixins + our output)
     * @param real_output_index the array index of the real output being spent in the public_keys array
     * @param k a random scalar (private key)
     */
    public async prepareRingSignatures (
        hash: string,
        key_image: string,
        public_keys: string[],
        real_output_index: number,
        k?: string
    ): Promise<IPreparedRingSignatures> {
        if (!isHex64(hash)) {
            throw new Error('Invalid hash found');
        }
        if (!isHex64(key_image)) {
            throw new Error('Invalid key image found');
        }
        if (!Array.isArray(public_keys)) {
            throw new Error('public_keys must be an array');
        }
        if (!isUInt(real_output_index) || real_output_index > public_keys.length - 1) {
            throw new Error('Invalid real index found');
        }

        if (k) {
            k = k.toLowerCase();
        }

        hash = hash.toLowerCase();

        key_image = key_image.toLowerCase();

        public_keys = public_keys.map(elem => elem.toLowerCase());

        for (const key of public_keys) {
            if (!await this.checkKey(key)) {
                throw new Error('Invalid public key found');
            }
        }

        const result = k
            ? await tryRunFunc('prepareRingSignatures', hash, key_image, public_keys, real_output_index, k)
            : await tryRunFunc('prepareRingSignatures', hash, key_image, public_keys, real_output_index);

        if (result) {
            return {
                signatures: result.signatures,
                k: result.k || result.key
            };
        } else {
            throw new Error('Could not prepare ring signatures');
        }
    }

    /**
     * Re-initializes the underlying cryptographic primitives
     */
    public async reloadCrypto (): Promise<boolean> {
        return initialize();
    }

    /**
     * Restores a key image from a set of partial key images generated by the other
     * participants in a multisig wallet
     * @param publicEphemeral the transaction public ephemeral
     * @param derivation the key derivation of the our output
     * @param output_index the index of our output in the transaction
     * @param partialKeyImages the array of partial key images from the needed
     * number of participants in the multisig scheme
     */
    public async restoreKeyImage (
        publicEphemeral: string,
        derivation: string,
        output_index: number,
        partialKeyImages: string[]
    ): Promise<string> {
        if (!await this.checkKey(publicEphemeral)) {
            throw new Error('Invalid public ephemeral found');
        }
        if (!isHex64(derivation)) {
            throw new Error('Invalid derivation found');
        }
        if (!isUInt(output_index)) {
            throw new Error('Invalid output index found');
        }
        if (!Array.isArray(partialKeyImages)) {
            throw new Error('partial key images must be an array');
        }

        partialKeyImages = partialKeyImages.map(elem => elem.toLowerCase());

        for (const key of partialKeyImages) {
            if (!isHex64(key)) {
                throw new Error('Invalid key image found');
            }
        }

        return tryRunFunc('restoreKeyImage',
            publicEphemeral.toLowerCase(), derivation.toLowerCase(), output_index, partialKeyImages);
    }

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
    public async restoreRingSignatures (
        derivation: string,
        output_index: number,
        partialSigningKeys: string[],
        real_output_index: number,
        k: string,
        signatures: string[]
    ): Promise<string[]> {
        if (!isHex64(derivation)) {
            throw new Error('Invalid derivation found');
        }
        if (!isUInt(output_index)) {
            throw new Error('Invalid output index found');
        }
        if (!Array.isArray(partialSigningKeys)) {
            throw new Error('partial signing keys must be an array');
        }
        if (!await this.checkScalar(k)) {
            throw new Error('Invalid k found');
        }
        if (!Array.isArray(signatures)) {
            throw new Error('signatures must be an array');
        }
        if (!isUInt(real_output_index) || real_output_index > signatures.length - 1) {
            throw new Error('Invalid real index found');
        }

        partialSigningKeys = partialSigningKeys.map(elem => elem.toLowerCase());

        signatures = signatures.map(elem => elem.toLowerCase());

        for (const key of partialSigningKeys) {
            if (!await this.checkScalar(key)) {
                throw new Error('Invalid partial signing key found');
            }
        }

        for (const sig of signatures) {
            if (!isHex128(sig)) {
                throw new Error('Invalid signature found');
            }
        }

        return tryRunFunc(
            'restoreRingSignatures',
            derivation.toLowerCase(),
            output_index,
            partialSigningKeys,
            real_output_index,
            k.toLowerCase(),
            signatures);
    }

    /**
     * Derives the public key using the derivation scalar
     * @param derivationScalar the derivation scalar
     * @param public_key the public key
     */
    public async scalarDerivePublicKey (derivationScalar: string, public_key: string): Promise<string> {
        if (!await this.checkScalar(derivationScalar)) {
            throw new Error('Invalid derivation scalar found');
        }

        if (!await this.checkKey(public_key)) {
            throw new Error('Invalid public key found');
        }

        return tryRunFunc('scalarDerivePublicKey',
            derivationScalar.toLowerCase(), public_key.toLowerCase());
    }

    /**
     * Derives the private key using the derivation scalar
     * @param derivationScalar the derivation scalar
     * @param private_key the private key
     */
    public async scalarDeriveSecretKey (derivationScalar: string, private_key: string): Promise<string> {
        if (!await this.checkScalar(derivationScalar)) {
            throw new Error('Invalid derivation scalar found');
        }

        if (!await this.checkScalar(private_key)) {
            throw new Error('Invalid private key found');
        }

        return tryRunFunc('scalarDeriveSecretKey',
            derivationScalar.toLowerCase(), private_key.toLowerCase());
    }

    /**
     * Multiplies two key images together
     * @param key_imageA
     * @param key_imageB
     */
    public async scalarmultKey (key_imageA: string, key_imageB: string): Promise<string> {
        if (!isHex64(key_imageA)) {
            throw new Error('Invalid key image A found');
        }
        if (!isHex64(key_imageB)) {
            throw new Error('Invalid key image B found');
        }

        return tryRunFunc('scalarmultKey',
            key_imageA.toLowerCase(), key_imageB.toLowerCase());
    }

    /**
     * Reduces a value to a scalar (mod q)
     * @param data
     */
    public async scReduce32 (data: string): Promise<string> {
        if (!isHex64(data)) {
            throw new Error('Invalid data format');
        }

        return tryRunFunc('scReduce32', data.toLowerCase());
    }

    /**
     * Calculates the public key of a private key
     * @param private_key
     */
    public async secretKeyToPublicKey (private_key: string): Promise<string> {
        if (!await this.checkScalar(private_key)) {
            throw new Error('Invalid private key found');
        }

        return tryRunFunc('secretKeyToPublicKey', private_key.toLowerCase());
    }

    /**
     * Calculates the merkle tree branch of the given hashes
     * @param hashes the array of hashes
     */
    public async tree_branch (hashes: string[]): Promise<string[]> {
        if (!Array.isArray(hashes)) {
            throw new Error('hashes must be an array');
        }

        hashes = hashes.map(elem => elem.toLowerCase());

        for (const hash of hashes) {
            if (!isHex64(hash)) {
                throw new Error('Invalid hash found');
            }
        }

        return tryRunFunc('tree_branch', hashes);
    }

    /**
     * Calculates the depth of the merkle tree
     * @param count the number of hashes in the tree
     */
    public async tree_depth (count: number): Promise<number> {
        if (!isUInt(count)) {
            throw new Error('Invalid count found');
        }

        return tryRunFunc('tree_depth', count);
    }

    /**
     * Calculates the merkle tree hash of the given hashes
     * @param hashes the array of hashes
     */
    public async tree_hash (hashes: string[]): Promise<string> {
        if (!Array.isArray(hashes)) {
            throw new Error('hashes must be an array');
        }

        hashes = hashes.map(elem => elem.toLowerCase());

        for (const hash of hashes) {
            if (!isHex64(hash)) {
                throw new Error('Invalid hash found');
            }
        }

        return tryRunFunc('tree_hash', hashes);
    }

    /**
     * Calculates the merkle tree hash from the given branch information
     * @param branches the merkle tree branches
     * @param leaf the leaf on the merkle tree
     * @param path the path on the merkle tree
     */
    public async tree_hash_from_branch (
        branches: string[],
        leaf: string,
        path: number
    ): Promise<string> {
        if (!Array.isArray(branches)) {
            throw new Error('branches must be an array');
        }
        if (!isHex64(leaf)) {
            throw new Error('Invalid leaf found');
        }
        if (!isUInt(path)) {
            throw new Error('Invalid path found');
        }

        branches = branches.map(elem => elem.toLowerCase());

        for (const branch of branches) {
            if (!isHex64(branch)) {
                throw new Error('Invalid branch found');
            }
        }

        if (moduleVars.type === CryptoType.NAPI) {
            return tryRunFunc('tree_hash_from_branch',
                branches, leaf.toLowerCase(), path);
        } else {
            return tryRunFunc('tree_hash_from_branch',
                branches, leaf.toLowerCase(), path.toString());
        }
    }

    /**
     * Underives a public key instead of deriving it
     * @param derivation the key derivation
     * @param output_index the index of the output in the transaction
     * @param outputKey the output key in the transaction
     */
    public async underivePublicKey (
        derivation: string,
        output_index: number,
        outputKey: string
    ): Promise<string> {
        if (!isHex64(derivation)) {
            throw new Error('Invalid derivation found');
        }
        if (!isUInt(output_index)) {
            throw new Error('Invalid output index found');
        }
        if (!await this.checkKey(outputKey)) {
            throw new Error('Invalid output key found');
        }

        return tryRunFunc('underivePublicKey',
            derivation.toLowerCase(), output_index, outputKey.toLowerCase());
    }

    /**
     * Calculates the hash of the data supplied using the cn_slow_hash_v0 method
     * @param data
     */
    public async cn_slow_hash_v0 (data: string): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }

        return tryRunFunc('cn_slow_hash_v0', data.toLowerCase());
    }

    /**
     * Calculates the hash of the data supplied using the cn_slow_hash_v1 method
     * @param data
     */
    public async cn_slow_hash_v1 (data: string): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }

        return tryRunFunc('cn_slow_hash_v1', data.toLowerCase());
    }

    /**
     * Calculates the hash of the data supplied using the cn_slow_hash_v2 method
     * @param data
     */
    public async cn_slow_hash_v2 (data: string): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }

        return tryRunFunc('cn_slow_hash_v2', data.toLowerCase());
    }

    /**
     * Calculates the hash of the data supplied using the cn_lite_slow_hash_v0 method
     * @param data
     */
    public async cn_lite_slow_hash_v0 (data: string): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }

        return tryRunFunc('cn_lite_slow_hash_v0', data.toLowerCase());
    }

    /**
     * Calculates the hash of the data supplied using the cn_lite_slow_hash_v1 method
     * @param data
     */
    public async cn_lite_slow_hash_v1 (data: string): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }

        return tryRunFunc('cn_lite_slow_hash_v1', data.toLowerCase());
    }

    /**
     * Calculates the hash of the data supplied using the cn_lite_slow_hash_v2 method
     * @param data
     */
    public async cn_lite_slow_hash_v2 (data: string): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }

        return tryRunFunc('cn_lite_slow_hash_v2', data.toLowerCase());
    }

    /**
     * Calculates the hash of the data supplied using the cn_dark_slow_hash_v0 method
     * @param data
     */
    public async cn_dark_slow_hash_v0 (data: string): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }

        return tryRunFunc('cn_dark_slow_hash_v0', data.toLowerCase());
    }

    /**
     * Calculates the hash of the data supplied using the cn_dark_slow_hash_v1 method
     * @param data
     */
    public async cn_dark_slow_hash_v1 (data: string): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }

        return tryRunFunc('cn_dark_slow_hash_v1', data.toLowerCase());
    }

    /**
     * Calculates the hash of the data supplied using the cn_dark_slow_hash_v2 method
     * @param data
     */
    public async cn_dark_slow_hash_v2 (data: string): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }

        return tryRunFunc('cn_dark_slow_hash_v2', data.toLowerCase());
    }

    /**
     * Calculates the hash of the data supplied using the cn_dark_lite_slow_hash_v0 method
     * @param data
     */
    public async cn_dark_lite_slow_hash_v0 (data: string): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }

        return tryRunFunc('cn_dark_lite_slow_hash_v0', data.toLowerCase());
    }

    /**
     * Calculates the hash of the data supplied using the cn_dark_lite_slow_hash_v1 method
     * @param data
     */
    public async cn_dark_lite_slow_hash_v1 (data: string): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }

        return tryRunFunc('cn_dark_lite_slow_hash_v1', data.toLowerCase());
    }

    /**
     * Calculates the hash of the data supplied using the cn_dark_lite_slow_hash_v2 method
     * @param data
     */
    public async cn_dark_lite_slow_hash_v2 (data: string): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }

        return tryRunFunc('cn_dark_lite_slow_hash_v2', data.toLowerCase());
    }

    /**
     * Calculates the hash of the data supplied using the cn_turtle_slow_hash_v0 method
     * @param data
     */
    public async cn_turtle_slow_hash_v0 (data: string): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }

        return tryRunFunc('cn_turtle_slow_hash_v0', data.toLowerCase());
    }

    /**
     * Calculates the hash of the data supplied using the cn_turtle_slow_hash_v1 method
     * @param data
     */
    public async cn_turtle_slow_hash_v1 (data: string): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }

        return tryRunFunc('cn_turtle_slow_hash_v1', data.toLowerCase());
    }

    /**
     * Calculates the hash of the data supplied using the cn_turtle_slow_hash_v2 method
     * @param data
     */
    public async cn_turtle_slow_hash_v2 (data: string): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }

        return tryRunFunc('cn_turtle_slow_hash_v2', data.toLowerCase());
    }

    /**
     * Calculates the hash of the data supplied using the cn_turtle_lite_slow_hash_v0 method
     * @param data
     */
    public async cn_turtle_lite_slow_hash_v0 (data: string): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }

        return tryRunFunc('cn_turtle_lite_slow_hash_v0', data.toLowerCase());
    }

    /**
     * Calculates the hash of the data supplied using the cn_turtle_lite_slow_hash_v1 method
     * @param data
     */
    public async cn_turtle_lite_slow_hash_v1 (data: string): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }

        return tryRunFunc('cn_turtle_lite_slow_hash_v1', data.toLowerCase());
    }

    /**
     * Calculates the hash of the data supplied using the cn_turtle_lite_slow_hash_v2 method
     * @param data
     */
    public async cn_turtle_lite_slow_hash_v2 (data: string): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }

        return tryRunFunc('cn_turtle_lite_slow_hash_v2', data.toLowerCase());
    }

    /**
     * Calculates the hash of the data supplied using the cn_soft_shell_slow_hash_v0 method
     * @param data
     * @param height the height of the blockchain
     */
    public async cn_soft_shell_slow_hash_v0 (data: string, height: number): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        if (!isUInt(height)) {
            throw new Error('Invalid height found');
        }

        return tryRunFunc('cn_soft_shell_slow_hash_v0', data.toLowerCase(), height);
    }

    /**
     * Calculates the hash of the data supplied using the cn_soft_shell_slow_hash_v1 method
     * @param data
     * @param height the height of the blockchain
     */
    public async cn_soft_shell_slow_hash_v1 (data: string, height: number): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        if (!isUInt(height)) {
            throw new Error('Invalid height found');
        }

        return tryRunFunc('cn_soft_shell_slow_hash_v1', data.toLowerCase(), height);
    }

    /**
     * Calculates the hash of the data supplied using the cn_soft_shell_slow_hash_v2 method
     * @param data
     * @param height the height of the blockchain
     */
    public async cn_soft_shell_slow_hash_v2 (data: string, height: number): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        if (!isUInt(height)) {
            throw new Error('Invalid height found');
        }

        return tryRunFunc('cn_soft_shell_slow_hash_v2', data.toLowerCase(), height);
    }

    /**
     * Calculates the hash of the data supplied using the chukwa_slow_hash method
     * @param data
     * @param version
     */
    public async chukwa_slow_hash (data: string, version = 1): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }

        let func = 'chukwa_slow_hash_';

        switch (version) {
            case 1:
                func += 'v1';
                break;
            case 2:
                func += 'v2';
                break;
            default:
                throw new Error('Unknown Chukwa version number');
        }

        return tryRunFunc(func, data.toLowerCase());
    }

    /**
     * Calculates the hash of the data supplied using the chukwa_slow_hash_base method
     * @param data
     * @param iterations
     * @param memory
     * @param threads
     */
    public async chukwa_slow_hash_base (
        data: string,
        iterations: number,
        memory: number,
        threads: number
    ): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }

        return tryRunFunc('chukwa_slow_hash_base',
            data.toLowerCase(), iterations, memory, threads);
    }

    /**
     * Calculates the hash of the data supplied using the chukwa_slow_hash_v1 method
     * @param data
     */
    public async chukwa_slow_hash_v1 (data: string): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }

        return tryRunFunc('chukwa_slow_hash_v1', data.toLowerCase());
    }

    /**
     * Calculates the hash of the data supplied using the chukwa_slow_hash_v2 method
     * @param data
     */
    public async chukwa_slow_hash_v2 (data: string): Promise<string> {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }

        return tryRunFunc('chukwa_slow_hash_v2', data.toLowerCase());
    }
}

/**
 * @ignore
 */
function initialize (): boolean {
    if (moduleVars.crypto === null) {
        return cryptoLoader.initialize();
    } else {
        return true;
    }
}

/**
 * @ignore
 */
async function tryRunFunc (...args: any[]): Promise<any> {
    const func: string = args.shift();

    return new Promise((resolve, reject) => {
        if ((userCryptoFunctions as any)[func]) {
            try {
                return resolve((userCryptoFunctions as any)[func](...args));
            } catch (e) {
                return reject(new Error('Error with use defined cryptographic primitive'));
            }
        } else if ((moduleVars.type === CryptoType.NAPI || moduleVars.type === CryptoType.REACTNATIVE) &&
            typeof moduleVars.crypto[func] === 'function') {
            /* The native modules return the value (or a promise of it) and throw an Error
               naming the argument on invalid input */
            try {
                return resolve(moduleVars.crypto[func](...args));
            } catch (e) {
                return reject(e instanceof Error ? e : new Error(String(e)));
            }
        } else if (moduleVars.type === CryptoType.EXTERNAL) {
            return reject(new Error('Could not locate method in underlying Cryptographic library: ' +
                func + ' is not registered in Crypto.userCryptoFunctions (external cryptography)'));
        } else {
            return reject(new Error('Could not locate method in underlying Cryptographic library'));
        }
    });
}

/**
 * @ignore
 * The key pair of a module result: { private_key, public_key }, { privateKey, publicKey }
 * or the { secretKey, publicKey } shape of the React Native host modules
 */
function keyPair (keys: any): IKeyPair {
    return {
        private_key: keys.private_key || keys.privateKey || keys.secretKey || keys.SecretKey,
        public_key: keys.public_key || keys.publicKey || keys.PublicKey
    };
}

/**
 * @ignore
 */
function isHex (value: string): boolean {
    if (value.length % 2 !== 0) {
        return false;
    }

    const regex = new RegExp('^[0-9a-fA-F]{' + value.length + '}$');

    return regex.test(value);
}

/**
 * @ignore
 */
function isHex64 (value: string): boolean {
    return (isHex(value) && value.length === 64);
}

/**
 * @ignore
 */
function isHex128 (value: string): boolean {
    return (isHex(value) && value.length === 128);
}

/**
 * @ignore
 * A non-negative integer that is exactly representable (array index, output index)
 */
function isIndex (value: number): boolean {
    return (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0);
}

/**
 * @ignore
 * Hex string to bytes without Buffer (not a global in every JS runtime)
 */
function hexToBytes (hex: string): number[] {
    const bytes: number[] = [];

    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }

    return bytes;
}

/**
 * @ignore
 * View tag in plain JS: keccak256("view_tag" || derivation || varint(output_index))[0]
 */
function deriveViewTagJS (derivation: string, output_index: number): string {
    const data: number[] = [0x76, 0x69, 0x65, 0x77, 0x5f, 0x74, 0x61, 0x67].concat(hexToBytes(derivation));

    /* LEB128 varint; arithmetic instead of bit operations so indexes above 2^31 work */
    let value = output_index;

    while (value >= 0x80) {
        data.push((value % 0x80) + 0x80);
        value = Math.floor(value / 0x80);
    }

    data.push(value);

    return keccak256(data).substr(0, 2);
}

/**
 * @ignore
 */
function isUInt (value: number) {
    return (value === toInt(value) && toInt(value) >= 0);
}

/**
 * @ignore
 */
function toInt (value: number | string): number | boolean {
    if (typeof value === 'number') {
        return value;
    } else {
        const tmp = parseInt(value, 10);
        if (tmp.toString().length === value.toString().length) {
            return tmp;
        }
    }

    return false;
}
