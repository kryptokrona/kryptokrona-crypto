// Copyright (c) 2026, The Kryptokrona Developers
//
// Please see the included LICENSE file for more information.

/*
 * The React Native entry point with the KryptokronaCrypto Turbo Native Module present
 * (CryptoType.REACTNATIVE). React Native is not available under Node.js, so a stand-in
 * `react-native` module is installed whose TurboModuleRegistry returns a module with the
 * methods and shapes of spec/NativeKryptokronaCrypto.ts, computed by the Node-API addon
 * (the same Rust core the C++ module calls). This checks the adapter (typescript/native.ts),
 * the automatic registration and the Crypto class on top; the C++ module itself is checked on
 * devices.
 *
 * Run on the built dist/ and the built addon (`npm run build && npm run build-napi`), in a
 * process of its own (`npm run test-react-native-module`).
 */

import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { before, describe, it } from 'mocha';

const Module: any = require('module');

const root = path.resolve(__dirname, '..');

const dist = path.join(root, 'dist');

const clsagVectors = JSON.parse(fs.readFileSync(path.join(__dirname, 'vectors', 'tx-v2-clsag.json'), 'utf8'));

const viewTagVectors = JSON.parse(
    fs.readFileSync(path.join(__dirname, 'vectors', 'tx-v2-view-tags.json'), 'utf8'));

function addonPath (): string {
    if (process.env.KRYPTOKRONA_CRYPTO_NAPI) {
        return path.resolve(process.env.KRYPTOKRONA_CRYPTO_NAPI);
    }

    const { platform, arch } = process;

    const name = platform === 'linux'
        ? 'linux-' + arch + '-gnu'
        : platform === 'win32' ? 'win32-' + arch + '-msvc' : platform + '-' + arch;

    return path.join(root, 'prebuilt', 'napi', 'kryptokrona-crypto.' + name + '.node');
}

const addon = require(addonPath());

const calls: string[] = [];

/* The KryptokronaCrypto module as the spec declares it */
const turboModule: any = {
    checkKey: (publicKey: string) => addon.checkKey(publicKey),
    checkSignature: (h: string, p: string, s: string) => addon.checkSignature(h, p, s),
    checkRingSignature: (h: string, i: string, keys: string[], sigs: string[]) =>
        addon.checkRingSignature(h, i, keys, sigs),
    cn_fast_hash: (data: string) => {
        calls.push('cn_fast_hash');

        return addon.cn_fast_hash(data);
    },
    secretKeyToPublicKey: (k: string) => addon.secretKeyToPublicKey(k),
    scReduce32: (s: string) => addon.scReduce32(s),
    hashToEllipticCurve: (h: string) => addon.hashToEllipticCurve(h),
    hashToScalar: (d: string) => addon.hashToScalar(d),
    generateKeys: () => {
        const keys = addon.generateKeys();

        return [keys.private_key, keys.public_key];
    },
    generateKeyDerivation: (p: string, s: string) => addon.generateKeyDerivation(p, s),
    derivePublicKey: (d: string, i: number, p: string) => addon.derivePublicKey(d, i, p),
    deriveSecretKey: (d: string, i: number, s: string) => addon.deriveSecretKey(d, i, s),
    underivePublicKey: (d: string, i: number, p: string) => addon.underivePublicKey(d, i, p),
    generateKeyImage: (p: string, s: string) => addon.generateKeyImage(p, s),
    generateSignature: (h: string, p: string, s: string) => addon.generateSignature(h, p, s),
    deriveViewTag: (d: string, i: number) => addon.deriveViewTag(d, i),
    clsagVerify: (h: string, ring: string[], image: string, c1: string, s: string[]) =>
        addon.clsagVerify(h, ring, image, c1, s),
    cn_turtle_lite_slow_hash_v2: (data: string) => addon.cn_turtle_lite_slow_hash_v2(data),
    generateDeterministicSubwalletKeys: async (base: string, index: number) => {
        const keys = addon.generateDeterministicSubwalletKeys(base, index);

        return [keys.private_key, keys.public_key];
    },
    generateRingSignatures: async (h: string, i: string, keys: string[], s: string, real: number) =>
        addon.generateRingSignatures(h, i, keys, s, real),
    clsagSign: async (h: string, ring: string[], s: string, real: number, alpha: string, decoys: string[]) => {
        const sig = addon.clsagSign(h, ring, s, real, alpha, decoys);

        return [sig.c1].concat(sig.s);
    },
    processBlockOutputs: (block: string, view: string, spend: string, isView: boolean, coinbase: boolean) =>
        addon.processBlockOutputs(block, view, spend, isView, coinbase),
    findPowShare: (blob: string, target: string, start: number, attempts: number, bits: number, value: number) =>
        addon.findPowShare(blob, target, start, attempts, bits, value)
};

/* A stand-in `react-native` module with just the TurboModuleRegistry */
function installReactNative (): void {
    const fake = path.join(root, 'node_modules', '.react-native-stand-in.js');

    const originalResolveFilename = Module._resolveFilename;

    Module._resolveFilename = function (this: any, request: string, ...rest: any[]) {
        if (request === 'react-native') {
            return fake;
        }

        return originalResolveFilename.call(this, request, ...rest);
    };

    const stub = new Module(fake);

    stub.filename = fake;

    stub.loaded = true;

    stub.exports = {
        TurboModuleRegistry: {
            get: (name: string) => (name === 'KryptokronaCrypto' ? turboModule : null)
        }
    };

    require.cache[fake] = stub;
}

describe('React Native entry point with the KryptokronaCrypto module', () => {
    let rn: any;

    let crypto: any;

    before(() => {
        installReactNative();

        for (const key of Object.keys(require.cache)) {
            if (key.indexOf(dist + path.sep) === 0) {
                delete require.cache[key];
            }
        }

        rn = require(path.join(dist, 'react-native.js'));

        crypto = new rn.Crypto();
    });

    it('Registers the module without any call by the app', () => {
        assert.strictEqual(rn.Crypto.type, rn.CryptoType.REACTNATIVE);

        assert.strictEqual(rn.Crypto.isNative, true);

        assert.strictEqual(rn.Crypto.isReady, true);

        assert(rn.nativeCrypto);
    });

    it('Derivation chain of kryptokrona-crypto tests/crypto.ts', async () => {
        const derivation = await crypto.generateKeyDerivation(
            '3b0cc2b066812e6b9fcc42a797dc3c723a7344b604fd4be0b22e06254ff57f94',
            '6968a0b8f744ec4b8cea5ec124a1b4bd1626a2e6f31e999f8adbab52c4dfa909');

        assert.strictEqual(derivation, '4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20');

        const spendPublic = '854a637b2863af9e8e8216eb2382f3d16616b3ac3e53d0976fbd6f8da6c56418';
        const spendSecret = 'd9d555a892a85f64916cae1a168bd3f7f400b6471c7b12b438b599601298210b';
        const outputKey = 'bb55bef919d1c9f74b5b52a8a6995a1dc4af4c0bb8824f5dc889012bc748173d';

        assert.strictEqual(await crypto.derivePublicKey(derivation, 2, spendPublic), outputKey);

        assert.strictEqual(
            await crypto.deriveSecretKey(derivation, 2, spendSecret),
            'e52ece5717f01843e3accc4df651d669e339c31eb8059145e881faae19ad4a0e');

        assert.strictEqual(await crypto.underivePublicKey(derivation, 2, outputKey), spendPublic);
    });

    it('Key pairs come back as { private_key, public_key }', async () => {
        const keys = await crypto.generateKeys();

        assert.strictEqual(keys.public_key, await crypto.secretKeyToPublicKey(keys.private_key));

        const sub = await crypto.generateDeterministicSubwalletKeys(
            'dd0c02d3202634821b4d9d91b63d919725f5c3e97e803f3512e52fb0dc2aab0c', 1);

        assert.strictEqual(sub.private_key, 'c55cbe4fd1c49dca5958fa1c7b9212c2dbf3fd5bfec84de741d434056e298600');

        assert.strictEqual(sub.public_key, await crypto.secretKeyToPublicKey(sub.private_key));
    });

    it('Ring signatures and the slow hash', async () => {
        const prefixHash = 'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0';
        const keyImage = '6865866ed8a25824e042e21dd36e946836b58b03366e489aecf979f444f599b0';
        const publicKeys = [
            '492390897da1cabd3886e3eff43ad1d04aa510a905bec0acd31a0a2f260e7862',
            '7644ccb5410cca2be18b033e5f7497aeeeafd1d8f317f29cba4803e4306aa402',
            'bb9a956ffdf8159ad69474e6b0811316c44a17a540d5e39a44642d4d933a6460',
            'e1cd9ccdfdf2b3a45ac2cfd1e29185d22c185742849f52368c3cdd1c0ce499c0'
        ];

        const signatures = await crypto.generateRingSignatures(
            prefixHash, keyImage, publicKeys, '73a8e577d58f7c11992201d4014ac7eef39c1e9f6f6d78673103de60a0c3240b', 3);

        assert(await crypto.checkRingSignatures(prefixHash, keyImage, publicKeys, signatures));

        const testdata =
            '0100fb8e8ac805899323371bb790db19218afd8db8e3755d8b90f39b3d5506a9' +
            'abce4fa912244500000000ee8146d49fa93ee724deb57d12cbc6c6f3b924d946' +
            '127c7a97418f9348828f0f02';

        assert.strictEqual(await crypto.cn_turtle_lite_slow_hash_v2(testdata),
            'b2172ec9466e1aee70ec8572a14c233ee354582bcb93f869d429744de5726a26');
    });

    it('CLSAG vectors sign and verify through the module', async () => {
        for (const vector of clsagVectors.vectors.slice(0, 3)) {
            const signature = await crypto.clsagSign(
                vector.message, vector.ring, vector.secret, vector.signer_index, vector.alpha,
                vector.decoy_responses);

            assert.deepStrictEqual(signature, { c1: vector.c1, s: vector.s });

            assert(await crypto.clsagVerify(vector.message, vector.ring, vector.key_image, vector.c1, vector.s));
        }
    });

    it('View tags', async () => {
        for (const vector of viewTagVectors.monero.slice(0, 10)) {
            assert.strictEqual(await crypto.deriveViewTag(vector.derivation, vector.index), vector.view_tag);
        }
    });

    it('A function the module does not have rejects, naming it', async () => {
        await assert.rejects(
            crypto.derivationToScalar('4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20', 2),
            /Could not locate method/);
    });

    it('processBlockOutputs and findPowShare exports', async () => {
        const view = await crypto.generateKeys();

        const spend = await crypto.generateKeys();

        const tx = await crypto.generateKeys();

        const derivation = await crypto.generateKeyDerivation(view.public_key, tx.private_key);

        const key = await crypto.derivePublicKey(derivation, 0, spend.public_key);

        const block = {
            transactions: [
                { keyOutputs: [{ key, amount: 3 }], hash: 'bb'.repeat(32), transactionPublicKey: tx.public_key }
            ]
        };

        const found = await rn.processBlockOutputs(
            block, view.private_key, [{ publicKey: spend.public_key, privateKey: '' }], true, true);

        assert.strictEqual(found.length, 1);

        assert.strictEqual(found[0].input.globalOutputIndex, -1);

        assert.strictEqual(found[0].input.keyImage, '0'.repeat(64));

        assert.strictEqual(await rn.findPowShare('', 'ffffffff', 0, 1), null);
    });

    it('Functions registered by the host take precedence over the module', async () => {
        const counted = calls.length;

        rn.Crypto.userCryptoFunctions = { cn_fast_hash: async () => 'ab'.repeat(32) };

        assert.strictEqual(await crypto.cn_fast_hash('00'), 'ab'.repeat(32));

        assert.strictEqual(calls.length, counted);
    });
});
