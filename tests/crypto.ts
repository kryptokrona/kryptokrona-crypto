// Copyright (c) 2018-2020, The TurtleCoin Developers
// Copyright (c) 2026, The Kryptokrona Developers
//
// Please see the included LICENSE file for more information.

import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { keccak256 } from 'js-sha3';
import { before, describe, it } from 'mocha';
import { Crypto, CryptoType, findPowShare, processBlockOutputs } from '../';

/* Fork 14 vectors exported by the Rust node (see tests/vectors/README.md) */
const loadVectors = (name: string): any =>
    JSON.parse(fs.readFileSync(path.join(__dirname, 'vectors', name), 'utf8'));

const viewTagVectors = loadVectors('tx-v2-view-tags.json');

const clsagVectors = loadVectors('tx-v2-clsag.json');

const TurtleCoinCrypto = new Crypto();

if (TurtleCoinCrypto.type !== CryptoType.NAPI) {
    console.error('The Node-API addon is not loaded: run `npm run build-napi` (or set KRYPTOKRONA_CRYPTO_NAPI)');
    process.exit(1);
}

console.warn('Performing tests with the Node-API addon');

const hashTestData =
    '0100fb8e8ac805899323371bb790db19218afd8db8e3755d8b90f39b3d5506a9' +
    'abce4fa912244500000000ee8146d49fa93ee724deb57d12cbc6c6f3b924d946' +
    '127c7a97418f9348828f0f02';

describe('Node-API addon', () => {
    it('Is the backend, and there is no JS build to switch to', () => {
        assert.strictEqual(TurtleCoinCrypto.type, CryptoType.NAPI);

        assert.strictEqual(TurtleCoinCrypto.isNative, true);

        assert.strictEqual(TurtleCoinCrypto.isReady, true);

        assert.strictEqual(TurtleCoinCrypto.forceJSCrypto(), false);

        assert.strictEqual(TurtleCoinCrypto.type, CryptoType.NAPI);
    });

    it('Key pairs carry the public key that belongs to the private key', async () => {
        const base = 'dd0c02d3202634821b4d9d91b63d919725f5c3e97e803f3512e52fb0dc2aab0c';

        for (const index of [0, 1, 64]) {
            const keys = await TurtleCoinCrypto.generateDeterministicSubwalletKeys(base, index);

            assert.strictEqual(keys.public_key, await TurtleCoinCrypto.secretKeyToPublicKey(keys.private_key));
        }

        const viewKeys = await TurtleCoinCrypto.generateViewKeysFromPrivateSpendKey(base);

        assert.strictEqual(viewKeys.public_key, await TurtleCoinCrypto.secretKeyToPublicKey(viewKeys.private_key));

        assert.strictEqual(
            viewKeys.private_key, await TurtleCoinCrypto.generatePrivateViewKeyFromPrivateSpendKey(base));

        const random = await TurtleCoinCrypto.generateKeys();

        assert.strictEqual(random.public_key, await TurtleCoinCrypto.secretKeyToPublicKey(random.private_key));
    });

    it('Input the addon refuses rejects with a message naming the argument', async () => {
        /* both pass the wrapper's own checks (hex of the right length) */
        const notAPoint = '4a078e76cd41a3d3b534b83dc6f2ea2de500b653ca82273b7bfad8045d85a400';

        await assert.rejects(
            TurtleCoinCrypto.scalarmultKey(notAPoint, '02' + '00'.repeat(31)),
            /key_image_a: not a valid public key/);

        await assert.rejects(TurtleCoinCrypto.cn_slow_hash_v1('00'), /data can not be hashed/);
    });

    it('tree_hash_from_branch of the first hash gives the tree hash', async () => {
        const hashes = [
            'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0',
            '1b606a3f4a07d6489a1bcd07697bd16696b61c8ae982f61a90160f4e52828a7f',
            'c9fae8425d8688dc236bcdbc42fdb42d376c6ec190501aa84b04a4b4cf1ee122',
            '871fcd6823f6a879bb3f33951c8e8e891d4043880b02dfa1bb3be498b50e7578'
        ];

        const branch = await TurtleCoinCrypto.tree_branch(hashes);

        assert.strictEqual(
            await TurtleCoinCrypto.tree_hash_from_branch(branch, hashes[0], 0),
            await TurtleCoinCrypto.tree_hash(hashes));
    });

    it('scalarmultKey: l times a key image is the identity', async () => {
        const l = 'edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010';

        const identity = '0100000000000000000000000000000000000000000000000000000000000000';

        const keyImage = await TurtleCoinCrypto.generateKeyImage(
            'bb55bef919d1c9f74b5b52a8a6995a1dc4af4c0bb8824f5dc889012bc748173d',
            'e52ece5717f01843e3accc4df651d669e339c31eb8059145e881faae19ad4a0e');

        assert.strictEqual(await TurtleCoinCrypto.scalarmultKey(keyImage, l), identity);

        const two = '02' + '00'.repeat(31);

        assert.notStrictEqual(await TurtleCoinCrypto.scalarmultKey(keyImage, two), identity);
    });

    it('processBlockOutputs finds the outputs of a wallet', async () => {
        const view = await TurtleCoinCrypto.generateKeys();

        const spend = await TurtleCoinCrypto.generateKeys();

        const tx = await TurtleCoinCrypto.generateKeys();

        const derivation = await TurtleCoinCrypto.generateKeyDerivation(view.public_key, tx.private_key);

        const key = await TurtleCoinCrypto.derivePublicKey(derivation, 1, spend.public_key);

        const other = await TurtleCoinCrypto.derivePublicKey(derivation, 0, tx.public_key);

        const block = {
            transactions: [{
                keyOutputs: [{ key: other, amount: 1, globalIndex: 10 }, { key, amount: 25, globalIndex: 11 }],
                hash: 'aa'.repeat(32),
                transactionPublicKey: tx.public_key
            }]
        };

        const found = await processBlockOutputs(
            block, view.private_key, [{ publicKey: spend.public_key, privateKey: spend.private_key }], false, true);

        const ephemeral = await TurtleCoinCrypto.deriveSecretKey(derivation, 1, spend.private_key);

        assert.deepStrictEqual(found, [{
            publicSpendKey: spend.public_key,
            input: {
                keyImage: await TurtleCoinCrypto.generateKeyImage(key, ephemeral),
                amount: 25,
                transactionIndex: 1,
                globalOutputIndex: 11,
                key,
                parentTransactionHash: 'aa'.repeat(32)
            }
        }]);
    });

    it('findPowShare finds a share for the easiest target and refuses unusable input', async () => {
        const share = await findPowShare(hashTestData, 'ffffffff', 7, 100);

        if (share === null || share.nonce === undefined || share.result === undefined) {
            throw new Error('no share for the easiest target');
        }

        assert(share.hashes_performed >= 1 && share.threads >= 1);

        /* the nonce sits at offset 39 of this blob */
        const blob = hashTestData.substr(0, 78) + share.nonce + hashTestData.substr(86);

        assert.strictEqual(share.result, await TurtleCoinCrypto.cn_turtle_lite_slow_hash_v2(blob));

        assert.strictEqual(await findPowShare('', 'ffffffff', 0, 1), null);

        assert.strictEqual(await findPowShare(hashTestData, '00000000', 0, 1), null);
    });

    it('cn_soft_shell_slow_hash_v* are not provided', async () => {
        await assert.rejects(TurtleCoinCrypto.cn_soft_shell_slow_hash_v0(hashTestData, 1000));
    });
});

describe('Cryptography', function () {
    describe('Core', () => {
        it('Generate Random Keys', async () => {
            const keys = await TurtleCoinCrypto.generateKeys();

            assert(keys.public_key);
            assert(keys.private_key);
        });

        it('Generate Random Keys - 1000 calls yield 1000 distinct key pairs', async () => {
            const secretKeys = new Set<string>();
            const publicKeys = new Set<string>();

            for (let i = 0; i < 1000; i++) {
                const keys = await TurtleCoinCrypto.generateKeys();

                secretKeys.add(keys.private_key);
                publicKeys.add(keys.public_key);
            }

            assert(secretKeys.size === 1000);
            assert(publicKeys.size === 1000);
        });

        it('Check Key - Public Key', async () => {
            const key = '7849297236cd7c0d6c69a3c8c179c038d3c1c434735741bb3c8995c3c9d6f2ac';
            const isValid = await TurtleCoinCrypto.checkKey(key);

            assert(isValid === true);
        });

        it('Check Key - Private Key', async () => {
            const key = '4a078e76cd41a3d3b534b83dc6f2ea2de500b653ca82273b7bfad8045d85a400';
            const isValid = await TurtleCoinCrypto.checkKey(key);

            assert(isValid === false);
        });

        it('Secret Key to Public Key', async () => {
            const key = '4a078e76cd41a3d3b534b83dc6f2ea2de500b653ca82273b7bfad8045d85a400';

            const generatedKey = await TurtleCoinCrypto.secretKeyToPublicKey(key);

            assert(generatedKey === '7849297236cd7c0d6c69a3c8c179c038d3c1c434735741bb3c8995c3c9d6f2ac');
        });

        describe('Traditional Derivation Math', () => {
            it('Generate Key Derivation', async () => {
                const derivation = await TurtleCoinCrypto.generateKeyDerivation(
                    '3b0cc2b066812e6b9fcc42a797dc3c723a7344b604fd4be0b22e06254ff57f94',
                    '6968a0b8f744ec4b8cea5ec124a1b4bd1626a2e6f31e999f8adbab52c4dfa909');

                assert(derivation === '4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20');
            });

            it('Derive Public Key', async () => {
                const publicKey = await TurtleCoinCrypto.derivePublicKey(
                    '4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20',
                    2,
                    '854a637b2863af9e8e8216eb2382f3d16616b3ac3e53d0976fbd6f8da6c56418');

                assert(publicKey === 'bb55bef919d1c9f74b5b52a8a6995a1dc4af4c0bb8824f5dc889012bc748173d');
            });

            it('Underive Public Key: Ours', async () => {
                const publicKey = await TurtleCoinCrypto.underivePublicKey(
                    '4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20',
                    2,
                    'bb55bef919d1c9f74b5b52a8a6995a1dc4af4c0bb8824f5dc889012bc748173d');

                assert(publicKey === '854a637b2863af9e8e8216eb2382f3d16616b3ac3e53d0976fbd6f8da6c56418');
            });

            it('Underive Public Key: Not Ours', async () => {
                const publicKey = await TurtleCoinCrypto.underivePublicKey(
                    '4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20',
                    0,
                    'bb55bef919d1c9f74b5b52a8a6995a1dc4af4c0bb8824f5dc889012bc748173d');

                assert(publicKey !== '854a637b2863af9e8e8216eb2382f3d16616b3ac3e53d0976fbd6f8da6c56418');
            });

            it('Derive Secret Key', async () => {
                const secretKey = await TurtleCoinCrypto.deriveSecretKey(
                    '4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20',
                    2,
                    'd9d555a892a85f64916cae1a168bd3f7f400b6471c7b12b438b599601298210b');

                assert(secretKey === 'e52ece5717f01843e3accc4df651d669e339c31eb8059145e881faae19ad4a0e');
            });
        });

        describe('New Derivation Math', () => {
            it('Generate Key Derivation Scalar', async () => {
                const derivationScalar = await TurtleCoinCrypto.generateKeyDerivationScalar(
                    '3b0cc2b066812e6b9fcc42a797dc3c723a7344b604fd4be0b22e06254ff57f94',
                    '6968a0b8f744ec4b8cea5ec124a1b4bd1626a2e6f31e999f8adbab52c4dfa909',
                    2);

                assert(derivationScalar === '0c5978af8447b9de51401e33e0c60272ee380dd79b8a7e91afcc604e07152903');
            });

            it('Derivation to Scalar', async () => {
                const derivation = await TurtleCoinCrypto.generateKeyDerivation(
                    '3b0cc2b066812e6b9fcc42a797dc3c723a7344b604fd4be0b22e06254ff57f94',
                    '6968a0b8f744ec4b8cea5ec124a1b4bd1626a2e6f31e999f8adbab52c4dfa909');

                const derivationScalar = await TurtleCoinCrypto.derivationToScalar(derivation, 2);

                assert(derivationScalar === '0c5978af8447b9de51401e33e0c60272ee380dd79b8a7e91afcc604e07152903');
            });

            it('Derive Public Key', async () => {
                const publicKey = await TurtleCoinCrypto.scalarDerivePublicKey(
                    '0c5978af8447b9de51401e33e0c60272ee380dd79b8a7e91afcc604e07152903',
                    '854a637b2863af9e8e8216eb2382f3d16616b3ac3e53d0976fbd6f8da6c56418');

                assert(publicKey === 'bb55bef919d1c9f74b5b52a8a6995a1dc4af4c0bb8824f5dc889012bc748173d');
            });

            it('Derive Secret Key', async () => {
                const secretKey = await TurtleCoinCrypto.scalarDeriveSecretKey(
                    '0c5978af8447b9de51401e33e0c60272ee380dd79b8a7e91afcc604e07152903',
                    'd9d555a892a85f64916cae1a168bd3f7f400b6471c7b12b438b599601298210b');

                assert(secretKey === 'e52ece5717f01843e3accc4df651d669e339c31eb8059145e881faae19ad4a0e');
            });
        });

        it('Generate Key Image', async () => {
            const keyImage = await TurtleCoinCrypto.generateKeyImage(
                'bb55bef919d1c9f74b5b52a8a6995a1dc4af4c0bb8824f5dc889012bc748173d',
                'e52ece5717f01843e3accc4df651d669e339c31eb8059145e881faae19ad4a0e');

            assert(keyImage === '5997cf23543ce2e05c327297a47f26e710af868344859a6f8d65683d8a2498b0');
        });

        it('Generate Deterministic Subwallet #0', async () => {
            const spendKey = await TurtleCoinCrypto.generateDeterministicSubwalletKeys(
                'dd0c02d3202634821b4d9d91b63d919725f5c3e97e803f3512e52fb0dc2aab0c', 0);

            assert(spendKey.private_key === 'dd0c02d3202634821b4d9d91b63d919725f5c3e97e803f3512e52fb0dc2aab0c');
        });

        it('Generate Deterministic Subwallet #1', async () => {
            const spendKey = await TurtleCoinCrypto.generateDeterministicSubwalletKeys(
                'dd0c02d3202634821b4d9d91b63d919725f5c3e97e803f3512e52fb0dc2aab0c', 1);

            assert(spendKey.private_key === 'c55cbe4fd1c49dca5958fa1c7b9212c2dbf3fd5bfec84de741d434056e298600');
        });

        it('Generate Deterministic Subwallet #64', async () => {
            const spendKey = await TurtleCoinCrypto.generateDeterministicSubwalletKeys(
                'dd0c02d3202634821b4d9d91b63d919725f5c3e97e803f3512e52fb0dc2aab0c', 64);

            assert(spendKey.private_key === '29c2afed13271e2bb3321c2483356fd8798f2709af4de3906b6627ec71727108');
        });

        it('Tree Hash', async () => {
            const expectedTreeHash = 'dff9b4e047803822e97fb25bb9acb8320648954e15a6ddf6fa757873793c535e';
            const treeHash = await TurtleCoinCrypto.tree_hash([
                'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0',
                '1b606a3f4a07d6489a1bcd07697bd16696b61c8ae982f61a90160f4e52828a7f',
                'c9fae8425d8688dc236bcdbc42fdb42d376c6ec190501aa84b04a4b4cf1ee122',
                '871fcd6823f6a879bb3f33951c8e8e891d4043880b02dfa1bb3be498b50e7578'
            ]);

            assert(treeHash === expectedTreeHash);
        });

        it('Tree Branch', async () => {
            const expectedTreeBranch = [
                'f49291f9b352701d97dffad838def8cefcc34d1e767e450558261b161ab78cb1',
                '1b606a3f4a07d6489a1bcd07697bd16696b61c8ae982f61a90160f4e52828a7f'
            ];

            const treeBranch = await TurtleCoinCrypto.tree_branch([
                'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0',
                '1b606a3f4a07d6489a1bcd07697bd16696b61c8ae982f61a90160f4e52828a7f',
                'c9fae8425d8688dc236bcdbc42fdb42d376c6ec190501aa84b04a4b4cf1ee122',
                '871fcd6823f6a879bb3f33951c8e8e891d4043880b02dfa1bb3be498b50e7578'
            ]);

            assert.deepStrictEqual(treeBranch, expectedTreeBranch);
        });

        it('Generate Ring Signatures', async () => {
            const prefixHash = 'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0';
            const keyImage = '6865866ed8a25824e042e21dd36e946836b58b03366e489aecf979f444f599b0';
            const publicKeys = [
                '492390897da1cabd3886e3eff43ad1d04aa510a905bec0acd31a0a2f260e7862',
                '7644ccb5410cca2be18b033e5f7497aeeeafd1d8f317f29cba4803e4306aa402',
                'bb9a956ffdf8159ad69474e6b0811316c44a17a540d5e39a44642d4d933a6460',
                'e1cd9ccdfdf2b3a45ac2cfd1e29185d22c185742849f52368c3cdd1c0ce499c0'
            ];
            const privateEphemeral = '73a8e577d58f7c11992201d4014ac7eef39c1e9f6f6d78673103de60a0c3240b';

            const signatures = await TurtleCoinCrypto.generateRingSignatures(
                prefixHash, keyImage, publicKeys, privateEphemeral, 3);

            const check = await TurtleCoinCrypto.checkRingSignatures(prefixHash, keyImage, publicKeys, signatures);

            assert(check);
        });

        it('Prepare Ring Signatures', async () => {
            const prefixHash = 'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0';
            const keyImage = '6865866ed8a25824e042e21dd36e946836b58b03366e489aecf979f444f599b0';
            const publicKeys = [
                '492390897da1cabd3886e3eff43ad1d04aa510a905bec0acd31a0a2f260e7862',
                '7644ccb5410cca2be18b033e5f7497aeeeafd1d8f317f29cba4803e4306aa402',
                'bb9a956ffdf8159ad69474e6b0811316c44a17a540d5e39a44642d4d933a6460',
                'e1cd9ccdfdf2b3a45ac2cfd1e29185d22c185742849f52368c3cdd1c0ce499c0'
            ];
            const privateEphemeral = '73a8e577d58f7c11992201d4014ac7eef39c1e9f6f6d78673103de60a0c3240b';

            const prep = await TurtleCoinCrypto.prepareRingSignatures(prefixHash, keyImage, publicKeys, 3);

            const signatures = await TurtleCoinCrypto.completeRingSignatures(
                privateEphemeral, 3, prep.k, prep.signatures);

            const check = await TurtleCoinCrypto.checkRingSignatures(prefixHash, keyImage, publicKeys, signatures);

            assert(check);
        });

        it('Prepare Ring Signatures - Precomputed K', async () => {
            const prefixHash = 'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0';
            const keyImage = '6865866ed8a25824e042e21dd36e946836b58b03366e489aecf979f444f599b0';
            const publicKeys = [
                '492390897da1cabd3886e3eff43ad1d04aa510a905bec0acd31a0a2f260e7862',
                '7644ccb5410cca2be18b033e5f7497aeeeafd1d8f317f29cba4803e4306aa402',
                'bb9a956ffdf8159ad69474e6b0811316c44a17a540d5e39a44642d4d933a6460',
                'e1cd9ccdfdf2b3a45ac2cfd1e29185d22c185742849f52368c3cdd1c0ce499c0'
            ];
            const privateEphemeral = '73a8e577d58f7c11992201d4014ac7eef39c1e9f6f6d78673103de60a0c3240b';

            const keys = await TurtleCoinCrypto.generateKeys();

            const prep = await TurtleCoinCrypto.prepareRingSignatures(
                prefixHash, keyImage, publicKeys, 3, keys.private_key);

            const signatures = await TurtleCoinCrypto.completeRingSignatures(
                privateEphemeral, 3, prep.k, prep.signatures);

            const check = await TurtleCoinCrypto.checkRingSignatures(prefixHash, keyImage, publicKeys, signatures);

            assert(check && prep.k === keys.private_key);
        });
    });

    describe('Multisig', () => {
        const party1 = {
            spend: {
                secretKey: 'a0ba0cae34ce1133b9cb658e5d0a56440608622a64562ac360907a2c68ea130d',
                publicKey: '6bce43e0d797b9ee674db41c173f9b147fab6841fed36e97d434bd7c6f5b81d5'
            },
            view: {
                secretKey: '01d85bf9ce5583c7a1039f2c2695cb562bf1ea97636bbaf9051af01dddc89e0b',
                publicKey: 'fb2ecf5c9492863580d8ac90f04d114a29d536bed166d7e80a845a90c2ee1e54'
            },
            multisig: {
                secretKeys: [
                    'ca67bdeba4cc489c86b0e6be24ed86ee75fd7e4caaf6566ea3b241946f40f901',
                    '98c2625a77504c46fb4d83bdf2c5dee505d4e3d0d30005bac636b0d49f90420f'
                ],
                publicKeys: [
                    'c578447b97b8cd9a5234ec25ba2ba54f37ec5504ae40167414e700ebf2bfe2bb',
                    'fe9ae30ba09e27f0dd50762321bd427b97ca43ab44e9c148e7508f2e4a3917b9'
                ]
            }
        };

        const party2 = {
            spend: {
                secretKey: '91ace6308728a8e1c7d833b2fe9beb4a5a808ec04218e7da8402260a3872120d',
                publicKey: 'ba719ff6486ae5ab5ea0c7e05f6b42468f898bd366f83a4d165e396c1f7c5eec'
            },
            view: {
                secretKey: '650110a79f0353624f0fa14aaaf8c5af405ddb009c3127366e5b8591ecec9704',
                publicKey: '7e95331e33950119be42ac0b84ce2c39c99ff90982c6f022e44de8ede33ed4e1'
            },
            multisig: {
                secretKeys: [
                    '1726bee3bd42cc2288a36524142d0369520673052d264309e2312e9c21d16a09',
                    'ca67bdeba4cc489c86b0e6be24ed86ee75fd7e4caaf6566ea3b241946f40f901'
                ],
                publicKeys: [
                    '13a5ab919024895573616fa7e4b852b52444caa9c91df4a1dbb9493e148d5d03',
                    'c578447b97b8cd9a5234ec25ba2ba54f37ec5504ae40167414e700ebf2bfe2bb'
                ]
            }
        };

        const party3 = {
            spend: {
                secretKey: '42b79cc7ac0b05ef34cd08716efec28a73366b702fcc6a09c37f5428ee52a802',
                publicKey: 'fd524a5384bf5044feeb61f19866e11f74b8dbf5e7d050238046b04289a31849'
            },
            view: {
                secretKey: '4f94fe294c541a5fe9740fa96ae86d70df9f51b13fe88ae5188ae59aae71910b',
                publicKey: '366afc95bcb0bfa9fb2282078133b4bc618f193ba948cb0dd896a3405057eafd'
            },
            multisig: {
                secretKeys: [
                    '98c2625a77504c46fb4d83bdf2c5dee505d4e3d0d30005bac636b0d49f90420f',
                    '1726bee3bd42cc2288a36524142d0369520673052d264309e2312e9c21d16a09'
                ],
                publicKeys: [
                    'fe9ae30ba09e27f0dd50762321bd427b97ca43ab44e9c148e7508f2e4a3917b9',
                    '13a5ab919024895573616fa7e4b852b52444caa9c91df4a1dbb9493e148d5d03'
                ]
            }
        };

        describe('N/N', () => {
            const sharedKeys = {
                spend: {
                    secretKey: '4493fd81a193a7bcaa07a29d7dac627a6088f0eaa66e119ee592a036a05c260a',
                    publicKey: 'caa8f9aaf673ff2c055025942eeefde720a71281420ec8c42f0a817225db032b'
                },
                view: {
                    secretKey: '7905764354f6c3d11a7648d4f193b2f16b4ec698ff9ce12f747575afc9b53600',
                    publicKey: '1b549cad10dfefe6c7cb1a7b707725ec914d2f87ba25337edb64b96c6a31d3ae'
                }
            };

            const tx = {
                input: {
                    key: 'e1cd9ccdfdf2b3a45ac2cfd1e29185d22c185742849f52368c3cdd1c0ce499c0',
                    index: 2
                },
                keys: {
                    publicKey: '4a037147e1236c13e6bc2b6fbd17758b7333c613a38738e468b586008de1c13e'
                },
                derivation: '9475ebaa9f869b06d967aa0ca09d1632f4b8a383211c8a66e39021bc04d80fc4',
                publicEphemeral: 'e1cd9ccdfdf2b3a45ac2cfd1e29185d22c185742849f52368c3cdd1c0ce499c0',
                privateEphemeral: '73a8e577d58f7c11992201d4014ac7eef39c1e9f6f6d78673103de60a0c3240b',
                keyImage: '6865866ed8a25824e042e21dd36e946836b58b03366e489aecf979f444f599b0'
            };

            describe('Party 1', () => {
                it('Generate Shared Public Spend Key', async () => {
                    const sharedKey = await TurtleCoinCrypto.calculateSharedPublicKey(
                        [party1.spend.publicKey, party2.spend.publicKey]);

                    assert(sharedKey === sharedKeys.spend.publicKey);
                });

                it('Generate Shared Private View Key', async () => {
                    const sharedKey = await TurtleCoinCrypto.calculateSharedPrivateKey(
                        [party1.view.secretKey, party2.view.secretKey]);

                    assert(sharedKey === sharedKeys.view.secretKey);
                });
            });

            describe('Party 2', () => {
                it('Generate Shared Public Spend Key', async () => {
                    const sharedKey = await TurtleCoinCrypto.calculateSharedPublicKey(
                        [party2.spend.publicKey, party1.spend.publicKey]);

                    assert(sharedKey === sharedKeys.spend.publicKey);
                });

                it('Generate Shared Private View Key', async () => {
                    const sharedKey = await TurtleCoinCrypto.calculateSharedPrivateKey(
                        [party2.view.secretKey, party1.view.secretKey]);

                    assert(sharedKey === sharedKeys.view.secretKey);
                });
            });

            describe('Transactions', () => {
                it('Restore KeyImage from Partial KeyImages', async () => {
                    const keyImage1 = await TurtleCoinCrypto.generateKeyImage(
                        tx.publicEphemeral, party1.spend.secretKey);

                    const keyImage2 = await TurtleCoinCrypto.generateKeyImage(
                        tx.publicEphemeral, party2.spend.secretKey);

                    const keyImage = await TurtleCoinCrypto.restoreKeyImage(
                        tx.publicEphemeral, tx.derivation, tx.input.index, [keyImage1, keyImage2]);

                    assert(keyImage === tx.keyImage);
                });

                it('Restore Ring Signatures from Partial Signing Keys', async () => {
                    const prefixHash = 'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0';
                    const publicKeys = [
                        '492390897da1cabd3886e3eff43ad1d04aa510a905bec0acd31a0a2f260e7862',
                        '7644ccb5410cca2be18b033e5f7497aeeeafd1d8f317f29cba4803e4306aa402',
                        'bb9a956ffdf8159ad69474e6b0811316c44a17a540d5e39a44642d4d933a6460',
                        'e1cd9ccdfdf2b3a45ac2cfd1e29185d22c185742849f52368c3cdd1c0ce499c0'
                    ];

                    const prep = await TurtleCoinCrypto.prepareRingSignatures(
                        prefixHash, tx.keyImage, publicKeys, 3);

                    const sig1 = await TurtleCoinCrypto.generatePartialSigningKey(
                        prep.signatures[3], party1.spend.secretKey);

                    const sig2 = await TurtleCoinCrypto.generatePartialSigningKey(
                        prep.signatures[3], party2.spend.secretKey);

                    const sigs = await TurtleCoinCrypto.restoreRingSignatures(
                        tx.derivation, tx.input.index, [sig1, sig2], 3, prep.k, prep.signatures);

                    const success = await TurtleCoinCrypto.checkRingSignatures(
                        prefixHash, tx.keyImage, publicKeys, sigs);

                    assert(success);
                });
            });
        });

        describe('N1/N', () => {
            const sharedKeys = {
                spend: {
                    secretKey: '8c7ce8ccbffc4ead3305d8fd4ce68928ced7d522ab1d9f314c1b200531a2a60a',
                    publicKey: '2f5a5c955f8510bb8c6601a3c16149c9451ffcd7e906fafa5e70407d59a61e77'
                },
                view: {
                    secretKey: 'c899746da04ade3004eb577d5c7c20624bee174a3f856c158dff5a4a7827c80b',
                    publicKey: '792b224e356def4ba73669a135300357f200dcf7acc7c2c5d2dd0feb3961c7fa'
                }
            };

            const tx = {
                input: {
                    key: '71e91d548fc24e21ece8388550c209c0862ffd47320317ddd456aea757f8309b',
                    index: 1
                },
                keys: {
                    publicKey: '9fa1c0df1af4b3a8d09f86d5be7ca4dbc9e37e28f2390184369589ee3e641627'
                },
                derivation: 'f6c1094900adf5d36393fa52b1f086886fb939078a9b6c411a4207780fb89bf6',
                publicEphemeral: '71e91d548fc24e21ece8388550c209c0862ffd47320317ddd456aea757f8309b',
                privateEphemeral: '2d4e27a9defb233deb37a7bf0bfdb239cae704f5d0d33222d5e93e619d45af08',
                keyImage: '174d0e7323ec00fa3e0d8432ffd3614cac829685d32a0a5b8f107cef80043178'
            };

            describe('Party 1', () => {
                it('Generate Multisig Keys', async () => {
                    const keys = await TurtleCoinCrypto.calculateMultisigPrivateKeys(
                        party1.spend.secretKey, [party2.spend.publicKey, party3.spend.publicKey]);

                    assert.deepStrictEqual(keys, party1.multisig.secretKeys);
                });

                it('Generate Shared Public Spend Key', async () => {
                    const keys = party1.multisig.publicKeys.concat(
                        party2.multisig.publicKeys, party3.multisig.publicKeys);
                    const sharedKey = await TurtleCoinCrypto.calculateSharedPublicKey(keys);

                    assert(sharedKey === sharedKeys.spend.publicKey);
                });

                it('Generate Shared Private View Key', async () => {
                    const sharedKey = await TurtleCoinCrypto.calculateSharedPrivateKey(
                        [party1.view.secretKey, party2.view.secretKey, party3.view.secretKey]);

                    assert(sharedKey === sharedKeys.view.secretKey);
                });
            });

            describe('Party 2', () => {
                it('Generate Multisig Keys', async () => {
                    const keys = await TurtleCoinCrypto.calculateMultisigPrivateKeys(
                        party2.spend.secretKey, [party3.spend.publicKey, party1.spend.publicKey]);

                    assert.deepStrictEqual(keys, party2.multisig.secretKeys);
                });

                it('Generate Shared Public Spend Key', async () => {
                    const keys = party2.multisig.publicKeys.concat(
                        party3.multisig.publicKeys, party1.multisig.publicKeys);

                    const sharedKey = await TurtleCoinCrypto.calculateSharedPublicKey(keys);

                    assert(sharedKey === sharedKeys.spend.publicKey);
                });

                it('Generate Shared Private View Key', async () => {
                    const sharedKey = await TurtleCoinCrypto.calculateSharedPrivateKey(
                        [party2.view.secretKey, party3.view.secretKey, party1.view.secretKey]);

                    assert(sharedKey === sharedKeys.view.secretKey);
                });
            });

            describe('Party 3', () => {
                it('Generate Multisig Keys', async () => {
                    const keys = await TurtleCoinCrypto.calculateMultisigPrivateKeys(
                        party3.spend.secretKey, [party1.spend.publicKey, party2.spend.publicKey]);

                    assert.deepStrictEqual(keys, party3.multisig.secretKeys);
                });

                it('Generate Shared Public Spend Key', async () => {
                    const keys = party3.multisig.publicKeys.concat(
                        party1.multisig.publicKeys, party2.multisig.publicKeys);

                    const sharedKey = await TurtleCoinCrypto.calculateSharedPublicKey(keys);

                    assert(sharedKey === sharedKeys.spend.publicKey);
                });

                it('Generate Shared Private View Key', async () => {
                    const sharedKey = await TurtleCoinCrypto.calculateSharedPrivateKey(
                        [party3.view.secretKey, party2.view.secretKey, party1.view.secretKey]);

                    assert(sharedKey === sharedKeys.view.secretKey);
                });
            });

            describe('Transactions', async function () {
                it('Restore KeyImage from Partial KeyImages of Party #1 & Party #2', async () => {
                    const partialKeyImages: string[] = [];

                    for (const key of party1.multisig.secretKeys) {
                        partialKeyImages.push(await TurtleCoinCrypto.generateKeyImage(tx.publicEphemeral, key));
                    }

                    for (const key of party2.multisig.secretKeys) {
                        partialKeyImages.push(await TurtleCoinCrypto.generateKeyImage(tx.publicEphemeral, key));
                    }

                    const keyImage = await TurtleCoinCrypto.restoreKeyImage(
                        tx.publicEphemeral, tx.derivation, tx.input.index, partialKeyImages);

                    assert(keyImage === tx.keyImage);
                });

                it('Restore KeyImage from Partial KeyImages of Party #1 & Party #3', async () => {
                    const partialKeyImages: string[] = [];

                    for (const key of party1.multisig.secretKeys) {
                        partialKeyImages.push(await TurtleCoinCrypto.generateKeyImage(tx.publicEphemeral, key));
                    }

                    for (const key of party3.multisig.secretKeys) {
                        partialKeyImages.push(await TurtleCoinCrypto.generateKeyImage(tx.publicEphemeral, key));
                    }

                    const keyImage = await TurtleCoinCrypto.restoreKeyImage(
                        tx.publicEphemeral, tx.derivation, tx.input.index, partialKeyImages);

                    assert(keyImage === tx.keyImage);
                });

                it('Restore KeyImage from Partial KeyImages of Party #2 & Party #3', async () => {
                    const partialKeyImages: string[] = [];

                    for (const key of party2.multisig.secretKeys) {
                        partialKeyImages.push(await TurtleCoinCrypto.generateKeyImage(tx.publicEphemeral, key));
                    }

                    for (const key of party3.multisig.secretKeys) {
                        partialKeyImages.push(await TurtleCoinCrypto.generateKeyImage(tx.publicEphemeral, key));
                    }

                    const keyImage = await TurtleCoinCrypto.restoreKeyImage(
                        tx.publicEphemeral, tx.derivation, tx.input.index, partialKeyImages);

                    assert(keyImage === tx.keyImage);
                });

                it('Restore KeyImage from Partial KeyImages of Parties #1, #2, & #3', async () => {
                    const partialKeyImages: string[] = [];

                    for (const key of party1.multisig.secretKeys) {
                        partialKeyImages.push(await TurtleCoinCrypto.generateKeyImage(tx.publicEphemeral, key));
                    }

                    for (const key of party2.multisig.secretKeys) {
                        partialKeyImages.push(await TurtleCoinCrypto.generateKeyImage(tx.publicEphemeral, key));
                    }

                    for (const key of party3.multisig.secretKeys) {
                        partialKeyImages.push(await TurtleCoinCrypto.generateKeyImage(tx.publicEphemeral, key));
                    }

                    const keyImage = await TurtleCoinCrypto.restoreKeyImage(
                        tx.publicEphemeral, tx.derivation, tx.input.index, partialKeyImages);

                    assert(keyImage === tx.keyImage);
                });

                it('Failure to Restore KeyImage from using Party #1 keys only', async () => {
                    const partialKeyImages: string[] = [];

                    for (const key of party1.multisig.secretKeys) {
                        partialKeyImages.push(await TurtleCoinCrypto.generateKeyImage(tx.publicEphemeral, key));
                    }

                    const keyImage = await TurtleCoinCrypto.restoreKeyImage(
                        tx.publicEphemeral, tx.derivation, tx.input.index, partialKeyImages);

                    assert(keyImage !== tx.keyImage);
                });

                it('Restore Ring Signatures from Partial Signing Keys of Party #1 & Party #2', async () => {
                    const prefixHash = 'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0';
                    const publicKeys = [
                        '492390897da1cabd3886e3eff43ad1d04aa510a905bec0acd31a0a2f260e7862',
                        '7644ccb5410cca2be18b033e5f7497aeeeafd1d8f317f29cba4803e4306aa402',
                        'bb9a956ffdf8159ad69474e6b0811316c44a17a540d5e39a44642d4d933a6460',
                        '71e91d548fc24e21ece8388550c209c0862ffd47320317ddd456aea757f8309b'
                    ];

                    const prep = await TurtleCoinCrypto.prepareRingSignatures(prefixHash, tx.keyImage, publicKeys, 3);

                    const partialSignatures: string[] = [];

                    for (const key of party1.multisig.secretKeys) {
                        partialSignatures.push(await TurtleCoinCrypto.generatePartialSigningKey(
                            prep.signatures[3], key));
                    }

                    for (const key of party2.multisig.secretKeys) {
                        partialSignatures.push(await TurtleCoinCrypto.generatePartialSigningKey(
                            prep.signatures[3], key));
                    }

                    const sigs = await TurtleCoinCrypto.restoreRingSignatures(
                        tx.derivation, tx.input.index, partialSignatures, 3, prep.k, prep.signatures);

                    const success = await TurtleCoinCrypto.checkRingSignatures(
                        prefixHash, tx.keyImage, publicKeys, sigs);

                    assert(success);
                });

                it('Restore Ring Signatures from Partial Signing Keys of Party #1 & Party #3', async () => {
                    const prefixHash = 'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0';
                    const publicKeys = [
                        '492390897da1cabd3886e3eff43ad1d04aa510a905bec0acd31a0a2f260e7862',
                        '7644ccb5410cca2be18b033e5f7497aeeeafd1d8f317f29cba4803e4306aa402',
                        'bb9a956ffdf8159ad69474e6b0811316c44a17a540d5e39a44642d4d933a6460',
                        '71e91d548fc24e21ece8388550c209c0862ffd47320317ddd456aea757f8309b'
                    ];

                    const prep = await TurtleCoinCrypto.prepareRingSignatures(prefixHash, tx.keyImage, publicKeys, 3);

                    const partialSignatures: string[] = [];

                    for (const key of party1.multisig.secretKeys) {
                        partialSignatures.push(await TurtleCoinCrypto.generatePartialSigningKey(
                            prep.signatures[3], key));
                    }

                    for (const key of party3.multisig.secretKeys) {
                        partialSignatures.push(await TurtleCoinCrypto.generatePartialSigningKey(
                            prep.signatures[3], key));
                    }

                    const sigs = await TurtleCoinCrypto.restoreRingSignatures(
                        tx.derivation, tx.input.index, partialSignatures, 3, prep.k, prep.signatures);

                    const success = await TurtleCoinCrypto.checkRingSignatures(
                        prefixHash, tx.keyImage, publicKeys, sigs);

                    assert(success);
                });

                it('Restore Ring Signatures from Partial Signing Keys of Party #2 & Party #3', async () => {
                    const prefixHash = 'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0';
                    const publicKeys = [
                        '492390897da1cabd3886e3eff43ad1d04aa510a905bec0acd31a0a2f260e7862',
                        '7644ccb5410cca2be18b033e5f7497aeeeafd1d8f317f29cba4803e4306aa402',
                        'bb9a956ffdf8159ad69474e6b0811316c44a17a540d5e39a44642d4d933a6460',
                        '71e91d548fc24e21ece8388550c209c0862ffd47320317ddd456aea757f8309b'
                    ];

                    const prep = await TurtleCoinCrypto.prepareRingSignatures(prefixHash, tx.keyImage, publicKeys, 3);

                    const partialSignatures: string[] = [];

                    for (const key of party2.multisig.secretKeys) {
                        partialSignatures.push(await TurtleCoinCrypto.generatePartialSigningKey(
                            prep.signatures[3], key));
                    }

                    for (const key of party3.multisig.secretKeys) {
                        partialSignatures.push(await TurtleCoinCrypto.generatePartialSigningKey(
                            prep.signatures[3], key));
                    }

                    const sigs = await TurtleCoinCrypto.restoreRingSignatures(
                        tx.derivation, tx.input.index, partialSignatures, 3, prep.k, prep.signatures);

                    const success = await TurtleCoinCrypto.checkRingSignatures(
                        prefixHash, tx.keyImage, publicKeys, sigs);

                    assert(success);
                });

                it('Restore Ring Signatures from Partial Signing Keys of Parties #1, #2, & #3', async () => {
                    const prefixHash = 'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0';
                    const publicKeys = [
                        '492390897da1cabd3886e3eff43ad1d04aa510a905bec0acd31a0a2f260e7862',
                        '7644ccb5410cca2be18b033e5f7497aeeeafd1d8f317f29cba4803e4306aa402',
                        'bb9a956ffdf8159ad69474e6b0811316c44a17a540d5e39a44642d4d933a6460',
                        '71e91d548fc24e21ece8388550c209c0862ffd47320317ddd456aea757f8309b'
                    ];

                    const prep = await TurtleCoinCrypto.prepareRingSignatures(prefixHash, tx.keyImage, publicKeys, 3);

                    const partialSignatures: string[] = [];

                    for (const key of party1.multisig.secretKeys) {
                        partialSignatures.push(await TurtleCoinCrypto.generatePartialSigningKey(
                            prep.signatures[3], key));
                    }

                    for (const key of party2.multisig.secretKeys) {
                        partialSignatures.push(await TurtleCoinCrypto.generatePartialSigningKey(
                            prep.signatures[3], key));
                    }

                    for (const key of party3.multisig.secretKeys) {
                        partialSignatures.push(await TurtleCoinCrypto.generatePartialSigningKey(
                            prep.signatures[3], key));
                    }

                    const sigs = await TurtleCoinCrypto.restoreRingSignatures(
                        tx.derivation, tx.input.index, partialSignatures, 3, prep.k, prep.signatures);

                    const success = await TurtleCoinCrypto.checkRingSignatures(
                        prefixHash, tx.keyImage, publicKeys, sigs);

                    assert(success);
                });

                it('Failure to Restore Ring Signatures from Partial Signing Keys of Party #1 keys only', async () => {
                    const prefixHash = 'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0';
                    const publicKeys = [
                        '492390897da1cabd3886e3eff43ad1d04aa510a905bec0acd31a0a2f260e7862',
                        '7644ccb5410cca2be18b033e5f7497aeeeafd1d8f317f29cba4803e4306aa402',
                        'bb9a956ffdf8159ad69474e6b0811316c44a17a540d5e39a44642d4d933a6460',
                        '71e91d548fc24e21ece8388550c209c0862ffd47320317ddd456aea757f8309b'
                    ];

                    const prep = await TurtleCoinCrypto.prepareRingSignatures(prefixHash, tx.keyImage, publicKeys, 3);

                    const partialSignatures: string[] = [];

                    for (const key of party1.multisig.secretKeys) {
                        partialSignatures.push(await TurtleCoinCrypto.generatePartialSigningKey(
                            prep.signatures[3], key));
                    }

                    const sigs = await TurtleCoinCrypto.restoreRingSignatures(
                        tx.derivation, tx.input.index, partialSignatures, 3, prep.k, prep.signatures);

                    const success = await TurtleCoinCrypto.checkRingSignatures(
                        prefixHash, tx.keyImage, publicKeys, sigs);

                    assert(!success);
                });
            });
        });
    });
});

describe('Hash Generation Methods', function () {
    const testdata =
        '0100fb8e8ac805899323371bb790db19218afd8db8e3755d8b90f39b3d5506a9' +
        'abce4fa912244500000000ee8146d49fa93ee724deb57d12cbc6c6f3b924d946' +
        '127c7a97418f9348828f0f02';

    const algos = [
        {
            name: 'CryptoNight Fast Hash',
            func: 'cn_fast_hash',
            hash: 'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0'
        },
        {
            name: 'CryptoNight v0',
            func: 'cn_slow_hash_v0',
            hash: '1b606a3f4a07d6489a1bcd07697bd16696b61c8ae982f61a90160f4e52828a7f'
        },
        {
            name: 'CryptoNight v1',
            func: 'cn_slow_hash_v1',
            hash: 'c9fae8425d8688dc236bcdbc42fdb42d376c6ec190501aa84b04a4b4cf1ee122'
        },
        {
            name: 'CryptoNight v2',
            func: 'cn_slow_hash_v2',
            hash: '871fcd6823f6a879bb3f33951c8e8e891d4043880b02dfa1bb3be498b50e7578'
        },
        {
            name: 'CryptoNight Lite v0',
            func: 'cn_lite_slow_hash_v0',
            hash: '28a22bad3f93d1408fca472eb5ad1cbe75f21d053c8ce5b3af105a57713e21dd'
        },
        {
            name: 'CryptoNight Lite v1',
            func: 'cn_lite_slow_hash_v1',
            hash: '87c4e570653eb4c2b42b7a0d546559452dfab573b82ec52f152b7ff98e79446f'
        },
        {
            name: 'CryptoNight Lite v2',
            func: 'cn_lite_slow_hash_v2',
            hash: 'b7e78fab22eb19cb8c9c3afe034fb53390321511bab6ab4915cd538a630c3c62'
        },
        {
            name: 'CryptoNight Dark v0',
            func: 'cn_dark_slow_hash_v0',
            hash: 'bea42eadd78614f875e55bb972aa5ec54a5edf2dd7068220fda26bf4b1080fb8'
        },
        {
            name: 'CryptoNight Dark v1',
            func: 'cn_dark_slow_hash_v1',
            hash: 'd18cb32bd5b465e5a7ba4763d60f88b5792f24e513306f1052954294b737e871'
        },
        {
            name: 'CryptoNight Dark v2',
            func: 'cn_dark_slow_hash_v2',
            hash: 'a18a14d94efea108757a42633a1b4d4dc11838084c3c4347850d39ab5211a91f'
        },
        {
            name: 'CryptoNight Dark Lite v0',
            func: 'cn_dark_lite_slow_hash_v0',
            hash: 'faa7884d9c08126eb164814aeba6547b5d6064277a09fb6b414f5dbc9d01eb2b'
        },
        {
            name: 'CryptoNight Dark Lite v1',
            func: 'cn_dark_lite_slow_hash_v1',
            hash: 'c75c010780fffd9d5e99838eb093b37c0dd015101c9d298217866daa2993d277'
        },
        {
            name: 'CryptoNight Dark Lite v2',
            func: 'cn_dark_lite_slow_hash_v2',
            hash: 'fdceb794c1055977a955f31c576a8be528a0356ee1b0a1f9b7f09e20185cda28'
        },
        {
            name: 'CryptoNight Turtle v0',
            func: 'cn_turtle_slow_hash_v0',
            hash: '546c3f1badd7c1232c7a3b88cdb013f7f611b7bd3d1d2463540fccbd12997982'
        },
        {
            name: 'CryptoNight Turtle v1',
            func: 'cn_turtle_slow_hash_v1',
            hash: '29e7831780a0ab930e0fe3b965f30e8a44d9b3f9ad2241d67cfbfea3ed62a64e'
        },
        {
            name: 'CryptoNight Turtle v2',
            func: 'cn_turtle_slow_hash_v2',
            hash: 'fc67dfccb5fc90d7855ae903361eabd76f1e40a22a72ad3ef2d6ad27b5a60ce5'
        },
        {
            name: 'CryptoNight Turtle Lite v0',
            func: 'cn_turtle_lite_slow_hash_v0',
            hash: '5e1891a15d5d85c09baf4a3bbe33675cfa3f77229c8ad66c01779e590528d6d3'
        },
        {
            name: 'CryptoNight Turtle Lite v1',
            func: 'cn_turtle_lite_slow_hash_v1',
            hash: 'ae7f864a7a2f2b07dcef253581e60a014972b9655a152341cb989164761c180a'
        },
        {
            name: 'CryptoNight Turtle Lite v2',
            func: 'cn_turtle_lite_slow_hash_v2',
            hash: 'b2172ec9466e1aee70ec8572a14c233ee354582bcb93f869d429744de5726a26'
        },
        {
            name: 'Chukwa v1',
            func: 'chukwa_slow_hash_v1',
            hash: 'c0dad0eeb9c52e92a1c3aa5b76a3cb90bd7376c28dce191ceeb1096e3a390d2e'
        },
        {
            name: 'Chukwa v2',
            func: 'chukwa_slow_hash_v2',
            hash: '3578c135261366a7bac407b8c0ff50f3ad96f096ec2813e9644e6e77a43f803d'
        }
    ];

    algos.forEach((algo) => {
        it(algo.name, async function () {
            // eslint-disable-next-line @typescript-eslint/ban-ts-comment
            // @ts-ignore
            const hash = await TurtleCoinCrypto[algo.func](testdata);

            assert(algo.hash === hash);
        });
    });

    it('chukwa_slow_hash', async function () {
        const hash = await TurtleCoinCrypto.chukwa_slow_hash(testdata);
        assert(hash === 'c0dad0eeb9c52e92a1c3aa5b76a3cb90bd7376c28dce191ceeb1096e3a390d2e');
    });

    it('chukwa_slow_hash [1]', async function () {
        const hash = await TurtleCoinCrypto.chukwa_slow_hash(testdata, 1);
        assert(hash === 'c0dad0eeb9c52e92a1c3aa5b76a3cb90bd7376c28dce191ceeb1096e3a390d2e');
    });

    it('chukwa_slow_hash [2]', async function () {
        const hash = await TurtleCoinCrypto.chukwa_slow_hash(testdata, 2);
        assert(hash === '3578c135261366a7bac407b8c0ff50f3ad96f096ec2813e9644e6e77a43f803d');
    });

    it('chukwa_slow_hash_base [3 iterations, 512KB, 1 thread]', async function () {
        const hash = await TurtleCoinCrypto.chukwa_slow_hash_base(testdata, 3, 512, 1);
        assert(hash === 'c0dad0eeb9c52e92a1c3aa5b76a3cb90bd7376c28dce191ceeb1096e3a390d2e');
    });

    it('chukwa_slow_hash_base [4 iterations, 1024KB, 1 thread]', async function () {
        const hash = await TurtleCoinCrypto.chukwa_slow_hash_base(testdata, 4, 1024, 1);
        assert(hash === '3578c135261366a7bac407b8c0ff50f3ad96f096ec2813e9644e6e77a43f803d');
    });
});

describe('Transaction Version 2 (Fork 14)', function () {
    describe('View Tags', () => {
        it('Monero derive_view_tag vectors', async () => {
            assert(viewTagVectors.monero.length === 70);

            for (const vector of viewTagVectors.monero) {
                const viewTag = await TurtleCoinCrypto.deriveViewTag(vector.derivation, vector.index);

                assert.strictEqual(viewTag, vector.view_tag, vector.derivation + ' / ' + vector.index);
            }
        });

        for (const tx of viewTagVectors.transactions) {
            it(tx.wallet + ', tx key ' + tx.tx_public_key.substr(0, 8), async () => {
                const wallet = viewTagVectors.wallets.find((elem: any) => elem.name === tx.wallet);

                assert(wallet);

                /* Sender (8*r*A) and recipient (8*a*R) reach the same derivation */
                const recipientDerivation = await TurtleCoinCrypto.generateKeyDerivation(
                    tx.tx_public_key, wallet.view_secret);

                const senderDerivation = await TurtleCoinCrypto.generateKeyDerivation(
                    wallet.view_public, tx.tx_secret_key);

                assert.strictEqual(recipientDerivation, tx.derivation);

                assert.strictEqual(senderDerivation, tx.derivation);

                for (const tag of tx.tags) {
                    const viewTag = await TurtleCoinCrypto.deriveViewTag(tx.derivation, tag.index);

                    assert.strictEqual(viewTag, tag.view_tag, 'index ' + tag.index);
                }
            });
        }

        it('Refuses a malformed derivation and index', async () => {
            await assert.rejects(TurtleCoinCrypto.deriveViewTag('00', 0));

            await assert.rejects(TurtleCoinCrypto.deriveViewTag(viewTagVectors.monero[0].derivation, -1));

            await assert.rejects(TurtleCoinCrypto.deriveViewTag(viewTagVectors.monero[0].derivation, 1.5));
        });
    });

    describe('CLSAG', () => {
        it('Domain separators', () => {
            const pad32 = (text: string) => Buffer.from(text, 'ascii').toString('hex').padEnd(64, '0');

            assert.strictEqual(clsagVectors.agg_domain, pad32('XKR_CLSAG_agg_0'));

            assert.strictEqual(clsagVectors.round_domain, pad32('XKR_CLSAG_round'));
        });

        for (const vector of clsagVectors.vectors) {
            const title = vector.name + ' (ring size ' + vector.ring_size + ', signer ' + vector.signer_index + ')';

            describe(title, () => {
                it('Secret, public key and key image', async () => {
                    const publicKey = await TurtleCoinCrypto.secretKeyToPublicKey(vector.secret);

                    assert.strictEqual(publicKey, vector.ring[vector.signer_index]);

                    const keyImage = await TurtleCoinCrypto.generateKeyImage(
                        vector.ring[vector.signer_index], vector.secret);

                    assert.strictEqual(keyImage, vector.key_image);
                });

                it('Verifies', async () => {
                    const valid = await TurtleCoinCrypto.clsagVerify(
                        vector.message, vector.ring, vector.key_image, vector.c1, vector.s);

                    assert.strictEqual(valid, true);
                });

                it('Re-signing with the explicit randomness reproduces c1 and s', async () => {
                    const signature = await TurtleCoinCrypto.clsagSign(
                        vector.message, vector.ring, vector.secret, vector.signer_index,
                        vector.alpha, vector.decoy_responses);

                    assert.strictEqual(signature.c1, vector.c1);

                    assert.deepStrictEqual(signature.s, vector.s);
                });
            });
        }

        describe('Negative cases (n = 11, l = 5)', () => {
            it('Case list', () => {
                assert.strictEqual(clsagVectors.negative.length, 26);

                assert.strictEqual(clsagVectors.negative[0].name, 'original');

                assert.strictEqual(clsagVectors.negative[0].expected, true);
            });

            for (const negative of clsagVectors.negative) {
                it(negative.name + ' -> ' + negative.expected, async () => {
                    const valid = await TurtleCoinCrypto.clsagVerify(
                        negative.message, negative.ring, negative.key_image, negative.c1, negative.s);

                    assert.strictEqual(valid, negative.expected);
                });
            }
        });

        it('Round trip with fresh randomness (vector ring n11_l5)', async () => {
            const vector = clsagVectors.vectors.find((elem: any) => elem.name === 'n11_l5');

            const signature = await TurtleCoinCrypto.clsagSign(
                vector.message, vector.ring, vector.secret, vector.signer_index);

            assert.strictEqual(signature.s.length, vector.ring.length);

            assert.notStrictEqual(signature.c1, vector.c1);

            assert(await TurtleCoinCrypto.clsagVerify(
                vector.message, vector.ring, vector.key_image, signature.c1, signature.s));

            const otherMessage = await TurtleCoinCrypto.cn_fast_hash(vector.message);

            assert(!await TurtleCoinCrypto.clsagVerify(
                otherMessage, vector.ring, vector.key_image, signature.c1, signature.s));
        });

        it('Round trip with fresh keys at every signer index', async () => {
            const prefixHash = 'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0';

            const keys = [];

            for (let i = 0; i < 4; i++) {
                keys.push(await TurtleCoinCrypto.generateKeys());
            }

            const ring = keys.map(elem => elem.public_key);

            for (let l = 0; l < ring.length; l++) {
                const keyImage = await TurtleCoinCrypto.generateKeyImage(ring[l], keys[l].private_key);

                const signature = await TurtleCoinCrypto.clsagSign(prefixHash, ring, keys[l].private_key, l);

                assert(await TurtleCoinCrypto.clsagVerify(prefixHash, ring, keyImage, signature.c1, signature.s));
            }
        });

        it('Refuses a secret that does not belong to the real index', async () => {
            const vector = clsagVectors.vectors.find((elem: any) => elem.name === 'n4_l2');

            await assert.rejects(TurtleCoinCrypto.clsagSign(
                vector.message, vector.ring, vector.secret, (vector.signer_index + 1) % vector.ring_size));

            await assert.rejects(TurtleCoinCrypto.clsagSign(
                vector.message, vector.ring, vector.secret, (vector.signer_index + 1) % vector.ring_size,
                vector.alpha, vector.decoy_responses));
        });

        it('Refuses malformed randomness', async () => {
            const vector = clsagVectors.vectors.find((elem: any) => elem.name === 'n4_l2');

            /* one decoy response short */
            await assert.rejects(TurtleCoinCrypto.clsagSign(
                vector.message, vector.ring, vector.secret, vector.signer_index,
                vector.alpha, vector.decoy_responses.slice(1)));

            /* alpha without decoy responses */
            await assert.rejects(TurtleCoinCrypto.clsagSign(
                vector.message, vector.ring, vector.secret, vector.signer_index, vector.alpha));

            /* a non-canonical alpha (l itself) */
            await assert.rejects(TurtleCoinCrypto.clsagSign(
                vector.message, vector.ring, vector.secret, vector.signer_index,
                'edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010', vector.decoy_responses));
        });
    });
});

describe('Test use of user crypto', async () => {
    const cn_fast_hash = (data: string): Promise<string> => {
        let hash: string;

        try {
            hash = keccak256(Buffer.from(data, 'hex'));
        } catch (e) {
            assert(false);
        }

        return Promise.resolve(hash);
    };

    const testdata =
        '0100fb8e8ac805899323371bb790db19218afd8db8e3755d8b90f39b3d5506a9' +
        'abce4fa912244500000000ee8146d49fa93ee724deb57d12cbc6c6f3b924d946' +
        '127c7a97418f9348828f0f02';

    const expected_hash = 'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0';

    before(() => {
        TurtleCoinCrypto.userCryptoFunctions = { cn_fast_hash };
    });

    it('Test cn_fast_hash', async () => {
        const hash = await TurtleCoinCrypto.cn_fast_hash(testdata);

        assert(hash === expected_hash);
    });
});
