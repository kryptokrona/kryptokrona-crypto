// Copyright (c) 2026, The Kryptokrona Developers
//
// Please see the included LICENSE file for more information.

/*
 * The React Native entry point (dist/react-native.js, the "react-native" field of
 * package.json). Run on the built dist/ (`npm run build` first) and in a process
 * of its own (`npm run test-react-native`): the entry point under test must be the
 * first one loaded, as it is in a React Native bundle.
 */

import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { keccak256 } from 'js-sha3';
import { after, before, describe, it } from 'mocha';

const Module: any = require('module');

const root = path.resolve(__dirname, '..');

const dist = path.join(root, 'dist');

const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

const viewTagVectors = JSON.parse(
    fs.readFileSync(path.join(__dirname, 'vectors', 'tx-v2-view-tags.json'), 'utf8'));

/* The Node.js addon in any form: the 2.x Node-API file, the 1.x addon (through `bindings`)
   and the Emscripten builds */
const isAddon = (request: string): boolean =>
    request === 'bindings' ||
    /turtlecoin-crypto/.test(request) ||
    /\.(node|wasm)$/.test(request) ||
    /wasm/i.test(request);

/* What the React Native entry point must never load: the addon and Node.js core modules */
const isForbidden = (request: string): boolean =>
    isAddon(request) ||
    (Module.builtinModules as string[]).indexOf(request.replace(/^node:/, '')) !== -1;

/* Provided by the app at run time, not part of this package's module graph */
const isHostModule = (request: string): boolean => request === 'react-native';

/* Every require() call in a file: the literal specifiers and the number of calls */
function requireCalls (source: string): { literals: string[], calls: number } {
    const literals: string[] = [];

    const literal = /\brequire\s*\(\s*(['"])([^'"]+)\1\s*\)/g;

    let match: RegExpExecArray | null;

    while ((match = literal.exec(source)) !== null) {
        literals.push(match[2]);
    }

    const calls = (source.match(/\brequire\s*\(/g) || []).length;

    return { literals, calls };
}

/* The files a bundler following literal require() calls reaches from `entry` */
function moduleGraph (entry: string): { files: string[], requests: string[], dynamic: string[] } {
    const files: string[] = [];

    const requests: string[] = [];

    const dynamic: string[] = [];

    const queue: string[] = [entry];

    while (queue.length > 0) {
        const file = queue.shift() as string;

        if (files.indexOf(file) !== -1) {
            continue;
        }

        files.push(file);

        const { literals, calls } = requireCalls(fs.readFileSync(file, 'utf8'));

        if (calls !== literals.length) {
            dynamic.push(path.relative(root, file));
        }

        for (const request of literals) {
            requests.push(request);

            if (isForbidden(request) || isHostModule(request)) {
                continue;
            }

            queue.push(require.resolve(request, { paths: [path.dirname(file)] }));
        }
    }

    return { files, requests, dynamic };
}

describe('React Native entry point: package.json', () => {
    it('"react-native" points to dist/react-native.js, "main" is still dist/index.js', () => {
        assert.strictEqual(pkg['react-native'], 'dist/react-native.js');

        assert.strictEqual(pkg.main, 'dist/index.js');

        assert(fs.existsSync(path.join(root, pkg['react-native'])), 'run `npm run build` first');
    });

    it('No WASM or asm.js build is shipped any more', () => {
        assert(!fs.existsSync(path.join(dist, 'turtlecoin-crypto-wasm.js')));

        assert(!fs.existsSync(path.join(dist, 'turtlecoin-crypto.js')));
    });

    it('The codegen spec and the native sources are in the package', () => {
        assert.strictEqual(pkg.codegenConfig.name, 'KryptokronaCryptoSpec');

        assert.strictEqual(pkg.codegenConfig.jsSrcsDir, 'spec');

        assert(fs.existsSync(path.join(root, 'spec', 'NativeKryptokronaCrypto.ts')));

        for (const entry of ['spec/', 'cpp/', 'ios/', 'prebuilt/', 'kryptokrona-crypto.podspec',
            'react-native.config.js']) {
            assert(pkg.files.indexOf(entry) !== -1, entry);
        }
    });
});

describe('React Native entry point: module graph (static)', () => {
    it('Reaches only Crypto.js, Interfaces.js, native.js, js-sha3 and react-native', () => {
        const graph = moduleGraph(path.join(dist, 'react-native.js'));

        const forbidden = graph.requests.filter(isForbidden);

        assert.deepStrictEqual(forbidden, []);

        assert.deepStrictEqual(graph.dynamic, []);

        const ours = graph.files
            .filter(file => file.indexOf(dist + path.sep) === 0)
            .map(file => path.relative(dist, file))
            .sort();

        assert.deepStrictEqual(ours, ['Crypto.js', 'Interfaces.js', 'native.js', 'react-native.js']);

        assert(graph.requests.indexOf('react-native') !== -1);

        const others = graph.files.filter(file => file.indexOf(dist + path.sep) !== 0);

        assert.strictEqual(others.length, 1);

        assert(others[0].indexOf(path.join('node_modules', 'js-sha3') + path.sep) !== -1, others[0]);
    });

    it('The Node.js entry point has no literal require of the addon', () => {
        /* A bundler that is handed dist/index.js still does not pull it in */
        const { literals } = requireCalls(fs.readFileSync(path.join(dist, 'index.js'), 'utf8'));

        assert.deepStrictEqual(literals.filter(isAddon), []);

        assert.deepStrictEqual(Array.from(new Set(literals)).sort(), ['./Crypto', './Interfaces', './native', 'path']);
    });

    it('The adapter module has no require besides Interfaces', () => {
        const { literals, calls } = requireCalls(fs.readFileSync(path.join(dist, 'native.js'), 'utf8'));

        assert.strictEqual(calls, literals.length);

        assert.deepStrictEqual(literals.filter(id => id !== './Interfaces'), []);
    });

    it('The shared core has no require of its own besides js-sha3 and Interfaces', () => {
        const { literals, calls } = requireCalls(fs.readFileSync(path.join(dist, 'Crypto.js'), 'utf8'));

        assert.strictEqual(calls, literals.length);

        assert.deepStrictEqual(Array.from(new Set(literals)).sort(), ['./Interfaces', 'js-sha3']);
    });
});

describe('React Native entry point: EXTERNAL mode', () => {
    const requested: string[] = [];

    const originalResolveFilename = Module._resolveFilename;

    const testdata =
        '0100fb8e8ac805899323371bb790db19218afd8db8e3755d8b90f39b3d5506a9' +
        'abce4fa912244500000000ee8146d49fa93ee724deb57d12cbc6c6f3b924d946' +
        '127c7a97418f9348828f0f02';

    const expectedHash = 'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0';

    const calls: { [name: string]: any[][] } = {};

    /* Stand-ins for the host's native functions (React Native: NativeModules.TurtleCoin) */
    const spy = (name: string, impl: (...args: any[]) => any) => (...args: any[]): Promise<any> => {
        (calls[name] = calls[name] || []).push(args);

        return Promise.resolve(impl(...args));
    };

    let rn: any;

    let crypto: any;

    before(() => {
        /* Records what the entry point and the modules it loads ask for (not what
           mocha itself loads meanwhile) */
        const entry = path.join(dist, 'react-native.js');

        const jsSha3 = path.join('node_modules', 'js-sha3') + path.sep;

        Module._resolveFilename = function (this: any, request: string, parent: any, ...rest: any[]) {
            const from: string = (parent && parent.filename) || '';

            if (request === entry || from.indexOf(dist + path.sep) === 0 || from.indexOf(jsSha3) !== -1) {
                requested.push(request);
            }

            return originalResolveFilename.call(this, request, parent, ...rest);
        };

        for (const key of Object.keys(require.cache)) {
            if (key.indexOf(dist + path.sep) === 0) {
                delete require.cache[key];
            }
        }

        rn = require(entry);
    });

    after(() => {
        Module._resolveFilename = originalResolveFilename;
    });

    it('Without the KryptokronaCrypto module new Crypto() starts in EXTERNAL mode', () => {
        crypto = new rn.Crypto();

        assert.strictEqual(rn.Crypto.type, rn.CryptoType.EXTERNAL);

        assert.strictEqual(crypto.type, rn.CryptoType.EXTERNAL);

        assert.strictEqual(rn.Crypto.isNative, false);

        assert.strictEqual(rn.Crypto.isReady, false);
    });

    it('forceJSCrypto() has no JS build to switch to', () => {
        assert.strictEqual(crypto.forceJSCrypto(), false);

        assert.strictEqual(rn.Crypto.type, rn.CryptoType.EXTERNAL);
    });

    it('A primitive the host did not register rejects, naming it', async () => {
        await assert.rejects(crypto.generateKeys(), /generateKeys is not registered/);

        await assert.rejects(crypto.scReduce32(expectedHash), /scReduce32 is not registered/);
    });

    it('cn_fast_hash falls back to js-sha3, without a global Buffer', async () => {
        const savedBuffer = (global as any).Buffer;

        let hash = '';

        try {
            (global as any).Buffer = undefined;

            hash = await crypto.cn_fast_hash(testdata);
        } finally {
            (global as any).Buffer = savedBuffer;
        }

        assert.strictEqual(hash, expectedHash);
    });

    it('deriveViewTag is computed in JS when the host registers none', async () => {
        for (const vector of viewTagVectors.monero) {
            assert.strictEqual(await crypto.deriveViewTag(vector.derivation, vector.index), vector.view_tag);
        }
    });

    it('Functions passed to new Crypto(config) are used (as kryptokrona-utils passes them)', async () => {
        const derivation = '4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20';

        const publicKey = '3b0cc2b066812e6b9fcc42a797dc3c723a7344b604fd4be0b22e06254ff57f94';

        const privateKey = '6968a0b8f744ec4b8cea5ec124a1b4bd1626a2e6f31e999f8adbab52c4dfa909';

        const other = new rn.Crypto({
            cn_fast_hash: spy('cn_fast_hash', (data: string) => keccak256(Buffer.from(data, 'hex'))),
            checkKey: spy('checkKey', () => true),
            scReduce32: spy('scReduce32', (data: string) => data),
            generateKeyDerivation: spy('generateKeyDerivation', () => derivation),
            /* React Native's native module answers with publicKey / secretKey */
            generateKeys: spy('generateKeys', () => ({ publicKey, secretKey: privateKey }))
        });

        assert.strictEqual(other.type, rn.CryptoType.EXTERNAL);

        assert.strictEqual(rn.Crypto.isReady, true);

        assert.strictEqual(await crypto.cn_fast_hash(testdata), expectedHash);

        assert.strictEqual(calls.cn_fast_hash.length, 1);

        assert.strictEqual(
            await crypto.generateKeyDerivation(publicKey.toUpperCase(), privateKey), derivation);

        assert.deepStrictEqual(calls.generateKeyDerivation, [[publicKey, privateKey]]);

        assert.deepStrictEqual(calls.checkKey, [[publicKey]]);

        assert.deepStrictEqual(calls.scReduce32, [[privateKey]]);

        assert.deepStrictEqual(await crypto.generateKeys(), { private_key: privateKey, public_key: publicKey });
    });

    it('Functions set through Crypto.userCryptoFunctions are used', async () => {
        rn.Crypto.userCryptoFunctions = { deriveViewTag: spy('deriveViewTag', () => 'ab') };

        const vector = viewTagVectors.monero[0];

        assert.strictEqual(await crypto.deriveViewTag(vector.derivation, vector.index), 'ab');

        assert.deepStrictEqual(calls.deriveViewTag, [[vector.derivation, vector.index]]);
    });

    it('A failing host function rejects', async () => {
        rn.Crypto.userCryptoFunctions = {
            underivePublicKey: () => {
                throw new Error('native failure');
            }
        };

        await assert.rejects(crypto.underivePublicKey(
            '4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20', 2,
            'bb55bef919d1c9f74b5b52a8a6995a1dc4af4c0bb8824f5dc889012bc748173d'),
        /Error with use defined cryptographic primitive/);
    });

    it('Nothing forbidden was requested while loading and using the entry point', () => {
        /* the entry point itself, ./Crypto, ./Interfaces, ./native, react-native (absent in
           Node.js) and js-sha3 */
        assert(requested.length >= 5, 'the require hook saw ' + JSON.stringify(requested));

        assert.deepStrictEqual(requested.filter(isForbidden), []);

        assert.strictEqual(rn.Crypto.type, rn.CryptoType.EXTERNAL);
    });
});
