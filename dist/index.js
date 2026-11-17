"use strict";
// Copyright (c) 2020, The TurtleCoin Developers
// Copyright (c) 2026, The Kryptokrona Developers
//
// Please see the included LICENSE file for more information.
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.findPowShare = exports.processBlockOutputs = exports.napiCandidates = exports.napiPlatform = void 0;
/*
 * The Node.js / Electron entry point ("main"): the Node-API addon of this package
 * (prebuilt/napi/kryptokrona-crypto.<platform>.node, Rust; see rust/napi).
 *
 * React Native (Metro) resolves the "react-native" field of package.json to
 * react-native.ts instead, which never loads it. Without an addon for the platform the
 * wrapper runs on the functions the host registers (CryptoType.EXTERNAL), as on React Native.
 */
const path = require("path");
const Interfaces_1 = require("./Interfaces");
const Crypto_1 = require("./Crypto");
const native_1 = require("./native");
var Crypto_2 = require("./Crypto");
Object.defineProperty(exports, "Crypto", { enumerable: true, get: function () { return Crypto_2.Crypto; } });
Object.defineProperty(exports, "CryptoType", { enumerable: true, get: function () { return Crypto_2.CryptoType; } });
/**
 * @ignore
 * require() with a computed specifier: bundlers (Metro, webpack, esbuild, ...) do not
 * follow it, so the addon is not pulled into a bundle that only references this file.
 * Node.js resolves it as usual.
 */
function loadOptionalModule(id) {
    return require(id);
}
/**
 * @ignore
 * The platform part of the addon file name, as napi-rs names its builds
 */
function napiPlatform() {
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
exports.napiPlatform = napiPlatform;
/**
 * @ignore
 * Where the addon is looked for: KRYPTOKRONA_CRYPTO_NAPI (a path to a .node file) first,
 * then the prebuilt file of this platform shipped in the package
 */
function napiCandidates() {
    const candidates = [];
    if (process.env.KRYPTOKRONA_CRYPTO_NAPI) {
        candidates.push(path.resolve(process.env.KRYPTOKRONA_CRYPTO_NAPI));
    }
    candidates.push(path.join(__dirname, '..', 'prebuilt', 'napi', 'kryptokrona-crypto.' + napiPlatform() + '.node'));
    return candidates;
}
exports.napiCandidates = napiCandidates;
/**
 * @ignore
 */
let addon = null;
/**
 * @ignore
 */
function loadNapi() {
    for (const candidate of napiCandidates()) {
        try {
            const Self = loadOptionalModule(candidate);
            if (Self && typeof Self.cn_fast_hash === 'function') {
                addon = Self;
                return Crypto_1.setCryptoModule(Self, Interfaces_1.CryptoType.NAPI);
            }
        }
        catch (e) {
            /* try the next one */
        }
    }
    return false;
}
Crypto_1.setCryptoLoader({
    initialize: () => loadNapi() || Crypto_1.useExternalCrypto(),
    forceJS: () => false
});
/**
 * Scans the outputs of a block for a wallet's subwallets (the hook that
 * wallet-backend-js installs with setBlockOutputProcessFunc), on the addon's thread pool.
 * Rejects when the addon is not loaded.
 */
function processBlockOutputs(block, privateViewKey, spendKeys, isViewWallet, processCoinbaseTransactions) {
    return __awaiter(this, void 0, void 0, function* () {
        return native_1.nativeExports(requireAddon()).processBlockOutputs(block, privateViewKey, spendKeys, isViewWallet, processCoinbaseTransactions);
    });
}
exports.processBlockOutputs = processBlockOutputs;
/**
 * Searches for a Hugin message proof-of-work share, on the addon's thread pool; null for
 * unusable input. Rejects when the addon is not loaded.
 */
function findPowShare(blobHex, targetHex, startNonce, maxAttempts, nonceTagBits = 0, nonceTagValue = 0) {
    return __awaiter(this, void 0, void 0, function* () {
        return native_1.nativeExports(requireAddon()).findPowShare(blobHex, targetHex, startNonce, maxAttempts, nonceTagBits, nonceTagValue);
    });
}
exports.findPowShare = findPowShare;
/**
 * @ignore
 */
function requireAddon() {
    if (addon === null) {
        loadNapi();
    }
    if (addon === null) {
        throw new Error('kryptokrona-crypto: no native addon for ' + napiPlatform());
    }
    return addon;
}
