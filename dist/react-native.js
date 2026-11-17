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
exports.findPowShare = exports.processBlockOutputs = exports.nativeCrypto = void 0;
/*
 * The React Native entry point (the "react-native" field of package.json, which Metro
 * reads before "main").
 *
 * When the app has the KryptokronaCrypto Turbo Native Module of this package (New
 * Architecture, autolinked from cpp/, ios/ and android/), the wrapper runs on it
 * (CryptoType.REACTNATIVE) without any registration by the app. Otherwise it starts in
 * CryptoType.EXTERNAL and every primitive comes from the functions the host registers,
 * either
 *
 *     Crypto.userCryptoFunctions = { cn_fast_hash, generateKeyDerivation, ... };
 *
 * or `new Crypto({ ... })` (kryptokrona-utils' CryptoNote and kryptokrona-wallet-backend-js
 * pass their crypto config this way). Registered functions take precedence over the module in
 * both cases. A primitive that is neither registered nor in the module rejects with an error
 * naming it. deriveViewTag falls back to a JS computation (js-sha3).
 *
 * It never requires the Node.js addon or any Node.js module: the module graph of this file is
 * Crypto.ts, Interfaces.ts, native.ts, js-sha3 and react-native.
 */
const Crypto_1 = require("./Crypto");
const Interfaces_1 = require("./Interfaces");
const native_1 = require("./native");
var Crypto_2 = require("./Crypto");
Object.defineProperty(exports, "Crypto", { enumerable: true, get: function () { return Crypto_2.Crypto; } });
Object.defineProperty(exports, "CryptoType", { enumerable: true, get: function () { return Crypto_2.CryptoType; } });
/**
 * @ignore
 * The Turbo Native Module, or null outside React Native or when the app does not have it
 */
function loadTurboModule() {
    try {
        const ReactNative = require('react-native');
        const registry = ReactNative && ReactNative.TurboModuleRegistry;
        if (registry && typeof registry.get === 'function') {
            return registry.get('KryptokronaCrypto') || null;
        }
    }
    catch (e) {
        /* not running in React Native */
    }
    return null;
}
/**
 * @ignore
 */
const turboModule = loadTurboModule();
/**
 * The KryptokronaCrypto module adapted to the Crypto method names and shapes, or null when the
 * app does not have the module. For direct calls; the Crypto class already uses it.
 */
exports.nativeCrypto = turboModule ? native_1.createReactNativeCrypto(turboModule) : null;
Crypto_1.setCryptoLoader({
    initialize: () => (exports.nativeCrypto ? Crypto_1.setCryptoModule(exports.nativeCrypto, Interfaces_1.CryptoType.REACTNATIVE) : Crypto_1.useExternalCrypto()),
    forceJS: () => false
});
/**
 * @ignore
 */
function requireModule() {
    if (!exports.nativeCrypto) {
        throw new Error('kryptokrona-crypto: the KryptokronaCrypto native module is not available');
    }
    return exports.nativeCrypto;
}
/**
 * Scans the outputs of a block for a wallet's subwallets (the hook that
 * wallet-backend-js installs with setBlockOutputProcessFunc), off the JS thread. Coinbase
 * first (when processed), then the transactions in order; a missing globalIndex gives
 * globalOutputIndex -1; a view wallet gets the all-zero key image. Rejects when the module is
 * not available.
 */
function processBlockOutputs(block, privateViewKey, spendKeys, isViewWallet, processCoinbaseTransactions) {
    return __awaiter(this, void 0, void 0, function* () {
        return native_1.nativeExports(requireModule()).processBlockOutputs(block, privateViewKey, spendKeys, isViewWallet, processCoinbaseTransactions);
    });
}
exports.processBlockOutputs = processBlockOutputs;
/**
 * Searches for a Hugin message proof-of-work share off the JS thread:
 * { job_id: '', nonce, result, hashes_performed, threads } when found,
 * { hashes_performed, threads } when not, null for unusable input. Rejects when the module is
 * not available.
 */
function findPowShare(blobHex, targetHex, startNonce, maxAttempts, nonceTagBits = 0, nonceTagValue = 0) {
    return __awaiter(this, void 0, void 0, function* () {
        return native_1.nativeExports(requireModule()).findPowShare(blobHex, targetHex, startNonce, maxAttempts, nonceTagBits, nonceTagValue);
    });
}
exports.findPowShare = findPowShare;
