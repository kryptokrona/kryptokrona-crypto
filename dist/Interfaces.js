"use strict";
// Copyright (c) 2020, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.
Object.defineProperty(exports, "__esModule", { value: true });
exports.CryptoType = void 0;
/**
 * Represents the type of underlying cryptographic methods
 */
var CryptoType;
(function (CryptoType) {
    CryptoType[CryptoType["UNKNOWN"] = 0] = "UNKNOWN";
    /** No longer used: the C++ (node-gyp) addon of 1.x, replaced by NAPI in 2.0.0 (the value is kept) */
    CryptoType[CryptoType["NODEADDON"] = 1] = "NODEADDON";
    /** No longer used: the WASM build was removed in 1.1.0 (the value is kept) */
    CryptoType[CryptoType["WASM"] = 2] = "WASM";
    /** No longer used: the WASM build was removed in 1.1.0 (the value is kept) */
    CryptoType[CryptoType["WASMJS"] = 3] = "WASMJS";
    /** No longer used: the JS (asm.js) build was removed in 2.0.0 (the value is kept) */
    CryptoType[CryptoType["JS"] = 4] = "JS";
    CryptoType[CryptoType["MIXED"] = 5] = "MIXED";
    /** No module of our own: the functions registered in Crypto.userCryptoFunctions */
    CryptoType[CryptoType["EXTERNAL"] = 6] = "EXTERNAL";
    /** The Node-API addon (Node.js and Electron), on the Rust crypto core */
    CryptoType[CryptoType["NAPI"] = 7] = "NAPI";
    /** The React Native Turbo Native Module KryptokronaCrypto, on the Rust crypto core */
    CryptoType[CryptoType["REACTNATIVE"] = 8] = "REACTNATIVE";
})(CryptoType = exports.CryptoType || (exports.CryptoType = {}));
