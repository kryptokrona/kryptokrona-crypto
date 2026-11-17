# Changelog

## 2.0.0

The native code of the package is now the crypto core of the Kryptokrona node: the Rust crates
`xkr-crypto-ffi` and `xkr-crypto` of the node repository (`xkr`), pinned by revision in
`rust/Cargo.toml`. Node.js, Electron and the React Native apps run the same implementation, and
the TypeScript `Crypto` API is unchanged.

### Changed

* **Node.js / Electron: a Node-API addon replaces the C++ addon.** `dist/index.js` loads
  `prebuilt/napi/kryptokrona-crypto.<platform>.node` (built from `rust/napi` with napi-rs;
  prebuilt for linux-x64-gnu, linux-arm64-gnu, darwin-x64, darwin-arm64 and win32-x64-msvc).
  Node-API is stable across versions, so one file per platform serves every Node.js and Electron
  release; there is no `node-gyp` step at install time any more. `KRYPTOKRONA_CRYPTO_NAPI` points
  the loader at another build. New `CryptoType.NAPI`; `Crypto.isNative` is `true` with it.
  Without an addon for the platform the wrapper starts in `CryptoType.EXTERNAL` (the functions in
  `Crypto.userCryptoFunctions`), as on React Native.
* **React Native: a C++ Turbo Native Module.** With the New Architecture the package autolinks
  the module `KryptokronaCrypto` (`cpp/`, one source for iOS and Android, over the static Rust
  library in `prebuilt/ios` and `prebuilt/android`), and the `react-native` entry point uses it
  automatically (`CryptoType.REACTNATIVE`). Functions registered in `Crypto.userCryptoFunctions`
  still take precedence; without the module the entry point behaves as in 1.1.0
  (`CryptoType.EXTERNAL`).
* Invalid input to a native function rejects with an `Error` whose message names the argument
  (for example `key_image_a: not a valid public key`). Fixed-size values need exactly their
  number of hex characters.
* `generateDeterministicSubwalletKeys` and `generateViewKeysFromPrivateSpendKey` resolve both
  `private_key` and `public_key` with every backend, and `prepareRingSignatures` accepts `k` or
  `key` in the result of a registered function.
* `tree_hash_from_branch` with the addon: `path` 0 keeps the leaf on the left; another number
  selects the side at depth `d` by bit `d`.
* `chukwa_slow_hash*` need at least 16 bytes of data (the salt).

### Added

* `processBlockOutputs(block, privateViewKey, spendKeys, isViewWallet, processCoinbase)` and
  `findPowShare(blobHex, targetHex, startNonce, maxAttempts[, nonceTagBits, nonceTagValue])`,
  exported by both entry points (not part of `Crypto`): the wallet output scan and the Hugin
  message share search of the mobile app, off the JavaScript thread. The `react-native` entry
  point also exports `nativeCrypto` (the module adapted to the `Crypto` method names).
* `CryptoType.NAPI`, `CryptoType.REACTNATIVE`.
* `rust/`: the crates `kryptokrona-crypto-napi` (addon), `kryptokrona-crypto-mobile` (static
  library with the C ABI of `cpp/xkr_crypto_ffi.h`) and `kryptokrona-crypto-extra` (multisig
  helpers, `scalarmultKey`, `tree_hash_from_branch` and Chukwa for the addon).
* `kryptokrona-crypto.podspec`, `android/`, `react-native.config.js`, `spec/` (codegen) and the
  `codegenConfig` in `package.json`.
* `.github/workflows/release.yml`: Rust tests, the addon for each platform with the mocha tests,
  the Android libraries (arm64-v8a, armeabi-v7a, x86_64, x86), the iOS XCFramework and the npm
  tarball.

### Removed

* The C++ sources (`src/`, `include/`, `external/`), `binding.gyp`, the CMake build, the C#
  example, the Emscripten build (`build_js.sh`, `emsdk`) and `dist/turtlecoin-crypto.js`; the
  dependencies `nan`, `bindings` and `prebuild-install`. `forceJSCrypto()` returns `false`
  (there is no JS build) and `CryptoType.NODEADDON` and `CryptoType.JS` are no longer set.
* `cn_soft_shell_slow_hash_v0/1/2` have no native implementation (the 1.x addon did not export
  them either); they reject unless a host registers them.

## 1.1.0

Primitives for transaction version 2 (fork 14: view tags and single-key CLSAG). The Rust node
(`xkr`, `crates/xkr-crypto`) is the reference implementation; the results match it byte for byte
on its exported test vectors.

React Native uses the package without patching it: a `react-native` entry point runs on the
functions the app registers and never loads the native addon or a JS/WASM build.

### Changed

* **React Native entry point.** `package.json` has `"react-native": "dist/react-native.js"`, which
  Metro reads before `main`. That module starts the wrapper in `CryptoType.EXTERNAL` and requires
  nothing but the wrapper itself and `js-sha3`: no `bindings`/native addon, no
  `turtlecoin-crypto.js`, no WASM, no Node.js module. Every primitive comes from
  `Crypto.userCryptoFunctions` (or `new Crypto(config)`); one that was not registered rejects with
  `... <name> is not registered in Crypto.userCryptoFunctions (external cryptography)`.
  `forceJSCrypto()` returns `false` there. This replaces the hugin-native patch of 1.0.3's
  `dist/index.js` (which replaced `initialize()` with an empty `EXTERNAL` module and commented
  out the `require`s of the JS and WASM builds).
* The TypeScript sources are split: `typescript/Crypto.ts` holds the `Crypto` class (unchanged
  API), `typescript/index.ts` is the Node.js entry point (native addon first, then the JS build,
  as before) and `typescript/react-native.ts` the React Native one. The Node.js entry point loads
  the addon and the JS build with a computed `require()`, so bundlers do not follow them.
* **The WASM build is gone.** `dist/turtlecoin-crypto-wasm.js` is no longer shipped, and the
  browser loaders (`window.TurtleCoinCrypto`, `turtlecoin-crypto-wasm.js`) are removed;
  `build_js.sh` only builds the JS (asm.js) file. `CryptoType.WASM` and `CryptoType.WASMJS` stay
  in the enum for compatibility but are never set. `npm run build` (new; `build-typescript` is an
  alias) runs only `tsc`, and `prepublishOnly` no longer runs Emscripten.
* `Crypto.isReady` in `EXTERNAL` mode is `true` once `cn_fast_hash` is registered (was always
  `false`). The JS fallback of `cn_fast_hash` no longer needs a global `Buffer`.

* `include/random.h` now reads every random byte directly from the operating system: `getrandom(2)`
  on Linux and Android (falling back to `/dev/urandom` on `ENOSYS`/`EPERM`), `arc4random_buf` on
  macOS, iOS and the BSDs, `BCryptGenRandom` on Windows, and `getentropy()` in the Emscripten
  builds. A failure throws `std::runtime_error`
  (an abort in Emscripten builds without exceptions). `Random::generator()` returns a stateless
  OS-backed engine (`Random::Engine`) and `randomValue<T>` draws through it. Windows builds link
  `bcrypt`.

### Added

* `deriveViewTag(derivation, output_index)`: view tag of an output,
  `cn_fast_hash("view_tag" || derivation || varint(output_index))[0]` (Monero's
  `derive_view_tag`), returned as two lowercase hex characters. The TypeScript wrapper computes it
  with `js-sha3` when the loaded module lacks the function or the index does not fit in 32 bits.
* `clsagSign(prefix_hash, ring, private_ephemeral, real_output_index[, alpha, decoy_responses])`:
  single-key CLSAG signature `{ c1, s }` with the domain separators `XKR_CLSAG_agg_0` and
  `XKR_CLSAG_round`. With `alpha` and the `ring.length - 1` decoy responses (consumption order
  `s[l+1], .., s[n-1], s[0], .., s[l-1]`) the signature is deterministic, as Rust's
  `clsag_sign_with_randomness`; without them the randomness is drawn in the same order.
* `clsagVerify(prefix_hash, ring, key_image, c1, s)`: rejects an empty ring, a wrong number of
  responses, non-canonical scalars, a key image that is the identity or outside the prime-order
  subgroup, non-canonical point encodings and a zero round hash.
* The three functions in every layer: C++ (`Crypto::crypto_ops::clsag_sign`, `clsag_verify`,
  `derive_view_tag`), the string API (`Core::Cryptography::clsagSign`, `clsagVerify`,
  `deriveViewTag`), the Node.js addon, the Emscripten (JS/WASM) bindings, the TypeScript `Crypto`
  class and its `ICryptoConfig` override hooks (new type `IClsagSignature`).
* Tests: `Random::randomBytes` sanity checks in `tests/cryptotest.cpp` (two draws differ, no byte
  value above twice its expected frequency in 10 000 bytes) and 1000 distinct `generateKeys` key
  pairs in `tests/crypto.ts`.
* Tests: `tests/vectors/tx-v2-clsag.json` and `tests/vectors/tx-v2-view-tags.json` (copies of the
  Rust vectors) in `tests/crypto.ts` and one vector of each in `tests/cryptotest.cpp`.
* Tests: `tests/react-native.ts` (`npm run test-react-native`, part of `npm test`): the module
  graph of `dist/react-native.js` (statically, and every `require` it makes at run time) reaches
  no addon, JS/WASM build or Node.js module; `EXTERNAL` mode with user-supplied functions. The CLSAG
  tests are skipped under `FORCE_JS` (the asm.js build has no CLSAG).

### Notes

* The committed `dist/` TypeScript output must be regenerated (`npm run build`) before
  publishing.
* `dist/turtlecoin-crypto.js` (the JS fallback of the Node.js entry point) is still the 1.0.x
  Emscripten build and is not rebuilt: it has no CLSAG (`deriveViewTag` falls back to js-sha3).
  `Crypto.type === CryptoType.NODEADDON` tells whether the native addon is loaded.
