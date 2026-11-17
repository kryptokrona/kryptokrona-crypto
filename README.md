# Kryptokrona: Cryptography Library

![Node](https://img.shields.io/badge/node-%3E%3D12.17-blue.svg) [![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-yellow.svg)](https://github.com/kryptokrona/kryptokrona-crypto/blob/master/LICENSE)

The cryptographic primitives of Kryptokrona (keys, derivations, key images, ring and CLSAG
signatures, view tags, CryptoNight and the other slow hashes) for JavaScript:

* **Node.js and Electron**: a Node-API addon (one prebuilt file per platform for every Node.js
  and Electron version),
* **React Native** (New Architecture): a C++ Turbo Native Module for iOS and Android,
* any other runtime, with the primitives supplied by the host.

All native code is the crypto core of the Kryptokrona node (the Rust crates `xkr-crypto-ffi` and
`xkr-crypto` of the node repository), so wallets, Hugin and the node compute with the same
implementation and the same test vectors.

## Installation

```bash
npm install kryptokrona-crypto
```

The package ships prebuilt native libraries for linux-x64-gnu, linux-arm64-gnu, darwin-x64,
darwin-arm64 and win32-x64-msvc (Node-API) and for Android (arm64-v8a, armeabi-v7a, x86_64, x86)
and iOS (device and simulator). Nothing is compiled at install time.

## Usage

```javascript
import { Crypto } from 'kryptokrona-crypto';   // or: const { Crypto } = require('kryptokrona-crypto')

const crypto = new Crypto();
const keys = await crypto.generateKeys();     // { private_key, public_key }
```

Every method returns a promise. Invalid input rejects with an `Error` naming the argument.

### Entry points

* `main` (`dist/index.js`, Node.js and Electron): loads
  `prebuilt/napi/kryptokrona-crypto.<platform>.node` (`CryptoType.NAPI`). The environment variable
  `KRYPTOKRONA_CRYPTO_NAPI` points it at another build. The addon is loaded with a computed
  `require()`, so bundlers do not follow it; Electron apps unpack `*.node` from the asar archive
  as usual. Without an addon for the platform the wrapper starts in `CryptoType.EXTERNAL` (below).
* `react-native` (`dist/react-native.js`, read by Metro before `main`): uses the Turbo Native
  Module `KryptokronaCrypto` of this package (`CryptoType.REACTNATIVE`); the app does not need to
  register anything. Without the module (old architecture, other runtimes) it starts in
  `CryptoType.EXTERNAL`. It never loads the Node.js addon or a Node.js module.

In every mode, functions registered by the host take precedence:

```javascript
Crypto.userCryptoFunctions = {
    cn_fast_hash: (data) => myNativeModule.cnFastHash(data),
    // ...
};
// or: new Crypto({ ... }), which is what kryptokrona-utils' CryptoNote and
// kryptokrona-wallet-backend-js do with their crypto config
```

In `CryptoType.EXTERNAL` a primitive that was not registered rejects with an error that names
it; `cn_fast_hash` and `deriveViewTag` fall back to a JS computation (js-sha3). Wrapper methods
check their inputs with other primitives, so register those too: most key and signature methods
call `checkKey` and `scReduce32` (through `checkScalar`). `Crypto.isReady` is `true` once
`cn_fast_hash` is available.

### React Native

Requirements: React Native 0.76 or later with the New Architecture (the default since 0.76),
iOS 15.1, Android API 24. Autolinking adds the pod (`kryptokrona-crypto.podspec`) and the
Android library; the module is created by the app's generated C++ module provider (the
`OnLoad.cpp` of a React Native app calls `autolinking_cxxModuleProvider`).

The module has the functions a mobile wallet needs: `checkKey`, `checkSignature`,
`checkRingSignature(s)`, `cn_fast_hash`, `secretKeyToPublicKey`, `scReduce32`,
`hashToEllipticCurve`, `hashToScalar`, `generateKeys`, `generateKeyDerivation`,
`derivePublicKey`, `deriveSecretKey`, `underivePublicKey`, `generateKeyImage`,
`generateSignature`, `generateRingSignatures`, `generateDeterministicSubwalletKeys`,
`cn_turtle_lite_slow_hash_v2`, `deriveViewTag`, `clsagSign`, `clsagVerify`. The slow hash, the
signing functions, the subwallet keys and the two exports below run on worker threads.

### Wallet scan and Hugin proof of work

Both entry points export two functions outside `Crypto`:

* `processBlockOutputs(block, privateViewKey, spendKeys, isViewWallet, processCoinbaseTransactions)`:
  the outputs of a wallet-backend `Block` owned by the subwallets `spendKeys`
  (`[{ publicKey, privateKey }]`), as `[{ publicSpendKey, input: { keyImage, amount,
  transactionIndex, globalOutputIndex, key, parentTransactionHash } }]`, coinbase first, then
  the transactions in order. A missing `globalIndex` gives `globalOutputIndex: -1`; a view
  wallet gets the all-zero key image; an output's `viewTag` (transaction version 2) is checked
  first and skips the point arithmetic on a mismatch.
* `findPowShare(blobHex, targetHex, startNonce, maxAttempts[, nonceTagBits, nonceTagValue])`:
  `{ job_id: '', nonce, result, hashes_performed, threads }` when a share was found,
  `{ hashes_performed, threads }` when not, `null` for unusable input. Workers:
  `max(1, floor(0.8 × cores))`, at most 8.

### Transaction version 2 (fork 14)

* `deriveViewTag(derivation, output_index)`: the first byte of
  `cn_fast_hash("view_tag" || derivation || varint(output_index))`, as two hex characters.
* `clsagSign(prefix_hash, ring, private_ephemeral, real_output_index[, alpha, decoy_responses])`:
  `{ c1, s }`. Without `alpha` and `decoy_responses` the randomness comes from the operating
  system; with them (the nonce, then the `ring.length - 1` responses of the other members in the
  order `s[l+1], .., s[l-1]`) the signature is deterministic.
* `clsagVerify(prefix_hash, ring, key_image, c1, s)`: `true` for a valid signature.

The Rust node (`xkr`) is the reference; `tests/vectors/` holds its test vectors.

### Not provided natively

`cn_soft_shell_slow_hash_v0/1/2` have no native implementation; they work only when the host
registers them.

## Native code

```text
rust/                 Cargo workspace (toolchain 1.100.0)
  napi/               Node-API addon (napi-rs)              -> prebuilt/napi/*.node
  mobile/             static library with the C ABI         -> prebuilt/android, prebuilt/ios
  extra/              multisig helpers, scalarmultKey, tree_hash_from_branch, Chukwa (addon only)
cpp/                  the C++ Turbo Native Module + xkr_crypto_ffi.h (the C ABI, from xkr)
ios/                  module provider for iOS
android/              build.gradle (codegen) + CMakeLists.txt
spec/                 codegen spec of the module
typescript/           the Crypto class and the entry points
```

### Building

```bash
npm ci --ignore-scripts
npm run build              # TypeScript -> dist/
npm run build-napi         # Rust addon for this machine -> prebuilt/napi/ (needs Rust 1.100.0)
npm test                   # mocha: Node.js addon, React Native entry point, module adapter
npm run test-rust          # cargo test of rust/extra
npm run build-android      # Android libraries (NDK, cargo-ndk); see scripts/build-android.sh
npm run build-ios          # iOS XCFramework (macOS + Xcode); see scripts/build-ios.sh
```

Run cargo from `rust/`. `rust/Cargo.toml` takes the node's crates from a release tag of the node repository
(`[workspace.metadata.xkr]`). To build against a local checkout of the node repository instead
(next to this one by default), switch to path dependencies and back before committing:

```bash
./scripts/xkr-source.sh local            # or: ./scripts/xkr-source.sh local /path/to/xkr
./scripts/xkr-source.sh git
```

CI checks that the committed manifest uses the git tag (`scripts/check-native.sh manifest`).

### Updating the crypto core

1. The change lands in the node repository (`xkr`): `xkr-crypto`, new `xkr-crypto-ffi`
   functions, test vectors, and an ABI version bump when the C ABI changes.
2. Set `tag` in `[workspace.metadata.xkr]` of `rust/Cargo.toml` to the new release tag, run
   `scripts/xkr-source.sh git` and `cargo update -p xkr-crypto-ffi` in `rust/`, copy
   `include/xkr_crypto_ffi.h` of that release to `cpp/` (`scripts/check-native.sh header`
   compares them).
3. Extend `spec/`, `cpp/`, `typescript/native.ts` and the addon for new functions.
4. Run the Rust and mocha tests; CI builds every prebuilt.
5. Release: a minor version adds functions, a major one removes or changes them.

## Thanks

Cryptonote Developers, Bytecoin Developers, Monero Developers, Forknote Project, TurtleCoin
Community

## License

GPL-3.0, see [LICENSE](LICENSE).
