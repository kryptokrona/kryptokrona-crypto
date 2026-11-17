// Copyright (c) 2026, The Kryptokrona Developers
//
// Please see the included LICENSE file for more information.

/*
 * KryptokronaCrypto: the pure C++ Turbo Native Module of kryptokrona-crypto for React Native
 * (New Architecture), one source for iOS and Android. Every method converts its arguments,
 * calls the C ABI of the Rust crypto core (xkr_crypto_ffi.h, linked from
 * prebuilt/<platform>) and converts the result back; parsing, validation and JSON handling
 * happen in Rust.
 *
 * Light methods are synchronous and throw a JS Error on failure. Heavy ones return promises
 * and run on a small worker pool (findPowShare on a thread of its own, it starts its own
 * workers); their promises settle on the JS thread through the CallInvoker.
 *
 * The spec is spec/NativeKryptokronaCrypto.ts; typescript/native.ts adapts the shapes to the
 * Crypto class.
 */

#pragma once

#include <KryptokronaCryptoSpecJSI.h>
#include <react/bridging/Promise.h>

#include <memory>
#include <string>
#include <vector>

namespace facebook::react
{
    class KryptokronaCryptoModule : public NativeKryptokronaCryptoCxxSpec<KryptokronaCryptoModule>
    {
      public:
        explicit KryptokronaCryptoModule(std::shared_ptr<CallInvoker> jsInvoker);

        /* synchronous */
        bool checkKey(jsi::Runtime &rt, std::string publicKey);

        bool checkSignature(jsi::Runtime &rt, std::string prefixHash, std::string publicKey, std::string signature);

        bool checkRingSignature(
            jsi::Runtime &rt,
            std::string prefixHash,
            std::string keyImage,
            std::vector<std::string> publicKeys,
            std::vector<std::string> signatures);

        std::string cn_fast_hash(jsi::Runtime &rt, std::string data);

        std::string secretKeyToPublicKey(jsi::Runtime &rt, std::string privateKey);

        std::string scReduce32(jsi::Runtime &rt, std::string scalar);

        std::string hashToEllipticCurve(jsi::Runtime &rt, std::string hash);

        std::string hashToScalar(jsi::Runtime &rt, std::string data);

        std::vector<std::string> generateKeys(jsi::Runtime &rt);

        std::string generateKeyDerivation(jsi::Runtime &rt, std::string publicKey, std::string privateKey);

        std::string derivePublicKey(jsi::Runtime &rt, std::string derivation, double outputIndex, std::string publicKey);

        std::string
            deriveSecretKey(jsi::Runtime &rt, std::string derivation, double outputIndex, std::string privateKey);

        std::string
            underivePublicKey(jsi::Runtime &rt, std::string derivation, double outputIndex, std::string derivedKey);

        std::string generateKeyImage(jsi::Runtime &rt, std::string publicKey, std::string privateKey);

        std::string
            generateSignature(jsi::Runtime &rt, std::string prefixHash, std::string publicKey, std::string privateKey);

        std::string deriveViewTag(jsi::Runtime &rt, std::string derivation, double outputIndex);

        bool clsagVerify(
            jsi::Runtime &rt,
            std::string prefixHash,
            std::vector<std::string> ring,
            std::string keyImage,
            std::string c1,
            std::vector<std::string> s);

        /* asynchronous */
        AsyncPromise<std::string> cn_turtle_lite_slow_hash_v2(jsi::Runtime &rt, std::string data);

        AsyncPromise<std::vector<std::string>>
            generateDeterministicSubwalletKeys(jsi::Runtime &rt, std::string basePrivateKey, double walletIndex);

        AsyncPromise<std::vector<std::string>> generateRingSignatures(
            jsi::Runtime &rt,
            std::string prefixHash,
            std::string keyImage,
            std::vector<std::string> publicKeys,
            std::string privateKey,
            double realIndex);

        AsyncPromise<std::vector<std::string>> clsagSign(
            jsi::Runtime &rt,
            std::string prefixHash,
            std::vector<std::string> ring,
            std::string privateEphemeral,
            double realOutputIndex,
            std::string alpha,
            std::vector<std::string> decoyResponses);

        AsyncPromise<std::string> processBlockOutputs(
            jsi::Runtime &rt,
            std::string blockJson,
            std::string privateViewKey,
            std::string spendKeysJson,
            bool isViewWallet,
            bool processCoinbaseTransactions);

        AsyncPromise<std::string> findPowShare(
            jsi::Runtime &rt,
            std::string blobHex,
            std::string targetHex,
            double startNonce,
            double maxAttempts,
            double nonceTagBits,
            double nonceTagValue);

      private:
        /* Empty when the linked library has the ABI of the header, else the reason every
           call fails */
        std::string abiProblem_;

        void requireAbi(jsi::Runtime &rt) const;
    };
} // namespace facebook::react
