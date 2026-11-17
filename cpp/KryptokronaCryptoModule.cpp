// Copyright (c) 2026, The Kryptokrona Developers
//
// Please see the included LICENSE file for more information.

#include "KryptokronaCryptoModule.h"

#include "xkr_crypto_ffi.h"

#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>

namespace facebook::react
{
    namespace
    {
        /* A fixed set of detached worker threads with a FIFO queue. It lives for the whole
           process (module instances come and go with reloads, the threads stay). */
        class WorkerPool
        {
          public:
            explicit WorkerPool(size_t threads)
            {
                for (size_t i = 0; i < threads; i++)
                {
                    std::thread([this]() { run(); }).detach();
                }
            }

            void post(std::function<void()> task)
            {
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    queue_.push_back(std::move(task));
                }
                ready_.notify_one();
            }

          private:
            void run()
            {
                for (;;)
                {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(mutex_);
                        ready_.wait(lock, [this]() { return !queue_.empty(); });
                        task = std::move(queue_.front());
                        queue_.pop_front();
                    }
                    task();
                }
            }

            std::mutex mutex_;
            std::condition_variable ready_;
            std::deque<std::function<void()>> queue_;
        };

        WorkerPool &workers()
        {
            static WorkerPool *pool = new WorkerPool(2);
            return *pool;
        }

        XkrCryptoStr str(const std::string &s)
        {
            return XkrCryptoStr {s.data(), s.size()};
        }

        std::vector<XkrCryptoStr> strs(const std::vector<std::string> &items)
        {
            std::vector<XkrCryptoStr> out;
            out.reserve(items.size());
            for (const auto &item : items)
            {
                out.push_back(str(item));
            }
            return out;
        }

        void check(int32_t status)
        {
            if (status != XKR_CRYPTO_OK)
            {
                throw std::runtime_error(xkr_crypto_status_message(status));
            }
        }

        /* A fixed-size hex result written by `call(out, capacity)` */
        template<typename F> std::string fixed(F call, size_t capacity = XKR_CRYPTO_HEX32_SIZE)
        {
            std::string out(capacity, '\0');
            check(call(out.data(), out.size()));
            out.resize(std::char_traits<char>::length(out.c_str()));
            return out;
        }

        std::string take(XkrCryptoBuffer buffer)
        {
            std::string out(reinterpret_cast<const char *>(buffer.ptr), buffer.len);
            xkr_crypto_buffer_free(buffer);
            return out;
        }

        std::vector<std::string> split(const std::string &joined, size_t width)
        {
            std::vector<std::string> out;
            for (size_t i = 0; i + width <= joined.size(); i += width)
            {
                out.push_back(joined.substr(i, width));
            }
            return out;
        }

        /* Runs a synchronous method body; a failure becomes a JS Error */
        template<typename F> auto runSync(jsi::Runtime &rt, F body) -> decltype(body())
        {
            try
            {
                return body();
            }
            catch (const std::exception &e)
            {
                throw jsi::JSError(rt, e.what());
            }
        }

        /* Runs `work` off the JS thread and settles the promise with its result */
        template<typename T, typename F>
        AsyncPromise<T> runAsync(
            jsi::Runtime &rt,
            const std::shared_ptr<CallInvoker> &jsInvoker,
            const std::string &abiProblem,
            F work,
            bool ownThread = false)
        {
            AsyncPromise<T> promise(rt, jsInvoker);
            if (!abiProblem.empty())
            {
                promise.reject(Error(abiProblem));
                return promise;
            }
            std::function<void()> task = [promise, work]() mutable
            {
                try
                {
                    promise.resolve(work());
                }
                catch (const std::exception &e)
                {
                    promise.reject(Error(e.what()));
                }
            };
            if (ownThread)
            {
                std::thread(std::move(task)).detach();
            }
            else
            {
                workers().post(std::move(task));
            }
            return promise;
        }
    } // namespace

    KryptokronaCryptoModule::KryptokronaCryptoModule(std::shared_ptr<CallInvoker> jsInvoker):
        NativeKryptokronaCryptoCxxSpec(std::move(jsInvoker))
    {
        if (xkr_crypto_abi_version() != XKR_CRYPTO_ABI_VERSION)
        {
            abiProblem_ = "KryptokronaCrypto: the linked crypto library has ABI version "
                          + std::to_string(xkr_crypto_abi_version()) + ", the module was built for "
                          + std::to_string(XKR_CRYPTO_ABI_VERSION);
        }
    }

    void KryptokronaCryptoModule::requireAbi(jsi::Runtime &rt) const
    {
        if (!abiProblem_.empty())
        {
            throw jsi::JSError(rt, abiProblem_);
        }
    }

    /* ---- synchronous ------------------------------------------------------------------ */

    bool KryptokronaCryptoModule::checkKey(jsi::Runtime &rt, std::string publicKey)
    {
        requireAbi(rt);
        return runSync(rt, [&]() {
            uint8_t valid = 0;
            check(xkr_crypto_check_key(str(publicKey), &valid));
            return valid != 0;
        });
    }

    bool KryptokronaCryptoModule::checkSignature(
        jsi::Runtime &rt,
        std::string prefixHash,
        std::string publicKey,
        std::string signature)
    {
        requireAbi(rt);
        return runSync(rt, [&]() {
            uint8_t valid = 0;
            check(xkr_crypto_check_signature(str(prefixHash), str(publicKey), str(signature), &valid));
            return valid != 0;
        });
    }

    bool KryptokronaCryptoModule::checkRingSignature(
        jsi::Runtime &rt,
        std::string prefixHash,
        std::string keyImage,
        std::vector<std::string> publicKeys,
        std::vector<std::string> signatures)
    {
        requireAbi(rt);
        return runSync(rt, [&]() {
            const auto keys = strs(publicKeys);
            const auto sigs = strs(signatures);
            uint8_t valid = 0;
            check(xkr_crypto_check_ring_signature(
                str(prefixHash), str(keyImage), keys.data(), keys.size(), sigs.data(), sigs.size(), &valid));
            return valid != 0;
        });
    }

    std::string KryptokronaCryptoModule::cn_fast_hash(jsi::Runtime &rt, std::string data)
    {
        requireAbi(rt);
        return runSync(rt, [&]() {
            return fixed([&](char *out, size_t cap) { return xkr_crypto_cn_fast_hash(str(data), out, cap); });
        });
    }

    std::string KryptokronaCryptoModule::secretKeyToPublicKey(jsi::Runtime &rt, std::string privateKey)
    {
        requireAbi(rt);
        return runSync(rt, [&]() {
            return fixed([&](char *out, size_t cap)
                         { return xkr_crypto_secret_key_to_public_key(str(privateKey), out, cap); });
        });
    }

    std::string KryptokronaCryptoModule::scReduce32(jsi::Runtime &rt, std::string scalar)
    {
        requireAbi(rt);
        return runSync(rt, [&]() {
            return fixed([&](char *out, size_t cap) { return xkr_crypto_sc_reduce32(str(scalar), out, cap); });
        });
    }

    std::string KryptokronaCryptoModule::hashToEllipticCurve(jsi::Runtime &rt, std::string hash)
    {
        requireAbi(rt);
        return runSync(rt, [&]() {
            return fixed([&](char *out, size_t cap)
                         { return xkr_crypto_hash_to_elliptic_curve(str(hash), out, cap); });
        });
    }

    std::string KryptokronaCryptoModule::hashToScalar(jsi::Runtime &rt, std::string data)
    {
        requireAbi(rt);
        return runSync(rt, [&]() {
            return fixed([&](char *out, size_t cap) { return xkr_crypto_hash_to_scalar(str(data), out, cap); });
        });
    }

    std::vector<std::string> KryptokronaCryptoModule::generateKeys(jsi::Runtime &rt)
    {
        requireAbi(rt);
        return runSync(rt, [&]() {
            std::string publicKey(XKR_CRYPTO_HEX32_SIZE, '\0');
            std::string privateKey(XKR_CRYPTO_HEX32_SIZE, '\0');
            check(xkr_crypto_generate_keys(
                publicKey.data(), publicKey.size(), privateKey.data(), privateKey.size()));
            publicKey.resize(64);
            privateKey.resize(64);
            return std::vector<std::string> {privateKey, publicKey};
        });
    }

    std::string
        KryptokronaCryptoModule::generateKeyDerivation(jsi::Runtime &rt, std::string publicKey, std::string privateKey)
    {
        requireAbi(rt);
        return runSync(rt, [&]() {
            return fixed([&](char *out, size_t cap)
                         { return xkr_crypto_generate_key_derivation(str(publicKey), str(privateKey), out, cap); });
        });
    }

    std::string KryptokronaCryptoModule::derivePublicKey(
        jsi::Runtime &rt,
        std::string derivation,
        double outputIndex,
        std::string publicKey)
    {
        requireAbi(rt);
        return runSync(rt, [&]() {
            return fixed(
                [&](char *out, size_t cap)
                { return xkr_crypto_derive_public_key(str(derivation), outputIndex, str(publicKey), out, cap); });
        });
    }

    std::string KryptokronaCryptoModule::deriveSecretKey(
        jsi::Runtime &rt,
        std::string derivation,
        double outputIndex,
        std::string privateKey)
    {
        requireAbi(rt);
        return runSync(rt, [&]() {
            return fixed(
                [&](char *out, size_t cap)
                { return xkr_crypto_derive_secret_key(str(derivation), outputIndex, str(privateKey), out, cap); });
        });
    }

    std::string KryptokronaCryptoModule::underivePublicKey(
        jsi::Runtime &rt,
        std::string derivation,
        double outputIndex,
        std::string derivedKey)
    {
        requireAbi(rt);
        return runSync(rt, [&]() {
            return fixed(
                [&](char *out, size_t cap)
                { return xkr_crypto_underive_public_key(str(derivation), outputIndex, str(derivedKey), out, cap); });
        });
    }

    std::string
        KryptokronaCryptoModule::generateKeyImage(jsi::Runtime &rt, std::string publicKey, std::string privateKey)
    {
        requireAbi(rt);
        return runSync(rt, [&]() {
            return fixed([&](char *out, size_t cap)
                         { return xkr_crypto_generate_key_image(str(publicKey), str(privateKey), out, cap); });
        });
    }

    std::string KryptokronaCryptoModule::generateSignature(
        jsi::Runtime &rt,
        std::string prefixHash,
        std::string publicKey,
        std::string privateKey)
    {
        requireAbi(rt);
        return runSync(rt, [&]() {
            return fixed(
                [&](char *out, size_t cap) {
                    return xkr_crypto_generate_signature(
                        str(prefixHash), str(publicKey), str(privateKey), out, cap);
                },
                XKR_CRYPTO_HEX64_SIZE);
        });
    }

    std::string KryptokronaCryptoModule::deriveViewTag(jsi::Runtime &rt, std::string derivation, double outputIndex)
    {
        requireAbi(rt);
        return runSync(rt, [&]() {
            return fixed(
                [&](char *out, size_t cap)
                { return xkr_crypto_derive_view_tag(str(derivation), outputIndex, out, cap); },
                XKR_CRYPTO_VIEW_TAG_SIZE);
        });
    }

    bool KryptokronaCryptoModule::clsagVerify(
        jsi::Runtime &rt,
        std::string prefixHash,
        std::vector<std::string> ring,
        std::string keyImage,
        std::string c1,
        std::vector<std::string> s)
    {
        requireAbi(rt);
        return runSync(rt, [&]() {
            const auto keys = strs(ring);
            const auto responses = strs(s);
            uint8_t valid = 0;
            check(xkr_crypto_clsag_verify(
                str(prefixHash),
                keys.data(),
                keys.size(),
                str(keyImage),
                str(c1),
                responses.data(),
                responses.size(),
                &valid));
            return valid != 0;
        });
    }

    /* ---- asynchronous ----------------------------------------------------------------- */

    AsyncPromise<std::string> KryptokronaCryptoModule::cn_turtle_lite_slow_hash_v2(jsi::Runtime &rt, std::string data)
    {
        return runAsync<std::string>(
            rt,
            jsInvoker_,
            abiProblem_,
            [data]() {
                return fixed([&](char *out, size_t cap)
                             { return xkr_crypto_cn_turtle_lite_slow_hash_v2(str(data), out, cap); });
            });
    }

    AsyncPromise<std::vector<std::string>> KryptokronaCryptoModule::generateDeterministicSubwalletKeys(
        jsi::Runtime &rt,
        std::string basePrivateKey,
        double walletIndex)
    {
        return runAsync<std::vector<std::string>>(
            rt,
            jsInvoker_,
            abiProblem_,
            [basePrivateKey, walletIndex]() {
                std::string publicKey(XKR_CRYPTO_HEX32_SIZE, '\0');
                std::string privateKey(XKR_CRYPTO_HEX32_SIZE, '\0');
                check(xkr_crypto_generate_deterministic_subwallet_keys(
                    str(basePrivateKey),
                    walletIndex,
                    publicKey.data(),
                    publicKey.size(),
                    privateKey.data(),
                    privateKey.size()));
                publicKey.resize(64);
                privateKey.resize(64);
                return std::vector<std::string> {privateKey, publicKey};
            });
    }

    AsyncPromise<std::vector<std::string>> KryptokronaCryptoModule::generateRingSignatures(
        jsi::Runtime &rt,
        std::string prefixHash,
        std::string keyImage,
        std::vector<std::string> publicKeys,
        std::string privateKey,
        double realIndex)
    {
        return runAsync<std::vector<std::string>>(
            rt,
            jsInvoker_,
            abiProblem_,
            [prefixHash, keyImage, publicKeys, privateKey, realIndex]() {
                const auto keys = strs(publicKeys);
                XkrCryptoBuffer buffer {nullptr, 0};
                check(xkr_crypto_generate_ring_signatures(
                    str(prefixHash), str(keyImage), keys.data(), keys.size(), str(privateKey), realIndex, &buffer));
                return split(take(buffer), 128);
            });
    }

    AsyncPromise<std::vector<std::string>> KryptokronaCryptoModule::clsagSign(
        jsi::Runtime &rt,
        std::string prefixHash,
        std::vector<std::string> ring,
        std::string privateEphemeral,
        double realOutputIndex,
        std::string alpha,
        std::vector<std::string> decoyResponses)
    {
        return runAsync<std::vector<std::string>>(
            rt,
            jsInvoker_,
            abiProblem_,
            [prefixHash, ring, privateEphemeral, realOutputIndex, alpha, decoyResponses]() {
                const auto keys = strs(ring);
                const auto decoys = strs(decoyResponses);
                std::string c1(XKR_CRYPTO_HEX32_SIZE, '\0');
                XkrCryptoBuffer s {nullptr, 0};
                check(xkr_crypto_clsag_sign(
                    str(prefixHash),
                    keys.data(),
                    keys.size(),
                    str(privateEphemeral),
                    realOutputIndex,
                    str(alpha),
                    decoys.data(),
                    decoys.size(),
                    c1.data(),
                    c1.size(),
                    &s));
                c1.resize(64);
                std::vector<std::string> out {c1};
                for (auto &response : split(take(s), 64))
                {
                    out.push_back(std::move(response));
                }
                return out;
            });
    }

    AsyncPromise<std::string> KryptokronaCryptoModule::processBlockOutputs(
        jsi::Runtime &rt,
        std::string blockJson,
        std::string privateViewKey,
        std::string spendKeysJson,
        bool isViewWallet,
        bool processCoinbaseTransactions)
    {
        return runAsync<std::string>(
            rt,
            jsInvoker_,
            abiProblem_,
            [blockJson, privateViewKey, spendKeysJson, isViewWallet, processCoinbaseTransactions]() {
                XkrCryptoBuffer json {nullptr, 0};
                check(xkr_crypto_process_block_outputs(
                    str(blockJson),
                    str(privateViewKey),
                    str(spendKeysJson),
                    isViewWallet ? 1 : 0,
                    processCoinbaseTransactions ? 1 : 0,
                    &json));
                return take(json);
            });
    }

    AsyncPromise<std::string> KryptokronaCryptoModule::findPowShare(
        jsi::Runtime &rt,
        std::string blobHex,
        std::string targetHex,
        double startNonce,
        double maxAttempts,
        double /* nonceTagBits: accepted, not used */,
        double /* nonceTagValue: accepted, not used */)
    {
        return runAsync<std::string>(
            rt,
            jsInvoker_,
            abiProblem_,
            [blobHex, targetHex, startNonce, maxAttempts]() -> std::string {
                XkrCryptoPowResult result {};
                const int32_t status = xkr_crypto_find_pow_share(
                    str(blobHex), str(targetHex), startNonce, maxAttempts, 0, &result);
                if (status == XKR_CRYPTO_ERR_INVALID_ARGUMENT)
                {
                    return "null";
                }
                check(status);
                const std::string counters = "\"hashes_performed\":" + std::to_string(result.hashes_performed)
                                             + ",\"threads\":" + std::to_string(result.threads);
                if (result.found == 0)
                {
                    return "{" + counters + "}";
                }
                return std::string("{\"job_id\":\"\",\"nonce\":\"") + result.nonce_hex + "\",\"result\":\""
                       + result.result_hex + "\"," + counters + "}";
            },
            true);
    }
} // namespace facebook::react
