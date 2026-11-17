/*
 * xkr_crypto_ffi.h - C ABI of the Rust crate xkr-crypto-ffi (Kryptokrona crypto core).
 *
 * Hand-written to match crates/xkr-crypto-ffi/src/ffi.rs (ABI version 1). The file
 * cbindgen.toml next to this directory regenerates an equivalent header with
 * `cbindgen --config cbindgen.toml --crate xkr-crypto-ffi --output include/xkr_crypto_ffi.h`;
 * either way, a change of a signature or struct bumps XKR_CRYPTO_ABI_VERSION.
 *
 * Conventions
 *   - Every function returns int32_t: XKR_CRYPTO_OK (0) or a negative XKR_CRYPTO_ERR_* code.
 *     Outputs are written only on success. xkr_crypto_status_message() names a code.
 *   - Strings are XkrCryptoStr (pointer + length, UTF-8, no terminator needed; ptr may be
 *     NULL when len == 0). Hex may be upper or lower case; output hex is lower case.
 *   - Fixed-size results are written as hex plus a terminating NUL into a caller buffer of
 *     the given capacity: XKR_CRYPTO_HEX32_SIZE (65) for keys/hashes/scalars,
 *     XKR_CRYPTO_HEX64_SIZE (129) for signatures, XKR_CRYPTO_VIEW_TAG_SIZE (3).
 *   - Variable-size results come back in an XkrCryptoBuffer allocated by the library; copy
 *     it, then release it exactly once with xkr_crypto_buffer_free().
 *   - Booleans are uint8_t (0/1). JavaScript numbers used as indexes are passed as double
 *     and must be finite integers in [0, 2^53 - 1] (else XKR_CRYPTO_ERR_INVALID_INDEX).
 *   - All functions are thread-safe. Heavy ones (cn_turtle_lite_slow_hash_v2,
 *     find_pow_share, process_block_outputs, generate_ring_signatures, clsag_sign) must run
 *     off the JavaScript thread.
 *   - Randomness (generate_keys, signatures) comes from the operating system.
 */
#ifndef XKR_CRYPTO_FFI_H
#define XKR_CRYPTO_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XKR_CRYPTO_ABI_VERSION 1u

#define XKR_CRYPTO_HEX32_SIZE 65
#define XKR_CRYPTO_HEX64_SIZE 129
#define XKR_CRYPTO_VIEW_TAG_SIZE 3

#define XKR_CRYPTO_OK 0
#define XKR_CRYPTO_ERR_NULL_POINTER (-1)
#define XKR_CRYPTO_ERR_INVALID_HEX (-2)
#define XKR_CRYPTO_ERR_INVALID_LENGTH (-3)
#define XKR_CRYPTO_ERR_INVALID_PUBLIC_KEY (-4)
#define XKR_CRYPTO_ERR_INVALID_SCALAR (-5)
#define XKR_CRYPTO_ERR_INVALID_INDEX (-6)
#define XKR_CRYPTO_ERR_BUFFER_TOO_SMALL (-7)
#define XKR_CRYPTO_ERR_INVALID_JSON (-8)
#define XKR_CRYPTO_ERR_SIGNING_FAILED (-9)
#define XKR_CRYPTO_ERR_INVALID_ARGUMENT (-10)
#define XKR_CRYPTO_ERR_DATA_CAN_NOT_BE_HASHED (-11)
#define XKR_CRYPTO_ERR_INTERNAL (-100)

typedef struct XkrCryptoStr {
    const char *ptr;
    size_t len;
} XkrCryptoStr;

typedef struct XkrCryptoBuffer {
    uint8_t *ptr;
    size_t len;
} XkrCryptoBuffer;

typedef struct XkrCryptoPowResult {
    uint8_t found;             /* 1 if a share was found */
    char nonce_hex[9];         /* 8 hex chars + NUL (the 4 nonce bytes as in the blob) */
    char result_hex[65];       /* 64 hex chars + NUL */
    uint64_t hashes_performed; /* all workers together */
    uint32_t threads;          /* workers used */
} XkrCryptoPowResult;

/* ---- library ---------------------------------------------------------------------- */
uint32_t xkr_crypto_abi_version(void);
const char *xkr_crypto_status_message(int32_t status);
void xkr_crypto_buffer_free(XkrCryptoBuffer buffer);

/* ---- keys ------------------------------------------------------------------------- */
int32_t xkr_crypto_check_key(XkrCryptoStr public_key, uint8_t *out_valid);
int32_t xkr_crypto_generate_keys(char *out_public_key, size_t public_cap,
                                 char *out_private_key, size_t private_cap);
int32_t xkr_crypto_secret_key_to_public_key(XkrCryptoStr private_key,
                                            char *out_public_key, size_t out_cap);
int32_t xkr_crypto_sc_reduce32(XkrCryptoStr scalar, char *out_scalar, size_t out_cap);
int32_t xkr_crypto_generate_deterministic_subwallet_keys(XkrCryptoStr base_private_key,
                                                         double wallet_index,
                                                         char *out_public_key, size_t public_cap,
                                                         char *out_private_key, size_t private_cap);

/* ---- derivations ------------------------------------------------------------------ */
int32_t xkr_crypto_generate_key_derivation(XkrCryptoStr public_key, XkrCryptoStr private_key,
                                           char *out_derivation, size_t out_cap);
int32_t xkr_crypto_derive_public_key(XkrCryptoStr derivation, double output_index,
                                     XkrCryptoStr public_key,
                                     char *out_public_key, size_t out_cap);
int32_t xkr_crypto_derive_secret_key(XkrCryptoStr derivation, double output_index,
                                     XkrCryptoStr private_key,
                                     char *out_private_key, size_t out_cap);
int32_t xkr_crypto_underive_public_key(XkrCryptoStr derivation, double output_index,
                                       XkrCryptoStr derived_key,
                                       char *out_public_key, size_t out_cap);
int32_t xkr_crypto_generate_key_image(XkrCryptoStr public_key, XkrCryptoStr private_key,
                                      char *out_key_image, size_t out_cap);
int32_t xkr_crypto_derive_view_tag(XkrCryptoStr derivation, double output_index,
                                   char *out_view_tag, size_t out_cap);

/* ---- hashing ---------------------------------------------------------------------- */
int32_t xkr_crypto_cn_fast_hash(XkrCryptoStr data, char *out_hash, size_t out_cap);
int32_t xkr_crypto_cn_turtle_lite_slow_hash_v2(XkrCryptoStr data, char *out_hash, size_t out_cap);
int32_t xkr_crypto_hash_to_elliptic_curve(XkrCryptoStr hash, char *out_point, size_t out_cap);
int32_t xkr_crypto_hash_to_scalar(XkrCryptoStr data, char *out_scalar, size_t out_cap);

/* ---- signatures ------------------------------------------------------------------- */
int32_t xkr_crypto_generate_signature(XkrCryptoStr prefix_hash, XkrCryptoStr public_key,
                                      XkrCryptoStr private_key,
                                      char *out_signature, size_t out_cap);
int32_t xkr_crypto_check_signature(XkrCryptoStr prefix_hash, XkrCryptoStr public_key,
                                   XkrCryptoStr signature, uint8_t *out_valid);
/* out_signatures: count * 128 hex chars, concatenated, no NUL */
int32_t xkr_crypto_generate_ring_signatures(XkrCryptoStr prefix_hash, XkrCryptoStr key_image,
                                            const XkrCryptoStr *public_keys,
                                            size_t public_keys_count,
                                            XkrCryptoStr private_key, double real_index,
                                            XkrCryptoBuffer *out_signatures);
int32_t xkr_crypto_check_ring_signature(XkrCryptoStr prefix_hash, XkrCryptoStr key_image,
                                        const XkrCryptoStr *public_keys,
                                        size_t public_keys_count,
                                        const XkrCryptoStr *signatures, size_t signatures_count,
                                        uint8_t *out_valid);
/* transaction version 2; alpha "" and no decoy responses = randomness from the OS.
   out_s: ring_count * 64 hex chars, concatenated, no NUL */
int32_t xkr_crypto_clsag_sign(XkrCryptoStr prefix_hash,
                              const XkrCryptoStr *ring, size_t ring_count,
                              XkrCryptoStr private_ephemeral, double real_output_index,
                              XkrCryptoStr alpha,
                              const XkrCryptoStr *decoy_responses, size_t decoy_responses_count,
                              char *out_c1, size_t c1_cap, XkrCryptoBuffer *out_s);
int32_t xkr_crypto_clsag_verify(XkrCryptoStr prefix_hash,
                                const XkrCryptoStr *ring, size_t ring_count,
                                XkrCryptoStr key_image, XkrCryptoStr c1,
                                const XkrCryptoStr *s, size_t s_count, uint8_t *out_valid);

/* ---- wallet scan and PoW ---------------------------------------------------------- */
/* block_json = JSON.stringify(block), spend_keys_json = JSON.stringify([{publicKey, privateKey}]);
   out_json = JSON array of {publicSpendKey, input: {keyImage, amount, transactionIndex,
   globalOutputIndex, key, parentTransactionHash}} */
int32_t xkr_crypto_process_block_outputs(XkrCryptoStr block_json, XkrCryptoStr private_view_key,
                                         XkrCryptoStr spend_keys_json, uint8_t is_view_wallet,
                                         uint8_t process_coinbase_transactions,
                                         XkrCryptoBuffer *out_json);
/* XKR_CRYPTO_ERR_INVALID_ARGUMENT where the JavaScript method resolves null (unusable blob
   or target). threads == 0: 80 % of the cores, 1..8. */
int32_t xkr_crypto_find_pow_share(XkrCryptoStr blob_hex, XkrCryptoStr target_hex,
                                  double start_nonce, double max_attempts, uint32_t threads,
                                  XkrCryptoPowResult *out);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* XKR_CRYPTO_FFI_H */
