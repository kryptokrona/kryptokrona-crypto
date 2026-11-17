//! The Node.js / Electron addon of kryptokrona-crypto 2.x (Node-API, so one build per platform
//! serves every Node.js and Electron version).
//!
//! Every function carries the name the TypeScript wrapper (`typescript/Crypto.ts`,
//! `tryRunFunc`) calls, takes the arguments the wrapper passes and returns the value the wrapper
//! resolves with: hex strings, booleans, arrays of hex strings and the objects
//! `{ private_key, public_key }`, `{ c1, s }` and `{ signatures, k }`. Invalid input throws a
//! JavaScript `Error` naming the argument (the wrapper turns it into a rejected promise).
//! The slow hashes and the wallet scan run on the libuv thread pool and return promises.
//!
//! Implementation: `xkr_crypto_ffi` (the crypto core shared with the mobile apps) and
//! `kryptokrona_crypto_extra` (multisig helpers, `scalarmultKey`, `tree_hash_from_branch`,
//! Chukwa). This crate has no unsafe code of its own; the allowance below is for the Node-API
//! glue that `#[napi]` generates.
#![allow(unsafe_code)]
// The functions are called from JavaScript; `#[must_use]` would only concern Rust callers.
#![allow(clippy::must_use_candidate)]

use kryptokrona_crypto_extra::hex32::js_index;
use kryptokrona_crypto_extra::merkle::BranchPath;
use kryptokrona_crypto_extra::{chukwa, merkle, multisig, points};
use napi::bindgen_prelude::AsyncTask;
use napi::{Env, Task};
use napi_derive::napi;
use xkr_crypto_ffi::api::{self, CnFamily};
use xkr_crypto_ffi::{CryptoError, CryptoResult, pow, scan};

// ---------------------------------------------------------------------------------------------
// plumbing

fn js<T>(result: CryptoResult<T>) -> napi::Result<T> {
    result.map_err(|e| napi::Error::new(napi::Status::InvalidArg, e.to_string()))
}

fn index(what: &'static str, value: f64) -> napi::Result<u64> {
    js(js_index(what, value))
}

fn count_u32(what: &'static str, value: f64) -> CryptoResult<u32> {
    u32::try_from(js_index(what, value)?).map_err(|_| CryptoError::InvalidArgument(what))
}

/// A computation for the libuv thread pool that resolves with a string.
pub struct Job(Option<Box<dyn FnOnce() -> CryptoResult<String> + Send>>);

impl std::fmt::Debug for Job {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Job").finish_non_exhaustive()
    }
}

impl Job {
    fn spawn(f: impl FnOnce() -> CryptoResult<String> + Send + 'static) -> AsyncTask<Self> {
        AsyncTask::new(Self(Some(Box::new(f))))
    }
}

impl Task for Job {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> napi::Result<String> {
        let f = self
            .0
            .take()
            .ok_or_else(|| napi::Error::from_reason("the task has already run"))?;
        js(f())
    }

    fn resolve(&mut self, _env: Env, output: String) -> napi::Result<String> {
        Ok(output)
    }
}

/// `{ private_key, public_key }` (`IKeyPair`).
#[napi(object)]
#[derive(Debug)]
pub struct KeyPair {
    /// The private key.
    #[napi(js_name = "private_key")]
    pub private_key: String,
    /// The public key.
    #[napi(js_name = "public_key")]
    pub public_key: String,
}

impl From<api::KeyPair> for KeyPair {
    fn from(keys: api::KeyPair) -> Self {
        Self {
            private_key: keys.private_key,
            public_key: keys.public_key,
        }
    }
}

/// `{ c1, s }` (`IClsagSignature`).
#[napi(object)]
#[derive(Debug)]
pub struct ClsagSignature {
    /// The challenge.
    pub c1: String,
    /// The responses, one per ring member.
    pub s: Vec<String>,
}

/// `{ signatures, k }` (`IPreparedRingSignatures`).
#[napi(object)]
#[derive(Debug)]
pub struct PreparedRingSignatures {
    /// The prepared signatures.
    pub signatures: Vec<String>,
    /// The nonce of the real member's signature.
    pub k: String,
}

// ---------------------------------------------------------------------------------------------
// keys

/// `checkKey(publicKey)`.
#[napi(js_name = "checkKey")]
pub fn check_key(public_key: String) -> bool {
    api::check_key(&public_key)
}

/// `generateKeys()`.
#[napi(js_name = "generateKeys")]
pub fn generate_keys() -> KeyPair {
    api::generate_keys().into()
}

/// `secretKeyToPublicKey(privateKey)`.
#[napi(js_name = "secretKeyToPublicKey")]
pub fn secret_key_to_public_key(private_key: String) -> napi::Result<String> {
    js(api::secret_key_to_public_key(&private_key))
}

/// `scReduce32(scalar)`.
#[napi(js_name = "scReduce32")]
pub fn sc_reduce32(scalar: String) -> napi::Result<String> {
    js(api::sc_reduce32(&scalar))
}

/// `generateDeterministicSubwalletKeys(basePrivateKey, walletIndex)`.
#[napi(js_name = "generateDeterministicSubwalletKeys")]
pub fn generate_deterministic_subwallet_keys(
    base_private_key: String,
    wallet_index: f64,
) -> napi::Result<KeyPair> {
    let index = index("walletIndex", wallet_index)?;
    js(api::generate_deterministic_subwallet_keys(
        &base_private_key,
        index,
    ))
    .map(KeyPair::from)
}

/// `generateViewKeysFromPrivateSpendKey(privateKey)`.
#[napi(js_name = "generateViewKeysFromPrivateSpendKey")]
pub fn generate_view_keys_from_private_spend_key(private_key: String) -> napi::Result<KeyPair> {
    js(api::generate_view_keys_from_private_spend_key(&private_key)).map(KeyPair::from)
}

/// `generatePrivateViewKeyFromPrivateSpendKey(privateKey)`.
#[napi(js_name = "generatePrivateViewKeyFromPrivateSpendKey")]
pub fn generate_private_view_key_from_private_spend_key(
    private_key: String,
) -> napi::Result<String> {
    js(api::generate_private_view_key_from_private_spend_key(
        &private_key,
    ))
}

// ---------------------------------------------------------------------------------------------
// derivations

/// `generateKeyDerivation(publicKey, privateKey)`.
#[napi(js_name = "generateKeyDerivation")]
pub fn generate_key_derivation(public_key: String, private_key: String) -> napi::Result<String> {
    js(api::generate_key_derivation(&public_key, &private_key))
}

/// `generateKeyDerivationScalar(publicKey, privateKey, outputIndex)`.
#[napi(js_name = "generateKeyDerivationScalar")]
pub fn generate_key_derivation_scalar(
    public_key: String,
    private_key: String,
    output_index: f64,
) -> napi::Result<String> {
    let index = index("outputIndex", output_index)?;
    js(api::generate_key_derivation_scalar(
        &public_key,
        &private_key,
        index,
    ))
}

/// `derivationToScalar(derivation, outputIndex)`.
#[napi(js_name = "derivationToScalar")]
pub fn derivation_to_scalar(derivation: String, output_index: f64) -> napi::Result<String> {
    let index = index("outputIndex", output_index)?;
    js(api::derivation_to_scalar(&derivation, index))
}

/// `derivePublicKey(derivation, outputIndex, publicKey)`.
#[napi(js_name = "derivePublicKey")]
pub fn derive_public_key(
    derivation: String,
    output_index: f64,
    public_key: String,
) -> napi::Result<String> {
    let index = index("outputIndex", output_index)?;
    js(api::derive_public_key(&derivation, index, &public_key))
}

/// `deriveSecretKey(derivation, outputIndex, privateKey)`.
#[napi(js_name = "deriveSecretKey")]
pub fn derive_secret_key(
    derivation: String,
    output_index: f64,
    private_key: String,
) -> napi::Result<String> {
    let index = index("outputIndex", output_index)?;
    js(api::derive_secret_key(&derivation, index, &private_key))
}

/// `underivePublicKey(derivation, outputIndex, derivedKey)`.
#[napi(js_name = "underivePublicKey")]
pub fn underive_public_key(
    derivation: String,
    output_index: f64,
    derived_key: String,
) -> napi::Result<String> {
    let index = index("outputIndex", output_index)?;
    js(api::underive_public_key(&derivation, index, &derived_key))
}

/// `scalarDerivePublicKey(derivationScalar, publicKey)`.
#[napi(js_name = "scalarDerivePublicKey")]
pub fn scalar_derive_public_key(
    derivation_scalar: String,
    public_key: String,
) -> napi::Result<String> {
    js(api::scalar_derive_public_key(
        &derivation_scalar,
        &public_key,
    ))
}

/// `scalarDeriveSecretKey(derivationScalar, privateKey)`.
#[napi(js_name = "scalarDeriveSecretKey")]
pub fn scalar_derive_secret_key(
    derivation_scalar: String,
    private_key: String,
) -> napi::Result<String> {
    js(api::scalar_derive_secret_key(
        &derivation_scalar,
        &private_key,
    ))
}

/// `deriveViewTag(derivation, outputIndex)` (transaction version 2): two hex characters.
#[napi(js_name = "deriveViewTag")]
pub fn derive_view_tag(derivation: String, output_index: f64) -> napi::Result<String> {
    let index = index("outputIndex", output_index)?;
    js(api::derive_view_tag(&derivation, index))
}

/// `generateKeyImage(publicKey, privateKey)`.
#[napi(js_name = "generateKeyImage")]
pub fn generate_key_image(public_key: String, private_key: String) -> napi::Result<String> {
    js(api::generate_key_image(&public_key, &private_key))
}

/// `scalarmultKey(keyImageA, keyImageB)`.
#[napi(js_name = "scalarmultKey")]
pub fn scalarmult_key(key_image_a: String, key_image_b: String) -> napi::Result<String> {
    js(points::scalarmult_key(&key_image_a, &key_image_b))
}

// ---------------------------------------------------------------------------------------------
// hashing

/// `cn_fast_hash(data)`.
#[napi(js_name = "cn_fast_hash")]
pub fn cn_fast_hash(data: String) -> napi::Result<String> {
    js(api::cn_fast_hash(&data))
}

/// `hashToEllipticCurve(hash)`.
#[napi(js_name = "hashToEllipticCurve")]
pub fn hash_to_elliptic_curve(hash: String) -> napi::Result<String> {
    js(api::hash_to_elliptic_curve(&hash))
}

/// `hashToScalar(data)`.
#[napi(js_name = "hashToScalar")]
pub fn hash_to_scalar(data: String) -> napi::Result<String> {
    js(api::hash_to_scalar(&data))
}

/// `tree_hash(hashes)`.
#[napi(js_name = "tree_hash")]
pub fn tree_hash(hashes: Vec<String>) -> napi::Result<String> {
    js(api::tree_hash(&hashes))
}

/// `tree_branch(hashes)`.
#[napi(js_name = "tree_branch")]
pub fn tree_branch(hashes: Vec<String>) -> napi::Result<Vec<String>> {
    js(api::tree_branch(&hashes))
}

/// `tree_depth(count)`.
#[napi(js_name = "tree_depth")]
pub fn tree_depth(count: f64) -> napi::Result<u32> {
    let count = index("count", count)?;
    Ok(api::tree_depth(count) as u32)
}

/// `tree_hash_from_branch(branches, leaf, path)`: `path` 0 keeps the leaf on the left; another
/// number selects the sides by its bits.
#[napi(js_name = "tree_hash_from_branch")]
pub fn tree_hash_from_branch(
    branches: Vec<String>,
    leaf: String,
    path: f64,
) -> napi::Result<String> {
    let path = BranchPath::from_number(index("path", path)?);
    js(merkle::tree_hash_from_branch(&branches, &leaf, path))
}

/// `cn_slow_hash_v0(data)`, on the thread pool.
#[napi(js_name = "cn_slow_hash_v0")]
pub fn cn_slow_hash_v0(data: String) -> AsyncTask<Job> {
    Job::spawn(move || api::cn_slow_hash(&data, CnFamily::Cn, 0))
}

/// `cn_slow_hash_v1(data)`, on the thread pool.
#[napi(js_name = "cn_slow_hash_v1")]
pub fn cn_slow_hash_v1(data: String) -> AsyncTask<Job> {
    Job::spawn(move || api::cn_slow_hash(&data, CnFamily::Cn, 1))
}

/// `cn_slow_hash_v2(data)`, on the thread pool.
#[napi(js_name = "cn_slow_hash_v2")]
pub fn cn_slow_hash_v2(data: String) -> AsyncTask<Job> {
    Job::spawn(move || api::cn_slow_hash(&data, CnFamily::Cn, 2))
}

/// `cn_lite_slow_hash_v0(data)`, on the thread pool.
#[napi(js_name = "cn_lite_slow_hash_v0")]
pub fn cn_lite_slow_hash_v0(data: String) -> AsyncTask<Job> {
    Job::spawn(move || api::cn_slow_hash(&data, CnFamily::Lite, 0))
}

/// `cn_lite_slow_hash_v1(data)`, on the thread pool.
#[napi(js_name = "cn_lite_slow_hash_v1")]
pub fn cn_lite_slow_hash_v1(data: String) -> AsyncTask<Job> {
    Job::spawn(move || api::cn_slow_hash(&data, CnFamily::Lite, 1))
}

/// `cn_lite_slow_hash_v2(data)`, on the thread pool.
#[napi(js_name = "cn_lite_slow_hash_v2")]
pub fn cn_lite_slow_hash_v2(data: String) -> AsyncTask<Job> {
    Job::spawn(move || api::cn_slow_hash(&data, CnFamily::Lite, 2))
}

/// `cn_dark_slow_hash_v0(data)`, on the thread pool.
#[napi(js_name = "cn_dark_slow_hash_v0")]
pub fn cn_dark_slow_hash_v0(data: String) -> AsyncTask<Job> {
    Job::spawn(move || api::cn_slow_hash(&data, CnFamily::Dark, 0))
}

/// `cn_dark_slow_hash_v1(data)`, on the thread pool.
#[napi(js_name = "cn_dark_slow_hash_v1")]
pub fn cn_dark_slow_hash_v1(data: String) -> AsyncTask<Job> {
    Job::spawn(move || api::cn_slow_hash(&data, CnFamily::Dark, 1))
}

/// `cn_dark_slow_hash_v2(data)`, on the thread pool.
#[napi(js_name = "cn_dark_slow_hash_v2")]
pub fn cn_dark_slow_hash_v2(data: String) -> AsyncTask<Job> {
    Job::spawn(move || api::cn_slow_hash(&data, CnFamily::Dark, 2))
}

/// `cn_dark_lite_slow_hash_v0(data)`, on the thread pool.
#[napi(js_name = "cn_dark_lite_slow_hash_v0")]
pub fn cn_dark_lite_slow_hash_v0(data: String) -> AsyncTask<Job> {
    Job::spawn(move || api::cn_slow_hash(&data, CnFamily::DarkLite, 0))
}

/// `cn_dark_lite_slow_hash_v1(data)`, on the thread pool.
#[napi(js_name = "cn_dark_lite_slow_hash_v1")]
pub fn cn_dark_lite_slow_hash_v1(data: String) -> AsyncTask<Job> {
    Job::spawn(move || api::cn_slow_hash(&data, CnFamily::DarkLite, 1))
}

/// `cn_dark_lite_slow_hash_v2(data)`, on the thread pool.
#[napi(js_name = "cn_dark_lite_slow_hash_v2")]
pub fn cn_dark_lite_slow_hash_v2(data: String) -> AsyncTask<Job> {
    Job::spawn(move || api::cn_slow_hash(&data, CnFamily::DarkLite, 2))
}

/// `cn_turtle_slow_hash_v0(data)`, on the thread pool.
#[napi(js_name = "cn_turtle_slow_hash_v0")]
pub fn cn_turtle_slow_hash_v0(data: String) -> AsyncTask<Job> {
    Job::spawn(move || api::cn_slow_hash(&data, CnFamily::Turtle, 0))
}

/// `cn_turtle_slow_hash_v1(data)`, on the thread pool.
#[napi(js_name = "cn_turtle_slow_hash_v1")]
pub fn cn_turtle_slow_hash_v1(data: String) -> AsyncTask<Job> {
    Job::spawn(move || api::cn_slow_hash(&data, CnFamily::Turtle, 1))
}

/// `cn_turtle_slow_hash_v2(data)`, on the thread pool.
#[napi(js_name = "cn_turtle_slow_hash_v2")]
pub fn cn_turtle_slow_hash_v2(data: String) -> AsyncTask<Job> {
    Job::spawn(move || api::cn_slow_hash(&data, CnFamily::Turtle, 2))
}

/// `cn_turtle_lite_slow_hash_v0(data)`, on the thread pool.
#[napi(js_name = "cn_turtle_lite_slow_hash_v0")]
pub fn cn_turtle_lite_slow_hash_v0(data: String) -> AsyncTask<Job> {
    Job::spawn(move || api::cn_slow_hash(&data, CnFamily::TurtleLite, 0))
}

/// `cn_turtle_lite_slow_hash_v1(data)`, on the thread pool.
#[napi(js_name = "cn_turtle_lite_slow_hash_v1")]
pub fn cn_turtle_lite_slow_hash_v1(data: String) -> AsyncTask<Job> {
    Job::spawn(move || api::cn_slow_hash(&data, CnFamily::TurtleLite, 1))
}

/// `cn_turtle_lite_slow_hash_v2(data)`, on the thread pool.
#[napi(js_name = "cn_turtle_lite_slow_hash_v2")]
pub fn cn_turtle_lite_slow_hash_v2(data: String) -> AsyncTask<Job> {
    Job::spawn(move || api::cn_slow_hash(&data, CnFamily::TurtleLite, 2))
}

/// `chukwa_slow_hash_base(data, iterations, memory, threads)` (Argon2id, `memory` in KiB), on
/// the thread pool.
#[napi(js_name = "chukwa_slow_hash_base")]
pub fn chukwa_slow_hash_base(
    data: String,
    iterations: f64,
    memory: f64,
    threads: f64,
) -> AsyncTask<Job> {
    Job::spawn(move || {
        chukwa::chukwa_slow_hash_base(
            &data,
            count_u32("iterations", iterations)?,
            count_u32("memory", memory)?,
            count_u32("threads", threads)?,
        )
    })
}

/// `chukwa_slow_hash_v1(data)`, on the thread pool.
#[napi(js_name = "chukwa_slow_hash_v1")]
pub fn chukwa_slow_hash_v1(data: String) -> AsyncTask<Job> {
    Job::spawn(move || chukwa::chukwa_slow_hash_v1(&data))
}

/// `chukwa_slow_hash_v2(data)`, on the thread pool.
#[napi(js_name = "chukwa_slow_hash_v2")]
pub fn chukwa_slow_hash_v2(data: String) -> AsyncTask<Job> {
    Job::spawn(move || chukwa::chukwa_slow_hash_v2(&data))
}

// ---------------------------------------------------------------------------------------------
// signatures

/// `generateSignature(prefixHash, publicKey, privateKey)`.
#[napi(js_name = "generateSignature")]
pub fn generate_signature(
    prefix_hash: String,
    public_key: String,
    private_key: String,
) -> napi::Result<String> {
    js(api::generate_signature(
        &prefix_hash,
        &public_key,
        &private_key,
    ))
}

/// `checkSignature(prefixHash, publicKey, signature)`.
#[napi(js_name = "checkSignature")]
pub fn check_signature(prefix_hash: String, public_key: String, signature: String) -> bool {
    api::check_signature(&prefix_hash, &public_key, &signature)
}

/// `generateRingSignatures(prefixHash, keyImage, publicKeys, privateKey, realIndex)`.
#[napi(js_name = "generateRingSignatures")]
pub fn generate_ring_signatures(
    prefix_hash: String,
    key_image: String,
    public_keys: Vec<String>,
    private_key: String,
    real_index: f64,
) -> napi::Result<Vec<String>> {
    let index = index("realIndex", real_index)?;
    js(api::generate_ring_signatures(
        &prefix_hash,
        &key_image,
        &public_keys,
        &private_key,
        index,
    ))
}

/// `checkRingSignature(prefixHash, keyImage, publicKeys, signatures)`.
#[napi(js_name = "checkRingSignature")]
pub fn check_ring_signature(
    prefix_hash: String,
    key_image: String,
    public_keys: Vec<String>,
    signatures: Vec<String>,
) -> bool {
    api::check_ring_signature(&prefix_hash, &key_image, &public_keys, &signatures)
}

/// `prepareRingSignatures(prefixHash, keyImage, publicKeys, realIndex, k?)`.
#[napi(js_name = "prepareRingSignatures")]
pub fn prepare_ring_signatures(
    prefix_hash: String,
    key_image: String,
    public_keys: Vec<String>,
    real_index: f64,
    k: Option<String>,
) -> napi::Result<PreparedRingSignatures> {
    let index = index("realIndex", real_index)?;
    let prepared = js(api::prepare_ring_signatures(
        &prefix_hash,
        &key_image,
        &public_keys,
        index,
        k.as_deref().filter(|k| !k.is_empty()),
    ))?;
    Ok(PreparedRingSignatures {
        signatures: prepared.signatures,
        k: prepared.k,
    })
}

/// `completeRingSignatures(privateKey, realIndex, k, signatures)`.
#[napi(js_name = "completeRingSignatures")]
pub fn complete_ring_signatures(
    private_key: String,
    real_index: f64,
    k: String,
    signatures: Vec<String>,
) -> napi::Result<Vec<String>> {
    let index = index("realIndex", real_index)?;
    js(api::complete_ring_signatures(
        &private_key,
        index,
        &k,
        &signatures,
    ))
}

/// `clsagSign(prefixHash, ring, privateEphemeral, realOutputIndex, alpha, decoyResponses)`
/// (transaction version 2); `alpha === ''` with no decoy responses draws fresh randomness.
#[napi(js_name = "clsagSign")]
pub fn clsag_sign(
    prefix_hash: String,
    ring: Vec<String>,
    private_ephemeral: String,
    real_output_index: f64,
    alpha: String,
    decoy_responses: Vec<String>,
) -> napi::Result<ClsagSignature> {
    let index = index("realOutputIndex", real_output_index)?;
    let sig = js(api::clsag_sign(
        &prefix_hash,
        &ring,
        &private_ephemeral,
        index,
        &alpha,
        &decoy_responses,
    ))?;
    Ok(ClsagSignature {
        c1: sig.c1,
        s: sig.s,
    })
}

/// `clsagVerify(prefixHash, ring, keyImage, c1, s)` (transaction version 2).
#[napi(js_name = "clsagVerify")]
pub fn clsag_verify(
    prefix_hash: String,
    ring: Vec<String>,
    key_image: String,
    c1: String,
    s: Vec<String>,
) -> bool {
    api::clsag_verify(&prefix_hash, &ring, &key_image, &c1, &s)
}

// ---------------------------------------------------------------------------------------------
// multisig

/// `calculateMultisigPrivateKeys(privateSpendKey, publicKeys)`.
#[napi(js_name = "calculateMultisigPrivateKeys")]
pub fn calculate_multisig_private_keys(
    private_spend_key: String,
    public_keys: Vec<String>,
) -> napi::Result<Vec<String>> {
    js(multisig::calculate_multisig_private_keys(
        &private_spend_key,
        &public_keys,
    ))
}

/// `calculateSharedPrivateKey(privateKeys)`.
#[napi(js_name = "calculateSharedPrivateKey")]
pub fn calculate_shared_private_key(private_keys: Vec<String>) -> napi::Result<String> {
    js(multisig::calculate_shared_private_key(&private_keys))
}

/// `calculateSharedPublicKey(publicKeys)`.
#[napi(js_name = "calculateSharedPublicKey")]
pub fn calculate_shared_public_key(public_keys: Vec<String>) -> napi::Result<String> {
    js(multisig::calculate_shared_public_key(&public_keys))
}

/// `generatePartialSigningKey(signature, privateKey)`.
#[napi(js_name = "generatePartialSigningKey")]
pub fn generate_partial_signing_key(
    signature: String,
    private_key: String,
) -> napi::Result<String> {
    js(multisig::generate_partial_signing_key(
        &signature,
        &private_key,
    ))
}

/// `restoreKeyImage(publicEphemeral, derivation, outputIndex, partialKeyImages)`.
#[napi(js_name = "restoreKeyImage")]
pub fn restore_key_image(
    public_ephemeral: String,
    derivation: String,
    output_index: f64,
    partial_key_images: Vec<String>,
) -> napi::Result<String> {
    let index = index("outputIndex", output_index)?;
    js(multisig::restore_key_image(
        &public_ephemeral,
        &derivation,
        index,
        &partial_key_images,
    ))
}

/// `restoreRingSignatures(derivation, outputIndex, partialSigningKeys, realIndex, k, signatures)`.
#[napi(js_name = "restoreRingSignatures")]
pub fn restore_ring_signatures(
    derivation: String,
    output_index: f64,
    partial_signing_keys: Vec<String>,
    real_index: f64,
    k: String,
    signatures: Vec<String>,
) -> napi::Result<Vec<String>> {
    let output_index = index("outputIndex", output_index)?;
    let real_index = index("realIndex", real_index)?;
    js(multisig::restore_ring_signatures(
        &derivation,
        output_index,
        &partial_signing_keys,
        real_index,
        &k,
        &signatures,
    ))
}

// ---------------------------------------------------------------------------------------------
// wallet scan and Hugin PoW (the same functions the React Native module offers)

/// `processBlockOutputs(blockJson, privateViewKey, spendKeysJson, isViewWallet,
/// processCoinbaseTransactions)`: JSON text in and out (see `xkr_crypto_ffi::scan`), on the
/// thread pool.
#[napi(js_name = "processBlockOutputs")]
pub fn process_block_outputs(
    block_json: String,
    private_view_key: String,
    spend_keys_json: String,
    is_view_wallet: bool,
    process_coinbase_transactions: bool,
) -> AsyncTask<Job> {
    Job::spawn(move || {
        scan::process_block_outputs_json(
            &block_json,
            &private_view_key,
            &spend_keys_json,
            is_view_wallet,
            process_coinbase_transactions,
        )
    })
}

/// `findPowShare(blobHex, targetHex, startNonce, maxAttempts, nonceTagBits, nonceTagValue)`:
/// the result as JSON text, `"null"` for unusable input (see `xkr_crypto_ffi::pow`), on the
/// thread pool. `nonceTagBits` and `nonceTagValue` are accepted and not used.
#[napi(js_name = "findPowShare")]
pub fn find_pow_share(
    blob_hex: String,
    target_hex: String,
    start_nonce: f64,
    max_attempts: f64,
    nonce_tag_bits: Option<f64>,
    nonce_tag_value: Option<f64>,
) -> AsyncTask<Job> {
    // accepted for the signature of the JavaScript method, not used (as in the mobile module)
    let _ = (nonce_tag_bits, nonce_tag_value);
    Job::spawn(move || {
        let search = pow::find_pow_share(
            &blob_hex,
            &target_hex,
            pow::start_nonce_from_js(start_nonce),
            pow::max_attempts_from_js(max_attempts),
            0,
        );
        Ok(pow_json(search.as_ref()))
    })
}

fn pow_json(search: Option<&pow::PowSearch>) -> String {
    match search {
        None => "null".to_owned(),
        Some(search) => match &search.share {
            Some(share) => format!(
                r#"{{"job_id":"","nonce":"{}","result":"{}","hashes_performed":{},"threads":{}}}"#,
                share.nonce, share.result, search.hashes_performed, search.threads
            ),
            None => format!(
                r#"{{"hashes_performed":{},"threads":{}}}"#,
                search.hashes_performed, search.threads
            ),
        },
    }
}
