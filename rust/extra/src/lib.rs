//! The functions of kryptokrona-crypto's `Crypto` class that the shared crypto core
//! (`xkr_crypto_ffi::api`) does not have, because only the Node.js backend offers them. Same
//! argument and result encoding as the core (hex strings in, lowercase hex out) and the same
//! results as the C++ addon of kryptokrona-crypto 1.x:
//!
//! | module | functions |
//! |---|---|
//! | [`multisig`] | `calculateMultisigPrivateKeys`, `calculateSharedPrivateKey`, `calculateSharedPublicKey`, `generatePartialSigningKey`, `restoreKeyImage`, `restoreRingSignatures` |
//! | [`points`] | `scalarmultKey` |
//! | [`merkle`] | `tree_hash_from_branch` |
//! | [`chukwa`] | `chukwa_slow_hash_base`, `chukwa_slow_hash_v1`, `chukwa_slow_hash_v2` (Argon2id) |
//!
//! Errors are [`xkr_crypto_ffi::CryptoError`], as in the core.

pub mod chukwa;
pub mod hex32;
pub mod merkle;
pub mod multisig;
pub mod points;

pub use xkr_crypto_ffi::{CryptoError, CryptoResult};
