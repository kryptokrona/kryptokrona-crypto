//! The multisig helpers of kryptokrona-crypto (C++ `Crypto::Multisig`, `multisig.cpp`).
//!
//! Key lists are deduplicated and sorted (descending byte order) before they are added, and
//! two values are added the way `multisig.cpp` adds them: when the running value is a canonical
//! scalar both are added as scalars mod `l`, otherwise both are decoded and added as points.
//! For the inputs the wallets produce (private keys, public keys and key images) this is plain
//! scalar or point addition; the rule is kept so that every participant computes the same
//! bytes as one running the 1.x addon.

use xkr_crypto::Scalar;
use xkr_types::{KeyDerivation, PublicKey, SecretKey};

use crate::hex32::{canonical, parse_fixed, parse_list32, parse32, point, to_hex};
use crate::{CryptoError, CryptoResult};

/// The key lists of these functions must not be empty (as the 1.x addon requires).
fn non_empty<T>(what: &'static str, items: Vec<T>) -> CryptoResult<Vec<T>> {
    if items.is_empty() {
        Err(CryptoError::InvalidArgument(what))
    } else {
        Ok(items)
    }
}

/// Removes duplicates and sorts in descending byte order (C++ `dedupeAndSortKeys`).
fn dedupe_and_sort(mut keys: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    keys.sort_unstable_by(|a, b| b.cmp(a));
    keys.dedup();
    keys
}

/// C++ `addKeys(a, b, c)`.
fn add_two(what: &'static str, a: &[u8; 32], b: &[u8; 32]) -> CryptoResult<[u8; 32]> {
    if xkr_crypto::sc_check(a) {
        let sum = Scalar::from_bytes_mod_order(*a) + Scalar::from_bytes_mod_order(*b);
        Ok(sum.to_bytes())
    } else {
        let sum = point(what, a)? + point(what, b)?;
        Ok(sum.compress().to_bytes())
    }
}

/// C++ `addKeys(keys)`: zero for no keys, the key itself for one.
fn add_all(what: &'static str, keys: &[[u8; 32]]) -> CryptoResult<[u8; 32]> {
    let Some((first, rest)) = keys.split_first() else {
        return Ok([0u8; 32]);
    };
    rest.iter()
        .try_fold(*first, |sum, key| add_two(what, &sum, key))
}

/// C++ `calculate_multisig_private_key`: `H_s(8 * sec * P)`.
fn multisig_private_key(public: &[u8; 32], sec: &Scalar) -> CryptoResult<String> {
    let p = point("public_keys", public)?;
    let shared = (p * sec).mul_by_cofactor().compress().to_bytes();
    Ok(to_hex(&xkr_crypto::hash_to_scalar(&shared).to_bytes()))
}

/// `calculateMultisigPrivateKeys(private_spend_key, public_keys)`: one key per other
/// participant; `public_keys` must not be empty.
pub fn calculate_multisig_private_keys<S: AsRef<str>>(
    private_spend_key: &str,
    public_keys: &[S],
) -> CryptoResult<Vec<String>> {
    let sec = canonical(
        "private_spend_key",
        &parse32("private_spend_key", private_spend_key)?,
    )?;
    non_empty("public_keys", parse_list32("public_keys", public_keys)?)?
        .iter()
        .map(|public| multisig_private_key(public, &sec))
        .collect()
}

/// `calculateSharedPrivateKey(private_keys)`: the sum of the distinct keys (at least one).
pub fn calculate_shared_private_key<S: AsRef<str>>(private_keys: &[S]) -> CryptoResult<String> {
    let keys = dedupe_and_sort(non_empty(
        "private_keys",
        parse_list32("private_keys", private_keys)?,
    )?);
    Ok(to_hex(&add_all("private_keys", &keys)?))
}

/// `calculateSharedPublicKey(public_keys)`: the sum of the distinct keys (at least one).
pub fn calculate_shared_public_key<S: AsRef<str>>(public_keys: &[S]) -> CryptoResult<String> {
    let keys = dedupe_and_sort(non_empty(
        "public_keys",
        parse_list32("public_keys", public_keys)?,
    )?);
    Ok(to_hex(&add_all("public_keys", &keys)?))
}

/// C++ `generate_partial_signing_key`: `c * x` mod `l`, `c` the first half of the signature.
fn partial_signing_key(signature: &[u8; 64], private_key: &[u8; 32]) -> [u8; 32] {
    let mut c = [0u8; 32];
    c.copy_from_slice(&signature[..32]);
    (Scalar::from_bytes_mod_order(c) * Scalar::from_bytes_mod_order(*private_key)).to_bytes()
}

/// `generatePartialSigningKey(signature, private_key)`.
pub fn generate_partial_signing_key(signature: &str, private_key: &str) -> CryptoResult<String> {
    let signature = parse_fixed::<64>("signature", signature)?;
    let private_key = parse32("private_key", private_key)?;
    Ok(to_hex(&partial_signing_key(&signature, &private_key)))
}

/// `restoreKeyImage(public_ephemeral, derivation, output_index, partial_key_images)`: the key
/// image of the output's derivation part plus the distinct partial key images (at least one).
pub fn restore_key_image<S: AsRef<str>>(
    public_ephemeral: &str,
    derivation: &str,
    output_index: u64,
    partial_key_images: &[S],
) -> CryptoResult<String> {
    let public = PublicKey(parse32("public_ephemeral", public_ephemeral)?);
    let derivation = KeyDerivation(parse32("derivation", derivation)?);
    let partials = dedupe_and_sort(non_empty(
        "partial_key_images",
        parse_list32("partial_key_images", partial_key_images)?,
    )?);
    let scalar = xkr_crypto::derivation_to_scalar(&derivation, output_index);
    let base = xkr_crypto::generate_key_image(&public, &SecretKey(scalar.to_bytes()));
    let mut keys = Vec::with_capacity(partials.len() + 1);
    keys.push(base.0);
    keys.extend(partials);
    Ok(to_hex(&add_all("partial_key_images", &keys)?))
}

/// `restoreRingSignatures(derivation, output_index, partial_signing_keys, real_output_index, k,
/// signatures)`: completes the real member's signature with `r = k - (c * H_s(D, i) + sum of
/// the distinct partial signing keys)`; at least one partial signing key.
pub fn restore_ring_signatures<S: AsRef<str>, T: AsRef<str>>(
    derivation: &str,
    output_index: u64,
    partial_signing_keys: &[S],
    real_output_index: u64,
    k: &str,
    signatures: &[T],
) -> CryptoResult<Vec<String>> {
    let derivation = KeyDerivation(parse32("derivation", derivation)?);
    let k = canonical("k", &parse32("k", k)?)?;
    let mut sigs = signatures
        .iter()
        .map(|s| parse_fixed::<64>("signatures", s.as_ref()))
        .collect::<CryptoResult<Vec<[u8; 64]>>>()?;
    let partials = non_empty(
        "partial_signing_keys",
        parse_list32("partial_signing_keys", partial_signing_keys)?,
    )?;
    for key in &partials {
        canonical("partial_signing_keys", key)?;
    }
    let real = usize::try_from(real_output_index)
        .ok()
        .filter(|i| *i < sigs.len())
        .ok_or(CryptoError::InvalidIndex("real_output_index"))?;
    let scalar = xkr_crypto::derivation_to_scalar(&derivation, output_index);
    let own = partial_signing_key(&sigs[real], &scalar.to_bytes());
    let mut keys = Vec::with_capacity(partials.len() + 1);
    keys.push(own);
    keys.extend(dedupe_and_sort(partials));
    let total = add_all("partial_signing_keys", &keys)?;
    let r = k - Scalar::from_bytes_mod_order(total);
    sigs[real][32..].copy_from_slice(&r.to_bytes());
    Ok(sigs.iter().map(hex::encode).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupe_sorts_descending() {
        let keys = dedupe_and_sort(vec![[1; 32], [3; 32], [1; 32], [2; 32]]);
        assert_eq!(keys, vec![[3; 32], [2; 32], [1; 32]]);
    }

    #[test]
    fn empty_key_lists_are_refused() {
        let none: [&str; 0] = [];
        let key = "01".repeat(32);
        assert_eq!(
            calculate_shared_private_key(&none),
            Err(CryptoError::InvalidArgument("private_keys"))
        );
        assert_eq!(
            calculate_shared_public_key(&none),
            Err(CryptoError::InvalidArgument("public_keys"))
        );
        assert_eq!(
            calculate_multisig_private_keys(&key, &none),
            Err(CryptoError::InvalidArgument("public_keys"))
        );
        assert_eq!(
            restore_key_image(&key, &key, 0, &none),
            Err(CryptoError::InvalidArgument("partial_key_images"))
        );
        assert_eq!(
            restore_ring_signatures(&key, 0, &none, 0, &key, &["00".repeat(64)]),
            Err(CryptoError::InvalidArgument("partial_signing_keys"))
        );
    }

    #[test]
    fn no_keys_add_up_to_zero_and_one_key_to_itself() {
        assert_eq!(add_all("k", &[]).unwrap(), [0u8; 32]);
        assert_eq!(add_all("k", &[[7; 32]]).unwrap(), [7; 32]);
    }
}
