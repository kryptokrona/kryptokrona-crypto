//! Hex parsing shared by the modules of this crate and the napi binding.

use xkr_crypto::{EdwardsPoint, Scalar};

use crate::{CryptoError, CryptoResult};

/// Exactly 32 bytes from 64 hex characters (upper or lower case).
pub fn parse32(what: &'static str, hex: &str) -> CryptoResult<[u8; 32]> {
    parse_fixed(what, hex)
}

/// Exactly `N` bytes from `2 * N` hex characters.
pub fn parse_fixed<const N: usize>(what: &'static str, hex: &str) -> CryptoResult<[u8; N]> {
    if hex.len() != 2 * N {
        return Err(CryptoError::InvalidLength {
            what,
            expected: 2 * N,
            got: hex.len(),
        });
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(hex, &mut out).map_err(|_| CryptoError::InvalidHex(what))?;
    Ok(out)
}

/// Any even number of hex characters.
pub fn parse_bytes(what: &'static str, hex: &str) -> CryptoResult<Vec<u8>> {
    hex::decode(hex).map_err(|_| CryptoError::InvalidHex(what))
}

/// A list of 32-byte values.
pub fn parse_list32<S: AsRef<str>>(what: &'static str, items: &[S]) -> CryptoResult<Vec<[u8; 32]>> {
    items.iter().map(|s| parse32(what, s.as_ref())).collect()
}

/// A point encoding as C++ `ge_frombytes_vartime` accepts it.
pub fn point(what: &'static str, bytes: &[u8; 32]) -> CryptoResult<EdwardsPoint> {
    xkr_crypto::decompress(bytes).ok_or(CryptoError::InvalidPublicKey(what))
}

/// A canonical scalar (`< l`, C++ `sc_check == 0`).
pub fn canonical(what: &'static str, bytes: &[u8; 32]) -> CryptoResult<Scalar> {
    Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes))
        .ok_or(CryptoError::InvalidScalar(what))
}

/// 32 bytes as lowercase hex.
#[must_use]
pub fn to_hex(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

/// A JavaScript number used as an index or count: finite, integral, `0 ..= 2^53 - 1`.
pub fn js_index(what: &'static str, value: f64) -> CryptoResult<u64> {
    const MAX_SAFE: f64 = 9_007_199_254_740_991.0;
    let integral = value.fract().abs().to_bits() == 0;
    if value.is_finite() && (0.0..=MAX_SAFE).contains(&value) && integral {
        Ok(value as u64)
    } else {
        Err(CryptoError::InvalidIndex(what))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_index_rules() {
        assert_eq!(js_index("i", 0.0), Ok(0));
        assert_eq!(
            js_index("i", 9_007_199_254_740_991.0),
            Ok(9_007_199_254_740_991)
        );
        assert_eq!(js_index("i", -1.0), Err(CryptoError::InvalidIndex("i")));
        assert_eq!(js_index("i", 0.5), Err(CryptoError::InvalidIndex("i")));
        assert_eq!(js_index("i", f64::NAN), Err(CryptoError::InvalidIndex("i")));
    }

    #[test]
    fn fixed_values_need_their_exact_length() {
        assert!(parse32("x", "00").is_err());
        assert!(parse32("x", &"zz".repeat(32)).is_err());
        assert_eq!(parse32("x", &"AB".repeat(32)), Ok([0xab; 32]));
    }
}
