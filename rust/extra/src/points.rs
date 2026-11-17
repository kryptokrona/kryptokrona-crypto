//! `scalarmultKey(key_image_a, key_image_b)`: the point `A` times the 32 bytes of `B` read as
//! an integer, not reduced mod `l` (so `scalarmultKey(I, l)` is the identity exactly when `I`
//! lies in the prime-order subgroup).
//!
//! The multiplier is evaluated in the signed radix-16 digits of C++ `ge_scalarmult`: 64 digits
//! in `-8 ..= 8`, the top one may reach 16 when the last byte is above 127 and then counts as
//! 0, as in `ge_scalarmult`. For every multiplier below `2^255` the result is the plain product.

use xkr_crypto::EdwardsPoint;

use crate::CryptoResult;
use crate::hex32::{parse32, point, to_hex};

/// The 64 signed radix-16 digits of `ge_scalarmult`, least significant first.
fn radix16(a: &[u8; 32]) -> [i32; 64] {
    let mut e = [0i32; 64];
    let mut carry = 0i32;
    for (i, byte) in a.iter().enumerate().take(31) {
        carry += i32::from(*byte);
        let carry2 = (carry + 8) >> 4;
        e[2 * i] = carry - (carry2 << 4);
        carry = (carry2 + 8) >> 4;
        e[2 * i + 1] = carry2 - (carry << 4);
    }
    carry += i32::from(a[31]);
    let carry2 = (carry + 8) >> 4;
    e[62] = carry - (carry2 << 4);
    e[63] = carry2;
    e
}

/// `A * a` with the digit rule of `ge_scalarmult` (variable time; the inputs are public).
#[must_use]
pub fn scalarmult(a_point: &EdwardsPoint, a: &[u8; 32]) -> EdwardsPoint {
    // 1A .. 8A
    let mut table = Vec::with_capacity(8);
    let mut multiple = *a_point;
    for _ in 0..8 {
        table.push(multiple);
        multiple += a_point;
    }
    let mut r = EdwardsPoint::default();
    for digit in radix16(a).iter().rev() {
        for _ in 0..4 {
            let twice = r;
            r += twice;
        }
        let magnitude = digit.unsigned_abs() as usize;
        if (1..=8).contains(&magnitude) {
            let term = table[magnitude - 1];
            r = if *digit < 0 { r - term } else { r + term };
        }
    }
    r
}

/// `scalarmultKey(key_image_a, key_image_b)`: `A` must be a valid point encoding.
pub fn scalarmult_key(key_image_a: &str, key_image_b: &str) -> CryptoResult<String> {
    let a = point("key_image_a", &parse32("key_image_a", key_image_a)?)?;
    let b = parse32("key_image_b", key_image_b)?;
    Ok(to_hex(&scalarmult(&a, &b).compress().to_bytes()))
}

#[cfg(test)]
mod tests {
    use xkr_crypto::Scalar;

    use super::*;

    /// l = 2^252 + 27742317777372353535851937790883648493, little-endian
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    #[test]
    fn digits_stay_in_the_table_range() {
        for a in [[0u8; 32], [0x7f; 32], L, [0x88; 32], [0xff; 32]] {
            let e = radix16(&a);
            assert!(e[..63].iter().all(|d| (-8..=8).contains(d)));
        }
        assert_eq!(radix16(&[0xff; 32])[63], 16);
    }

    #[test]
    fn canonical_multipliers_match_scalar_multiplication() {
        let p = EdwardsPoint::mul_base(&Scalar::from(7u64));
        for k in [1u64, 2, 15, 16, 255, 256, 123_456_789] {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&k.to_le_bytes());
            assert_eq!(scalarmult(&p, &bytes), p * Scalar::from(k));
        }
    }

    #[test]
    fn l_times_a_subgroup_point_is_the_identity() {
        let p = EdwardsPoint::mul_base(&Scalar::from(12_345u64));
        assert_eq!(scalarmult(&p, &L), EdwardsPoint::default());
        let image = to_hex(&p.compress().to_bytes());
        let identity = to_hex(&EdwardsPoint::default().compress().to_bytes());
        assert_eq!(scalarmult_key(&image, &to_hex(&L)).unwrap(), identity);
    }
}
