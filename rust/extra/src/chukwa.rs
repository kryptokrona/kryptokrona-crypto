//! Chukwa: Argon2id (version 0x13) with the first 16 bytes of the input as salt and a 32-byte
//! output (C++ `chukwa_slow_hash_base`).

use argon2::{Algorithm, Argon2, Params, Version};

use crate::hex32::{parse_bytes, to_hex};
use crate::{CryptoError, CryptoResult};

/// Bytes of the input used as salt.
pub const SALT_LEN: usize = 16;

/// `chukwa_slow_hash_base(data, iterations, memory, threads)`: `memory` in KiB. The data must
/// have at least [`SALT_LEN`] bytes.
pub fn chukwa_slow_hash_base(
    data: &str,
    iterations: u32,
    memory: u32,
    threads: u32,
) -> CryptoResult<String> {
    let bytes = parse_bytes("data", data)?;
    if bytes.len() < SALT_LEN {
        return Err(CryptoError::DataCanNotBeHashed);
    }
    let params = Params::new(memory, iterations, threads, Some(32))
        .map_err(|_| CryptoError::InvalidArgument("chukwa parameters"))?;
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(&bytes, &bytes[..SALT_LEN], &mut out)
        .map_err(|_| CryptoError::InvalidArgument("chukwa parameters"))?;
    Ok(to_hex(&out))
}

/// `chukwa_slow_hash_v1(data)`: 3 iterations, 512 KiB, 1 lane.
pub fn chukwa_slow_hash_v1(data: &str) -> CryptoResult<String> {
    chukwa_slow_hash_base(data, 3, 512, 1)
}

/// `chukwa_slow_hash_v2(data)`: 4 iterations, 1024 KiB, 1 lane.
pub fn chukwa_slow_hash_v2(data: &str) -> CryptoResult<String> {
    chukwa_slow_hash_base(data, 4, 1024, 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TESTDATA: &str = "0100fb8e8ac805899323371bb790db19218afd8db8e3755d8b90f39b3d5506a9abce4fa912244500000000ee8146d49fa93ee724deb57d12cbc6c6f3b924d946127c7a97418f9348828f0f02";

    #[test]
    fn known_answers_of_kryptokrona_crypto() {
        // tests/crypto.ts, "Hash Generation Methods"
        assert_eq!(
            chukwa_slow_hash_v1(TESTDATA).unwrap(),
            "c0dad0eeb9c52e92a1c3aa5b76a3cb90bd7376c28dce191ceeb1096e3a390d2e"
        );
        assert_eq!(
            chukwa_slow_hash_v2(TESTDATA).unwrap(),
            "3578c135261366a7bac407b8c0ff50f3ad96f096ec2813e9644e6e77a43f803d"
        );
        assert_eq!(
            chukwa_slow_hash_base(TESTDATA, 4, 1024, 1).unwrap(),
            chukwa_slow_hash_v2(TESTDATA).unwrap()
        );
    }

    #[test]
    fn short_data_and_bad_parameters_are_refused() {
        assert_eq!(
            chukwa_slow_hash_v1("00"),
            Err(CryptoError::DataCanNotBeHashed)
        );
        assert!(chukwa_slow_hash_base(TESTDATA, 0, 512, 1).is_err());
    }
}
