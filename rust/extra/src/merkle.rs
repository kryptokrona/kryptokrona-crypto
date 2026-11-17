//! `tree_hash_from_branch(branches, leaf, path)`.

use xkr_types::Hash;

use crate::CryptoResult;
use crate::hex32::{parse_list32, parse32, to_hex};

/// The side selection of [`tree_hash_from_branch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchPath {
    /// The leaf is always on the left (`path` 0: the parent block's miner transaction).
    Left,
    /// Bit `d` of the 32 bytes (byte `d >> 3`, bit `d & 7`) puts the running hash on the right
    /// at depth `d`.
    Bits([u8; 32]),
}

impl BranchPath {
    /// The path from a JavaScript number: 0 is [`BranchPath::Left`], any other value gives its
    /// bits in little-endian order.
    #[must_use]
    pub fn from_number(path: u64) -> Self {
        if path == 0 {
            Self::Left
        } else {
            let mut bits = [0u8; 32];
            bits[..8].copy_from_slice(&path.to_le_bytes());
            Self::Bits(bits)
        }
    }
}

/// The Merkle root from a branch, the leaf and the path (C++ `tree_hash_from_branch`).
pub fn tree_hash_from_branch<S: AsRef<str>>(
    branches: &[S],
    leaf: &str,
    path: BranchPath,
) -> CryptoResult<String> {
    let branch: Vec<Hash> = parse_list32("branches", branches)?
        .into_iter()
        .map(Hash)
        .collect();
    let leaf = Hash(parse32("leaf", leaf)?);
    let root = match path {
        BranchPath::Left => xkr_crypto::tree_hash_from_branch(&branch, &leaf, None),
        BranchPath::Bits(bits) => {
            xkr_crypto::tree_hash_from_branch(&branch, &leaf, Some(&Hash(bits)))
        }
    };
    Ok(to_hex(&root.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASHES: [&str; 4] = [
        "b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0",
        "1b606a3f4a07d6489a1bcd07697bd16696b61c8ae982f61a90160f4e52828a7f",
        "c9fae8425d8688dc236bcdbc42fdb42d376c6ec190501aa84b04a4b4cf1ee122",
        "871fcd6823f6a879bb3f33951c8e8e891d4043880b02dfa1bb3be498b50e7578",
    ];

    #[test]
    fn the_branch_of_the_first_hash_gives_the_tree_hash() {
        // kryptokrona-crypto tests/crypto.ts: tree_hash and tree_branch of these four hashes
        let root = xkr_crypto_ffi::api::tree_hash(&HASHES).unwrap();
        assert_eq!(
            root,
            "dff9b4e047803822e97fb25bb9acb8320648954e15a6ddf6fa757873793c535e"
        );
        let branch = xkr_crypto_ffi::api::tree_branch(&HASHES).unwrap();
        assert_eq!(
            tree_hash_from_branch(&branch, HASHES[0], BranchPath::Left).unwrap(),
            root
        );
        assert_eq!(
            tree_hash_from_branch(&branch, HASHES[0], BranchPath::from_number(0)).unwrap(),
            root
        );
    }

    #[test]
    fn an_empty_branch_is_the_leaf() {
        let none: [&str; 0] = [];
        assert_eq!(
            tree_hash_from_branch(&none, HASHES[2], BranchPath::from_number(5)).unwrap(),
            HASHES[2]
        );
    }
}
