//! Crypto utility module wrapped on-top of `mbedtls` for `rust-sgx` applications

/// Ephemeral key managment based on curve 25519
pub mod ephemeral_diffie_hellman;
/// Intel specific keys and related constants
pub mod intel;
/// RSA verification key management
pub mod verification_key;
/// Hashing utilities
pub mod hash {
    use mbedtls::hash::{Md as Hasher, Type as HashType};
    pub fn sha256(data: &[u8], out: &mut [u8]) {
        Hasher::hash(HashType::Sha256, data, out).unwrap();
    }
}
