//! Crypto utility module wrapped on-top of `mbedtls` for `rust-sgx` applications

/// Ephemeral key managment based on curve 25519
pub mod ephemeral_diffie_hellman;
/// RSA verification key management
pub mod verification_key;
/// Hashing utilities
pub mod hash {
    use mbedtls::hash::{Md as Hasher, Type as HashType};
    pub fn sha256(data: &[u8], out: &mut [u8]) {
        Hasher::hash(HashType::Sha256, data, out).unwrap();
    }
}

pub mod intel {
    use attestation_types::{H128, Public};

    pub fn quote_manifest(g_a: Public, g_b: Public, vk: H128) -> [u8; 64] {
        let mut input: Vec<u8> = Vec::new();
        let mut digest = [0_u8; 64];

        input.extend(g_a.as_bytes());
        input.extend(g_b.as_bytes());
        input.extend(vk.as_bytes());
        crate::hash::sha256(&input, &mut digest);
        digest
    }
}

pub mod mac;
pub mod key_derivation;
