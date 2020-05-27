use mbedtls::hash::{Md as Hasher, Type as HashType};

pub fn sha256(data: &[u8], out: &mut [u8]) {
    Hasher::hash(HashType::Sha256, data, out).unwrap();
}
