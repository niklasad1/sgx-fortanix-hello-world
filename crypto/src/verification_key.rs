// use mbedtls::bignum::Mpi;
// use mbedtls::ecp::{EcGroup, EcPoint};
use mbedtls::pk::Pk;
// use mbedtls::rng::Rdrand;

pub struct Keypair(Pk);

impl Keypair {
    pub fn from_private_key_pem_bytes(bytes: &[u8]) -> Self {
        let mut bytes = bytes.to_vec();
        match bytes.last().copied() {
            Some(0) => (),
            Some(_) => bytes.push(0_u8),
            None => panic!("Can't generate keypair from empty bytes"),
        };
        Self(Pk::from_private_key(&bytes, None).unwrap())
    }
}
