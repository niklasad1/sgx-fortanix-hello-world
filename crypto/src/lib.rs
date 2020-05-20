use mbedtls::bignum::Mpi;
use mbedtls::ecp::{EcGroup, EcPoint};
use mbedtls::pk::{EcGroupId, Pk};
use mbedtls::rng::Rdrand;
use mbedtls::hash::{Md as Hasher, Type as HashType};

const PRIVATE_PEM: &[u8] = std::include_bytes!("../../private.pem");

pub const CURVE_25519_PUBLIC_KEY_SIZE: usize = 32;
pub const CURVE_25519_PRIVATE_KEY_SIZE: usize = 32;
pub const CURVE_25519_SHARED_SECRET_SIZE: usize = 32;

/// Intel Service Provider ID
pub const SPID_SIZE: usize = 16;

pub struct RsaVerificationKeypair(Pk);

impl RsaVerificationKeypair {
    pub fn new() -> Self {
        // mbedtls requires `\0` terminated buffer
        let mut key: Vec<u8> = PRIVATE_PEM.to_vec();
        key.push(0x00);
        Self(Pk::from_private_key(&key, None).unwrap())
    }
}

pub struct EphemeralKeypair(Pk);

impl EphemeralKeypair {
    pub fn new() -> Self {
        Self(Pk::generate_ec(&mut Rdrand, EcGroupId::Curve25519).unwrap())
    }

    pub fn public(&self) -> Vec<u8> {
        let ec_group = self.0.ec_public().unwrap();
        let mut g_a = Vec::new();
        g_a.extend(ec_group.x().unwrap().to_binary().unwrap());
        g_a.extend(ec_group.y().unwrap().to_binary().unwrap());
        assert_eq!(g_a.len(), CURVE_25519_PUBLIC_KEY_SIZE);
        g_a
    }

    /// Compute a shared secret also known as `g_ab`
    pub fn shared_secret(&mut self, public: &[u8]) -> Vec<u8> {
        let mut shared = vec![0_u8; CURVE_25519_SHARED_SECRET_SIZE];

        let x = Mpi::from_binary(&public[0..16]).unwrap();
        let y = Mpi::from_binary(&public[16..]).unwrap();
        let ec_point = EcPoint::from_components(x, y).unwrap();

        let curve = EcGroup::new(EcGroupId::Curve25519).unwrap();
        let other = Pk::public_from_ec_components(curve, ec_point).unwrap();

        self.0.agree(&other, &mut shared, &mut Rdrand).unwrap();
        shared
    }
}

pub fn sha256(data: &[u8], out: &mut [u8]) {
    Hasher::hash(HashType::Sha256, data, out).unwrap();
}
