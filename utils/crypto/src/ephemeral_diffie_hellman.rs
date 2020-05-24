use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use attestation_types::*;

pub struct Keypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl Keypair {
    pub fn new() -> Self {
        let secret = StaticSecret::new(&mut OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key(&self) -> Public {
        let mut p = [0_u8; 32];
        p.copy_from_slice(self.public.as_bytes());
        p.into()
    }

    /// Compute a shared secret also known as `g_ab`
    pub fn shared_secret(&self, p: Public) -> Public {
        let mut secret = [0_u8; 32];
        secret.copy_from_slice(self.secret.diffie_hellman(&PublicKey::from(p.to_fixed_bytes())).as_bytes());
        secret.into()
    }
}


/// 1. Generate a random EC key using the P-256 curve. This key will become Gb.
/// 2. Derive the key derivation key (KDK) from Ga and Gb:
///        a) Compute the shared secret using the client's public session key, Ga, and the service provider's private session key (obtained from Step 1), Gb. The result of this operation will be the x coordinate of Gab, denoted as Gabx.
///        b) Convert Gabx to little-endian byte order by reversing its bytes.
///        c) Perform an AES-128 CMAC on the little-endian form of Gabx using a block of 0x00 bytes for the key.
///        d) The result of 2.3 is the KDK.
///
/// Derive the SMK from the KDK by performing an AES-128 CMAC on the byte sequence:
///     0x01 || SMK || 0x00 || 0x80 || 0x00
///
pub fn derive_key(g_b: Public, g_a: Keypair) {
    let mut g_ab = g_a.shared_secret(g_b);
    
    g_ab.as_bytes_mut().reverse();



}



#[cfg(test)]
mod tests {
    use super::Keypair;

    #[test]
    fn key_agreement() {
        let mut key1 = Keypair::new();
        let mut key2 = Keypair::new();
        let secret_12 = key1.shared_secret(key2.public_key());
        let secret_21 = key2.shared_secret(key1.public_key());
        assert_eq!(secret_12, secret_21);
    }
}
