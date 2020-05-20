use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

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

    pub fn public_key(&self) -> [u8; 32] {
        let mut p = [0_u8; 32];
        p.copy_from_slice(self.public.as_bytes());
        p
    }

    /// Compute a shared secret also known as `g_ab`
    pub fn shared_secret(&self, p: [u8; 32]) -> [u8; 32] {
        let mut secret = [0_u8; 32];
        secret.copy_from_slice(self.secret.diffie_hellman(&PublicKey::from(p)).as_bytes());
        secret
    }
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
