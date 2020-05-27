use rand_core::OsRng;
use types::Public;
use x25519_dalek::{StaticSecret, PublicKey};

pub struct EphemeralKeypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl EphemeralKeypair {
    pub fn new() -> Self {
        let secret = StaticSecret::new(&mut OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key(&self) -> Public {
        Public::from_slice(self.public.as_bytes())
    }

    /// Compute a shared secret also known as `g_ab`
    pub fn shared_secret(&self, p: Public) -> Public {
        let mut secret = [0_u8; 32];
        secret.copy_from_slice(self.secret.diffie_hellman(&PublicKey::from(p.to_fixed_bytes())).as_bytes());
        secret.into()
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
