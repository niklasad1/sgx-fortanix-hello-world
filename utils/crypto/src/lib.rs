//! Crypto utility module wrapped on-top of `mbedtls` for `rust-sgx` applications

/// Ephemeral key managment based on curve 25519
pub mod key_agreement;
/// Hashing utilities
pub mod hash;
/// Intel specific key derivation
pub mod key_derivation;
/// Message authentication
pub mod mac;

pub mod x509 {
    use mbedtls::x509::Certificate as InnerCertificate;
    use mbedtls::hash::Md as Hash;

    #[derive(Debug, Clone)]
    pub struct Certificate(InnerCertificate);

    impl Certificate {
        pub fn from_pem(bytes: &[u8]) -> Certificate {
            let mut bytes = bytes.to_vec();
            match bytes.last().copied() {
                Some(0) => (),
                Some(_) => bytes.push(0_u8),
                None => panic!("Can't generate from empty certificate"),
            };
            Self(InnerCertificate::from_pem(&bytes).unwrap())
        }

        pub fn verify_certificate(&mut self, root_ca: &mut Self) -> Result<(), ()> {
            self.0.verify(&mut root_ca.0, None).map_err(|_e| ())
        }

        pub fn verify_signature(&mut self, msg: &[u8], signature: &[u8]) -> Result<(), ()> {
            let mut digest = [0_u8; 32];
            let digest_type = self.0.digest_type();
            Hash::hash(digest_type, msg, &mut digest).unwrap();
            self.0
                .public_key_mut()
                .verify(digest_type, &digest, signature)
                .map_err(|_e| ())
        }
    }

    // TODO: do something better, want handle revocation lists
    impl PartialEq for Certificate {
        fn eq(&self, other: &Self) -> bool {
            self.0.as_der() == other.0.as_der()
        }
    }
}

