//! Attestation crate
//!
//! Enclave                                 Client
//!
//! 1. ->  Send its public key (g_c)
//!
//! 2. Generate shared secret (g_ec)
//!    <-  (g_e | spid | quote_kind | g_ec | sig_rl)
//!
//! 3.
//!     i) Verify shared secret
//!     ii) compute manifest sha256(g_e | g_c)
//!     iii) generate target report,  report(manifest, target_info)
//!     iiii) qoute(report)
//!
//!   -> Quote
//!
//! 4.
//!     i) send `Quote` to the IAS (Intel Attestation Service) for verification
//!     ii) valid or not
//!
//!   <- Status whether a secure channel has been established

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct EnclaveHello {
    pub g_e: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClientHello {
    /// Public key of the client
    pub g_c: [u8; 32],
    /// Shared secret
    pub g_ce: [u8; 32],
    // TODO(check if we need to send gid, quote_kind, revocation_list, spid)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QuoteReport {
    pub q: Vec<u8>,
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
