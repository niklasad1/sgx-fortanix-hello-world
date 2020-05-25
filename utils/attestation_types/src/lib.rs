//! Remote Attestation types
//!
//! Based on https://software.intel.com/content/www/us/en/develop/articles/code-sample-intel-software-guard-extensions-remote-attestation-end-to-end-example.html
//!
//! # Acronyms
//!     - GID: Group ID used by the Intel Attestation Service to verify that a given key is a valid Intel key
//!     - SPID: Service Provider ID
//!     - Quote: Special enclave to rely on Intel Attestation Service to verify validity of an enclave
//!  
//!  # Description
//!
//!  For attestation we will have four different modules/entities
//!     1) Application enclave
//!     2) Application (or Client application)
//!     3) Service provider
//!     4) Intel attestation Service (IAS)
//!
//! The flow is quite completed but it depends on four different stages or messages as this crate
//! provides.
//!
//!

use fixed_hash::construct_fixed_hash;
use serde::{Deserialize, Serialize};
use uint::construct_uint;

construct_uint! {
    #[derive(Serialize, Deserialize)]
    pub struct U128(16);
}

construct_fixed_hash! {
    #[derive(Serialize, Deserialize)]
    pub struct H128(16);
}

construct_fixed_hash! {
    #[derive(Serialize, Deserialize)]
    pub struct H256(32);
}

pub type Public = H256;
pub type Private = H256;
pub type Signature = H256;
pub type SharedSecret = H256;
pub type Nonce = Vec<u8>;
pub type Spid = Vec<u8>;
pub type Mac = H128;

/// Sent from the Client to the Service Provider
///
/// If the extended group ID = 0, then Intel is the attestation service for the device.  Continue msg1 -> msg4 as normal.
/// If the extended group ID != 0, then a third party is providing the attestation service and the system was provisioned by the third party, so the messages need to follow that implementation.
///
/// Hardcoded to `0` for now
#[derive(Debug, Serialize, Deserialize)]
pub struct MessageZero {
    pub extended_gid: u64,
}

/// Client -> Service Provider
#[derive(Debug, Serialize, Deserialize)]
pub struct MessageOne {
    /// Ephemeral public key of the enclave
    pub g_a: Public,
    /// GID fetched by the client from the `aesmd service`
    pub gid: Vec<u8>,
}

/// Service Provider -> Client -> Application Enclave
#[derive(Debug, Serialize, Deserialize)]
pub struct MessageTwo {
    pub g_ab: Signature,
    pub g_b: Public,
    pub kdf_id: u32,
    pub quote_kind: u32,
    pub sig_rl: Vec<u8>,
    pub spid: Spid,
    pub mac: Mac,
}

impl MessageTwo {
    pub fn new<Mac: Fn(&H128, &[u8]) -> H128>(
        g_ab: Signature,
        g_b: Public,
        quote_kind: u32,
        sig_rl: Vec<u8>,
        spid: Spid,
        smk: &H128,
        mac: Mac,
    ) -> Self {
        let mut msg = Self {
            g_ab,
            g_b,
            kdf_id: 0x1,
            quote_kind,
            sig_rl,
            spid,
            mac: Default::default(),
        };
        let raw = msg.as_raw();
        msg.mac = mac(smk, &raw);
        msg
    }

    pub fn verify<Mac: Fn(&H128, &[u8], &H128) -> bool>(
        &self,
        smk: &H128,
        mac: Mac,
    ) -> bool {
        let raw = self.as_raw();
        mac(smk, &raw, &self.mac)
    }

    fn as_raw(&self) -> Vec<u8> {
        let mut raw: Vec<u8> = Vec::new();
        raw.extend(self.g_ab.as_bytes());
        raw.extend(self.g_b.as_bytes());
        raw.extend(&self.kdf_id.to_ne_bytes());
        raw.extend(&self.quote_kind.to_ne_bytes());
        raw.extend(self.sig_rl.clone());
        raw.extend(self.spid.clone());
        raw
    }
}

/// Client -> Service Provider
#[derive(Debug, Serialize, Deserialize)]
pub struct MessageThree {
    pub g_a: Public,
    pub ps_security_prop: Vec<u8>,
    pub quote: Vec<u8>,
    pub mac: Mac,
}

impl MessageThree {
    pub fn new<Mac: Fn(&H128, &[u8]) -> H128>(
        g_a: Public,
        ps_security_prop: Vec<u8>,
        quote: Vec<u8>,
        m: Mac,
        smk: &H128,
    ) -> Self {

       let mut msg = Self {
            g_a,
            ps_security_prop,
            quote,
            mac: Default::default(),
        };
        let raw = msg.as_raw();
        msg.mac = m(smk, &raw);
        msg
    }

    pub fn verify<Mac: Fn(&H128, &[u8], &H128) -> bool>(
        &self,
        smk: &H128,
        mac: Mac,
    ) -> bool {
        let raw = self.as_raw();
        mac(smk, &raw, &self.mac)
    }

    fn as_raw(&self) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend(self.g_a.as_bytes());
        raw.extend(self.ps_security_prop.clone());
        raw.extend(self.quote.clone());
        raw
    }
}

/// Service provider -> Client
#[derive(Debug, Serialize, Deserialize)]
pub struct MessageFour {
    pub encrypted_secret: Vec<u8>,
}
