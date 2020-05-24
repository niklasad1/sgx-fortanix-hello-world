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

use uint::construct_uint;
use fixed_hash::construct_fixed_hash;
use serde::{Deserialize, Serialize};

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
pub type Nonce = U128;
pub type Spid = H128;
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
    /// Public key of the service provider
    pub g_b: Public,
    /// Service provider ID
    pub spid: Spid,
    /// Linkable (1), Unlinkable (0)
    pub quote_kind: u32,
    /// Key derivation function ID
    pub kdf_id: u32,
    /// Digital signature
    // TODO(currently not signed)
    pub g_ab: Signature,
    /// Signature revocation list
    pub sig_rl: Vec<u8>,
    /// Message authentication code
    pub mac: Mac,
}

/// Client -> Service Provider
#[derive(Debug, Serialize, Deserialize)]
pub struct MessageThree {
    pub quote: Vec<u8>,
    pub ps_security_prop: Vec<u8>,
    pub g_a: Public,
    pub mac: Mac,
}

/// Service provider -> Client
#[derive(Debug, Serialize, Deserialize)]
pub struct MessageFour {
    pub encrypted_secret: Vec<u8>,
}
