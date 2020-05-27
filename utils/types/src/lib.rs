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

pub mod attestation_messages;
pub mod error;

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
