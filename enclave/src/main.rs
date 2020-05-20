#![allow(unused)]

mod remote_attestation;

use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::{TcpListener, TcpStream};

use aesm_client::sgx::AesmClientExt;
use aesm_client::AesmClient;
use crypto::verification_key::{Keypair as VerificationKeypair};
use crypto::ephemeral_diffie_hellman::{Keypair as EphemeralKeypair};
use sgx_isa::{Report, Targetinfo};

const SOCKADDR: &str = "127.0.0.1:63001";
const QUOTING_SOCKADDR: &str = "127.0.0.1:63002";
const PRIVATE_KEY_PEM: &[u8] = std::include_bytes!("../../private.pem");

fn main() -> std::io::Result<()> {
    println!("Starting Enclave: {}", SOCKADDR);
    let stream = TcpListener::bind(SOCKADDR)?.accept()?.0;
    // TODO(should return `signing key || master key`)
    remote_attestation::attest(VerificationKeypair::from_private_key_pem_bytes(PRIVATE_KEY_PEM), EphemeralKeypair::new(), stream);

    Ok(())
}
