#![allow(unused)]

mod remote_attestation;

use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::{TcpListener, TcpStream};

use aesm_client::sgx::AesmClientExt;
use aesm_client::AesmClient;
use crypto::{RsaVerificationKeypair, EphemeralKeypair};
use sgx_isa::{Report, Targetinfo};

const SOCKADDR: &str = "127.0.0.1:63001";
const QUOTING_SOCKADDR: &str = "127.0.0.1:63002";


fn main() -> std::io::Result<()> {
    println!("Starting Enclave: {}", SOCKADDR);
    let stream = TcpListener::bind(SOCKADDR)?.accept()?.0;
    // TODO(should return `signing key || master key`)
    remote_attestation::attest(RsaVerificationKeypair::new(), EphemeralKeypair::new(), stream);

    Ok(())
}
